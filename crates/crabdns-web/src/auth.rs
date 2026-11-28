use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::{Duration, Instant};

use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version};
use aws_lc_rs::pbkdf2;
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use axum::Json;
use axum::extract::{ConnectInfo, Extension, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::RouterState;

// OWASP minimum recommended Argon2id parameters (19 MiB, 2 iterations, 1 lane).
const ARGON2ID_M_COST_KIB: u32 = 19_456;
const ARGON2ID_T_COST: u32 = 2;
const ARGON2ID_P_COST: u32 = 1;
const SESSION_COOKIE_NAME: &str = "crabdns_session";
const SESSION_TTL: Duration = Duration::from_hours(24);
const MAX_LOGIN_FAILURES: u32 = 5;
const LOGIN_WINDOW: Duration = Duration::from_secs(60);
const LOGIN_LOCKOUT: Duration = Duration::from_secs(60);
const MAX_LOGIN_ATTEMPT_ENTRIES: usize = 4_096;
const MAX_SESSIONS: usize = 256;

#[derive(Debug, Clone)]
struct LoginAttempt {
    failures: u32,
    window_start: Instant,
    locked_until: Option<Instant>,
}

pub struct LoginRateLimiter {
    attempts: DashMap<IpAddr, LoginAttempt>,
}

impl Default for LoginRateLimiter {
    fn default() -> Self {
        Self {
            attempts: DashMap::with_shard_amount(16),
        }
    }
}

impl LoginRateLimiter {
    pub fn tracked_entries(&self) -> usize {
        self.attempts.len()
    }

    pub fn prune_expired(&self) -> usize {
        self.prune_expired_at(Instant::now())
    }

    fn prune_expired_at(&self, now: Instant) -> usize {
        let before = self.attempts.len();
        self.attempts.retain(|_, entry| {
            let locked = entry.locked_until.is_some_and(|until| now < until);
            let active_window = now.duration_since(entry.window_start) <= LOGIN_WINDOW;
            locked || active_window
        });
        let after = self.attempts.len();
        if after == 0 || after.saturating_mul(4) < before {
            self.attempts.shrink_to_fit();
        }
        before.saturating_sub(after)
    }

    fn evict_oldest_batch(&self, count: usize) -> usize {
        let mut candidates: Vec<(IpAddr, Instant)> = self
            .attempts
            .iter()
            .map(|e| (*e.key(), e.value().window_start))
            .collect();
        if candidates.is_empty() || count == 0 {
            return 0;
        }
        let remove_n = count.min(candidates.len());
        if remove_n < candidates.len() {
            candidates.select_nth_unstable_by_key(remove_n - 1, |(_, ts)| *ts);
        }
        let mut removed = 0;
        for (ip, _) in candidates.into_iter().take(remove_n) {
            if self.attempts.remove(&ip).is_some() {
                removed += 1;
            }
        }
        removed
    }

    pub fn check_locked(&self, ip: IpAddr) -> Option<u64> {
        let now = Instant::now();
        let entry = self.attempts.get(&ip)?;
        if let Some(until) = entry.locked_until
            && now < until
        {
            return Some((until - now).as_secs().max(1));
        }
        if now.duration_since(entry.window_start) > LOGIN_WINDOW {
            drop(entry);
            self.attempts.remove(&ip);
        }
        None
    }

    pub fn record_failure(&self, ip: IpAddr) {
        let now = Instant::now();
        if !self.attempts.contains_key(&ip) && self.attempts.len() >= MAX_LOGIN_ATTEMPT_ENTRIES {
            self.prune_expired_at(now);
            if self.attempts.len() >= MAX_LOGIN_ATTEMPT_ENTRIES {
                let batch = (MAX_LOGIN_ATTEMPT_ENTRIES / 16).max(1);
                let _ = self.evict_oldest_batch(batch);
            }
        }
        let mut entry = self.attempts.entry(ip).or_insert(LoginAttempt {
            failures: 0,
            window_start: now,
            locked_until: None,
        });
        if now.duration_since(entry.window_start) > LOGIN_WINDOW {
            entry.failures = 0;
            entry.window_start = now;
            entry.locked_until = None;
        }
        entry.failures = entry.failures.saturating_add(1);
        if entry.failures >= MAX_LOGIN_FAILURES {
            entry.locked_until = Some(now + LOGIN_LOCKOUT);
        }
    }

    pub fn clear(&self, ip: IpAddr) {
        self.attempts.remove(&ip);
    }
}

#[derive(Debug, Clone)]
struct SessionEntry {
    username: String,
    expires_at: Instant,
}

pub struct SessionStore {
    sessions: DashMap<String, SessionEntry>,
}

impl Default for SessionStore {
    fn default() -> Self {
        Self {
            sessions: DashMap::with_shard_amount(8),
        }
    }
}

impl SessionStore {
    pub fn active_sessions(&self) -> usize {
        self.sessions.len()
    }

    pub fn prune_expired(&self) -> usize {
        self.prune_expired_at(Instant::now())
    }

    fn prune_expired_at(&self, now: Instant) -> usize {
        let before = self.sessions.len();
        self.sessions.retain(|_, entry| now < entry.expires_at);
        let after = self.sessions.len();
        if after == 0 || after.saturating_mul(4) < before {
            self.sessions.shrink_to_fit();
        }
        before.saturating_sub(after)
    }

    fn evict_earliest_session(&self) -> bool {
        let earliest = self
            .sessions
            .iter()
            .min_by_key(|e| e.value().expires_at)
            .map(|e| e.key().clone());
        if let Some(token) = earliest {
            self.sessions.remove(&token);
            true
        } else {
            false
        }
    }

    pub fn create_session(&self, username: &str) -> Option<String> {
        let now = Instant::now();
        self.prune_expired_at(now);
        while self.sessions.len() >= MAX_SESSIONS {
            if !self.evict_earliest_session() {
                break;
            }
        }

        let mut bytes = [0_u8; 32];
        SystemRandom::new().fill(&mut bytes).ok()?;
        let token = hex_encode(&bytes);
        self.sessions.insert(
            token.clone(),
            SessionEntry {
                username: username.to_string(),
                expires_at: now + SESSION_TTL,
            },
        );
        Some(token)
    }

    pub fn validate(&self, token: &str) -> Option<String> {
        let entry = self.sessions.get(token)?;
        if Instant::now() >= entry.expires_at {
            drop(entry);
            self.sessions.remove(token);
            return None;
        }
        Some(entry.username.clone())
    }

    pub fn revoke(&self, token: &str) {
        self.sessions.remove(token);
    }

    pub fn clear_all(&self) {
        self.sessions.clear();
    }
}

#[derive(Debug, Serialize, TS)]
#[ts(export)]
pub struct AuthStatusResponse {
    pub auth_enabled: bool,
    pub authenticated: bool,
    pub username: Option<String>,
}

#[derive(Debug, Deserialize, TS)]
#[ts(export)]
pub struct LoginPayload {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct LoginResponse {
    pub token: String,
    pub username: String,
}

#[derive(Debug, Deserialize, TS)]
#[ts(export)]
pub struct AuthUpdatePayload {
    pub enabled: bool,
    pub username: String,
    pub password: Option<String>,
}

fn argon2id_hasher() -> Result<Argon2<'static>, String> {
    let params = Params::new(ARGON2ID_M_COST_KIB, ARGON2ID_T_COST, ARGON2ID_P_COST, None)
        .map_err(|e| format!("invalid argon2id parameters: {e}"))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

pub fn hash_password(password: &str) -> Result<String, String> {
    argon2id_hasher()?
        .hash_password(password.as_bytes())
        .map(|hash| hash.to_string())
        .map_err(|e| format!("failed to hash password: {e}"))
}

pub fn verify_password(password: &str, stored_hash: &str) -> bool {
    if stored_hash.starts_with("$argon2id$") {
        let Ok(parsed) = PasswordHash::new(stored_hash) else {
            return false;
        };
        return Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok();
    }
    if stored_hash.starts_with("pbkdf2$") {
        return verify_pbkdf2_password(password, stored_hash);
    }
    false
}

fn verify_pbkdf2_password(password: &str, stored_hash: &str) -> bool {
    let mut parts = stored_hash.split('$');
    let (Some("pbkdf2"), Some(iter_str), Some(salt_hex), Some(hash_hex), None) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return false;
    };
    let Ok(iters_val) = iter_str.parse::<u32>() else {
        return false;
    };
    let Some(iters) = NonZeroU32::new(iters_val) else {
        return false;
    };
    let (Some(salt), Some(expected)) = (hex_decode(salt_hex), hex_decode(hash_hex)) else {
        return false;
    };
    pbkdf2::verify(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iters,
        &salt,
        password.as_bytes(),
        &expected,
    )
    .is_ok()
}

pub async fn require_auth(State(state): State<RouterState>, req: Request, next: Next) -> Response {
    let cfg = state.app.config.load();
    if !cfg.web_auth_enabled {
        return next.run(req).await;
    }

    if let Some(token) = extract_token(req.headers())
        && state.sessions.validate(&token).is_some()
    {
        return next.run(req).await;
    }

    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({ "error": "Unauthorized" })),
    )
        .into_response()
}

fn has_bearer_auth(headers: &HeaderMap) -> bool {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| s.trim().len() > 7 && s.trim()[..7].eq_ignore_ascii_case("bearer "))
}

fn extract_authority_from_url(raw: &str) -> Option<&str> {
    let rest = raw
        .strip_prefix("https://")
        .or_else(|| raw.strip_prefix("http://"))?;
    Some(rest.split(['/', '?', '#']).next().unwrap_or(""))
}

fn is_csrf_origin_valid(headers: &HeaderMap) -> bool {
    if let Some(sec_fetch) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        let val = sec_fetch.trim();
        if !val.eq_ignore_ascii_case("same-origin") && !val.eq_ignore_ascii_case("none") {
            return false;
        }
    }

    let Some(host) = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|h| !h.is_empty())
    else {
        return false;
    };

    if let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        return extract_authority_from_url(origin.trim())
            .is_some_and(|auth| auth.eq_ignore_ascii_case(host));
    }

    if let Some(referer) = headers.get(header::REFERER).and_then(|v| v.to_str().ok()) {
        return extract_authority_from_url(referer.trim())
            .is_some_and(|auth| auth.eq_ignore_ascii_case(host));
    }

    false
}

/// Enforces strict same-origin CSRF verification for state-changing requests authenticated
/// via browser session cookies (Bearer token API clients are exempt).
pub async fn csrf_protection(
    State(state): State<RouterState>,
    req: Request,
    next: Next,
) -> Response {
    let method = req.method();
    if matches!(method, &Method::GET | &Method::HEAD | &Method::OPTIONS) {
        return next.run(req).await;
    }
    let cfg = state.app.config.load();
    if !cfg.web_auth_enabled || has_bearer_auth(req.headers()) {
        return next.run(req).await;
    }
    if !is_csrf_origin_valid(req.headers()) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "CSRF check failed: untrusted request origin" })),
        )
            .into_response();
    }
    next.run(req).await
}

pub async fn auth_status(
    State(state): State<RouterState>,
    headers: HeaderMap,
) -> Json<AuthStatusResponse> {
    let cfg = state.app.config.load();
    if !cfg.web_auth_enabled {
        return Json(AuthStatusResponse {
            auth_enabled: false,
            authenticated: true,
            username: Some(cfg.web_username.clone()),
        });
    }

    let authed_user = extract_token(&headers).and_then(|t| state.sessions.validate(&t));
    Json(AuthStatusResponse {
        auth_enabled: true,
        authenticated: authed_user.is_some(),
        username: authed_user,
    })
}

fn login_client_ip(
    trusted_proxies: &[String],
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: &HeaderMap,
) -> IpAddr {
    crate::proxy::extract_client_ip(connect_info, headers, trusted_proxies)
}

pub(crate) fn is_https_request(
    trusted_proxies: &[String],
    connect_info: Option<&Extension<ConnectInfo<SocketAddr>>>,
    headers: &HeaderMap,
) -> bool {
    if let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok())
        && origin.starts_with("https://")
    {
        return true;
    }
    if let Some(referer) = headers.get(header::REFERER).and_then(|v| v.to_str().ok())
        && referer.starts_with("https://")
    {
        return true;
    }
    if !trusted_proxies.is_empty()
        && let Some(Extension(ci)) = connect_info
        && let Ok(nets) = crabdns_core::acl::parse_cidr_list(trusted_proxies)
        && nets.iter().any(|net| net.contains(ci.0.ip()))
        && headers
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|proto| proto.trim().eq_ignore_ascii_case("https"))
    {
        return true;
    }
    false
}

pub async fn login(
    State(state): State<RouterState>,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(payload): Json<LoginPayload>,
) -> Response {
    let cfg = state.app.config.load();
    if !cfg.web_auth_enabled {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Web authentication is disabled" })),
        )
            .into_response();
    }

    let secure_cookie = is_https_request(&cfg.trusted_proxies, connect_info.as_ref(), &headers);
    let client_ip = login_client_ip(&cfg.trusted_proxies, connect_info, &headers);
    if let Some(retry_after) = state.login_limiter.check_locked(client_ip) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "error": format!("Too many failed login attempts; retry in {retry_after}s")
            })),
        )
            .into_response();
    }

    let user_ok = payload.username.trim() == cfg.web_username;
    let password_for_upgrade =
        (user_ok && cfg.web_password_hash.starts_with("pbkdf2$")).then(|| payload.password.clone());
    let pass_ok = if user_ok {
        let password = payload.password;
        let stored_hash = cfg.web_password_hash.clone();
        tokio::task::spawn_blocking(move || verify_password(&password, &stored_hash))
            .await
            .unwrap_or(false)
    } else {
        false
    };
    if !user_ok || !pass_ok {
        state.login_limiter.record_failure(client_ip);
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "Invalid username or password" })),
        )
            .into_response();
    }
    state.login_limiter.clear(client_ip);

    if let Some(pw) = password_for_upgrade {
        upgrade_legacy_password_hash(&state, &cfg.web_password_hash, &pw).await;
    }

    let Some(token) = state.sessions.create_session(&cfg.web_username) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Failed to create session" })),
        )
            .into_response();
    };

    let cookie = session_cookie_header(&token, secure_cookie);
    let mut resp = Json(LoginResponse {
        token,
        username: cfg.web_username.clone(),
    })
    .into_response();
    if let Ok(val) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().insert(header::SET_COOKIE, val);
    }
    resp
}

async fn upgrade_legacy_password_hash(state: &RouterState, legacy_hash: &str, password: &str) {
    let _config_guard = state.app.storage.config_lock().lock().await;
    let current = state.app.config.load_full();
    if current.web_password_hash != legacy_hash {
        return;
    }
    let pw_owned = password.to_string();
    let new_hash = match tokio::task::spawn_blocking(move || hash_password(&pw_owned)).await {
        Ok(Ok(hash)) => hash,
        Ok(Err(err)) => {
            tracing::warn!("failed to upgrade legacy password hash to Argon2id: {err}");
            return;
        }
        Err(err) => {
            tracing::warn!("failed to join password hash upgrade task: {err}");
            return;
        }
    };

    let mut next = (*current).clone();
    next.web_password_hash = new_hash;
    let storage = Arc::clone(&state.app.storage);
    let to_save = next.clone();
    match tokio::task::spawn_blocking(move || storage.save_config(&to_save.runtime)).await {
        Ok(Ok(())) => {
            state.app.config.store(Arc::new(next));
        }
        Ok(Err(err)) => {
            tracing::warn!("failed to persist upgraded Argon2id password hash: {err}");
        }
        Err(err) => {
            tracing::warn!("failed to join config save task during hash upgrade: {err}");
        }
    }
}

pub(crate) fn session_cookie_header(token: &str, secure_cookie: bool) -> String {
    let secure_attr = if secure_cookie { "; Secure" } else { "" };
    format!(
        "{SESSION_COOKIE_NAME}={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age={}{secure_attr}",
        SESSION_TTL.as_secs()
    )
}

pub async fn logout(
    State(state): State<RouterState>,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
) -> Response {
    if let Some(token) = extract_token(&headers) {
        state.sessions.revoke(&token);
    }
    let cfg = state.app.config.load();
    let secure_attr = if is_https_request(&cfg.trusted_proxies, connect_info.as_ref(), &headers) {
        "; Secure"
    } else {
        ""
    };
    let cookie =
        format!("{SESSION_COOKIE_NAME}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0{secure_attr}");
    let mut resp = Json(serde_json::json!({ "status": "logged_out" })).into_response();
    if let Ok(val) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().insert(header::SET_COOKIE, val);
    }
    resp
}

pub async fn update_auth(
    State(state): State<RouterState>,
    Json(payload): Json<AuthUpdatePayload>,
) -> Result<Json<AuthStatusResponse>, (StatusCode, Json<serde_json::Value>)> {
    let username = payload.username.trim().to_string();
    if username.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Username cannot be empty" })),
        ));
    }

    let _config_guard = state.app.storage.config_lock().lock().await;
    let current = state.app.config.load_full();
    let new_pass = payload
        .password
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    if payload.enabled && new_pass.is_none() && current.web_password_hash.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Password is required to enable authentication" })),
        ));
    }

    let mut next = (*current).clone();
    next.web_auth_enabled = payload.enabled;
    next.web_username.clone_from(&username);
    let mut clear_sessions = false;
    if let Some(pw) = new_pass {
        let pw_owned = pw.to_string();
        next.web_password_hash = tokio::task::spawn_blocking(move || hash_password(&pw_owned))
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": e.to_string() })),
                )
            })?
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": e })),
                )
            })?;
        clear_sessions = true;
    } else if !payload.enabled {
        clear_sessions = true;
    }

    let storage = Arc::clone(&state.app.storage);
    let to_save = next.clone();
    tokio::task::spawn_blocking(move || storage.save_config(&to_save.runtime))
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
        })?
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
        })?;
    if clear_sessions {
        state.sessions.clear_all();
    }
    state.app.config.store(Arc::new(next));

    Ok(Json(AuthStatusResponse {
        auth_enabled: payload.enabled,
        authenticated: !payload.enabled,
        username: Some(username),
    }))
}

pub(crate) fn extract_token(headers: &HeaderMap) -> Option<String> {
    if let Some(auth_val) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        && let Some(bearer) = auth_val.strip_prefix("Bearer ")
    {
        let trimmed = bearer.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }

    if let Some(cookie_hdr) = headers.get(header::COOKIE).and_then(|v| v.to_str().ok()) {
        for pair in cookie_hdr.split(';') {
            let trimmed = pair.trim();
            if let Some(val) = trimmed.strip_prefix(&format!("{SESSION_COOKIE_NAME}="))
                && !val.is_empty()
            {
                return Some(val.to_string());
            }
        }
    }
    None
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    for chunk in hex.as_bytes().as_chunks::<2>().0 {
        let s = std::str::from_utf8(chunk).ok()?;
        let byte = u8::from_str_radix(s, 16).ok()?;
        out.push(byte);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hash_and_verify() {
        let hash = hash_password("s3cr3t-pass").expect("hash");
        assert!(hash.starts_with("$argon2id$"));
        assert!(verify_password("s3cr3t-pass", &hash));
        assert!(!verify_password("wrong-pass", &hash));
        assert!(!verify_password("s3cr3t-pass", "invalid-format"));
    }

    #[test]
    fn test_legacy_pbkdf2_password_verify() {
        let salt = [0x11_u8; 16];
        let mut out = [0_u8; 32];
        let iterations = 100_000_u32;
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            NonZeroU32::new(iterations).expect("non-zero"),
            &salt,
            b"legacy-pass",
            &mut out,
        );
        let legacy_hash = format!(
            "pbkdf2${iterations}${}${}",
            hex_encode(&salt),
            hex_encode(&out)
        );
        assert!(verify_password("legacy-pass", &legacy_hash));
        assert!(!verify_password("wrong-pass", &legacy_hash));
    }

    #[test]
    fn test_session_store_lifecycle() {
        let store = SessionStore::default();
        let token = store.create_session("admin").expect("token");
        assert_eq!(store.validate(&token).as_deref(), Some("admin"));
        store.revoke(&token);
        assert!(store.validate(&token).is_none());
    }

    #[test]
    fn test_session_store_prunes_expired_and_caps_total() {
        let store = SessionStore::default();
        let expired_at = Instant::now()
            .checked_sub(Duration::from_secs(5))
            .unwrap_or_else(Instant::now);
        for i in 0..10 {
            store.sessions.insert(
                format!("expired-{i}"),
                SessionEntry {
                    username: "admin".to_string(),
                    expires_at: expired_at,
                },
            );
        }
        assert_eq!(store.active_sessions(), 10);

        // Creating one session prunes all expired entries first.
        let fresh = store.create_session("admin").expect("token");
        assert_eq!(store.active_sessions(), 1);
        assert!(store.validate(&fresh).is_some());

        // Cap enforces <= MAX_SESSIONS.
        for _ in 0..(MAX_SESSIONS + 25) {
            let _ = store.create_session("admin").expect("token");
        }
        assert_eq!(store.active_sessions(), MAX_SESSIONS);
    }

    #[test]
    fn test_login_rate_limiter_prunes_expired_and_caps_entries() {
        let limiter = LoginRateLimiter::default();
        let stale_ip: IpAddr = "198.51.100.10".parse().unwrap();
        limiter.record_failure(stale_ip);
        assert_eq!(limiter.tracked_entries(), 1);

        let future = Instant::now() + LOGIN_WINDOW + Duration::from_secs(5);
        assert_eq!(limiter.prune_expired_at(future), 1);
        assert_eq!(limiter.tracked_entries(), 0);

        for i in 0..(MAX_LOGIN_ATTEMPT_ENTRIES + 64) {
            let b = ((i >> 16) & 0xff) as u8;
            let c = ((i >> 8) & 0xff) as u8;
            let d = (i & 0xff) as u8;
            let ip: IpAddr = format!("10.{b}.{c}.{d}").parse().unwrap();
            limiter.record_failure(ip);
        }
        assert!(limiter.tracked_entries() <= MAX_LOGIN_ATTEMPT_ENTRIES);
    }
}
