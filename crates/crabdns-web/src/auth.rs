use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Json;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use dashmap::DashMap;
use ring::pbkdf2;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::RouterState;

const PBKDF2_ITERATIONS: u32 = 100_000;
const SESSION_COOKIE_NAME: &str = "crabdns_session";
const SESSION_TTL: Duration = Duration::from_hours(24);

#[derive(Debug, Clone)]
struct SessionEntry {
    username: String,
    expires_at: Instant,
}

#[derive(Default)]
pub struct SessionStore {
    sessions: DashMap<String, SessionEntry>,
}

impl SessionStore {
    pub fn create_session(&self, username: &str) -> Option<String> {
        let mut bytes = [0_u8; 32];
        SystemRandom::new().fill(&mut bytes).ok()?;
        let token = hex_encode(&bytes);
        self.sessions.insert(
            token.clone(),
            SessionEntry {
                username: username.to_string(),
                expires_at: Instant::now() + SESSION_TTL,
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

pub fn hash_password(password: &str) -> Result<String, String> {
    let mut salt = [0_u8; 16];
    SystemRandom::new()
        .fill(&mut salt)
        .map_err(|_| "failed to generate random salt".to_string())?;
    let mut out = [0_u8; 32];
    let iters = NonZeroU32::new(PBKDF2_ITERATIONS).expect("non-zero");
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iters,
        &salt,
        password.as_bytes(),
        &mut out,
    );
    Ok(format!(
        "pbkdf2${PBKDF2_ITERATIONS}${}${}",
        hex_encode(&salt),
        hex_encode(&out)
    ))
}

pub fn verify_password(password: &str, stored_hash: &str) -> bool {
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

pub async fn login(
    State(state): State<RouterState>,
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

    let user_ok = payload.username.trim() == cfg.web_username;
    let pass_ok = verify_password(&payload.password, &cfg.web_password_hash);
    if !user_ok || !pass_ok {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "Invalid username or password" })),
        )
            .into_response();
    }

    let Some(token) = state.sessions.create_session(&cfg.web_username) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Failed to create session" })),
        )
            .into_response();
    };

    let cookie = format!(
        "{SESSION_COOKIE_NAME}={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age={}",
        SESSION_TTL.as_secs()
    );
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

pub async fn logout(State(state): State<RouterState>, headers: HeaderMap) -> Response {
    if let Some(token) = extract_token(&headers) {
        state.sessions.revoke(&token);
    }
    let cookie = format!("{SESSION_COOKIE_NAME}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0");
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
    if let Some(pw) = new_pass {
        next.web_password_hash = hash_password(pw).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e })),
            )
        })?;
        state.sessions.clear_all();
    } else if !payload.enabled {
        state.sessions.clear_all();
    }

    state.app.storage.save_config(&next).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
    })?;
    state.app.config.store(Arc::new(next));

    Ok(Json(AuthStatusResponse {
        auth_enabled: payload.enabled,
        authenticated: !payload.enabled,
        username: Some(username),
    }))
}

fn extract_token(headers: &HeaderMap) -> Option<String> {
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
        assert!(hash.starts_with("pbkdf2$"));
        assert!(verify_password("s3cr3t-pass", &hash));
        assert!(!verify_password("wrong-pass", &hash));
        assert!(!verify_password("s3cr3t-pass", "invalid-format"));
    }

    #[test]
    fn test_session_store_lifecycle() {
        let store = SessionStore::default();
        let token = store.create_session("admin").expect("token");
        assert_eq!(store.validate(&token).as_deref(), Some("admin"));
        store.revoke(&token);
        assert!(store.validate(&token).is_none());
    }
}
