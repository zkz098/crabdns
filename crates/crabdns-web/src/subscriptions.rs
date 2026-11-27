use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use chrono::Utc;
use crabdns_core::{DnsPipeline, FilterEngine};
use crabdns_storage::{FilterSubscription, StorageEngine};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use ts_rs::TS;

use crate::RouterState;
use crate::update_api::GH_PROXY_PREFIX;

pub(crate) const MAX_SUBSCRIPTION_BYTES: usize = 50 * 1024 * 1024;
const DIRECT_GITHUB_TIMEOUT: Duration = Duration::from_secs(12);
const PROGRESS_NOTIFY_INTERVAL_MS: u64 = 150;

const GITHUB_MIRROR_HOSTS: &[&str] = &[
    "github.com",
    "raw.githubusercontent.com",
    "gist.githubusercontent.com",
    "objects.githubusercontent.com",
    "codeload.github.com",
    "release-assets.githubusercontent.com",
];

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum SubscriptionLoadPhase {
    #[default]
    Idle,
    Downloading,
    Parsing,
    Rebuilding,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SubscriptionProgressStatus {
    pub active: bool,
    pub phase: SubscriptionLoadPhase,
    pub current_id: Option<String>,
    pub current_name: Option<String>,
    pub current_index: usize,
    pub total_count: usize,
    #[ts(type = "number")]
    pub downloaded_bytes: u64,
    #[ts(type = "number | null")]
    pub total_bytes: Option<u64>,
    pub using_mirror: bool,
}

#[derive(Debug)]
pub struct SubscriptionProgressManager {
    status: Mutex<SubscriptionProgressStatus>,
    status_tx: watch::Sender<u64>,
    created_at: Instant,
    last_notify_ms: AtomicU64,
}

impl Default for SubscriptionProgressManager {
    fn default() -> Self {
        let (status_tx, _) = watch::channel(0);
        Self {
            status: Mutex::new(SubscriptionProgressStatus::default()),
            status_tx,
            created_at: Instant::now(),
            last_notify_ms: AtomicU64::new(0),
        }
    }
}

impl SubscriptionProgressManager {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn subscribe_status(&self) -> watch::Receiver<u64> {
        self.status_tx.subscribe()
    }

    #[must_use]
    pub fn status_snapshot(&self) -> SubscriptionProgressStatus {
        self.status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn notify_changed(&self) {
        self.status_tx.send_modify(|rev| *rev = rev.wrapping_add(1));
    }

    pub fn begin_batch(&self, total_count: usize) -> SubscriptionProgressGuard<'_> {
        self.last_notify_ms.store(0, Ordering::Relaxed);
        {
            let mut s = self
                .status
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *s = SubscriptionProgressStatus {
                active: true,
                phase: SubscriptionLoadPhase::Downloading,
                current_id: None,
                current_name: None,
                current_index: 0,
                total_count: total_count.max(1),
                downloaded_bytes: 0,
                total_bytes: None,
                using_mirror: false,
            };
        }
        self.notify_changed();
        SubscriptionProgressGuard(self)
    }

    pub fn begin_item(&self, index: usize, id: Option<&str>, name: &str) {
        self.last_notify_ms.store(0, Ordering::Relaxed);
        {
            let mut s = self
                .status
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            s.active = true;
            s.phase = SubscriptionLoadPhase::Downloading;
            s.current_id = id.map(ToString::to_string);
            s.current_name = Some(name.to_string());
            s.current_index = index;
            s.downloaded_bytes = 0;
            s.total_bytes = None;
            s.using_mirror = false;
        }
        self.notify_changed();
    }

    pub fn update_download(&self, downloaded: u64, total: Option<u64>, using_mirror: bool) {
        let mirror_changed = {
            let mut s = self
                .status
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let changed = s.using_mirror != using_mirror;
            s.phase = SubscriptionLoadPhase::Downloading;
            s.downloaded_bytes = downloaded;
            s.total_bytes = total.filter(|&v| v > 0);
            s.using_mirror = using_mirror;
            changed
        };
        let now_ms = u64::try_from(self.created_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        let prev = self.last_notify_ms.load(Ordering::Relaxed);
        let is_complete = total.is_some_and(|t| downloaded >= t);
        if mirror_changed
            || ((is_complete
                || prev == 0
                || now_ms.saturating_sub(prev) >= PROGRESS_NOTIFY_INTERVAL_MS)
                && self
                    .last_notify_ms
                    .compare_exchange(prev, now_ms.max(1), Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok())
        {
            self.notify_changed();
        }
    }

    pub fn set_phase(&self, phase: SubscriptionLoadPhase) {
        {
            let mut s = self
                .status
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            s.phase = phase;
        }
        self.notify_changed();
    }

    pub fn finish(&self) {
        {
            let mut s = self
                .status
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *s = SubscriptionProgressStatus::default();
        }
        self.notify_changed();
    }
}

pub struct SubscriptionProgressGuard<'a>(&'a SubscriptionProgressManager);

impl Drop for SubscriptionProgressGuard<'_> {
    fn drop(&mut self) {
        self.0.finish();
    }
}

#[derive(Debug, Deserialize, TS)]
#[ts(export)]
pub struct CreateSubscriptionPayload {
    pub name: String,
    pub url: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Deserialize, TS)]
#[ts(export)]
pub struct UpdateSubscriptionPayload {
    pub name: Option<String>,
    pub url: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct ApiError {
    pub error: String,
}

fn default_true() -> bool {
    true
}

type ApiResult<T> = std::result::Result<T, (StatusCode, Json<ApiError>)>;

fn err_response(status: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<ApiError>) {
    (status, Json(ApiError { error: msg.into() }))
}

const MAX_SUBSCRIPTION_REDIRECTS: usize = 5;

#[derive(Debug)]
struct SsrfSafeResolver;

async fn resolve_public_addrs(host: &str) -> std::io::Result<Vec<SocketAddr>> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, 0)).await?.collect();
    if addrs.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("no IP addresses resolved for '{host}'"),
        ));
    }
    for addr in &addrs {
        if is_private_or_reserved_ip(addr.ip()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "Subscription host '{host}' resolved to private IP {}",
                    addr.ip()
                ),
            ));
        }
    }
    Ok(addrs)
}

impl reqwest::dns::Resolve for SsrfSafeResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            let addrs = resolve_public_addrs(&host)
                .await
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
            let iter: reqwest::dns::Addrs = Box::new(addrs.into_iter());
            Ok(iter)
        })
    }
}

pub fn build_subscription_http_client(allow_private: bool) -> reqwest::Client {
    let redirect_policy = reqwest::redirect::Policy::custom(move |attempt| {
        if attempt.previous().len() >= MAX_SUBSCRIPTION_REDIRECTS {
            return attempt.error("too many redirects");
        }
        match validate_subscription_url_with_policy(attempt.url().as_str(), allow_private) {
            Ok(_) => attempt.follow(),
            Err(err) => attempt.error(err),
        }
    });

    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("crabdns/0.1")
        .redirect(redirect_policy);
    if !allow_private {
        builder = builder.dns_resolver(Arc::new(SsrfSafeResolver));
    }
    builder.build().unwrap_or_default()
}

pub fn build_http_client() -> reqwest::Client {
    build_subscription_http_client(false)
}

pub fn is_private_or_reserved_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0b1100_0000) == 64)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

pub fn validate_subscription_url(raw: &str) -> Result<String, String> {
    validate_subscription_url_with_policy(raw, false)
}

pub fn validate_subscription_url_with_policy(
    raw: &str,
    allow_private: bool,
) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("URL cannot be empty".to_string());
    }
    let parsed = reqwest::Url::parse(trimmed).map_err(|e| format!("Invalid URL: {e}"))?;
    match parsed.scheme() {
        "http" | "https" => {}
        other => {
            return Err(format!(
                "Unsupported URL scheme '{other}'; use http or https"
            ));
        }
    }
    if !allow_private {
        let host = parsed
            .host_str()
            .ok_or_else(|| "URL must contain a host".to_string())?;
        let lower = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_ascii_lowercase();
        if lower == "localhost"
            || lower.ends_with(".localhost")
            || std::path::Path::new(&lower)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("local"))
        {
            return Err("Subscription URL host cannot be localhost or .local".to_string());
        }
        if let Ok(ip) = lower.parse::<IpAddr>()
            && is_private_or_reserved_ip(ip)
        {
            return Err(format!(
                "Subscription URL host '{ip}' is a private or reserved IP"
            ));
        }
    }
    Ok(trimmed.to_string())
}

pub async fn fetch_subscription_text(
    client: &reqwest::Client,
    url: &str,
) -> Result<String, String> {
    fetch_subscription_text_with_policy(client, url, false).await
}

pub(crate) async fn verify_url_ssrf_policy(url: &str, allow_private: bool) -> Result<(), String> {
    validate_subscription_url_with_policy(url, allow_private)?;

    if !allow_private
        && let Ok(parsed) = reqwest::Url::parse(url)
        && let Some(host) = parsed.host_str()
    {
        let port = parsed.port_or_known_default().unwrap_or(443);
        let clean_host = host.trim_start_matches('[').trim_end_matches(']');
        if clean_host.parse::<IpAddr>().is_err()
            && let Ok(addrs) = tokio::net::lookup_host((clean_host, port)).await
        {
            for addr in addrs {
                if is_private_or_reserved_ip(addr.ip()) {
                    return Err(format!(
                        "Subscription host '{clean_host}' resolved to private IP {}",
                        addr.ip()
                    ));
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn github_mirror_url(raw_url: &str, mirror_prefix: &str) -> Option<String> {
    let trimmed = raw_url.trim();
    if trimmed.is_empty() || trimmed.starts_with(mirror_prefix) {
        return None;
    }
    let parsed = reqwest::Url::parse(trimmed).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return None;
    }
    let host = parsed.host_str()?.to_ascii_lowercase();
    if !GITHUB_MIRROR_HOSTS
        .iter()
        .any(|candidate| host == *candidate)
    {
        return None;
    }
    let prefix = if mirror_prefix.ends_with('/') {
        mirror_prefix.to_string()
    } else {
        format!("{mirror_prefix}/")
    };
    Some(format!("{prefix}{trimmed}"))
}

async fn fetch_single_subscription_attempt<F>(
    client: &reqwest::Client,
    url: &str,
    allow_private: bool,
    timeout_override: Option<Duration>,
    using_mirror: bool,
    on_progress: &mut F,
) -> Result<String, String>
where
    F: FnMut(u64, Option<u64>, bool),
{
    verify_url_ssrf_policy(url, allow_private).await?;

    let mut req = client.get(url);
    if let Some(t) = timeout_override {
        req = req.timeout(t);
    }

    let resp = req
        .send()
        .await
        .map_err(|e| format!("Request failed: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }

    let total_bytes = resp.content_length().filter(|&v| v > 0);
    on_progress(0, total_bytes, using_mirror);
    let bytes =
        read_response_bounded_with_progress(resp, MAX_SUBSCRIPTION_BYTES, |downloaded, total| {
            on_progress(downloaded, total, using_mirror);
        })
        .await?;
    Ok(String::from_utf8(bytes)
        .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned()))
}

pub async fn fetch_subscription_text_with_policy(
    client: &reqwest::Client,
    url: &str,
    allow_private: bool,
) -> Result<String, String> {
    fetch_subscription_with_fallback_and_progress(
        client,
        url,
        allow_private,
        Some(GH_PROXY_PREFIX),
        |_, _, _| {},
    )
    .await
}

pub(crate) fn ordered_github_candidates(
    url: &str,
    mirror_prefix: Option<&str>,
    prefer_mirror: bool,
) -> Vec<(String, bool)> {
    let Some(mirror) = mirror_prefix.and_then(|prefix| github_mirror_url(url, prefix)) else {
        return vec![(url.to_string(), false)];
    };
    if prefer_mirror {
        vec![(mirror, true), (url.to_string(), false)]
    } else {
        vec![(url.to_string(), false), (mirror, true)]
    }
}

pub(crate) async fn fetch_subscription_with_fallback_and_progress<F>(
    client: &reqwest::Client,
    url: &str,
    allow_private: bool,
    mirror_prefix: Option<&str>,
    mut on_progress: F,
) -> Result<String, String>
where
    F: FnMut(u64, Option<u64>, bool),
{
    let candidates = ordered_github_candidates(
        url,
        mirror_prefix,
        crate::update_api::is_china_deployment(),
    );
    let has_fallback = candidates.len() > 1;
    let mut errors = Vec::new();

    for (idx, (candidate_url, using_mirror)) in candidates.iter().enumerate() {
        let is_last = idx + 1 == candidates.len();
        let timeout_override = if has_fallback && !is_last {
            Some(DIRECT_GITHUB_TIMEOUT)
        } else {
            None
        };
        if idx > 0 {
            on_progress(0, None, *using_mirror);
        }
        match fetch_single_subscription_attempt(
            client,
            candidate_url,
            allow_private,
            timeout_override,
            *using_mirror,
            &mut on_progress,
        )
        .await
        {
            Ok(text) => return Ok(text),
            Err(err) => {
                if !is_last {
                    tracing::info!(
                        url = %candidate_url,
                        using_mirror = *using_mirror,
                        error = %err,
                        "subscription fetch attempt failed, trying fallback"
                    );
                }
                errors.push(if *using_mirror {
                    format!("gh-proxy mirror failed: {err}")
                } else {
                    err
                });
            }
        }
    }

    Err(errors.join("; "))
}

pub(crate) async fn read_response_bounded(
    resp: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, String> {
    read_response_bounded_with_progress(resp, max_bytes, |_, _| {}).await
}

pub(crate) async fn read_response_bounded_with_progress<F>(
    mut resp: reqwest::Response,
    max_bytes: usize,
    mut on_progress: F,
) -> Result<Vec<u8>, String>
where
    F: FnMut(u64, Option<u64>),
{
    let total_len = resp.content_length().filter(|&v| v > 0);
    if let Some(len) = total_len
        && len > max_bytes as u64
    {
        return Err("Subscription file exceeds 50 MB limit".to_string());
    }

    let mut out = Vec::with_capacity(
        usize::try_from(total_len.unwrap_or(0))
            .unwrap_or(0)
            .min(max_bytes),
    );
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| format!("Failed to read response body: {e}"))?
    {
        if out.len().saturating_add(chunk.len()) > max_bytes {
            return Err("Subscription file exceeds 50 MB limit".to_string());
        }
        out.extend_from_slice(&chunk);
        on_progress(out.len() as u64, total_len);
    }
    Ok(out)
}

pub fn rebuild_filter_engine(
    storage: &StorageEngine,
    pipeline: &DnsPipeline,
) -> Result<(), String> {
    let start = Instant::now();
    let custom_rules = storage
        .load_custom_rules()
        .map_err(|e| e.to_string())?
        .unwrap_or_default();
    let custom_enabled = storage
        .load_custom_rules_enabled()
        .map_err(|e| e.to_string())?;
    let mut named_sources = storage
        .load_enabled_named_subscription_contents()
        .map_err(|e| e.to_string())?;
    let rewrites = storage.list_dns_rewrites().map_err(|e| e.to_string())?;
    let rewrite_lines: Vec<String> = rewrites
        .into_iter()
        .filter(|r| r.enabled)
        .map(|r| r.to_filter_rule())
        .collect();
    if !rewrite_lines.is_empty() {
        named_sources.push(("rewrites".to_string(), rewrite_lines.join("\n")));
    }

    pipeline
        .filter()
        .reload_from_named_sources(&custom_rules, custom_enabled, &named_sources);
    let elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    pipeline.record_filter_reload(elapsed_ms);
    Ok(())
}

pub async fn rebuild_filter_engine_async(
    storage: &Arc<StorageEngine>,
    pipeline: &Arc<DnsPipeline>,
) -> Result<(), String> {
    let st = Arc::clone(storage);
    let pipe = Arc::clone(pipeline);
    tokio::task::spawn_blocking(move || rebuild_filter_engine(&st, &pipe))
        .await
        .map_err(|e| format!("filter rebuild task panicked: {e}"))?
}

async fn storage_blocking<T, F>(storage: &Arc<StorageEngine>, f: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce(&StorageEngine) -> crabdns_storage::Result<T> + Send + 'static,
{
    let st = Arc::clone(storage);
    tokio::task::spawn_blocking(move || f(&st))
        .await
        .map_err(|e| format!("storage task panicked: {e}"))?
        .map_err(|e| e.to_string())
}

fn generate_sub_id() -> String {
    let nanos = Utc::now()
        .timestamp_nanos_opt()
        .unwrap_or(0)
        .cast_unsigned();
    format!("sub-{nanos:x}")
}

async fn fetch_and_store_subscription(
    client: &reqwest::Client,
    storage: &Arc<StorageEngine>,
    sub: &mut FilterSubscription,
    allow_private: bool,
    progress: Option<&SubscriptionProgressManager>,
) {
    let fetch_res = fetch_subscription_with_fallback_and_progress(
        client,
        &sub.url,
        allow_private,
        Some(GH_PROXY_PREFIX),
        |downloaded, total, using_mirror| {
            if let Some(mgr) = progress {
                mgr.update_download(downloaded, total, using_mirror);
            }
        },
    )
    .await;

    match fetch_res {
        Ok(text) => {
            if let Some(mgr) = progress {
                mgr.set_phase(SubscriptionLoadPhase::Parsing);
            }
            let st = Arc::clone(storage);
            let sub_id = sub.id.clone();
            let save_res = tokio::task::spawn_blocking(move || {
                let stats = FilterEngine::count_rules_in_text(&text);
                st.save_subscription_content(&sub_id, &text)?;
                Ok::<_, crabdns_storage::StorageError>(stats.total_rules)
            })
            .await;

            match save_res {
                Ok(Ok(total_rules)) => {
                    sub.rule_count = total_rules;
                    sub.last_updated = Some(Utc::now());
                    sub.last_error = None;
                }
                Ok(Err(err)) => {
                    sub.last_error = Some(err.to_string());
                }
                Err(err) => {
                    sub.last_error = Some(format!("save task panicked: {err}"));
                }
            }
        }
        Err(err) => {
            sub.last_error = Some(err);
        }
    }
}

pub async fn refresh_enabled_subscriptions_job(
    client: &reqwest::Client,
    storage: &Arc<StorageEngine>,
    pipeline: &Arc<DnsPipeline>,
) -> Result<Vec<FilterSubscription>, String> {
    refresh_enabled_subscriptions_job_with_policy(client, storage, pipeline, false).await
}

pub async fn refresh_enabled_subscriptions_job_with_policy(
    client: &reqwest::Client,
    storage: &Arc<StorageEngine>,
    pipeline: &Arc<DnsPipeline>,
    allow_private: bool,
) -> Result<Vec<FilterSubscription>, String> {
    refresh_enabled_subscriptions_job_with_progress(client, storage, pipeline, allow_private, None)
        .await
}

pub async fn refresh_enabled_subscriptions_job_with_progress(
    client: &reqwest::Client,
    storage: &Arc<StorageEngine>,
    pipeline: &Arc<DnsPipeline>,
    allow_private: bool,
    progress: Option<&SubscriptionProgressManager>,
) -> Result<Vec<FilterSubscription>, String> {
    let mut snapshot = {
        let _guard = storage.subscription_lock().lock().await;
        storage_blocking(storage, StorageEngine::list_subscriptions).await?
    };

    let enabled_total = snapshot.iter().filter(|s| s.enabled).count();
    let _progress_guard = (enabled_total > 0)
        .then(|| progress.map(|mgr| mgr.begin_batch(enabled_total)))
        .flatten();

    let mut idx = 0_usize;
    for sub in &mut snapshot {
        if sub.enabled {
            idx += 1;
            if let Some(mgr) = progress {
                mgr.begin_item(idx, Some(&sub.id), &sub.name);
            }
            fetch_and_store_subscription(client, storage, sub, allow_private, progress).await;
        }
    }

    let updated = {
        let _guard = storage.subscription_lock().lock().await;
        let mut latest = storage_blocking(storage, StorageEngine::list_subscriptions).await?;
        for fetched in snapshot {
            if fetched.enabled
                && let Some(cur) = latest.iter_mut().find(|s| s.id == fetched.id)
            {
                cur.rule_count = fetched.rule_count;
                cur.last_updated = fetched.last_updated;
                cur.last_error = fetched.last_error;
            }
        }
        let to_save = latest.clone();
        storage_blocking(storage, move |st| st.save_subscriptions(&to_save)).await?;
        latest
    };

    if let Some(mgr) = progress {
        mgr.set_phase(SubscriptionLoadPhase::Rebuilding);
    }
    rebuild_filter_engine_async(storage, pipeline).await?;
    Ok(updated)
}

pub async fn get_subscription_progress(
    State(state): State<RouterState>,
) -> Json<SubscriptionProgressStatus> {
    Json(state.subscription_progress.status_snapshot())
}

pub async fn list_subscriptions(
    State(state): State<RouterState>,
) -> ApiResult<Json<Vec<FilterSubscription>>> {
    let subs = storage_blocking(&state.app.storage, StorageEngine::list_subscriptions)
        .await
        .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(subs))
}

pub async fn create_subscription(
    State(state): State<RouterState>,
    Json(payload): Json<CreateSubscriptionPayload>,
) -> ApiResult<(StatusCode, Json<FilterSubscription>)> {
    let name = payload.name.trim().to_string();
    if name.is_empty() {
        return Err(err_response(
            StatusCode::BAD_REQUEST,
            "Name cannot be empty",
        ));
    }
    let allow_private = state.app.config.load().allow_private_subscriptions;
    let url = validate_subscription_url_with_policy(&payload.url, allow_private)
        .map_err(|e| err_response(StatusCode::BAD_REQUEST, e))?;

    let mut sub = FilterSubscription {
        id: generate_sub_id(),
        name,
        url,
        enabled: payload.enabled,
        rule_count: 0,
        last_updated: None,
        last_error: None,
    };

    if sub.enabled {
        let _progress_guard = state.subscription_progress.begin_batch(1);
        state
            .subscription_progress
            .begin_item(1, Some(&sub.id), &sub.name);
        let client = state.subscription_client(allow_private);
        fetch_and_store_subscription(
            client,
            &state.app.storage,
            &mut sub,
            allow_private,
            Some(&state.subscription_progress),
        )
        .await;
        if sub.last_error.is_none() {
            state
                .subscription_progress
                .set_phase(SubscriptionLoadPhase::Rebuilding);
        }
    }

    let _guard = state.app.storage.subscription_lock().lock().await;
    let mut subs = storage_blocking(&state.app.storage, StorageEngine::list_subscriptions)
        .await
        .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    subs.push(sub.clone());
    storage_blocking(&state.app.storage, move |st| st.save_subscriptions(&subs))
        .await
        .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    if sub.enabled && sub.last_error.is_none() {
        let _progress_guard = state.subscription_progress.begin_batch(1);
        state
            .subscription_progress
            .begin_item(1, Some(&sub.id), &sub.name);
        state
            .subscription_progress
            .set_phase(SubscriptionLoadPhase::Rebuilding);
        rebuild_filter_engine_async(&state.app.storage, &state.app.pipeline)
            .await
            .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    }

    Ok((StatusCode::CREATED, Json(sub)))
}

pub async fn update_subscription(
    State(state): State<RouterState>,
    Path(id): Path<String>,
    Json(payload): Json<UpdateSubscriptionPayload>,
) -> ApiResult<Json<FilterSubscription>> {
    let allow_private = state.app.config.load().allow_private_subscriptions;
    let next_url = match payload.url {
        Some(ref raw) => Some(
            validate_subscription_url_with_policy(raw, allow_private)
                .map_err(|e| err_response(StatusCode::BAD_REQUEST, e))?,
        ),
        None => None,
    };

    let mut should_fetch = false;
    let mut updated_sub = {
        let _guard = state.app.storage.subscription_lock().lock().await;
        let mut subs = storage_blocking(&state.app.storage, StorageEngine::list_subscriptions)
            .await
            .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e))?;
        let Some(sub) = subs.iter_mut().find(|s| s.id == id) else {
            return Err(err_response(
                StatusCode::NOT_FOUND,
                "Subscription not found",
            ));
        };

        if let Some(name) = payload.name {
            let trimmed = name.trim().to_string();
            if trimmed.is_empty() {
                return Err(err_response(
                    StatusCode::BAD_REQUEST,
                    "Name cannot be empty",
                ));
            }
            sub.name = trimmed;
        }
        if let Some(url) = next_url
            && sub.url != url
        {
            sub.url = url;
            should_fetch = sub.enabled;
        }
        if let Some(enabled) = payload.enabled {
            sub.enabled = enabled;
            if enabled && sub.last_updated.is_none() {
                should_fetch = true;
            }
        }

        let clone = sub.clone();
        storage_blocking(&state.app.storage, move |st| st.save_subscriptions(&subs))
            .await
            .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e))?;
        clone
    };

    if should_fetch {
        let _progress_guard = state.subscription_progress.begin_batch(1);
        state
            .subscription_progress
            .begin_item(1, Some(&updated_sub.id), &updated_sub.name);
        let client = state.subscription_client(allow_private);
        fetch_and_store_subscription(
            client,
            &state.app.storage,
            &mut updated_sub,
            allow_private,
            Some(&state.subscription_progress),
        )
        .await;
    }

    let _guard = state.app.storage.subscription_lock().lock().await;
    if should_fetch {
        let mut subs = storage_blocking(&state.app.storage, StorageEngine::list_subscriptions)
            .await
            .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e))?;
        if let Some(sub) = subs.iter_mut().find(|s| s.id == id) {
            sub.rule_count = updated_sub.rule_count;
            sub.last_updated = updated_sub.last_updated;
            sub.last_error.clone_from(&updated_sub.last_error);
            storage_blocking(&state.app.storage, move |st| st.save_subscriptions(&subs))
                .await
                .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e))?;
        }
    }

    rebuild_filter_engine_async(&state.app.storage, &state.app.pipeline)
        .await
        .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(Json(updated_sub))
}

pub async fn delete_subscription(
    State(state): State<RouterState>,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let _guard = state.app.storage.subscription_lock().lock().await;
    let mut subs = storage_blocking(&state.app.storage, StorageEngine::list_subscriptions)
        .await
        .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let before = subs.len();
    subs.retain(|s| s.id != id);
    if subs.len() == before {
        return Err(err_response(
            StatusCode::NOT_FOUND,
            "Subscription not found",
        ));
    }
    let del_id = id.clone();
    storage_blocking(&state.app.storage, move |st| {
        st.save_subscriptions(&subs)?;
        st.delete_subscription_content(&del_id)
    })
    .await
    .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    rebuild_filter_engine_async(&state.app.storage, &state.app.pipeline)
        .await
        .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn refresh_subscription(
    State(state): State<RouterState>,
    Path(id): Path<String>,
) -> ApiResult<Json<FilterSubscription>> {
    let mut target = {
        let _guard = state.app.storage.subscription_lock().lock().await;
        let subs = storage_blocking(&state.app.storage, StorageEngine::list_subscriptions)
            .await
            .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e))?;
        subs.into_iter()
            .find(|s| s.id == id)
            .ok_or_else(|| err_response(StatusCode::NOT_FOUND, "Subscription not found"))?
    };

    let allow_private = state.app.config.load().allow_private_subscriptions;
    let client = state.subscription_client(allow_private);
    {
        let _progress_guard = state.subscription_progress.begin_batch(1);
        state
            .subscription_progress
            .begin_item(1, Some(&target.id), &target.name);
        fetch_and_store_subscription(
            client,
            &state.app.storage,
            &mut target,
            allow_private,
            Some(&state.subscription_progress),
        )
        .await;

        let _guard = state.app.storage.subscription_lock().lock().await;
        let mut subs = storage_blocking(&state.app.storage, StorageEngine::list_subscriptions)
            .await
            .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e))?;
        if let Some(sub) = subs.iter_mut().find(|s| s.id == id) {
            sub.rule_count = target.rule_count;
            sub.last_updated = target.last_updated;
            sub.last_error.clone_from(&target.last_error);
            storage_blocking(&state.app.storage, move |st| st.save_subscriptions(&subs))
                .await
                .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e))?;
        }

        if target.enabled {
            state
                .subscription_progress
                .set_phase(SubscriptionLoadPhase::Rebuilding);
            rebuild_filter_engine_async(&state.app.storage, &state.app.pipeline)
                .await
                .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e))?;
        }
    }

    Ok(Json(target))
}

pub async fn refresh_all_subscriptions(
    State(state): State<RouterState>,
) -> ApiResult<Json<Vec<FilterSubscription>>> {
    let allow_private = state.app.config.load().allow_private_subscriptions;
    let client = state.subscription_client(allow_private);
    let subs = refresh_enabled_subscriptions_job_with_progress(
        client,
        &state.app.storage,
        &state.app.pipeline,
        allow_private,
        Some(&state.subscription_progress),
    )
    .await
    .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(subs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_read_response_bounded_rejects_oversized_chunked_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut req_buf = [0_u8; 1024];
                let mut total = 0;
                while total < req_buf.len() {
                    let Ok(n) = stream.read(&mut req_buf[total..]).await else {
                        break;
                    };
                    if n == 0 {
                        break;
                    }
                    total += n;
                    if req_buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let header = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n";
                let _ = stream.write_all(header.as_bytes()).await;
                let chunk = vec![b'a'; 2048];
                let chunk_hdr = format!("{:x}\r\n", chunk.len());
                for _ in 0..3 {
                    let _ = stream.write_all(chunk_hdr.as_bytes()).await;
                    let _ = stream.write_all(&chunk).await;
                    let _ = stream.write_all(b"\r\n").await;
                }
                let _ = stream.write_all(b"0\r\n\r\n").await;
                let _ = stream.flush().await;
                let _ = done_rx.await;
            }
        });

        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://{addr}/list.txt"))
            .send()
            .await
            .expect("send");
        let err = read_response_bounded(resp, 4096)
            .await
            .expect_err("chunked stream over 4096 bytes should fail");
        let _ = done_tx.send(());
        assert!(err.contains("exceeds"), "unexpected err: {err}");
    }

    #[tokio::test]
    async fn test_ssrf_resolver_and_redirect_limit() {
        // SsrfSafeResolver rejects loopback/private resolution directly.
        let err = resolve_public_addrs("localhost")
            .await
            .expect_err("localhost must be blocked by SsrfSafeResolver");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);

        // Redirect loop exceeds MAX_SUBSCRIPTION_REDIRECTS (5) and aborts cleanly.
        let app = axum::Router::new().route(
            "/loop",
            axum::routing::get(|| async { axum::response::Redirect::temporary("/loop") }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let client = build_subscription_http_client(true);
        let fetch_err =
            fetch_subscription_text_with_policy(&client, &format!("http://{addr}/loop"), true)
                .await
                .expect_err("redirect loop must fail");
        assert!(
            fetch_err.contains("Request failed"),
            "unexpected redirect error: {fetch_err}"
        );
    }

    #[test]
    fn test_github_mirror_url() {
        assert_eq!(
            github_mirror_url(
                "https://raw.githubusercontent.com/Cats-Team/AdRules/main/dns.txt",
                GH_PROXY_PREFIX
            ),
            Some(
                "https://v6.gh-proxy.org/https://raw.githubusercontent.com/Cats-Team/AdRules/main/dns.txt"
                    .to_string()
            )
        );
        assert_eq!(
            github_mirror_url(
                "https://github.com/StevenBlack/hosts/raw/master/hosts",
                "https://v6.gh-proxy.org"
            ),
            Some(
                "https://v6.gh-proxy.org/https://github.com/StevenBlack/hosts/raw/master/hosts"
                    .to_string()
            )
        );
        assert_eq!(
            github_mirror_url(
                "https://v6.gh-proxy.org/https://raw.githubusercontent.com/a/b/c.txt",
                GH_PROXY_PREFIX
            ),
            None
        );
        assert_eq!(
            github_mirror_url(
                "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
                GH_PROXY_PREFIX
            ),
            None
        );
        assert_eq!(
            github_mirror_url("https://small.oisd.nl", GH_PROXY_PREFIX),
            None
        );

        let cn_order = ordered_github_candidates(
            "https://raw.githubusercontent.com/Cats-Team/AdRules/main/dns.txt",
            Some(GH_PROXY_PREFIX),
            true,
        );
        assert_eq!(
            cn_order,
            vec![
                (
                    "https://v6.gh-proxy.org/https://raw.githubusercontent.com/Cats-Team/AdRules/main/dns.txt".to_string(),
                    true
                ),
                (
                    "https://raw.githubusercontent.com/Cats-Team/AdRules/main/dns.txt".to_string(),
                    false
                ),
            ]
        );

        let default_order = ordered_github_candidates(
            "https://raw.githubusercontent.com/Cats-Team/AdRules/main/dns.txt",
            Some(GH_PROXY_PREFIX),
            false,
        );
        assert_eq!(
            default_order,
            vec![
                (
                    "https://raw.githubusercontent.com/Cats-Team/AdRules/main/dns.txt".to_string(),
                    false
                ),
                (
                    "https://v6.gh-proxy.org/https://raw.githubusercontent.com/Cats-Team/AdRules/main/dns.txt".to_string(),
                    true
                ),
            ]
        );
    }

    #[test]
    fn test_subscription_progress_manager_lifecycle_and_drop_reset() {
        let mgr = SubscriptionProgressManager::new();
        assert!(!mgr.status_snapshot().active);
        assert_eq!(mgr.status_snapshot().phase, SubscriptionLoadPhase::Idle);

        {
            let _guard = mgr.begin_batch(3);
            mgr.begin_item(2, Some("sub-2"), "AdRules");
            mgr.update_download(1024, Some(2048), true);
            let snap = mgr.status_snapshot();
            assert!(snap.active);
            assert_eq!(snap.phase, SubscriptionLoadPhase::Downloading);
            assert_eq!(snap.current_id.as_deref(), Some("sub-2"));
            assert_eq!(snap.current_name.as_deref(), Some("AdRules"));
            assert_eq!(snap.current_index, 2);
            assert_eq!(snap.total_count, 3);
            assert_eq!(snap.downloaded_bytes, 1024);
            assert_eq!(snap.total_bytes, Some(2048));
            assert!(snap.using_mirror);

            mgr.set_phase(SubscriptionLoadPhase::Rebuilding);
            assert_eq!(
                mgr.status_snapshot().phase,
                SubscriptionLoadPhase::Rebuilding
            );
        }

        let after = mgr.status_snapshot();
        assert!(!after.active);
        assert_eq!(after.phase, SubscriptionLoadPhase::Idle);
        assert_eq!(after.downloaded_bytes, 0);
        assert!(!after.using_mirror);
    }

    #[tokio::test]
    async fn test_fetch_subscription_progress_callback_reports_bytes() {
        let body = "||ads.example.com^\n||tracker.example.com^\n";
        let app = axum::Router::new().route(
            "/rules.txt",
            axum::routing::get(move || async move { body }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let client = build_subscription_http_client(true);
        let mut events = Vec::new();
        let text = fetch_subscription_with_fallback_and_progress(
            &client,
            &format!("http://{addr}/rules.txt"),
            true,
            None,
            |downloaded, total, using_mirror| {
                events.push((downloaded, total, using_mirror));
            },
        )
        .await
        .expect("fetch should succeed");

        assert_eq!(text, body);
        assert!(!events.is_empty());
        let last = events.last().copied().unwrap();
        assert_eq!(last.0, body.len() as u64);
        assert_eq!(last.1, Some(body.len() as u64));
        assert!(!last.2);
    }
}
