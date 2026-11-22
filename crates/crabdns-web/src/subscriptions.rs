use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use chrono::Utc;
use crabdns_core::{DnsPipeline, FilterEngine};
use crabdns_storage::{FilterSubscription, StorageEngine};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::RouterState;

const MAX_SUBSCRIPTION_BYTES: usize = 50 * 1024 * 1024;

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

pub fn build_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("crabdns/0.1")
        .build()
        .unwrap_or_default()
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

pub async fn fetch_subscription_text_with_policy(
    client: &reqwest::Client,
    url: &str,
    allow_private: bool,
) -> Result<String, String> {
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

    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("Request failed: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }

    let bytes = read_response_bounded(resp, MAX_SUBSCRIPTION_BYTES).await?;
    Ok(String::from_utf8(bytes)
        .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned()))
}

async fn read_response_bounded(
    mut resp: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, String> {
    if let Some(len) = resp.content_length()
        && len > max_bytes as u64
    {
        return Err("Subscription file exceeds 50 MB limit".to_string());
    }

    let mut out = Vec::with_capacity(
        usize::try_from(resp.content_length().unwrap_or(0))
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
    }
    Ok(out)
}

pub fn rebuild_filter_engine(
    storage: &StorageEngine,
    pipeline: &DnsPipeline,
) -> Result<(), String> {
    let custom_rules = storage
        .load_custom_rules()
        .map_err(|e| e.to_string())?
        .unwrap_or_default();
    let custom_enabled = storage
        .load_custom_rules_enabled()
        .map_err(|e| e.to_string())?;
    let sub_contents = storage
        .load_enabled_named_subscription_contents()
        .map_err(|e| e.to_string())?;

    pipeline
        .filter()
        .reload_from_named_sources(&custom_rules, custom_enabled, &sub_contents);
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
) {
    match fetch_subscription_text_with_policy(client, &sub.url, allow_private).await {
        Ok(text) => {
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
    let mut snapshot = {
        let _guard = storage.subscription_lock().lock().await;
        storage_blocking(storage, StorageEngine::list_subscriptions).await?
    };

    for sub in &mut snapshot {
        if sub.enabled {
            fetch_and_store_subscription(client, storage, sub, allow_private).await;
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

    rebuild_filter_engine_async(storage, pipeline).await?;
    Ok(updated)
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
        fetch_and_store_subscription(
            &state.http_client,
            &state.app.storage,
            &mut sub,
            allow_private,
        )
        .await;
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
        fetch_and_store_subscription(
            &state.http_client,
            &state.app.storage,
            &mut updated_sub,
            allow_private,
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
    fetch_and_store_subscription(
        &state.http_client,
        &state.app.storage,
        &mut target,
        allow_private,
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
        rebuild_filter_engine_async(&state.app.storage, &state.app.pipeline)
            .await
            .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    }

    Ok(Json(target))
}

pub async fn refresh_all_subscriptions(
    State(state): State<RouterState>,
) -> ApiResult<Json<Vec<FilterSubscription>>> {
    let allow_private = state.app.config.load().allow_private_subscriptions;
    let subs = refresh_enabled_subscriptions_job_with_policy(
        &state.http_client,
        &state.app.storage,
        &state.app.pipeline,
        allow_private,
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
}
