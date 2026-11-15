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

pub fn validate_subscription_url(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("URL cannot be empty".to_string());
    }
    let parsed = reqwest::Url::parse(trimmed).map_err(|e| format!("Invalid URL: {e}"))?;
    match parsed.scheme() {
        "http" | "https" => Ok(trimmed.to_string()),
        other => Err(format!("Unsupported URL scheme '{other}'; use http or https")),
    }
}

pub async fn fetch_subscription_text(client: &reqwest::Client, url: &str) -> Result<String, String> {
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("Request failed: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }

    if let Some(len) = resp.content_length()
        && len > MAX_SUBSCRIPTION_BYTES as u64
    {
        return Err("Subscription file exceeds 50 MB limit".to_string());
    }

    let bytes = resp
        .bytes()
        .await
        .map_err(|e| format!("Failed to read response body: {e}"))?;

    if bytes.len() > MAX_SUBSCRIPTION_BYTES {
        return Err("Subscription file exceeds 50 MB limit".to_string());
    }

    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

pub fn rebuild_filter_engine(storage: &StorageEngine, pipeline: &DnsPipeline) -> Result<(), String> {
    let custom_rules = storage
        .load_custom_rules()
        .map_err(|e| e.to_string())?
        .unwrap_or_default();
    let custom_enabled = storage
        .load_custom_rules_enabled()
        .map_err(|e| e.to_string())?;
    let sub_contents = storage
        .load_enabled_subscription_contents()
        .map_err(|e| e.to_string())?;

    pipeline
        .filter()
        .reload_from_sources(&custom_rules, custom_enabled, &sub_contents);
    Ok(())
}

fn generate_sub_id() -> String {
    let nanos = Utc::now().timestamp_nanos_opt().unwrap_or(0).cast_unsigned();
    format!("sub-{nanos:x}")
}

async fn fetch_and_store_subscription(
    client: &reqwest::Client,
    storage: &StorageEngine,
    sub: &mut FilterSubscription,
) {
    match fetch_subscription_text(client, &sub.url).await {
        Ok(text) => {
            let stats = FilterEngine::count_rules_in_text(&text);
            if let Err(err) = storage.save_subscription_content(&sub.id, &text) {
                sub.last_error = Some(err.to_string());
                return;
            }
            sub.rule_count = stats.total_rules;
            sub.last_updated = Some(Utc::now());
            sub.last_error = None;
        }
        Err(err) => {
            sub.last_error = Some(err);
        }
    }
}

pub async fn refresh_enabled_subscriptions_job(
    client: &reqwest::Client,
    storage: &StorageEngine,
    pipeline: &DnsPipeline,
) -> Result<Vec<FilterSubscription>, String> {
    let mut subs = storage.list_subscriptions().map_err(|e| e.to_string())?;
    for sub in &mut subs {
        if sub.enabled {
            fetch_and_store_subscription(client, storage, sub).await;
        }
    }
    storage.save_subscriptions(&subs).map_err(|e| e.to_string())?;
    rebuild_filter_engine(storage, pipeline)?;
    Ok(subs)
}

pub async fn list_subscriptions(State(state): State<RouterState>) -> ApiResult<Json<Vec<FilterSubscription>>> {
    let subs = state
        .app
        .storage
        .list_subscriptions()
        .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(subs))
}

pub async fn create_subscription(
    State(state): State<RouterState>,
    Json(payload): Json<CreateSubscriptionPayload>,
) -> ApiResult<(StatusCode, Json<FilterSubscription>)> {
    let name = payload.name.trim().to_string();
    if name.is_empty() {
        return Err(err_response(StatusCode::BAD_REQUEST, "Name cannot be empty"));
    }
    let url = validate_subscription_url(&payload.url)
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
        fetch_and_store_subscription(&state.http_client, &state.app.storage, &mut sub).await;
    }

    let _guard = state.sub_lock.lock().await;
    let mut subs = state
        .app
        .storage
        .list_subscriptions()
        .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    subs.push(sub.clone());
    state
        .app
        .storage
        .save_subscriptions(&subs)
        .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if sub.enabled && sub.last_error.is_none() {
        rebuild_filter_engine(&state.app.storage, &state.app.pipeline)
            .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    }

    Ok((StatusCode::CREATED, Json(sub)))
}

pub async fn update_subscription(
    State(state): State<RouterState>,
    Path(id): Path<String>,
    Json(payload): Json<UpdateSubscriptionPayload>,
) -> ApiResult<Json<FilterSubscription>> {
    let next_url = match payload.url {
        Some(ref raw) => Some(
            validate_subscription_url(raw)
                .map_err(|e| err_response(StatusCode::BAD_REQUEST, e))?,
        ),
        None => None,
    };

    let mut should_fetch = false;
    let mut updated_sub = {
        let _guard = state.sub_lock.lock().await;
        let mut subs = state
            .app
            .storage
            .list_subscriptions()
            .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let Some(sub) = subs.iter_mut().find(|s| s.id == id) else {
            return Err(err_response(StatusCode::NOT_FOUND, "Subscription not found"));
        };

        if let Some(name) = payload.name {
            let trimmed = name.trim().to_string();
            if trimmed.is_empty() {
                return Err(err_response(StatusCode::BAD_REQUEST, "Name cannot be empty"));
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
        state
            .app
            .storage
            .save_subscriptions(&subs)
            .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        clone
    };

    if should_fetch {
        fetch_and_store_subscription(&state.http_client, &state.app.storage, &mut updated_sub).await;
        let _guard = state.sub_lock.lock().await;
        let mut subs = state
            .app
            .storage
            .list_subscriptions()
            .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        if let Some(sub) = subs.iter_mut().find(|s| s.id == id) {
            sub.rule_count = updated_sub.rule_count;
            sub.last_updated = updated_sub.last_updated;
            sub.last_error.clone_from(&updated_sub.last_error);
            state
                .app
                .storage
                .save_subscriptions(&subs)
                .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        }
    }

    rebuild_filter_engine(&state.app.storage, &state.app.pipeline)
        .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(Json(updated_sub))
}

pub async fn delete_subscription(
    State(state): State<RouterState>,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    {
        let _guard = state.sub_lock.lock().await;
        let mut subs = state
            .app
            .storage
            .list_subscriptions()
            .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let before = subs.len();
        subs.retain(|s| s.id != id);
        if subs.len() == before {
            return Err(err_response(StatusCode::NOT_FOUND, "Subscription not found"));
        }
        state
            .app
            .storage
            .save_subscriptions(&subs)
            .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        state
            .app
            .storage
            .delete_subscription_content(&id)
            .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    rebuild_filter_engine(&state.app.storage, &state.app.pipeline)
        .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn refresh_subscription(
    State(state): State<RouterState>,
    Path(id): Path<String>,
) -> ApiResult<Json<FilterSubscription>> {
    let mut target = {
        let subs = state
            .app
            .storage
            .list_subscriptions()
            .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        subs.into_iter()
            .find(|s| s.id == id)
            .ok_or_else(|| err_response(StatusCode::NOT_FOUND, "Subscription not found"))?
    };

    fetch_and_store_subscription(&state.http_client, &state.app.storage, &mut target).await;

    {
        let _guard = state.sub_lock.lock().await;
        let mut subs = state
            .app
            .storage
            .list_subscriptions()
            .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        if let Some(sub) = subs.iter_mut().find(|s| s.id == id) {
            sub.rule_count = target.rule_count;
            sub.last_updated = target.last_updated;
            sub.last_error.clone_from(&target.last_error);
            state
                .app
                .storage
                .save_subscriptions(&subs)
                .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        }
    }

    if target.enabled {
        rebuild_filter_engine(&state.app.storage, &state.app.pipeline)
            .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    }

    Ok(Json(target))
}

pub async fn refresh_all_subscriptions(
    State(state): State<RouterState>,
) -> ApiResult<Json<Vec<FilterSubscription>>> {
    let _guard = state.sub_lock.lock().await;
    let subs = refresh_enabled_subscriptions_job(
        &state.http_client,
        &state.app.storage,
        &state.app.pipeline,
    )
    .await
    .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(subs))
}
