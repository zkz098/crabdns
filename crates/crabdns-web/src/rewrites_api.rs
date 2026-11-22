use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use chrono::Utc;
use crabdns_core::{DnsRewriteEntry, DnsRewriteKind, validate_dns_rewrite};
use serde::Deserialize;
use ts_rs::TS;

use crate::RouterState;
use crate::subscriptions::{ApiError, rebuild_filter_engine_async};

static REWRITE_ID_SEQ: AtomicU64 = AtomicU64::new(1);

const fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, TS)]
#[ts(export)]
pub struct DnsRewritePayload {
    pub domain: String,
    #[serde(default)]
    pub kind: DnsRewriteKind,
    pub answer: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub comment: String,
}

type ApiResult<T> = std::result::Result<T, (StatusCode, Json<ApiError>)>;

fn err_response(status: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<ApiError>) {
    (status, Json(ApiError { error: msg.into() }))
}

fn generate_rewrite_id() -> String {
    let nanos = Utc::now()
        .timestamp_nanos_opt()
        .unwrap_or(0)
        .cast_unsigned();
    let seq = REWRITE_ID_SEQ.fetch_add(1, Ordering::Relaxed);
    format!("rw-{nanos:x}-{seq}")
}

fn normalize_rewrite(id: String, payload: &DnsRewritePayload) -> ApiResult<DnsRewriteEntry> {
    let (domain, kind, answer) =
        validate_dns_rewrite(&payload.domain, payload.kind, &payload.answer)
            .map_err(|e| err_response(StatusCode::BAD_REQUEST, e.to_string()))?;
    Ok(DnsRewriteEntry {
        id,
        domain,
        kind,
        answer,
        enabled: payload.enabled,
        comment: payload.comment.trim().to_string(),
    })
}

async fn apply_rewrites_and_reload(state: &RouterState) -> ApiResult<()> {
    rebuild_filter_engine_async(&state.app.storage, &state.app.pipeline)
        .await
        .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    state.app.pipeline.cache().flush();
    Ok(())
}

pub async fn list_rewrites(
    State(state): State<RouterState>,
) -> ApiResult<Json<Vec<DnsRewriteEntry>>> {
    let storage = Arc::clone(&state.app.storage);
    let list = tokio::task::spawn_blocking(move || storage.list_dns_rewrites())
        .await
        .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(list))
}

pub async fn create_rewrite(
    State(state): State<RouterState>,
    Json(payload): Json<DnsRewritePayload>,
) -> ApiResult<(StatusCode, Json<DnsRewriteEntry>)> {
    let entry = normalize_rewrite(generate_rewrite_id(), &payload)?;
    let _guard = state.app.storage.rewrite_lock().lock().await;
    let storage = Arc::clone(&state.app.storage);
    let entry_clone = entry.clone();
    tokio::task::spawn_blocking(move || -> crabdns_storage::Result<()> {
        let mut list = storage.list_dns_rewrites()?;
        list.push(entry_clone);
        storage.save_dns_rewrites(&list)
    })
    .await
    .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    apply_rewrites_and_reload(&state).await?;
    Ok((StatusCode::CREATED, Json(entry)))
}

pub async fn update_rewrite(
    State(state): State<RouterState>,
    Path(id): Path<String>,
    Json(payload): Json<DnsRewritePayload>,
) -> ApiResult<Json<DnsRewriteEntry>> {
    let updated = normalize_rewrite(id.clone(), &payload)?;
    let _guard = state.app.storage.rewrite_lock().lock().await;
    let storage = Arc::clone(&state.app.storage);
    let updated_clone = updated.clone();
    let found = tokio::task::spawn_blocking(move || -> crabdns_storage::Result<bool> {
        let mut list = storage.list_dns_rewrites()?;
        let Some(slot) = list.iter_mut().find(|r| r.id == id) else {
            return Ok(false);
        };
        *slot = updated_clone;
        storage.save_dns_rewrites(&list)?;
        Ok(true)
    })
    .await
    .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if !found {
        return Err(err_response(StatusCode::NOT_FOUND, "DNS rewrite not found"));
    }

    apply_rewrites_and_reload(&state).await?;
    Ok(Json(updated))
}

pub async fn delete_rewrite(
    State(state): State<RouterState>,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let _guard = state.app.storage.rewrite_lock().lock().await;
    let storage = Arc::clone(&state.app.storage);
    let found = tokio::task::spawn_blocking(move || -> crabdns_storage::Result<bool> {
        let mut list = storage.list_dns_rewrites()?;
        let before = list.len();
        list.retain(|r| r.id != id);
        if list.len() == before {
            return Ok(false);
        }
        storage.save_dns_rewrites(&list)?;
        Ok(true)
    })
    .await
    .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if !found {
        return Err(err_response(StatusCode::NOT_FOUND, "DNS rewrite not found"));
    }

    apply_rewrites_and_reload(&state).await?;
    Ok(StatusCode::NO_CONTENT)
}
