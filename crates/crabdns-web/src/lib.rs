use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::{StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use crabdns_core::{Config, DnsPipeline, FilterStats, QueryEvent};
use crabdns_storage::{StatsSnapshot, StorageEngine};
use rust_embed::Embed;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tower_http::cors::CorsLayer;

#[derive(Embed)]
#[folder = "../../webui/dist"]
struct WebAssets;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub pipeline: Arc<DnsPipeline>,
    pub storage: Arc<StorageEngine>,
    pub live_tx: broadcast::Sender<QueryEvent>,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    cache_entries: u64,
    filter_rules: usize,
}

#[derive(Debug, Serialize)]
struct StatsResponse {
    stats: StatsSnapshot,
    filter: FilterStats,
    cache_entries: u64,
}

#[derive(Debug, Deserialize)]
struct LogsQuery {
    limit: Option<usize>,
    search: Option<String>,
    outcome: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RulesPayload {
    rules_text: String,
    #[serde(default)]
    stats: Option<FilterStats>,
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/api/health", get(health))
        .route("/api/stats", get(get_stats))
        .route("/api/logs", get(get_logs))
        .route("/api/logs/ws", get(ws_logs))
        .route("/api/rules", get(get_rules).put(update_rules))
        .route("/api/config", get(get_config))
        .fallback(serve_spa)
        .layer(CorsLayer::permissive())
        .with_state(state)
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    let filter_stats = state.pipeline.filter().stats();
    Json(HealthResponse {
        status: "ok",
        cache_entries: state.pipeline.cache().entry_count(),
        filter_rules: filter_stats.total_rules,
    })
}

async fn get_stats(State(state): State<AppState>) -> Json<StatsResponse> {
    Json(StatsResponse {
        stats: state.storage.stats_snapshot(),
        filter: state.pipeline.filter().stats(),
        cache_entries: state.pipeline.cache().entry_count(),
    })
}

async fn get_logs(
    State(state): State<AppState>,
    Query(params): Query<LogsQuery>,
) -> std::result::Result<Json<Vec<QueryEvent>>, StatusCode> {
    let limit = params.limit.unwrap_or(100).clamp(1, 1000);
    let logs = state
        .storage
        .query_logs(limit, params.search.as_deref(), params.outcome.as_deref())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(logs))
}

async fn ws_logs(ws: WebSocketUpgrade, State(state): State<AppState>) -> Response {
    ws.on_upgrade(move |socket| handle_ws(socket, state.live_tx.subscribe()))
}

async fn handle_ws(mut socket: WebSocket, mut rx: broadcast::Receiver<QueryEvent>) {
    while let Ok(event) = rx.recv().await {
        let Ok(json) = serde_json::to_string(&event) else {
            continue;
        };
        if socket.send(Message::Text(json.into())).await.is_err() {
            break;
        }
    }
}

async fn get_rules(State(state): State<AppState>) -> Json<RulesPayload> {
    Json(RulesPayload {
        rules_text: state.pipeline.filter().raw_rules_text(),
        stats: Some(state.pipeline.filter().stats()),
    })
}

async fn update_rules(
    State(state): State<AppState>,
    Json(payload): Json<RulesPayload>,
) -> std::result::Result<Json<RulesPayload>, StatusCode> {
    state
        .storage
        .save_custom_rules(&payload.rules_text)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let filter_stats = state
        .pipeline
        .filter()
        .reload_from_text(&payload.rules_text);
    Ok(Json(RulesPayload {
        rules_text: payload.rules_text,
        stats: Some(filter_stats),
    }))
}

async fn get_config(State(state): State<AppState>) -> Json<Config> {
    Json((*state.config).clone())
}

async fn serve_spa(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    let target = if path.is_empty() { "index.html" } else { path };

    if let Some(content) = WebAssets::get(target) {
        let mime = mime_guess::from_path(target).first_or_octet_stream();
        return (
            StatusCode::OK,
            [(header::CONTENT_TYPE, mime.as_ref())],
            content.data,
        )
            .into_response();
    }

    if let Some(index) = WebAssets::get("index.html") {
        return (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            index.data,
        )
            .into_response();
    }

    (StatusCode::NOT_FOUND, "Web UI assets not built").into_response()
}
