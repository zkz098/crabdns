use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use axum::extract::{DefaultBodyLimit, Query, Request, State};
use axum::http::{Method, StatusCode, Uri, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post, put};
use axum::{Json, Router};
use crabdns_core::{
    CacheStats, Config, DnsPipeline, FilterStats, QueryEvent, UpstreamCapabilities, UpstreamStatus,
    probe_upstreams as probe_upstream_caps,
};
use crabdns_storage::{LogsFilter, StatsSnapshot, StorageEngine};
use rust_embed::Embed;
use serde::{Deserialize, Serialize};
use tokio::sync::{Semaphore, broadcast};
use tower_http::cors::{Any, CorsLayer};
use ts_rs::TS;

pub mod auth;
pub mod backup_api;
pub mod clients_api;
pub mod config_api;
pub mod controls;
pub mod doh;
pub mod metrics;
pub mod proxy;
pub mod rewrites_api;
pub mod subscriptions;
pub mod tls_api;
pub mod update_api;

#[derive(Embed)]
#[folder = "../../webui/dist"]
struct WebAssets;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<ArcSwap<Config>>,
    pub pipeline: Arc<DnsPipeline>,
    pub storage: Arc<StorageEngine>,
    pub live_tx: broadcast::Sender<QueryEvent>,
    pub tls_reloader: Option<Arc<dyn tls_api::TlsReloader>>,
}

const DOH_MAX_INFLIGHT: usize = 512;
const API_REQUEST_TIMEOUT: Duration = Duration::from_secs(45);
const UPDATE_APPLY_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Clone)]
pub struct RouterState {
    pub app: AppState,
    pub http_client: reqwest::Client,
    pub http_client_private: reqwest::Client,
    pub sessions: Arc<auth::SessionStore>,
    pub login_limiter: Arc<auth::LoginRateLimiter>,
    pub doh_limiter: Arc<Semaphore>,
    pub updater: Arc<update_api::UpdateManager>,
}

impl RouterState {
    pub fn subscription_client(&self, allow_private: bool) -> &reqwest::Client {
        if allow_private {
            &self.http_client_private
        } else {
            &self.http_client
        }
    }
}

#[derive(Debug, Serialize, TS)]
#[ts(export)]
struct HealthResponse {
    status: &'static str,
    #[ts(type = "number")]
    cache_entries: u64,
    filter_rules: usize,
}

#[derive(Debug, Serialize, TS)]
#[ts(export)]
struct StatsResponse {
    stats: StatsSnapshot,
    filter: FilterStats,
    #[ts(type = "number")]
    cache_entries: u64,
    cache_stats: CacheStats,
}

#[derive(Debug, Deserialize)]
struct LogsQuery {
    limit: Option<usize>,
    search: Option<String>,
    outcome: Option<String>,
    protocol: Option<String>,
    qtype: Option<String>,
    client: Option<String>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Serialize, Deserialize, TS)]
#[ts(export)]
struct RulesPayload {
    rules_text: String,
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default)]
    stats: Option<FilterStats>,
}

#[derive(Debug, Deserialize, TS)]
#[ts(export)]
pub struct UpstreamProbePayload {
    pub upstreams: Vec<String>,
    #[serde(default)]
    pub bootstrap_dns: Option<Vec<String>>,
    #[serde(default)]
    #[ts(type = "number | null")]
    pub timeout_ms: Option<u64>,
}

pub use config_api::{ConfigResponse, ConfigUpdatePayload};

pub fn build_router(state: AppState) -> Router {
    build_router_with_updater(state, Arc::new(update_api::UpdateManager::new()))
}

#[allow(clippy::too_many_lines)]
pub fn build_router_with_updater(
    state: AppState,
    updater: Arc<update_api::UpdateManager>,
) -> Router {
    let router_state = RouterState {
        app: state,
        http_client: subscriptions::build_subscription_http_client(false),
        http_client_private: subscriptions::build_subscription_http_client(true),
        sessions: Arc::new(auth::SessionStore::default()),
        login_limiter: Arc::new(auth::LoginRateLimiter::default()),
        doh_limiter: Arc::new(Semaphore::new(DOH_MAX_INFLIGHT)),
        updater,
    };

    let protected_api = Router::new()
        .route("/api/stats", get(get_stats))
        .route("/api/stats/reset", post(reset_stats))
        .route("/api/logs", get(get_logs).delete(clear_logs))
        .route("/api/logs/ws", get(controls::ws_logs))
        .route(
            "/api/backup",
            get(backup_api::export_backup).post(backup_api::import_backup),
        )
        .route("/api/rules", get(get_rules).put(update_rules))
        .route("/api/rules/quick", post(controls::quick_rule))
        .route("/api/rules/test", post(controls::test_rule))
        .route(
            "/api/rewrites",
            get(rewrites_api::list_rewrites).post(rewrites_api::create_rewrite),
        )
        .route(
            "/api/rewrites/{id}",
            put(rewrites_api::update_rewrite).delete(rewrites_api::delete_rewrite),
        )
        .route("/api/cache/flush", post(controls::flush_cache))
        .route("/api/blocking/status", get(controls::get_blocking_status))
        .route("/api/blocking/pause", post(controls::pause_blocking))
        .route("/api/blocking/resume", post(controls::resume_blocking))
        .route(
            "/api/subscriptions",
            get(subscriptions::list_subscriptions).post(subscriptions::create_subscription),
        )
        .route(
            "/api/subscriptions/refresh",
            post(subscriptions::refresh_all_subscriptions),
        )
        .route(
            "/api/subscriptions/{id}",
            patch(subscriptions::update_subscription).delete(subscriptions::delete_subscription),
        )
        .route(
            "/api/subscriptions/{id}/refresh",
            post(subscriptions::refresh_subscription),
        )
        .route(
            "/api/clients",
            get(clients_api::list_clients_overview).post(clients_api::create_client),
        )
        .route(
            "/api/clients/{id}",
            put(clients_api::update_client).delete(clients_api::delete_client),
        )
        .route("/api/client-groups", post(clients_api::create_group))
        .route(
            "/api/client-groups/{id}",
            put(clients_api::update_group).delete(clients_api::delete_group),
        )
        .route("/api/tls/status", get(tls_api::get_tls_status))
        .route("/api/tls/reload", post(tls_api::reload_tls))
        .route(
            "/api/config",
            get(config_api::get_config).put(config_api::update_config),
        )
        .route(
            "/api/upstreams/health",
            get(get_upstream_health).post(probe_upstreams),
        )
        .route("/api/upstreams/probe", post(probe_upstream_capabilities))
        .route("/api/auth/settings", put(auth::update_auth))
        .route("/api/update/status", get(update_api::get_update_status))
        .route("/api/update/check", post(update_api::check_update))
        .route("/api/update/apply", post(update_api::apply_update));

    #[cfg(all(feature = "prof-jemalloc", unix))]
    let protected_api = protected_api.route("/debug/pprof/heap", get(metrics::pprof_heap));

    let protected_api = protected_api.layer(middleware::from_fn_with_state(
        router_state.clone(),
        auth::require_auth,
    ));

    let doh_cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE, header::ACCEPT]);

    let doh_routes = Router::new()
        .route("/dns-query", get(doh::doh_get).post(doh::doh_post))
        .route(
            "/dns-query/{client_id}",
            get(doh::doh_get_client).post(doh::doh_post_client),
        )
        .layer(DefaultBodyLimit::max(doh::MAX_DOH_PACKET_BYTES))
        .layer(doh_cors);

    Router::new()
        .route("/api/health", get(health))
        .route("/metrics", get(metrics::prometheus_metrics))
        .merge(doh_routes)
        .route("/api/auth/status", get(auth::auth_status))
        .route("/api/auth/login", post(auth::login))
        .route("/api/auth/logout", post(auth::logout))
        .merge(protected_api)
        .fallback(serve_spa)
        .layer(middleware::from_fn(request_timeout_middleware))
        .with_state(router_state)
}

async fn request_timeout_middleware(req: Request, next: Next) -> Response {
    if req.uri().path() == "/api/logs/ws" {
        return next.run(req).await;
    }
    let timeout = if req.uri().path() == "/api/update/apply" {
        UPDATE_APPLY_TIMEOUT
    } else {
        API_REQUEST_TIMEOUT
    };
    match tokio::time::timeout(timeout, next.run(req)).await {
        Ok(resp) => resp,
        Err(_) => (StatusCode::REQUEST_TIMEOUT, "request timed out").into_response(),
    }
}

async fn get_upstream_health(State(state): State<RouterState>) -> Json<Vec<UpstreamStatus>> {
    Json(state.app.pipeline.upstream().health_snapshot())
}

async fn probe_upstreams(State(state): State<RouterState>) -> Json<Vec<UpstreamStatus>> {
    let pool = state.app.pipeline.upstream();
    pool.probe_all().await;
    Json(pool.health_snapshot())
}

const MAX_PROBE_UPSTREAMS: usize = 16;

async fn probe_upstream_capabilities(
    State(state): State<RouterState>,
    Json(payload): Json<UpstreamProbePayload>,
) -> std::result::Result<Json<Vec<UpstreamCapabilities>>, (StatusCode, Json<serde_json::Value>)> {
    let upstreams: Vec<String> = payload
        .upstreams
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if upstreams.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "at least one upstream server is required" })),
        ));
    }
    if upstreams.len() > MAX_PROBE_UPSTREAMS {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!("too many upstreams to probe at once (max {MAX_PROBE_UPSTREAMS})")
            })),
        ));
    }

    let cfg = state.app.config.load();
    let bootstrap_dns: Vec<String> = payload
        .bootstrap_dns
        .unwrap_or_else(|| cfg.bootstrap_dns.clone())
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let timeout_ms = payload
        .timeout_ms
        .unwrap_or(cfg.upstream_timeout_ms)
        .clamp(500, 10_000);

    let results = probe_upstream_caps(&upstreams, &bootstrap_dns, timeout_ms)
        .await
        .map_err(|err| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": err.to_string() })),
            )
        })?;
    Ok(Json(results))
}

async fn health(State(state): State<RouterState>) -> Json<HealthResponse> {
    let filter_stats = state.app.pipeline.filter().stats();
    Json(HealthResponse {
        status: "ok",
        cache_entries: state.app.pipeline.cache().entry_count(),
        filter_rules: filter_stats.total_rules,
    })
}

async fn get_stats(State(state): State<RouterState>) -> Json<StatsResponse> {
    let cache_stats = state.app.pipeline.cache().stats();
    Json(StatsResponse {
        stats: state.app.storage.stats_snapshot(),
        filter: state.app.pipeline.filter().stats(),
        cache_entries: cache_stats.entries,
        cache_stats,
    })
}

async fn get_logs(
    State(state): State<RouterState>,
    Query(params): Query<LogsQuery>,
) -> std::result::Result<Json<Vec<QueryEvent>>, StatusCode> {
    let limit = params.limit.unwrap_or(100).clamp(1, 1000);
    let storage = Arc::clone(&state.app.storage);
    let search = params.search;
    let outcome = params.outcome;
    let protocol = params.protocol;
    let qtype = params.qtype;
    let client = params.client;
    let logs = tokio::task::spawn_blocking(move || {
        storage.query_logs_filtered(
            limit,
            &LogsFilter {
                search: search.as_deref(),
                outcome: outcome.as_deref(),
                protocol: protocol.as_deref(),
                qtype: qtype.as_deref(),
                client: client.as_deref(),
            },
        )
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(logs))
}

async fn clear_logs(
    State(state): State<RouterState>,
) -> std::result::Result<Json<serde_json::Value>, StatusCode> {
    let storage = Arc::clone(&state.app.storage);
    let removed = tokio::task::spawn_blocking(move || storage.clear_logs())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::json!({ "removed": removed })))
}

async fn reset_stats(
    State(state): State<RouterState>,
) -> std::result::Result<Json<StatsResponse>, StatusCode> {
    let storage = Arc::clone(&state.app.storage);
    tokio::task::spawn_blocking(move || storage.reset_stats())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let cache_stats = state.app.pipeline.cache().stats();
    Ok(Json(StatsResponse {
        stats: state.app.storage.stats_snapshot(),
        filter: state.app.pipeline.filter().stats(),
        cache_entries: cache_stats.entries,
        cache_stats,
    }))
}

async fn get_rules(
    State(state): State<RouterState>,
) -> std::result::Result<Json<RulesPayload>, StatusCode> {
    let storage = Arc::clone(&state.app.storage);
    let enabled = tokio::task::spawn_blocking(move || storage.load_custom_rules_enabled())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(RulesPayload {
        rules_text: state.app.pipeline.filter().raw_rules_text(),
        enabled,
        stats: Some(state.app.pipeline.filter().stats()),
    }))
}

async fn update_rules(
    State(state): State<RouterState>,
    Json(payload): Json<RulesPayload>,
) -> std::result::Result<Json<RulesPayload>, StatusCode> {
    let _guard = state.app.storage.subscription_lock().lock().await;
    let storage = Arc::clone(&state.app.storage);
    let rules_text = payload.rules_text.clone();
    let enabled = payload.enabled;
    tokio::task::spawn_blocking(move || -> Result<(), crabdns_storage::StorageError> {
        storage.save_custom_rules(&rules_text)?;
        storage.save_custom_rules_enabled(enabled)?;
        Ok(())
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    subscriptions::rebuild_filter_engine_async(&state.app.storage, &state.app.pipeline)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let filter_stats = state.app.pipeline.filter().stats();
    Ok(Json(RulesPayload {
        rules_text: payload.rules_text,
        enabled: payload.enabled,
        stats: Some(filter_stats),
    }))
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
