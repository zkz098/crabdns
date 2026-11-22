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

#[cfg(test)]
mod tests {
    use super::*;
    use crabdns_core::{DnsCache, FilterEngine, UpstreamPool};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_web_api_endpoints_and_spa() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Arc::new(StorageEngine::open(dir.path()).expect("open fjall"));
        let cfg = Config {
            allow_private_subscriptions: true,
            ..Config::default()
        };
        let config = Arc::new(ArcSwap::from_pointee(cfg));
        let filter = Arc::new(FilterEngine::new(&["||initial.test^".to_string()]));
        let cache = Arc::new(DnsCache::new(64, true));
        let upstream =
            Arc::new(UpstreamPool::new(&["udp://127.0.0.1:1".to_string()], 200).expect("pool"));
        let pipeline = Arc::new(DnsPipeline::new(filter, cache, upstream, None));
        let (live_tx, _) = broadcast::channel(16);

        let app = build_router(AppState {
            config,
            pipeline: Arc::clone(&pipeline),
            storage,
            live_tx,
            tls_reloader: None,
        });

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let base = format!("http://{addr}");
        let client = reqwest::Client::new();

        let health_res = client
            .get(format!("{base}/api/health"))
            .send()
            .await
            .expect("health");
        assert_eq!(health_res.status(), StatusCode::OK);

        let stats_res = client
            .get(format!("{base}/api/stats"))
            .send()
            .await
            .expect("stats");
        assert_eq!(stats_res.status(), StatusCode::OK);

        let logs_res = client
            .get(format!("{base}/api/logs?limit=10"))
            .send()
            .await
            .expect("logs");
        assert_eq!(logs_res.status(), StatusCode::OK);

        let cfg_res = client
            .get(format!("{base}/api/config"))
            .send()
            .await
            .expect("config");
        assert_eq!(cfg_res.status(), StatusCode::OK);

        let rules_get = client
            .get(format!("{base}/api/rules"))
            .send()
            .await
            .expect("get rules");
        assert_eq!(rules_get.status(), StatusCode::OK);

        let body = serde_json::to_vec(&RulesPayload {
            rules_text: "||updated.test^\n".to_string(),
            enabled: true,
            stats: None,
        })
        .expect("json");
        let rules_put = client
            .put(format!("{base}/api/rules"))
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .expect("put rules");
        assert_eq!(rules_put.status(), StatusCode::OK);
        assert_eq!(pipeline.filter().stats().block_rules, 1);

        let spa_res = client.get(format!("{base}/")).send().await.expect("spa");
        assert_eq!(spa_res.status(), StatusCode::OK);
    }

    async fn spawn_mock_list_server() -> std::net::SocketAddr {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_clone = Arc::clone(&hits);
        let mock_app = Router::new().route(
            "/list.txt",
            get(move || {
                let count = hits_clone.fetch_add(1, Ordering::SeqCst);
                async move {
                    if count == 0 {
                        "||sub-ad1.test^\n||sub-ad2.test^\n".to_string()
                    } else {
                        "||sub-ad1.test^\n||sub-ad2.test^\n||sub-ad3.test^\n".to_string()
                    }
                }
            }),
        );
        let mock_listener = TcpListener::bind("127.0.0.1:0").await.expect("mock bind");
        let mock_addr = mock_listener.local_addr().expect("mock addr");
        tokio::spawn(async move {
            let _ = axum::serve(mock_listener, mock_app).await;
        });
        mock_addr
    }

    #[tokio::test]
    async fn test_subscription_crud_toggle_and_refresh() {
        use crabdns_core::FilterAction;
        use crabdns_storage::FilterSubscription;

        let mock_addr = spawn_mock_list_server().await;

        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Arc::new(StorageEngine::open(dir.path()).expect("open fjall"));
        let cfg = Config {
            allow_private_subscriptions: true,
            ..Config::default()
        };
        let config = Arc::new(ArcSwap::from_pointee(cfg));
        let filter = Arc::new(FilterEngine::new(&["||custom.test^".to_string()]));
        storage
            .save_custom_rules("||custom.test^\n")
            .expect("save custom");
        let cache = Arc::new(DnsCache::new(64, true));
        let upstream =
            Arc::new(UpstreamPool::new(&["udp://127.0.0.1:1".to_string()], 200).expect("pool"));
        let pipeline = Arc::new(DnsPipeline::new(filter, cache, upstream, None));
        let (live_tx, _) = broadcast::channel(16);

        let app = build_router(AppState {
            config,
            pipeline: Arc::clone(&pipeline),
            storage,
            live_tx,
            tls_reloader: None,
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let base = format!("http://{addr}");
        let client = reqwest::Client::new();

        // Create subscription
        let create_body = serde_json::to_vec(&serde_json::json!({
            "name": "Test List",
            "url": format!("http://{mock_addr}/list.txt"),
            "enabled": true
        }))
        .expect("json");
        let create_res = client
            .post(format!("{base}/api/subscriptions"))
            .header("content-type", "application/json")
            .body(create_body)
            .send()
            .await
            .expect("create sub");
        assert_eq!(create_res.status(), StatusCode::CREATED);
        let created: FilterSubscription =
            serde_json::from_slice(&create_res.bytes().await.expect("bytes")).expect("json");
        assert_eq!(created.rule_count, 2);
        assert!(created.last_updated.is_some());
        assert!(created.last_error.is_none());
        assert_eq!(pipeline.filter().stats().total_rules, 3);
        assert_eq!(
            pipeline.filter().evaluate("sub-ad1.test").action,
            FilterAction::Block
        );

        // Disable subscription
        let toggle_res = client
            .patch(format!("{base}/api/subscriptions/{}", created.id))
            .header("content-type", "application/json")
            .body(r#"{"enabled":false}"#)
            .send()
            .await
            .expect("disable sub");
        assert_eq!(toggle_res.status(), StatusCode::OK);
        assert_eq!(pipeline.filter().stats().total_rules, 1);
        assert_eq!(
            pipeline.filter().evaluate("sub-ad1.test").action,
            FilterAction::Allow
        );

        // Re-enable and refresh
        let enable_res = client
            .patch(format!("{base}/api/subscriptions/{}", created.id))
            .header("content-type", "application/json")
            .body(r#"{"enabled":true}"#)
            .send()
            .await
            .expect("enable sub");
        assert_eq!(enable_res.status(), StatusCode::OK);
        assert_eq!(pipeline.filter().stats().total_rules, 3);

        let refresh_res = client
            .post(format!("{base}/api/subscriptions/{}/refresh", created.id))
            .send()
            .await
            .expect("refresh sub");
        assert_eq!(refresh_res.status(), StatusCode::OK);
        let refreshed: FilterSubscription =
            serde_json::from_slice(&refresh_res.bytes().await.expect("bytes"))
                .expect("refreshed json");
        assert_eq!(refreshed.rule_count, 3);
        assert_eq!(pipeline.filter().stats().total_rules, 4);

        // Delete subscription
        let del_res = client
            .delete(format!("{base}/api/subscriptions/{}", created.id))
            .send()
            .await
            .expect("delete sub");
        assert_eq!(del_res.status(), StatusCode::NO_CONTENT);
        assert_eq!(pipeline.filter().stats().total_rules, 1);
    }

    #[tokio::test]
    async fn test_web_auth_login_protected_routes_and_logout() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Arc::new(StorageEngine::open(dir.path()).expect("open storage"));
        let config = Arc::new(ArcSwap::from_pointee(Config {
            data_dir: dir.path().to_path_buf(),
            ..Config::default()
        }));
        let filter = Arc::new(FilterEngine::new(&[]));
        let cache = Arc::new(DnsCache::new(64, false));
        let upstream =
            Arc::new(UpstreamPool::new(&["udp://1.1.1.1:53".to_string()], 1000).unwrap());
        let pipeline = Arc::new(DnsPipeline::new(filter, cache, upstream, None));
        let (live_tx, _) = broadcast::channel(16);

        let app = build_router(AppState {
            config,
            pipeline,
            storage,
            live_tx,
            tls_reloader: None,
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let base = format!("http://{addr}");
        let client = reqwest::Client::new();

        // Enable auth while currently unauthenticated (auth starts disabled)
        let enable_res = client
            .put(format!("{base}/api/auth/settings"))
            .header("content-type", "application/json")
            .body(r#"{"enabled":true,"username":"admin","password":"secret-password"}"#)
            .send()
            .await
            .expect("enable auth");
        assert_eq!(enable_res.status(), StatusCode::OK);

        // Public health still works; protected endpoints require auth
        let health_res = client
            .get(format!("{base}/api/health"))
            .send()
            .await
            .unwrap();
        assert_eq!(health_res.status(), StatusCode::OK);

        let unauthed = client
            .get(format!("{base}/api/config"))
            .send()
            .await
            .unwrap();
        assert_eq!(unauthed.status(), StatusCode::UNAUTHORIZED);

        // Wrong password rejected
        let bad_login = client
            .post(format!("{base}/api/auth/login"))
            .header("content-type", "application/json")
            .body(r#"{"username":"admin","password":"wrong"}"#)
            .send()
            .await
            .unwrap();
        assert_eq!(bad_login.status(), StatusCode::UNAUTHORIZED);

        // Valid login returns bearer token
        let good_login = client
            .post(format!("{base}/api/auth/login"))
            .header("content-type", "application/json")
            .body(r#"{"username":"admin","password":"secret-password"}"#)
            .send()
            .await
            .unwrap();
        assert_eq!(good_login.status(), StatusCode::OK);
        let login_json: auth::LoginResponse =
            serde_json::from_slice(&good_login.bytes().await.unwrap()).unwrap();

        // Protected endpoint succeeds with Bearer token
        let authed = client
            .get(format!("{base}/api/config"))
            .header("authorization", format!("Bearer {}", login_json.token))
            .send()
            .await
            .unwrap();
        assert_eq!(authed.status(), StatusCode::OK);

        // Logout invalidates token
        let logout_res = client
            .post(format!("{base}/api/auth/logout"))
            .header("authorization", format!("Bearer {}", login_json.token))
            .send()
            .await
            .unwrap();
        assert_eq!(logout_res.status(), StatusCode::OK);

        let after_logout = client
            .get(format!("{base}/api/config"))
            .header("authorization", format!("Bearer {}", login_json.token))
            .send()
            .await
            .unwrap();
        assert_eq!(after_logout.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_upstream_probe_endpoint_validation_and_response() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Arc::new(StorageEngine::open(dir.path()).expect("open storage"));
        let config = Arc::new(ArcSwap::from_pointee(Config {
            data_dir: dir.path().to_path_buf(),
            ..Config::default()
        }));
        let filter = Arc::new(FilterEngine::new(&[]));
        let cache = Arc::new(DnsCache::new(64, false));
        let upstream =
            Arc::new(UpstreamPool::new(&["udp://127.0.0.1:1".to_string()], 500).unwrap());
        let pipeline = Arc::new(DnsPipeline::new(filter, cache, upstream, None));
        let (live_tx, _) = broadcast::channel(16);

        let app = build_router(AppState {
            config,
            pipeline,
            storage,
            live_tx,
            tls_reloader: None,
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let base = format!("http://{addr}");
        let client = reqwest::Client::new();

        // Empty list rejected
        let empty_res = client
            .post(format!("{base}/api/upstreams/probe"))
            .header("content-type", "application/json")
            .body(r#"{"upstreams":[]}"#)
            .send()
            .await
            .unwrap();
        assert_eq!(empty_res.status(), StatusCode::BAD_REQUEST);

        // Unreachable local port returns structured capability entry
        let probe_res = client
            .post(format!("{base}/api/upstreams/probe"))
            .header("content-type", "application/json")
            .body(r#"{"upstreams":["udp://127.0.0.1:1"],"timeout_ms":500}"#)
            .send()
            .await
            .unwrap();
        assert_eq!(probe_res.status(), StatusCode::OK);
        let caps: Vec<UpstreamCapabilities> =
            serde_json::from_slice(&probe_res.bytes().await.unwrap()).unwrap();
        assert_eq!(caps.len(), 1);
        assert!(!caps[0].reachable);
        assert_eq!(caps[0].endpoint, "udp://127.0.0.1:1");
    }

    #[tokio::test]
    async fn test_doh_body_limit_and_atomic_config_rollback() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Arc::new(StorageEngine::open(dir.path()).expect("open storage"));
        let config = Arc::new(ArcSwap::from_pointee(Config {
            data_dir: dir.path().to_path_buf(),
            upstreams: vec!["udp://1.1.1.1:53".to_string()],
            ..Config::default()
        }));
        let filter = Arc::new(FilterEngine::new(&[]));
        let cache = Arc::new(DnsCache::new(64, false));
        let upstream =
            Arc::new(UpstreamPool::new(&["udp://1.1.1.1:53".to_string()], 1000).unwrap());
        let pipeline = Arc::new(DnsPipeline::new(filter, cache, upstream, None));
        let (live_tx, _) = broadcast::channel(16);

        let app = build_router(AppState {
            config: Arc::clone(&config),
            pipeline: Arc::clone(&pipeline),
            storage: Arc::clone(&storage),
            live_tx,
            tls_reloader: None,
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let base = format!("http://{addr}");
        let client = reqwest::Client::new();

        // Oversized DoH POST body (> 65,535 bytes) is rejected at DefaultBodyLimit.
        let big_res = client
            .post(format!("{base}/dns-query"))
            .header("content-type", "application/dns-message")
            .body(vec![0_u8; 70_000])
            .send()
            .await
            .unwrap();
        assert_eq!(big_res.status(), StatusCode::PAYLOAD_TOO_LARGE);

        // Partial invalid config (valid upstreams change + invalid split_dns) must NOT partially mutate pipeline.
        let bad_cfg = serde_json::json!({
            "upstreams": ["udp://9.9.9.9:53"],
            "cache_size": 128,
            "optimistic_cache": true,
            "upstream_timeout_ms": 1500,
            "log_retention_hours": 12,
            "split_dns": [{"domain": "corp.test", "upstreams": ["not-an-upstream"]}]
        });
        let put_res = client
            .put(format!("{base}/api/config"))
            .header("content-type", "application/json")
            .body(serde_json::to_vec(&bad_cfg).unwrap())
            .send()
            .await
            .unwrap();
        assert_eq!(put_res.status(), StatusCode::BAD_REQUEST);

        // Upstream in pipeline and stored config remain untouched (still 1.1.1.1).
        let snap = pipeline.upstream().health_snapshot();
        assert_eq!(snap[0].endpoint, "udp://1.1.1.1:53");
        assert_eq!(
            config.load().upstreams,
            vec!["udp://1.1.1.1:53".to_string()]
        );
        assert!(storage.load_config().unwrap().is_none());
    }

    #[tokio::test]
    async fn test_cors_tightened_and_metrics_histogram_exported() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Arc::new(StorageEngine::open(dir.path()).expect("open storage"));
        let config = Arc::new(ArcSwap::from_pointee(Config {
            data_dir: dir.path().to_path_buf(),
            ..Config::default()
        }));
        let filter = Arc::new(FilterEngine::new(&["||blocked.test^".to_string()]));
        let cache = Arc::new(DnsCache::new(64, false));
        let upstream =
            Arc::new(UpstreamPool::new(&["udp://1.1.1.1:53".to_string()], 1000).unwrap());
        let pipeline = Arc::new(DnsPipeline::new(filter, cache, upstream, None));
        let (live_tx, _) = broadcast::channel(16);

        let app = build_router(AppState {
            config,
            pipeline: Arc::clone(&pipeline),
            storage,
            live_tx,
            tls_reloader: None,
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let base = format!("http://{addr}");
        let client = reqwest::Client::new();

        // /api/* must NOT emit permissive Access-Control-Allow-Origin for untrusted Origin.
        let api_res = client
            .get(format!("{base}/api/health"))
            .header("origin", "https://evil.example")
            .send()
            .await
            .unwrap();
        assert_eq!(api_res.status(), StatusCode::OK);
        assert!(
            api_res
                .headers()
                .get("access-control-allow-origin")
                .is_none(),
            "API routes must not allow arbitrary cross-origin access"
        );

        // /dns-query keeps DoH CORS headers.
        let doh_opt = client
            .request(reqwest::Method::OPTIONS, format!("{base}/dns-query"))
            .header("origin", "https://dns.example")
            .header("access-control-request-method", "POST")
            .send()
            .await
            .unwrap();
        assert_eq!(
            doh_opt
                .headers()
                .get("access-control-allow-origin")
                .and_then(|v| v.to_str().ok()),
            Some("*")
        );

        // /metrics includes histogram and saturation counters.
        let metrics_text = client
            .get(format!("{base}/metrics"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        for expected in [
            "crabdns_query_duration_seconds_bucket{le=\"+Inf\"}",
            "crabdns_query_duration_seconds_count",
            "crabdns_udp_dropped_inflight_total",
            "crabdns_active_connections{protocol=\"tcp\"}",
            "crabdns_rejected_connections_total{protocol=\"dot\"}",
            "crabdns_doh_rejected_inflight_total",
            "crabdns_storage_log_batches_total",
            "crabdns_filter_reloads_total",
        ] {
            assert!(
                metrics_text.contains(expected),
                "missing metric '{expected}' in /metrics output"
            );
        }
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn test_backup_export_import_advanced_logs_and_stats_reset() {
        use chrono::Utc;
        use crabdns_core::{
            ClientGroup, ClientProfile, DnsRewriteEntry, DnsRewriteKind, FilterAction,
            QueryOutcome, QueryProtocol,
        };
        use crabdns_storage::FilterSubscription;

        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Arc::new(StorageEngine::open(dir.path()).expect("open storage"));
        let config = Arc::new(ArcSwap::from_pointee(Config {
            data_dir: dir.path().to_path_buf(),
            allow_private_subscriptions: true,
            ..Config::default()
        }));
        let filter = Arc::new(FilterEngine::new(&["||initial-block.test^".to_string()]));
        storage
            .save_custom_rules("||initial-block.test^\n")
            .expect("save rules");
        storage
            .save_dns_rewrites(&[DnsRewriteEntry {
                id: "rw-1".to_string(),
                domain: "nas.local".to_string(),
                kind: DnsRewriteKind::A,
                answer: "192.168.1.10".to_string(),
                enabled: true,
                comment: "NAS".to_string(),
            }])
            .expect("save rewrites");
        storage
            .save_client_groups(&[ClientGroup {
                id: "grp-kids".to_string(),
                name: "Kids".to_string(),
                description: "Kids devices".to_string(),
                blocking_enabled: true,
                use_global_rules: true,
                custom_rules: "||games.test^".to_string(),
                upstreams: Vec::new(),
                block_mode: None,
                cname_cloaking_blocking: None,
            }])
            .expect("save groups");
        storage
            .save_clients(&[ClientProfile {
                id: "cli-pad".to_string(),
                name: "Kid Pad".to_string(),
                identifiers: vec!["192.168.1.99".to_string()],
                group_id: Some("grp-kids".to_string()),
                blocking_enabled: None,
                use_global_rules: None,
                custom_rules: String::new(),
                upstreams: Vec::new(),
                block_mode: None,
                tags: vec!["tablet".to_string()],
            }])
            .expect("save clients");
        storage
            .save_subscriptions(&[FilterSubscription {
                id: "sub-1".to_string(),
                name: "Local List".to_string(),
                url: "https://example.com/list.txt".to_string(),
                enabled: true,
                rule_count: 1,
                last_updated: Some(Utc::now()),
                last_error: None,
            }])
            .expect("save subs");
        storage
            .save_subscription_content("sub-1", "||sub-blocked.test^\n")
            .expect("save sub content");

        storage
            .record_batch(&[
                QueryEvent {
                    timestamp: Utc::now(),
                    client_ip: "192.168.1.99".to_string(),
                    client_name: Some("Kid Pad".to_string()),
                    client_id: Some("kid-pad".to_string()),
                    profile_id: Some("cli-pad".to_string()),
                    protocol: QueryProtocol::Doq,
                    domain: "sub-blocked.test".to_string(),
                    qtype: "HTTPS".to_string(),
                    outcome: QueryOutcome::Blocked,
                    matched_rule: Some("||sub-blocked.test^".to_string()),
                    matched_list: Some("Local List".to_string()),
                    upstream: None,
                    elapsed_us: 55,
                    rcode: "NOERROR".to_string(),
                    answers: Vec::new(),
                },
                QueryEvent {
                    timestamp: Utc::now(),
                    client_ip: "192.168.1.10".to_string(),
                    client_name: Some("NAS".to_string()),
                    client_id: None,
                    profile_id: None,
                    protocol: QueryProtocol::Udp,
                    domain: "rust-lang.org".to_string(),
                    qtype: "A".to_string(),
                    outcome: QueryOutcome::Forwarded,
                    matched_rule: None,
                    matched_list: None,
                    upstream: Some("udp://1.1.1.1:53".to_string()),
                    elapsed_us: 800,
                    rcode: "NOERROR".to_string(),
                    answers: vec!["1.2.3.4".to_string()],
                },
            ])
            .expect("record batch");

        let cache = Arc::new(DnsCache::new(64, false));
        let upstream =
            Arc::new(UpstreamPool::new(&["udp://1.1.1.1:53".to_string()], 1000).unwrap());
        let pipeline = Arc::new(DnsPipeline::new(filter, cache, upstream, None));
        let (live_tx, _) = broadcast::channel(16);

        let app = build_router(AppState {
            config: Arc::clone(&config),
            pipeline: Arc::clone(&pipeline),
            storage: Arc::clone(&storage),
            live_tx,
            tls_reloader: None,
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let base = format!("http://{addr}");
        let client = reqwest::Client::new();

        // 1. Verify 24h timeseries in /api/stats
        let stats_res = client
            .get(format!("{base}/api/stats"))
            .send()
            .await
            .unwrap();
        assert_eq!(stats_res.status(), StatusCode::OK);
        let stats_json: serde_json::Value =
            serde_json::from_slice(&stats_res.bytes().await.unwrap()).unwrap();
        let ts = stats_json["stats"]["timeseries_24h"]
            .as_array()
            .expect("timeseries_24h array");
        assert_eq!(ts.len(), 24);
        assert_eq!(ts.last().unwrap()["total"].as_u64(), Some(2));
        assert_eq!(ts.last().unwrap()["blocked"].as_u64(), Some(1));

        // 2. Verify advanced log filters (protocol, qtype, client)
        let doq_bytes = client
            .get(format!(
                "{base}/api/logs?protocol=doq&qtype=HTTPS&client=Kid"
            ))
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        let doq_logs: Vec<QueryEvent> = serde_json::from_slice(&doq_bytes).unwrap();
        assert_eq!(doq_logs.len(), 1);
        assert_eq!(doq_logs[0].domain, "sub-blocked.test");

        // 3. Export backup
        let export_res = client
            .get(format!("{base}/api/backup"))
            .send()
            .await
            .unwrap();
        assert_eq!(export_res.status(), StatusCode::OK);
        let mut backup: backup_api::SystemBackupPayload =
            serde_json::from_slice(&export_res.bytes().await.unwrap()).unwrap();
        assert_eq!(backup.version, 1);
        assert_eq!(backup.rewrites.len(), 1);
        assert_eq!(backup.clients.len(), 1);
        assert_eq!(backup.client_groups.len(), 1);
        assert_eq!(backup.subscriptions.len(), 1);

        // Mutate backup and import it into live server
        backup.custom_rules = "||restored-ad.test^\n".to_string();
        backup.config.cache_size = 2048;
        let import_res = client
            .post(format!("{base}/api/backup"))
            .header("content-type", "application/json")
            .body(serde_json::to_vec(&backup).unwrap())
            .send()
            .await
            .unwrap();
        assert_eq!(import_res.status(), StatusCode::OK);

        // Live filter engine & config reflect imported backup
        assert_eq!(config.load().cache_size, 2048);
        assert_eq!(
            pipeline.filter().evaluate("restored-ad.test").action,
            FilterAction::Block
        );
        assert_eq!(
            pipeline.filter().evaluate("sub-blocked.test").action,
            FilterAction::Block
        );

        // 4. Clear logs & reset stats
        let clear_res = client
            .delete(format!("{base}/api/logs"))
            .send()
            .await
            .unwrap();
        assert_eq!(clear_res.status(), StatusCode::OK);
        let after_clear_bytes = client
            .get(format!("{base}/api/logs"))
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        let after_clear: Vec<QueryEvent> = serde_json::from_slice(&after_clear_bytes).unwrap();
        assert!(after_clear.is_empty());

        let reset_res = client
            .post(format!("{base}/api/stats/reset"))
            .send()
            .await
            .unwrap();
        assert_eq!(reset_res.status(), StatusCode::OK);
        let reset_json: serde_json::Value =
            serde_json::from_slice(&reset_res.bytes().await.unwrap()).unwrap();
        assert_eq!(reset_json["stats"]["total_queries"].as_u64(), Some(0));
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn test_web_update_api_status_check_and_apply() {
        use sigilup::UrlPolicy;
        use sigilup::core::{ArtifactHasher, SecretKeyBundle};
        use sigilup::manifest::{
            KeyPinFile, PlatformAsset, SignedManifest, UpdateManifest, current_platform_base,
            semver,
        };
        use std::collections::BTreeMap;
        use update_api::{
            EXPECTED_EXE_NAME, InstallTarget, UpdateConfig, UpdateManager, UpdateStatusResponse,
        };

        let sk = SecretKeyBundle::generate().expect("keygen");
        let pins = KeyPinFile::new(vec![sk.public_key().clone()]);
        let binary_payload = b"#!/bin/sh\necho crabdns-updated-via-web\n".to_vec();

        // Serve a signed manifest and raw binary artifact over a local mock server
        let mock_bin_for_route = binary_payload.clone();
        let asset_router = Router::new().route(
            &format!("/{EXPECTED_EXE_NAME}"),
            get(move || {
                let bytes = mock_bin_for_route.clone();
                async move { bytes }
            }),
        );
        let asset_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind asset");
        let asset_addr = asset_listener.local_addr().expect("asset addr");
        tokio::spawn(async move {
            let _ = axum::serve(asset_listener, asset_router).await;
        });

        let asset_url = format!("http://{asset_addr}/{EXPECTED_EXE_NAME}");
        let mut assets = BTreeMap::new();
        assets.insert(
            format!("{}-portable", current_platform_base()),
            PlatformAsset {
                kind: "portable".to_string(),
                url: asset_url.clone(),
                fallback_urls: Vec::new(),
                digest: ArtifactHasher::hash_bytes(&binary_payload),
                metadata: None::<serde_json::Value>,
            },
        );
        let manifest = UpdateManifest {
            schema_version: 2,
            version: semver::Version::new(9, 8, 7),
            security_epoch: 1,
            min_supported_version: None,
            published_at: 1_760_000_000,
            expires_at: None,
            notes: "Web API E2E update release notes".to_string(),
            assets,
            key_rotations: Vec::new(),
        };
        let signed = SignedManifest::sign(&manifest, &sk, 1_760_000_000).expect("sign");
        let manifest_json = serde_json::to_vec(&signed).expect("json");

        let manifest_router = Router::new().route(
            "/latest.hsig.json",
            get(move || {
                let bytes = manifest_json.clone();
                async move { bytes }
            }),
        );
        let manifest_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind manifest");
        let manifest_addr = manifest_listener.local_addr().expect("manifest addr");
        tokio::spawn(async move {
            let _ = axum::serve(manifest_listener, manifest_router).await;
        });

        let dir = tempfile::tempdir().expect("tempdir");
        let target_exe = dir.path().join("installed").join(EXPECTED_EXE_NAME);
        let mut url_policy = UrlPolicy::with_prefixes([format!("http://{asset_addr}/")]);
        url_policy.require_https = false;

        let updater = Arc::new(UpdateManager::new());
        updater.set_config_override(UpdateConfig {
            manifest_urls: vec![format!("http://{manifest_addr}/latest.hsig.json")],
            pins,
            url_policy,
            enforce_version_url_prefix: false,
            verify_timestamp_unix: Some(1_760_000_000),
            install_target: InstallTarget::CustomPath(target_exe.clone()),
        });

        let storage = Arc::new(StorageEngine::open(dir.path()).expect("open storage"));
        let config = Arc::new(ArcSwap::from_pointee(Config {
            data_dir: dir.path().to_path_buf(),
            ..Config::default()
        }));
        let filter = Arc::new(FilterEngine::new(&[]));
        let cache = Arc::new(DnsCache::new(64, false));
        let upstream =
            Arc::new(UpstreamPool::new(&["udp://127.0.0.1:1".to_string()], 200).unwrap());
        let pipeline = Arc::new(DnsPipeline::new(filter, cache, upstream, None));
        let (live_tx, _) = broadcast::channel(16);

        let app = build_router_with_updater(
            AppState {
                config,
                pipeline,
                storage,
                live_tx,
                tls_reloader: None,
            },
            updater,
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind web");
        let addr = listener.local_addr().expect("web addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let base = format!("http://{addr}");
        let client = reqwest::Client::new();

        // 1. Initial GET /api/update/status
        let status_res = client
            .get(format!("{base}/api/update/status"))
            .send()
            .await
            .unwrap();
        assert_eq!(status_res.status(), StatusCode::OK);
        let initial_status: UpdateStatusResponse =
            serde_json::from_slice(&status_res.bytes().await.unwrap()).unwrap();
        assert!(!initial_status.update_available);
        assert!(!initial_status.restart_pending);

        // 2. POST /api/update/check discovers v9.8.7
        let check_res = client
            .post(format!("{base}/api/update/check"))
            .send()
            .await
            .unwrap();
        assert_eq!(check_res.status(), StatusCode::OK);
        let checked_status: UpdateStatusResponse =
            serde_json::from_slice(&check_res.bytes().await.unwrap()).unwrap();
        assert!(checked_status.update_available);
        assert_eq!(checked_status.latest_version.as_deref(), Some("9.8.7"));
        assert_eq!(
            checked_status.notes.as_deref(),
            Some("Web API E2E update release notes")
        );

        // 3. POST /api/update/apply downloads, verifies, and installs the binary
        let apply_res = client
            .post(format!("{base}/api/update/apply"))
            .send()
            .await
            .unwrap();
        assert_eq!(apply_res.status(), StatusCode::OK);
        let applied_status: UpdateStatusResponse =
            serde_json::from_slice(&apply_res.bytes().await.unwrap()).unwrap();
        assert!(!applied_status.update_available);
        assert!(applied_status.restart_pending);
        assert_eq!(std::fs::read(&target_exe).unwrap(), binary_payload);
    }
}
