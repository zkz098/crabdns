use std::sync::Arc;

use arc_swap::ArcSwap;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::{StatusCode, Uri, header};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post, put};
use axum::{Json, Router};
use crabdns_core::{CacheStats, Config, DnsPipeline, FilterStats, QueryEvent, UpstreamStatus};
use crabdns_storage::{StatsSnapshot, StorageEngine};
use rust_embed::Embed;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, broadcast};
use tower_http::cors::CorsLayer;
use ts_rs::TS;

pub mod auth;
pub mod config_api;
pub mod controls;
pub mod doh;
pub mod metrics;
pub mod subscriptions;

#[derive(Embed)]
#[folder = "../../webui/dist"]
struct WebAssets;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<ArcSwap<Config>>,
    pub pipeline: Arc<DnsPipeline>,
    pub storage: Arc<StorageEngine>,
    pub live_tx: broadcast::Sender<QueryEvent>,
}

#[derive(Clone)]
pub struct RouterState {
    pub app: AppState,
    pub sub_lock: Arc<Mutex<()>>,
    pub http_client: reqwest::Client,
    pub sessions: Arc<auth::SessionStore>,
    pub login_limiter: Arc<auth::LoginRateLimiter>,
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

pub use config_api::{ConfigResponse, ConfigUpdatePayload};

pub fn build_router(state: AppState) -> Router {
    let router_state = RouterState {
        app: state,
        sub_lock: Arc::new(Mutex::new(())),
        http_client: subscriptions::build_http_client(),
        sessions: Arc::new(auth::SessionStore::default()),
        login_limiter: Arc::new(auth::LoginRateLimiter::default()),
    };

    let protected_api = Router::new()
        .route("/api/stats", get(get_stats))
        .route("/api/logs", get(get_logs))
        .route("/api/logs/ws", get(ws_logs))
        .route("/api/rules", get(get_rules).put(update_rules))
        .route("/api/rules/quick", post(controls::quick_rule))
        .route("/api/rules/test", post(controls::test_rule))
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
            "/api/config",
            get(config_api::get_config).put(config_api::update_config),
        )
        .route(
            "/api/upstreams/health",
            get(get_upstream_health).post(probe_upstreams),
        )
        .route("/api/auth/settings", put(auth::update_auth))
        .layer(middleware::from_fn_with_state(
            router_state.clone(),
            auth::require_auth,
        ));

    Router::new()
        .route("/api/health", get(health))
        .route("/metrics", get(metrics::prometheus_metrics))
        .route("/dns-query", get(doh::doh_get).post(doh::doh_post))
        .route("/api/auth/status", get(auth::auth_status))
        .route("/api/auth/login", post(auth::login))
        .route("/api/auth/logout", post(auth::logout))
        .merge(protected_api)
        .fallback(serve_spa)
        .layer(CorsLayer::permissive())
        .with_state(router_state)
}

async fn get_upstream_health(State(state): State<RouterState>) -> Json<Vec<UpstreamStatus>> {
    Json(state.app.pipeline.upstream().health_snapshot())
}

async fn probe_upstreams(State(state): State<RouterState>) -> Json<Vec<UpstreamStatus>> {
    let pool = state.app.pipeline.upstream();
    pool.probe_all().await;
    Json(pool.health_snapshot())
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
    let logs = state
        .app
        .storage
        .query_logs(limit, params.search.as_deref(), params.outcome.as_deref())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(logs))
}

async fn ws_logs(ws: WebSocketUpgrade, State(state): State<RouterState>) -> Response {
    ws.on_upgrade(move |socket| handle_ws(socket, state.app.live_tx.subscribe()))
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

async fn get_rules(
    State(state): State<RouterState>,
) -> std::result::Result<Json<RulesPayload>, StatusCode> {
    let enabled = state
        .app
        .storage
        .load_custom_rules_enabled()
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
    state
        .app
        .storage
        .save_custom_rules(&payload.rules_text)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    state
        .app
        .storage
        .save_custom_rules_enabled(payload.enabled)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    subscriptions::rebuild_filter_engine(&state.app.storage, &state.app.pipeline)
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
}
