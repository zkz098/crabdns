use std::sync::Arc;

use arc_swap::ArcSwap;
use axum::Router;
use axum::http::StatusCode;
use axum::routing::get;
use crabdns_core::{
    Config, DnsCache, DnsPipeline, FilterEngine, QueryEvent, UpstreamCapabilities, UpstreamPool,
};
use crabdns_storage::StorageEngine;
use crabdns_web::{AppState, auth, backup_api, build_router, build_router_with_updater};
use tokio::net::TcpListener;
use tokio::sync::broadcast;

#[tokio::test]
async fn test_web_api_endpoints_and_spa() {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(StorageEngine::open(dir.path()).expect("open fjall"));
    let cfg = Config {
        runtime: crabdns_core::RuntimeConfig {
            allow_private_subscriptions: true,
            ..Default::default()
        },
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

    let body = serde_json::to_vec(&serde_json::json!({
        "rules_text": "||updated.test^\n",
        "enabled": true,
    }))
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
        runtime: crabdns_core::RuntimeConfig {
            allow_private_subscriptions: true,
            ..Default::default()
        },
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
        serde_json::from_slice(&refresh_res.bytes().await.expect("bytes")).expect("refreshed json");
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
    let mut cfg = Config::default();
    cfg.bootstrap.data_dir = dir.path().to_path_buf();
    let config = Arc::new(ArcSwap::from_pointee(cfg));
    let filter = Arc::new(FilterEngine::new(&[]));
    let cache = Arc::new(DnsCache::new(64, false));
    let upstream = Arc::new(UpstreamPool::new(&["udp://1.1.1.1:53".to_string()], 1000).unwrap());
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
    let mut cfg = Config::default();
    cfg.bootstrap.data_dir = dir.path().to_path_buf();
    let config = Arc::new(ArcSwap::from_pointee(cfg));
    let filter = Arc::new(FilterEngine::new(&[]));
    let cache = Arc::new(DnsCache::new(64, false));
    let upstream = Arc::new(UpstreamPool::new(&["udp://127.0.0.1:1".to_string()], 500).unwrap());
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
    let mut cfg = Config::default();
    cfg.bootstrap.data_dir = dir.path().to_path_buf();
    cfg.upstreams = vec!["udp://1.1.1.1:53".to_string()];
    let config = Arc::new(ArcSwap::from_pointee(cfg));
    let filter = Arc::new(FilterEngine::new(&[]));
    let cache = Arc::new(DnsCache::new(64, false));
    let upstream = Arc::new(UpstreamPool::new(&["udp://1.1.1.1:53".to_string()], 1000).unwrap());
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
    let mut cfg = Config::default();
    cfg.bootstrap.data_dir = dir.path().to_path_buf();
    let config = Arc::new(ArcSwap::from_pointee(cfg));
    let filter = Arc::new(FilterEngine::new(&["||blocked.test^".to_string()]));
    let cache = Arc::new(DnsCache::new(64, false));
    let upstream = Arc::new(UpstreamPool::new(&["udp://1.1.1.1:53".to_string()], 1000).unwrap());
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
        ClientGroup, ClientProfile, DnsRewriteEntry, DnsRewriteKind, FilterAction, QueryOutcome,
        QueryProtocol,
    };
    use crabdns_storage::FilterSubscription;

    let dir = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(StorageEngine::open(dir.path()).expect("open storage"));
    let mut cfg = Config::default();
    cfg.bootstrap.data_dir = dir.path().to_path_buf();
    cfg.allow_private_subscriptions = true;
    let config = Arc::new(ArcSwap::from_pointee(cfg));
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
            safesearch_enabled: None,
            blocked_services: None,
            upstream_policy: crabdns_core::UpstreamPolicy::default(),
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
            safesearch_enabled: None,
            blocked_services: None,
            upstream_policy: crabdns_core::UpstreamPolicy::default(),
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
    let upstream = Arc::new(UpstreamPool::new(&["udp://1.1.1.1:53".to_string()], 1000).unwrap());
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
    use crabdns_web::update_api::{
        EXPECTED_EXE_NAME, InstallTarget, UpdateConfig, UpdateManager, UpdateStatusResponse,
    };
    use sigilup::UrlPolicy;
    use sigilup::core::{ArtifactHasher, SecretKeyBundle};
    use sigilup::manifest::{
        KeyPinFile, PlatformAsset, SignedManifest, UpdateManifest, current_platform_base, semver,
    };
    use std::collections::BTreeMap;

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
    let mut cfg = Config::default();
    cfg.bootstrap.data_dir = dir.path().to_path_buf();
    let config = Arc::new(ArcSwap::from_pointee(cfg));
    let filter = Arc::new(FilterEngine::new(&[]));
    let cache = Arc::new(DnsCache::new(64, false));
    let upstream = Arc::new(UpstreamPool::new(&["udp://127.0.0.1:1".to_string()], 200).unwrap());
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

#[tokio::test]
async fn test_setup_mobileconfig_endpoint() {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(StorageEngine::open(dir.path()).expect("open fjall"));
    let cfg = Config::default();
    let filter = Arc::new(FilterEngine::new(&[]));
    let cache = Arc::new(DnsCache::new(64, true));
    let pool = Arc::new(UpstreamPool::new(&cfg.upstreams, 1000).unwrap());
    let pipeline = Arc::new(DnsPipeline::new(filter, cache, pool, None));
    let (live_tx, _) = tokio::sync::broadcast::channel(16);

    let app = build_router(AppState {
        config: Arc::new(ArcSwap::from_pointee(cfg)),
        pipeline,
        storage,
        live_tx,
        tls_reloader: None,
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let client = reqwest::Client::new();
    let res = client
        .get(format!(
            "http://{addr}/api/setup/mobileconfig?protocol=doh&hostname=dns.example.com&client_id=iphone"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = res.text().await.unwrap();
    assert!(body.contains("<string>HTTPS</string>"));
    assert!(body.contains("https://dns.example.com/dns-query/iphone"));

    let bad = client
        .get(format!(
            "http://{addr}/api/setup/mobileconfig?protocol=ftp&hostname=dns.example.com"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_initial_setup_wizard_endpoints() {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(StorageEngine::open(dir.path()).expect("open fjall"));
    let cfg = Config::default();
    let filter = Arc::new(FilterEngine::new(&[]));
    let cache = Arc::new(DnsCache::new(64, true));
    let pool = Arc::new(UpstreamPool::new(&cfg.upstreams, 1000).unwrap());
    let pipeline = Arc::new(DnsPipeline::new(filter, cache, pool, None));
    let (live_tx, _) = tokio::sync::broadcast::channel(16);

    let app = build_router(AppState {
        config: Arc::new(ArcSwap::from_pointee(cfg)),
        pipeline,
        storage,
        live_tx,
        tls_reloader: None,
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let client = reqwest::Client::new();

    let status_res = client
        .get(format!("http://{addr}/api/setup/status"))
        .send()
        .await
        .unwrap();
    assert_eq!(status_res.status(), StatusCode::OK);
    let status_json: serde_json::Value =
        serde_json::from_str(&status_res.text().await.unwrap()).unwrap();
    assert_eq!(status_json["setup_required"], true);

    let complete_res = client
        .post(format!("http://{addr}/api/setup/complete"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(
            serde_json::json!({
                "skip": false,
                "enable_auth": true,
                "username": "admin",
                "password": "wizard-password-123",
                "upstreams": ["1.1.1.1:53"],
                "block_mode": "nx_domain",
                "dnssec_enabled": true
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(complete_res.status(), StatusCode::OK);
    let set_cookie = complete_res
        .headers()
        .get(reqwest::header::SET_COOKIE)
        .expect("session cookie should be set")
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let complete_json: serde_json::Value =
        serde_json::from_str(&complete_res.text().await.unwrap()).unwrap();
    assert_eq!(complete_json["auth_enabled"], true);
    assert_eq!(complete_json["authenticated"], true);

    // Subsequent status check reports setup_required = false
    let after_status_text = client
        .get(format!("http://{addr}/api/setup/status"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let after_status: serde_json::Value = serde_json::from_str(&after_status_text).unwrap();
    assert_eq!(after_status["setup_required"], false);

    // Re-running setup complete is rejected with 409 Conflict
    let second_complete = client
        .post(format!("http://{addr}/api/setup/complete"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(serde_json::json!({ "skip": true }).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(second_complete.status(), StatusCode::CONFLICT);

    // Unauthenticated request to protected route is rejected
    let unauth_cfg = client
        .get(format!("http://{addr}/api/config"))
        .send()
        .await
        .unwrap();
    assert_eq!(unauth_cfg.status(), StatusCode::UNAUTHORIZED);

    // Cookie issued by complete_setup grants access to protected routes
    let cfg_res = client
        .get(format!("http://{addr}/api/config"))
        .header(reqwest::header::COOKIE, set_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(cfg_res.status(), StatusCode::OK);
    let cfg_json: serde_json::Value = serde_json::from_str(&cfg_res.text().await.unwrap()).unwrap();
    assert_eq!(cfg_json["web_auth_enabled"], true);
    assert_eq!(cfg_json["dnssec_enabled"], true);
    assert_eq!(cfg_json["upstreams"][0], "1.1.1.1:53");
}

#[tokio::test]
async fn test_port_precheck_endpoint() {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(StorageEngine::open(dir.path()).expect("open fjall"));
    let cfg = Config::default();
    let expected_dns = cfg.bootstrap.listen_dns.to_string();
    let filter = Arc::new(FilterEngine::new(&[]));
    let cache = Arc::new(DnsCache::new(64, true));
    let pool = Arc::new(UpstreamPool::new(&cfg.upstreams, 1000).unwrap());
    let pipeline = Arc::new(DnsPipeline::new(filter, cache, pool, None));
    let (live_tx, _) = tokio::sync::broadcast::channel(16);

    let app = build_router(AppState {
        config: Arc::new(ArcSwap::from_pointee(cfg)),
        pipeline,
        storage,
        live_tx,
        tls_reloader: None,
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    // Keep an occupied port open for testing in_use detection
    let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let occupied_addr = occupied.local_addr().unwrap().to_string();

    let client = reqwest::Client::new();
    let res = client
        .post(format!("http://{addr}/api/setup/check-ports"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(
            serde_json::json!({
                "dns_addr": expected_dns,
                "web_addr": occupied_addr,
                "web_tls_addr": "not-an-addr",
                "dot_addr": "127.0.0.1:0"
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let json: serde_json::Value = serde_json::from_str(&res.text().await.unwrap()).unwrap();
    let results = json["results"].as_array().unwrap();
    assert_eq!(results.len(), 4);

    assert_eq!(results[0]["key"], "dns");
    assert_eq!(results[0]["available"], true);
    assert_eq!(results[0]["in_use_by_self"], true);
    assert_eq!(results[0]["reason"], "self");

    assert_eq!(results[1]["key"], "web");
    assert_eq!(results[1]["available"], false);
    assert_eq!(results[1]["reason"], "in_use");

    assert_eq!(results[2]["key"], "web_tls");
    assert_eq!(results[2]["available"], false);
    assert_eq!(results[2]["reason"], "invalid_addr");

    assert_eq!(results[3]["key"], "dot");
    assert_eq!(results[3]["available"], true);
    assert_eq!(results[3]["in_use_by_self"], false);
}

#[tokio::test]
async fn test_acme_http01_challenge_and_status_api() {
    use crabdns_web::acme_api::AcmeManager;
    use crabdns_web::build_router_with_managers;
    use crabdns_web::update_api::UpdateManager;

    let dir = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(StorageEngine::open(dir.path()).expect("open storage"));
    let mut cfg = Config::default();
    cfg.bootstrap.data_dir = dir.path().to_path_buf();
    cfg.acme_enabled = true;
    cfg.acme_domains = vec!["dns.example.com".to_string()];
    let config = Arc::new(ArcSwap::from_pointee(cfg));
    let filter = Arc::new(FilterEngine::new(&[]));
    let cache = Arc::new(DnsCache::new(64, false));
    let upstream = Arc::new(UpstreamPool::new(&["udp://1.1.1.1:53".to_string()], 1000).unwrap());
    let pipeline = Arc::new(DnsPipeline::new(filter, cache, upstream, None));
    let (live_tx, _) = broadcast::channel(16);
    let acme = Arc::new(AcmeManager::new());

    acme.http_challenges
        .set("tok-abc".to_string(), "tok-abc.thumbprint".to_string());

    let app = build_router_with_managers(
        AppState {
            config,
            pipeline,
            storage,
            live_tx,
            tls_reloader: None,
        },
        Arc::new(UpdateManager::new()),
        Arc::clone(&acme),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    let hit = client
        .get(format!("{base}/.well-known/acme-challenge/tok-abc"))
        .send()
        .await
        .unwrap();
    assert_eq!(hit.status(), StatusCode::OK);
    assert_eq!(hit.text().await.unwrap(), "tok-abc.thumbprint");

    let miss = client
        .get(format!("{base}/.well-known/acme-challenge/missing"))
        .send()
        .await
        .unwrap();
    assert_eq!(miss.status(), StatusCode::NOT_FOUND);

    let status_res = client
        .get(format!("{base}/api/acme/status"))
        .send()
        .await
        .unwrap();
    assert_eq!(status_res.status(), StatusCode::OK);
    let status_json: serde_json::Value =
        serde_json::from_slice(&status_res.bytes().await.unwrap()).unwrap();
    assert_eq!(status_json["enabled"], true);
    assert_eq!(status_json["domains"][0], "dns.example.com");
}

async fn recv_ws_json(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> serde_json::Value {
    use futures_util::StreamExt as _;
    use tokio_tungstenite::tungstenite::Message;

    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while let Some(item) = ws.next().await {
            let msg = item.expect("ws frame");
            if let Message::Text(text) = msg {
                return serde_json::from_str::<serde_json::Value>(&text).expect("valid ws json");
            }
        }
        panic!("ws stream closed before message");
    })
    .await
    .expect("timed out waiting for ws message")
}

fn sample_query_event(
    domain: &str,
    outcome: crabdns_core::QueryOutcome,
    protocol: crabdns_core::QueryProtocol,
) -> QueryEvent {
    QueryEvent {
        timestamp: chrono::Utc::now(),
        client_ip: "192.168.1.42".to_string(),
        client_name: Some("workstation".to_string()),
        client_id: Some("desk-1".to_string()),
        profile_id: None,
        protocol,
        domain: domain.to_string(),
        qtype: "A".to_string(),
        outcome,
        matched_rule: None,
        matched_list: None,
        upstream: None,
        elapsed_us: 120,
        rcode: "NOERROR".to_string(),
        answers: vec!["1.2.3.4".to_string()],
    }
}

async fn send_ws_json(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    payload: &serde_json::Value,
) {
    use futures_util::SinkExt as _;
    use tokio_tungstenite::tungstenite::Message;

    ws.send(Message::Text(payload.to_string().into()))
        .await
        .expect("send ws json");
}

async fn spawn_ws_test_server(
    cfg: Config,
    updater: Option<Arc<crabdns_web::update_api::UpdateManager>>,
) -> (
    std::net::SocketAddr,
    broadcast::Sender<QueryEvent>,
    Arc<DnsPipeline>,
    tempfile::TempDir,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut full_cfg = cfg;
    full_cfg.bootstrap.data_dir = dir.path().to_path_buf();
    let storage = Arc::new(StorageEngine::open(dir.path()).expect("open storage"));
    let config = Arc::new(ArcSwap::from_pointee(full_cfg));
    let filter = Arc::new(FilterEngine::new(&[]));
    let cache = Arc::new(DnsCache::new(64, false));
    let upstream = Arc::new(UpstreamPool::new(&["udp://1.1.1.1:53".to_string()], 1000).unwrap());
    let pipeline = Arc::new(DnsPipeline::new(filter, cache, upstream, None));
    let (live_tx, _) = broadcast::channel(32);

    let app_state = AppState {
        config,
        pipeline: Arc::clone(&pipeline),
        storage,
        live_tx: live_tx.clone(),
        tls_reloader: None,
    };
    let app = match updater {
        Some(u) => build_router_with_updater(app_state, u),
        None => build_router(app_state),
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (addr, live_tx, pipeline, dir)
}

#[tokio::test]
async fn test_ws_events_requires_auth_when_enabled() {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;

    let password_hash = auth::hash_password("s3cret-pass").expect("hash");
    let auth_cfg = Config {
        runtime: crabdns_core::RuntimeConfig {
            web_auth_enabled: true,
            web_username: "admin".to_string(),
            web_password_hash: password_hash,
            ..Default::default()
        },
        ..Config::default()
    };
    let (addr, _live_tx, _pipeline, _dir) = spawn_ws_test_server(auth_cfg, None).await;

    let ws_url = format!("ws://{addr}/api/ws");
    let unauthed = tokio_tungstenite::connect_async(&ws_url).await;
    match unauthed {
        Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => {
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        }
        other => panic!("expected 401 on unauthenticated ws upgrade, got {other:?}"),
    }

    let client = reqwest::Client::new();
    let login_res = client
        .post(format!("http://{addr}/api/auth/login"))
        .header("content-type", "application/json")
        .body(
            serde_json::to_vec(&serde_json::json!({
                "username": "admin",
                "password": "s3cret-pass",
            }))
            .unwrap(),
        )
        .send()
        .await
        .expect("login");
    assert_eq!(login_res.status(), StatusCode::OK);
    let login_json: serde_json::Value =
        serde_json::from_slice(&login_res.bytes().await.expect("login body")).expect("login json");
    let token = login_json["token"].as_str().expect("token");

    let mut req = ws_url.into_client_request().expect("ws req");
    req.headers_mut().insert(
        axum::http::header::COOKIE,
        axum::http::HeaderValue::from_str(&format!("crabdns_session={token}")).unwrap(),
    );
    let (mut ws, _) = tokio_tungstenite::connect_async(req)
        .await
        .expect("authenticated ws connect");

    send_ws_json(
        &mut ws,
        &serde_json::json!({ "type": "subscribe", "topics": ["blocking"] }),
    )
    .await;

    let sub_ack = recv_ws_json(&mut ws).await;
    assert_eq!(sub_ack["type"], "subscribed");
    assert_eq!(sub_ack["data"]["topics"], serde_json::json!(["blocking"]));

    let blocking_snap = recv_ws_json(&mut ws).await;
    assert_eq!(blocking_snap["type"], "blocking");
    assert_eq!(blocking_snap["data"]["paused"], false);
}

async fn post_ok(client: &reqwest::Client, url: String, body: Option<serde_json::Value>) {
    let req = client.post(url);
    let req = match body {
        Some(json) => req
            .header("content-type", "application/json")
            .body(serde_json::to_vec(&json).unwrap()),
        None => req,
    };
    assert_eq!(req.send().await.expect("post").status(), StatusCode::OK);
}

#[tokio::test]
async fn test_ws_events_subscriptions_and_log_filtering() {
    use crabdns_core::{QueryOutcome, QueryProtocol};
    use futures_util::SinkExt as _;
    use tokio_tungstenite::tungstenite::Message;

    let (addr, live_tx, _pipeline, _dir) = spawn_ws_test_server(Config::default(), None).await;
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/api/ws"))
        .await
        .expect("connect ws");

    // Before subscribing to logs, live events are not pushed.
    let _ = live_tx.send(sample_query_event(
        "ignored-before-sub.test",
        QueryOutcome::Blocked,
        QueryProtocol::Udp,
    ));

    send_ws_json(
        &mut ws,
        &serde_json::json!({
            "type": "subscribe",
            "topics": ["stats", "blocking", "update", "cf_cdn"],
        }),
    )
    .await;

    assert_eq!(recv_ws_json(&mut ws).await["type"], "subscribed");
    let mut initial_types = Vec::new();
    for _ in 0..4 {
        initial_types.push(
            recv_ws_json(&mut ws).await["type"]
                .as_str()
                .unwrap()
                .to_string(),
        );
    }
    assert_eq!(initial_types, vec!["stats", "blocking", "update", "cf_cdn"]);

    let client = reqwest::Client::new();
    post_ok(
        &client,
        format!("http://{addr}/api/blocking/pause"),
        Some(serde_json::json!({ "duration_secs": 60 })),
    )
    .await;
    let paused_msg = recv_ws_json(&mut ws).await;
    assert_eq!(paused_msg["type"], "blocking");
    assert_eq!(paused_msg["data"]["paused"], true);

    post_ok(&client, format!("http://{addr}/api/blocking/resume"), None).await;
    let resumed_msg = recv_ws_json(&mut ws).await;
    assert_eq!(resumed_msg["type"], "blocking");
    assert_eq!(resumed_msg["data"]["paused"], false);

    post_ok(&client, format!("http://{addr}/api/cache/flush"), None).await;
    assert_eq!(recv_ws_json(&mut ws).await["type"], "stats");

    // Subscribe to logs with server-side filter.
    send_ws_json(
        &mut ws,
        &serde_json::json!({
            "type": "subscribe",
            "topics": ["logs"],
            "log_filter": { "search": "match", "outcome": "blocked" },
        }),
    )
    .await;
    let logs_ack = recv_ws_json(&mut ws).await;
    assert_eq!(logs_ack["type"], "subscribed");
    assert_eq!(logs_ack["data"]["topics"], serde_json::json!(["logs"]));

    for (domain, outcome) in [
        ("match-allowed.test", QueryOutcome::Forwarded),
        ("other-blocked.test", QueryOutcome::Blocked),
        ("match-blocked.test", QueryOutcome::Blocked),
    ] {
        let _ = live_tx.send(sample_query_event(domain, outcome, QueryProtocol::Udp));
    }
    let log_msg = recv_ws_json(&mut ws).await;
    assert_eq!(log_msg["type"], "log");
    assert_eq!(log_msg["data"]["domain"], "match-blocked.test");

    // Update filter via set_log_filter and verify malformed JSON yields an Error frame.
    send_ws_json(
        &mut ws,
        &serde_json::json!({ "type": "set_log_filter", "filter": { "protocol": "doh" } }),
    )
    .await;
    ws.send(Message::Text("not-json".into()))
        .await
        .expect("send invalid");
    assert_eq!(recv_ws_json(&mut ws).await["type"], "error");

    for (domain, proto) in [
        ("udp-skip.test", QueryProtocol::Udp),
        ("doh-keep.test", QueryProtocol::Doh),
    ] {
        let _ = live_tx.send(sample_query_event(domain, QueryOutcome::Forwarded, proto));
    }
    let doh_msg = recv_ws_json(&mut ws).await;
    assert_eq!(doh_msg["type"], "log");
    assert_eq!(doh_msg["data"]["domain"], "doh-keep.test");
}

#[tokio::test]
async fn test_ws_events_cf_cdn_and_update_push() {
    use crabdns_core::CfCdnConfig;
    use crabdns_web::update_api::{EXPECTED_EXE_NAME, InstallTarget, UpdateConfig, UpdateManager};
    use sigilup::UrlPolicy;

    let dead_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let dead_addr = dead_listener.local_addr().expect("addr");
    drop(dead_listener);

    let pins = UpdateConfig::default_production()
        .expect("default update cfg")
        .pins;
    let mut url_policy = UrlPolicy::with_prefixes([format!("http://{dead_addr}/")]);
    url_policy.require_https = false;
    let updater = Arc::new(UpdateManager::new());
    updater.set_config_override(UpdateConfig {
        manifest_urls: vec![format!("http://{dead_addr}/latest.hsig.json")],
        pins,
        url_policy,
        enforce_version_url_prefix: false,
        verify_timestamp_unix: None,
        install_target: InstallTarget::CustomPath(std::path::PathBuf::from(EXPECTED_EXE_NAME)),
    });

    let (addr, _live_tx, pipeline, _dir) =
        spawn_ws_test_server(Config::default(), Some(updater)).await;
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/api/ws"))
        .await
        .expect("connect ws");

    send_ws_json(
        &mut ws,
        &serde_json::json!({ "type": "subscribe", "topics": ["cf_cdn", "update"] }),
    )
    .await;

    assert_eq!(recv_ws_json(&mut ws).await["type"], "subscribed");
    assert_eq!(recv_ws_json(&mut ws).await["type"], "update");
    let initial_cf = recv_ws_json(&mut ws).await;
    assert_eq!(initial_cf["type"], "cf_cdn");
    assert_eq!(initial_cf["data"]["enabled"], false);

    pipeline.cf_cdn_manager().reload_config(CfCdnConfig {
        enabled: true,
        ..CfCdnConfig::default()
    });
    let cf_push = recv_ws_json(&mut ws).await;
    assert_eq!(cf_push["type"], "cf_cdn");
    assert_eq!(cf_push["data"]["enabled"], true);

    let client = reqwest::Client::new();
    let check_res = client
        .post(format!("http://{addr}/api/update/check"))
        .send()
        .await
        .expect("update check");
    assert_eq!(check_res.status(), StatusCode::BAD_GATEWAY);

    let mut saw_error = false;
    for _ in 0..4 {
        let msg = recv_ws_json(&mut ws).await;
        assert_eq!(msg["type"], "update");
        if msg["data"]["last_error"].is_string() && msg["data"]["busy"] == false {
            saw_error = true;
            break;
        }
    }
    assert!(saw_error, "expected update push with last_error");
}

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn test_split_dns_groups_and_cache_invalidation_via_config_api() {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(StorageEngine::open(dir.path()).expect("open fjall"));
    let cfg = Config::default();
    let config = Arc::new(ArcSwap::from_pointee(cfg));
    let filter = Arc::new(FilterEngine::new(&[]));
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

    // Seed an entry in cache to verify split_dns config update invalidates cache
    let cache_key = crabdns_core::cache::CacheKey {
        qname: "example.com.".to_string(),
        qtype: 1,
        qclass: 1,
        ecs_subnet: None,
        dnssec_do: false,
        upstream_scope: None,
    };
    pipeline
        .cache()
        .insert(cache_key.clone(), vec![0_u8; 12], 60);
    assert!(pipeline.cache().get(&cache_key, 1).is_some());

    let payload = serde_json::json!({
        "upstreams": ["udp://1.1.1.1:53"],
        "cache_size": 64,
        "optimistic_cache": true,
        "upstream_timeout_ms": 1000,
        "log_retention_hours": 24,
        "upstream_groups": [
            {
                "name": "cn_dns",
                "upstreams": ["udp://223.5.5.5:53"],
                "fallback_groups": [],
                "proxy_url": null,
                "policy": { "disable_ipv6": true }
            }
        ],
        "split_dns_match_mode": "config_order",
        "split_dns_before_client_upstreams": true,
        "split_dns": [
            {
                "name": "CN Rule",
                "enabled": true,
                "domain": "cn",
                "domains_file": null,
                "domains_url": null,
                "exclude_domains": ["gov.cn"],
                "qtypes": ["A", "AAAA"],
                "client_cidrs": [],
                "client_groups": [],
                "client_tags": [],
                "protocols": [],
                "upstreams": ["@cn_dns"],
                "fallback_upstreams": [],
                "fallback_to_default": true,
                "fallback_on_nxdomain": false,
                "is_local": false,
                "policy": {},
                "response_ip": {
                    "expected_cidrs": ["1.0.1.0/24"],
                    "invert": false,
                    "fallback_upstreams": ["udp://8.8.8.8:53"],
                    "fallback_delay_ms": 100,
                    "match_cname_domains": [],
                    "fallback_on_empty": true
                }
            }
        ]
    });

    let put_res = client
        .put(format!("{base}/api/config"))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&payload).expect("json"))
        .send()
        .await
        .expect("put config");
    assert_eq!(put_res.status(), StatusCode::OK);
    let raw_bytes = put_res.bytes().await.expect("response bytes");
    let body: serde_json::Value = serde_json::from_slice(&raw_bytes).expect("parse response");
    assert_eq!(body["split_dns_match_mode"], "config_order");
    assert_eq!(body["split_dns_before_client_upstreams"], true);
    assert_eq!(body["upstream_groups"][0]["name"], "cn_dns");
    assert_eq!(body["split_dns"][0]["name"], "CN Rule");
    assert_eq!(
        body["split_dns"][0]["response_ip"]["fallback_delay_ms"],
        100
    );

    // Cache must be flushed when split_dns / upstream_groups change
    assert!(pipeline.cache().get(&cache_key, 1).is_none());
    assert!(pipeline.split_router().resolve("qq.cn").is_some());
    assert!(pipeline.split_router().resolve("gov.cn").is_none());
}

#[tokio::test]
#[allow(clippy::too_many_lines, clippy::items_after_statements)]
async fn test_split_dns_conditional_sync_status_and_interval() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::http::HeaderMap;
    use axum::response::IntoResponse;

    let hits = Arc::new(AtomicUsize::new(0));
    let hits_srv = Arc::clone(&hits);
    let list_app = Router::new().route(
        "/list.txt",
        get(move |headers: HeaderMap| {
            let hits = Arc::clone(&hits_srv);
            async move {
                let n = hits.fetch_add(1, Ordering::SeqCst);
                let inm = headers
                    .get("if-none-match")
                    .and_then(|v| v.to_str().ok())
                    .map(ToString::to_string);
                match n {
                    0 => ([("etag", "\"v1\"")], "alpha.test\n").into_response(),
                    1 if inm.as_deref() == Some("\"v1\"") => {
                        StatusCode::NOT_MODIFIED.into_response()
                    }
                    1 => (StatusCode::BAD_REQUEST, "missing etag").into_response(),
                    2 => (StatusCode::INTERNAL_SERVER_ERROR, "boom").into_response(),
                    _ => ([("etag", "\"v2\"")], "beta.test\n").into_response(),
                }
            }
        }),
    );
    let list_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind list");
    let list_addr = list_listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(list_listener, list_app).await;
    });
    let list_url = format!("http://{list_addr}/list.txt");

    let dir = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(StorageEngine::open(dir.path()).expect("open fjall"));
    let cfg = Config {
        runtime: crabdns_core::RuntimeConfig {
            allow_private_subscriptions: true,
            split_dns: vec![crabdns_core::SplitDnsRule {
                domains_url: Some(list_url.clone()),
                upstreams: vec!["udp://10.0.0.1:53".to_string()],
                ..Default::default()
            }],
            ..Default::default()
        },
        ..Config::default()
    };
    let config = Arc::new(ArcSwap::from_pointee(cfg));
    let filter = Arc::new(FilterEngine::new(&[]));
    let cache = Arc::new(DnsCache::new(64, true));
    let upstream =
        Arc::new(UpstreamPool::new(&["udp://127.0.0.1:1".to_string()], 200).expect("pool"));
    let pipeline = Arc::new(DnsPipeline::new(filter, cache, upstream, None));
    let (live_tx, _) = broadcast::channel(16);
    let app = build_router(AppState {
        config,
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

    async fn refresh(client: &reqwest::Client, base: &str) -> serde_json::Value {
        let res = client
            .post(format!("{base}/api/split-dns/refresh"))
            .send()
            .await
            .expect("refresh");
        assert_eq!(res.status(), StatusCode::OK);
        serde_json::from_slice(&res.bytes().await.expect("bytes")).expect("json")
    }

    // 1) 200 + ETag: updated and routed
    let s1 = refresh(&client, &base).await;
    assert_eq!(s1["updated"], 1);
    assert_eq!(s1["sources"][0]["entry_count"], 1);
    assert_eq!(s1["sources"][0]["etag"], "\"v1\"");
    assert!(pipeline.split_router().resolve("www.alpha.test").is_some());

    // 2) 304 via If-None-Match
    let s2 = refresh(&client, &base).await;
    assert_eq!(s2["not_modified"], 1);
    assert_eq!(s2["updated"], 0);
    assert_eq!(s2["sources"][0]["not_modified"], true);

    // 3) 500: old cache kept, error recorded
    let s3 = refresh(&client, &base).await;
    assert_eq!(s3["failed"], 1);
    let status_res = client
        .get(format!("{base}/api/split-dns/status"))
        .send()
        .await
        .expect("status");
    assert_eq!(status_res.status(), StatusCode::OK);
    let status: serde_json::Value =
        serde_json::from_slice(&status_res.bytes().await.expect("bytes")).expect("json");
    assert_eq!(status[0]["kind"], "url");
    assert_eq!(status[0]["cached"], true);
    assert!(status[0]["last_error"].as_str().is_some());
    assert!(
        storage
            .load_split_dns_list(&list_url)
            .unwrap()
            .unwrap()
            .contains("alpha.test")
    );
    assert!(pipeline.split_router().resolve("www.alpha.test").is_some());

    // 4) 200 new content: error cleared, routing updated
    let s4 = refresh(&client, &base).await;
    assert_eq!(s4["updated"], 1);
    assert!(s4["sources"][0]["last_error"].is_null());
    assert!(pipeline.split_router().resolve("www.beta.test").is_some());
    assert!(pipeline.split_router().resolve("www.alpha.test").is_none());
    assert_eq!(hits.load(Ordering::SeqCst), 4);

    // Interval validation + roundtrip
    let mk = |secs: u64| {
        serde_json::json!({
            "upstreams": ["udp://1.1.1.1:53"],
            "cache_size": 64,
            "optimistic_cache": true,
            "upstream_timeout_ms": 1000,
            "log_retention_hours": 24,
            "split_dns_refresh_interval_secs": secs,
        })
    };
    let bad = client
        .put(format!("{base}/api/config"))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&mk(30)).unwrap())
        .send()
        .await
        .expect("put bad");
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
    let good = client
        .put(format!("{base}/api/config"))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&mk(3600)).unwrap())
        .send()
        .await
        .expect("put good");
    assert_eq!(good.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&good.bytes().await.expect("bytes")).expect("json");
    assert_eq!(body["split_dns_refresh_interval_secs"], 3600);
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn test_security_headers_csrf_and_commit_confirm() {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(StorageEngine::open(dir.path()).expect("open storage"));
    let mut cfg = Config::default();
    cfg.bootstrap.data_dir = dir.path().to_path_buf();
    let config = Arc::new(ArcSwap::from_pointee(cfg));
    let filter = Arc::new(FilterEngine::new(&[]));
    let cache = Arc::new(DnsCache::new(64, false));
    let upstream = Arc::new(UpstreamPool::new(&["udp://1.1.1.1:53".to_string()], 1000).unwrap());
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

    // Enable auth
    let enable_res = client
        .put(format!("{base}/api/auth/settings"))
        .header("content-type", "application/json")
        .body(r#"{"enabled":true,"username":"admin","password":"s3cret-pass"}"#)
        .send()
        .await
        .expect("enable auth");
    assert_eq!(enable_res.status(), StatusCode::OK);

    // 1. Security headers present on /api/health
    let health_res = client
        .get(format!("{base}/api/health"))
        .send()
        .await
        .expect("health");
    assert_eq!(health_res.status(), StatusCode::OK);
    assert_eq!(
        health_res
            .headers()
            .get("x-content-type-options")
            .and_then(|v| v.to_str().ok()),
        Some("nosniff")
    );
    assert_eq!(
        health_res
            .headers()
            .get("x-frame-options")
            .and_then(|v| v.to_str().ok()),
        Some("DENY")
    );
    assert!(health_res.headers().contains_key("content-security-policy"));

    // Login to get both cookie and bearer token
    let login_res = client
        .post(format!("{base}/api/auth/login"))
        .header("content-type", "application/json")
        .body(r#"{"username":"admin","password":"s3cret-pass"}"#)
        .send()
        .await
        .expect("login");
    assert_eq!(login_res.status(), StatusCode::OK);
    let cookie = login_res
        .headers()
        .get(reqwest::header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .expect("set-cookie")
        .split(';')
        .next()
        .expect("cookie pair")
        .to_string();
    let login_json: auth::LoginResponse =
        serde_json::from_slice(&login_res.bytes().await.expect("bytes")).expect("json");

    // 2. Cookie-authenticated state-changing request without Origin/Referer is rejected by CSRF guard
    let csrf_blocked = client
        .post(format!("{base}/api/cache/flush"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .expect("csrf blocked");
    assert_eq!(csrf_blocked.status(), StatusCode::FORBIDDEN);

    // Cross-site Origin is rejected
    let csrf_cross = client
        .post(format!("{base}/api/cache/flush"))
        .header(reqwest::header::COOKIE, &cookie)
        .header(reqwest::header::ORIGIN, "https://evil.example")
        .send()
        .await
        .expect("csrf cross");
    assert_eq!(csrf_cross.status(), StatusCode::FORBIDDEN);

    // Same-origin Cookie request succeeds
    let csrf_ok = client
        .post(format!("{base}/api/cache/flush"))
        .header(reqwest::header::COOKIE, &cookie)
        .header(reqwest::header::ORIGIN, format!("http://{addr}"))
        .header("sec-fetch-site", "same-origin")
        .send()
        .await
        .expect("csrf ok");
    assert_eq!(csrf_ok.status(), StatusCode::OK);

    // 3. Commit-Confirm config update + confirm endpoint
    let update_body = serde_json::json!({
        "upstreams": ["udp://1.1.1.1:53"],
        "cache_size": 2048,
        "optimistic_cache": true,
        "upstream_timeout_ms": 2000,
        "log_retention_hours": 24,
        "confirm_timeout_secs": 30
    });
    let update_res = client
        .put(format!("{base}/api/config"))
        .header("authorization", format!("Bearer {}", login_json.token))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&update_body).unwrap())
        .send()
        .await
        .expect("update config");
    assert_eq!(update_res.status(), StatusCode::OK);

    let pending_bytes = client
        .get(format!("{base}/api/config/pending-confirm"))
        .header("authorization", format!("Bearer {}", login_json.token))
        .send()
        .await
        .expect("pending")
        .bytes()
        .await
        .expect("bytes");
    let pending: serde_json::Value = serde_json::from_slice(&pending_bytes).expect("json");
    assert_eq!(pending["pending"], true);

    let confirmed_bytes = client
        .post(format!("{base}/api/config/confirm"))
        .header("authorization", format!("Bearer {}", login_json.token))
        .send()
        .await
        .expect("confirm")
        .bytes()
        .await
        .expect("bytes");
    let confirmed: serde_json::Value = serde_json::from_slice(&confirmed_bytes).expect("json");
    assert_eq!(confirmed["confirmed"], true);
}
