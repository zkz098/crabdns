use std::sync::Arc;

use arc_swap::ArcSwap;
use crabdns_core::{Config, DnsCache, DnsPipeline, FilterEngine, UpstreamPool};
use crabdns_storage::StorageEngine;
use crabdns_web::{AppState, build_router};
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use tokio::net::TcpListener;
use tokio::sync::broadcast;

async fn spawn_test_web(auth_enabled: bool) -> (String, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let storage = Arc::new(StorageEngine::open(dir.path()).unwrap());
    let mut cfg = Config::default();
    if auth_enabled {
        cfg.web_auth_enabled = true;
        cfg.web_username = "admin".to_string();
        cfg.web_password_hash = crabdns_web::auth::hash_password("secret123").unwrap();
    }
    let config = Arc::new(ArcSwap::from_pointee(cfg));
    let filter = Arc::new(FilterEngine::new(&["||blocked.test^".to_string()]));
    let cache = Arc::new(DnsCache::new(64, true));
    let upstream = Arc::new(UpstreamPool::new(&["udp://127.0.0.1:9".to_string()], 200).unwrap());
    let pipeline = Arc::new(DnsPipeline::new(filter, cache, upstream, None));
    let (live_tx, _) = broadcast::channel(16);
    let router = build_router(AppState {
        config,
        pipeline,
        storage,
        live_tx,
        tls_reloader: None,
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    (format!("http://{addr}"), dir)
}

async fn post_json(
    client: &reqwest::Client,
    url: &str,
    body: serde_json::Value,
) -> reqwest::Response {
    client
        .post(url)
        .header("content-type", "application/json")
        .body(serde_json::to_string(&body).unwrap())
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn test_doh_metrics_blocking_cache_and_rules_apis() {
    let (base, _dir) = spawn_test_web(false).await;
    let client = reqwest::Client::new();

    // 1. DoH POST for blocked domain
    let mut query = Message::new(0x1234, MessageType::Query, OpCode::Query);
    query.add_query(Query::query(
        Name::from_ascii("blocked.test.").unwrap(),
        RecordType::A,
    ));
    let wire = query.to_vec().unwrap();

    let doh_resp = client
        .post(format!("{base}/dns-query"))
        .header("content-type", "application/dns-message")
        .body(wire)
        .send()
        .await
        .unwrap();
    assert_eq!(doh_resp.status(), reqwest::StatusCode::OK);
    let resp_bytes = doh_resp.bytes().await.unwrap();
    let resp_msg = Message::from_vec(&resp_bytes).unwrap();
    assert_eq!(resp_msg.id, 0x1234);
    assert_eq!(resp_msg.answers.len(), 1);

    // 2. Prometheus /metrics
    let metrics_text = client
        .get(format!("{base}/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(metrics_text.contains("crabdns_queries_total"));
    assert!(metrics_text.contains("crabdns_cache_hits_total"));
    assert!(metrics_text.contains("crabdns_log_channel_dropped_total"));
    assert!(metrics_text.contains("crabdns_singleflight_inflight"));
    assert!(metrics_text.contains("crabdns_rdns_inflight"));
    assert!(metrics_text.contains("crabdns_bg_refresh_inflight"));
    assert!(metrics_text.contains("crabdns_acl_tracked_clients"));
    assert!(metrics_text.contains("crabdns_auth_sessions"));
    assert!(metrics_text.contains("crabdns_auth_login_attempts"));
    assert!(metrics_text.contains("crabdns_storage_tracked_entries"));
    #[cfg(target_os = "linux")]
    {
        assert!(metrics_text.contains("crabdns_process_resident_memory_bytes"));
        assert!(metrics_text.contains("crabdns_process_open_fds"));
    }

    // 3. Pause / Resume blocking
    let pause_resp = post_json(
        &client,
        &format!("{base}/api/blocking/pause"),
        serde_json::json!({ "duration_secs": 300 }),
    )
    .await;
    let pause_json: serde_json::Value =
        serde_json::from_slice(&pause_resp.bytes().await.unwrap()).unwrap();
    assert_eq!(pause_json["paused"], true);

    let resume_resp = client
        .post(format!("{base}/api/blocking/resume"))
        .send()
        .await
        .unwrap();
    let resume_json: serde_json::Value =
        serde_json::from_slice(&resume_resp.bytes().await.unwrap()).unwrap();
    assert_eq!(resume_json["paused"], false);

    // 4. Quick rule + Rule test
    let quick_resp = post_json(
        &client,
        &format!("{base}/api/rules/quick"),
        serde_json::json!({ "domain": "ads.example.org", "action": "block" }),
    )
    .await;
    assert_eq!(quick_resp.status(), reqwest::StatusCode::OK);

    let test_resp = post_json(
        &client,
        &format!("{base}/api/rules/test"),
        serde_json::json!({ "domain": "sub.ads.example.org" }),
    )
    .await;
    let test_json: serde_json::Value =
        serde_json::from_slice(&test_resp.bytes().await.unwrap()).unwrap();
    assert_eq!(test_json["action"], "block");
    assert_eq!(test_json["matched_rule"], "||ads.example.org^");

    // 5. Cache flush
    let flush_resp = client
        .post(format!("{base}/api/cache/flush"))
        .send()
        .await
        .unwrap();
    assert_eq!(flush_resp.status(), reqwest::StatusCode::OK);
}

#[tokio::test]
async fn test_login_rate_limit_and_subscription_ssrf() {
    let (base, _dir) = spawn_test_web(true).await;
    let client = reqwest::Client::new();

    for _ in 0..5 {
        let resp = post_json(
            &client,
            &format!("{base}/api/auth/login"),
            serde_json::json!({ "username": "admin", "password": "wrong" }),
        )
        .await;
        assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
    }

    let locked_resp = post_json(
        &client,
        &format!("{base}/api/auth/login"),
        serde_json::json!({ "username": "admin", "password": "secret123" }),
    )
    .await;
    assert_eq!(locked_resp.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);

    assert!(
        crabdns_web::subscriptions::validate_subscription_url("http://127.0.0.1/a.txt").is_err()
    );
    assert!(
        crabdns_web::subscriptions::validate_subscription_url("http://192.168.1.1/a.txt").is_err()
    );
    assert!(
        crabdns_web::subscriptions::validate_subscription_url("http://localhost/a.txt").is_err()
    );
    assert!(
        crabdns_web::subscriptions::validate_subscription_url("https://example.com/a.txt").is_ok()
    );
}
