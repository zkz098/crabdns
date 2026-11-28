use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use crabdns_core::{Config, QueryEvent, QueryOutcome};
use crabdns_server::spawn_server;
use futures_util::StreamExt;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio_tungstenite::tungstenite::Message as WsMessage;

fn build_query(id: u16, domain: &str, qtype: RecordType) -> Vec<u8> {
    let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    let name = Name::from_ascii(domain).expect("valid domain");
    msg.add_query(Query::query(name, qtype));
    msg.to_vec().expect("encode query")
}

fn build_mock_upstream_response(raw_query: &[u8]) -> Option<Vec<u8>> {
    let req = Message::from_vec(raw_query).ok()?;
    let q = req.queries.first()?.clone();
    let qname = q.name().clone();
    let qtype = q.query_type();

    let mut resp = Message::new(req.id, MessageType::Response, OpCode::Query);
    resp.metadata.recursion_desired = req.recursion_desired;
    resp.metadata.recursion_available = true;
    resp.metadata.response_code = ResponseCode::NoError;
    resp.add_query(q);

    if qname.to_utf8() == "cloaked.example.com." {
        let target = Name::from_ascii("tracker.evil.com.").expect("valid cname");
        resp.add_answer(Record::from_rdata(qname, 60, RData::CNAME(CNAME(target))));
    } else {
        match qtype {
            RecordType::A => {
                resp.add_answer(Record::from_rdata(
                    qname,
                    60,
                    RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
                ));
            }
            RecordType::AAAA => {
                resp.add_answer(Record::from_rdata(
                    qname,
                    60,
                    RData::AAAA(AAAA(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))),
                ));
            }
            _ => {}
        }
    }

    resp.to_vec().ok()
}

async fn spawn_mock_udp_upstream() -> (SocketAddr, Arc<AtomicUsize>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind mock udp");
    let addr = socket.local_addr().expect("mock udp addr");
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_clone = Arc::clone(&hits);

    tokio::spawn(async move {
        let mut buf = [0_u8; 4096];
        while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
            hits_clone.fetch_add(1, Ordering::SeqCst);
            if let Some(resp) = build_mock_upstream_response(&buf[..len]) {
                let _ = socket.send_to(&resp, peer).await;
            }
        }
    });

    (addr, hits)
}

async fn spawn_mock_tcp_upstream() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock tcp");
    let addr = listener.local_addr().expect("mock tcp addr");
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_clone = Arc::clone(&hits);

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let hits_inner = Arc::clone(&hits_clone);
            tokio::spawn(async move {
                let mut len_buf = [0_u8; 2];
                while stream.read_exact(&mut len_buf).await.is_ok() {
                    let len = usize::from(u16::from_be_bytes(len_buf));
                    let mut query = vec![0_u8; len];
                    if stream.read_exact(&mut query).await.is_err() {
                        break;
                    }
                    hits_inner.fetch_add(1, Ordering::SeqCst);
                    if let Some(resp) = build_mock_upstream_response(&query) {
                        let resp_len = u16::try_from(resp.len()).expect("len u16");
                        let _ = stream.write_all(&resp_len.to_be_bytes()).await;
                        let _ = stream.write_all(&resp).await;
                        let _ = stream.flush().await;
                    }
                }
            });
        }
    });

    (addr, hits)
}

async fn send_udp_query(server_addr: SocketAddr, query: &[u8]) -> Message {
    let sock = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind client udp");
    sock.send_to(query, server_addr).await.expect("send udp");
    let mut buf = [0_u8; 4096];
    let (len, _) = tokio::time::timeout(Duration::from_secs(3), sock.recv_from(&mut buf))
        .await
        .expect("udp recv timeout")
        .expect("udp recv");
    Message::from_vec(&buf[..len]).expect("decode udp dns response")
}

async fn send_tcp_query(server_addr: SocketAddr, query: &[u8]) -> Message {
    let mut stream = tokio::net::TcpStream::connect(server_addr)
        .await
        .expect("connect tcp");
    let q_len = u16::try_from(query.len()).expect("query len u16");
    stream
        .write_all(&q_len.to_be_bytes())
        .await
        .expect("write tcp len");
    stream.write_all(query).await.expect("write tcp body");
    stream.flush().await.expect("flush tcp");

    let mut len_buf = [0_u8; 2];
    tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut len_buf))
        .await
        .expect("tcp len timeout")
        .expect("read tcp len");
    let resp_len = usize::from(u16::from_be_bytes(len_buf));
    let mut resp_buf = vec![0_u8; resp_len];
    tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut resp_buf))
        .await
        .expect("tcp body timeout")
        .expect("read tcp body");
    Message::from_vec(&resp_buf).expect("decode tcp dns response")
}

async fn get_json<T: serde::de::DeserializeOwned>(client: &reqwest::Client, url: &str) -> T {
    let resp = client.get(url).send().await.expect("http get");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let bytes = resp.bytes().await.expect("http body bytes");
    serde_json::from_slice(&bytes).expect("decode json")
}

async fn put_json<B: serde::Serialize>(
    client: &reqwest::Client,
    url: &str,
    body: &B,
) -> reqwest::Response {
    let payload = serde_json::to_vec(body).expect("encode json");
    client
        .put(url)
        .header("content-type", "application/json")
        .body(payload)
        .send()
        .await
        .expect("http put")
}

async fn wait_for_total_queries(client: &reqwest::Client, base_url: &str, expected: u64) -> Value {
    for _ in 0..40 {
        let stats: Value = get_json(client, &format!("{base_url}/api/stats")).await;
        if stats["stats"]["total_queries"].as_u64() == Some(expected) {
            return stats;
        }
        tokio::time::sleep(Duration::from_millis(75)).await;
    }
    panic!("timed out waiting for total_queries == {expected}");
}

async fn collect_ws_events(
    ws_stream: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    count: usize,
) -> Vec<QueryEvent> {
    let mut events = Vec::with_capacity(count);
    for _ in 0..count {
        let msg = tokio::time::timeout(Duration::from_secs(3), ws_stream.next())
            .await
            .expect("ws recv timeout")
            .expect("ws stream open")
            .expect("ws frame ok");
        if let WsMessage::Text(text) = msg {
            let ev: QueryEvent = serde_json::from_str(&text).expect("valid QueryEvent JSON");
            events.push(ev);
        }
    }
    events
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn test_full_chain_dns_udp_tcp_cache_filter_storage_web_ws_and_restart() {
    let (upstream_addr, upstream_hits) = spawn_mock_udp_upstream().await;
    let data_dir = tempfile::tempdir().expect("tempdir");

    let mut config = Config::default();
    config.bootstrap.listen_dns = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    config.bootstrap.listen_web = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    config.bootstrap.data_dir = data_dir.path().to_path_buf();
    config.bootstrap.custom_rules = vec![
        "||ads.example.com^".to_string(),
        "||tracker.evil.com^".to_string(),
        "||nas.local^$dnsrewrite=192.168.1.50".to_string(),
    ];
    config.upstreams = vec![format!("udp://{upstream_addr}")];
    config.cache_size = 1024;
    config.optimistic_cache = true;
    config.upstream_timeout_ms = 2000;
    config.log_retention_hours = 24;

    let server = spawn_server(config.clone())
        .await
        .expect("spawn crabdns server");
    let dns_addr = server.dns_addr;
    let base_url = format!("http://{}", server.web_addr);
    let ws_url = format!("ws://{}/api/logs/ws", server.web_addr);

    // Connect WebSocket client before sending DNS queries so we observe live events
    let (mut ws_stream, _) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .expect("connect ws");

    // 1. Forwarded UDP A query
    let r1 = send_udp_query(
        dns_addr,
        &build_query(0x1001, "allowed.example.com.", RecordType::A),
    )
    .await;
    assert_eq!(r1.id, 0x1001);
    assert_eq!(r1.response_code, ResponseCode::NoError);
    assert_eq!(r1.answers[0].data, RData::A(A(Ipv4Addr::new(1, 2, 3, 4))));
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);

    // 2. Cached UDP A query (same domain, new TX ID, upstream hit count stays 1)
    let r2 = send_udp_query(
        dns_addr,
        &build_query(0x1002, "allowed.example.com.", RecordType::A),
    )
    .await;
    assert_eq!(r2.id, 0x1002);
    assert_eq!(r2.answers[0].data, RData::A(A(Ipv4Addr::new(1, 2, 3, 4))));
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);

    // 3. Cached TCP A query
    let r3 = send_tcp_query(
        dns_addr,
        &build_query(0x1003, "allowed.example.com.", RecordType::A),
    )
    .await;
    assert_eq!(r3.id, 0x1003);
    assert_eq!(r3.answers[0].data, RData::A(A(Ipv4Addr::new(1, 2, 3, 4))));
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);

    // 4. Blocked UDP A query -> 0.0.0.0
    let r4 = send_udp_query(
        dns_addr,
        &build_query(0x1004, "ads.example.com.", RecordType::A),
    )
    .await;
    assert_eq!(r4.id, 0x1004);
    assert_eq!(r4.answers[0].data, RData::A(A(Ipv4Addr::UNSPECIFIED)));

    // 5. Blocked UDP AAAA query -> ::
    let r5 = send_udp_query(
        dns_addr,
        &build_query(0x1005, "ads.example.com.", RecordType::AAAA),
    )
    .await;
    assert_eq!(r5.id, 0x1005);
    assert_eq!(r5.answers[0].data, RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED)));

    // 6. Rewritten UDP A query -> 192.168.1.50
    let r6 = send_udp_query(dns_addr, &build_query(0x1006, "nas.local.", RecordType::A)).await;
    assert_eq!(r6.id, 0x1006);
    assert_eq!(
        r6.answers[0].data,
        RData::A(A(Ipv4Addr::new(192, 168, 1, 50)))
    );

    // 7. CNAME cloaking blocked -> upstream queried (hits = 2), response is 0.0.0.0
    let r7 = send_udp_query(
        dns_addr,
        &build_query(0x1007, "cloaked.example.com.", RecordType::A),
    )
    .await;
    assert_eq!(r7.id, 0x1007);
    assert_eq!(r7.answers[0].data, RData::A(A(Ipv4Addr::UNSPECIFIED)));
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 2);

    // 8. Forwarded TCP A query
    let r8 = send_tcp_query(
        dns_addr,
        &build_query(0x1008, "tcp-live.example.com.", RecordType::A),
    )
    .await;
    assert_eq!(r8.id, 0x1008);
    assert_eq!(r8.answers[0].data, RData::A(A(Ipv4Addr::new(1, 2, 3, 4))));
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 3);

    // Verify all 8 QueryEvents arrive over WebSocket /api/logs/ws
    let ws_events = collect_ws_events(&mut ws_stream, 8).await;
    assert_eq!(ws_events.len(), 8);
    assert!(
        ws_events
            .iter()
            .any(|e| e.domain == "nas.local" && e.outcome == QueryOutcome::Rewritten)
    );
    assert!(
        ws_events
            .iter()
            .any(|e| e.domain == "cloaked.example.com" && e.outcome == QueryOutcome::Blocked)
    );
    assert!(
        ws_events
            .iter()
            .any(|e| e.domain == "tcp-live.example.com" && e.outcome == QueryOutcome::Forwarded)
    );

    // Verify HTTP APIs after log sink flushes to Fjall
    let http = reqwest::Client::new();
    let stats = wait_for_total_queries(&http, &base_url, 8).await;
    assert_eq!(stats["stats"]["blocked_queries"].as_u64(), Some(3));
    assert_eq!(stats["stats"]["cached_queries"].as_u64(), Some(2));
    assert_eq!(stats["stats"]["rewritten_queries"].as_u64(), Some(1));
    assert_eq!(stats["stats"]["error_queries"].as_u64(), Some(0));

    let health: Value = get_json(&http, &format!("{base_url}/api/health")).await;
    assert_eq!(health["status"].as_str(), Some("ok"));
    assert_eq!(health["filter_rules"].as_u64(), Some(3));

    let blocked_logs: Vec<QueryEvent> = get_json(
        &http,
        &format!("{base_url}/api/logs?outcome=blocked&limit=20"),
    )
    .await;
    assert_eq!(blocked_logs.len(), 3);

    let search_logs: Vec<QueryEvent> =
        get_json(&http, &format!("{base_url}/api/logs?search=nas.local")).await;
    assert_eq!(search_logs.len(), 1);
    assert_eq!(search_logs[0].outcome, QueryOutcome::Rewritten);

    // Hot-reload rules via PUT /api/rules
    let put_resp = put_json(
        &http,
        &format!("{base_url}/api/rules"),
        &serde_json::json!({
            "rules_text": "||dynamic-block.test^\n"
        }),
    )
    .await;
    assert_eq!(put_resp.status(), reqwest::StatusCode::OK);

    // Verify new rule blocks `dynamic-block.test` and old rule no longer blocks `ads.example.com`
    let r9 = send_udp_query(
        dns_addr,
        &build_query(0x1009, "dynamic-block.test.", RecordType::A),
    )
    .await;
    assert_eq!(r9.answers[0].data, RData::A(A(Ipv4Addr::UNSPECIFIED)));

    let r10 = send_udp_query(
        dns_addr,
        &build_query(0x100A, "ads.example.com.", RecordType::A),
    )
    .await;
    assert_eq!(r10.answers[0].data, RData::A(A(Ipv4Addr::new(1, 2, 3, 4))));

    let _ = wait_for_total_queries(&http, &base_url, 10).await;

    // Graceful shutdown + restart on the same data_dir with empty config.custom_rules
    server.shutdown().await;

    let mut restart_config = config;
    restart_config.bootstrap.custom_rules = vec![];
    let restarted = spawn_server(restart_config).await.expect("restart server");
    let restarted_base = format!("http://{}", restarted.web_addr);

    // Persisted custom rules from Fjall must still block `dynamic-block.test`
    let r11 = send_udp_query(
        restarted.dns_addr,
        &build_query(0x100B, "dynamic-block.test.", RecordType::A),
    )
    .await;
    assert_eq!(r11.answers[0].data, RData::A(A(Ipv4Addr::UNSPECIFIED)));

    let persisted_stats = wait_for_total_queries(&http, &restarted_base, 11).await;
    assert_eq!(
        persisted_stats["stats"]["blocked_queries"].as_u64(),
        Some(5)
    );

    restarted.shutdown().await;
}

#[tokio::test]
async fn test_full_chain_upstream_failover_and_servfail() {
    let (tcp_upstream_addr, tcp_hits) = spawn_mock_tcp_upstream().await;
    let data_dir = tempfile::tempdir().expect("tempdir");

    // 1. Failover from unreachable UDP upstream to healthy TCP upstream
    let mut failover_cfg = Config::default();
    failover_cfg.bootstrap.listen_dns = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    failover_cfg.bootstrap.listen_web = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    failover_cfg.bootstrap.data_dir = data_dir.path().to_path_buf();
    failover_cfg.upstreams = vec![
        "udp://127.0.0.1:1".to_string(),
        format!("tcp://{tcp_upstream_addr}"),
    ];
    failover_cfg.cache_size = 128;
    failover_cfg.optimistic_cache = false;
    failover_cfg.upstream_timeout_ms = 500;
    failover_cfg.log_retention_hours = 24;

    let server = spawn_server(failover_cfg)
        .await
        .expect("spawn failover server");
    let resp = send_udp_query(
        server.dns_addr,
        &build_query(0x2001, "failover.example.com.", RecordType::A),
    )
    .await;
    assert_eq!(resp.id, 0x2001);
    assert_eq!(resp.response_code, ResponseCode::NoError);
    assert_eq!(resp.answers[0].data, RData::A(A(Ipv4Addr::new(1, 2, 3, 4))));
    assert_eq!(tcp_hits.load(Ordering::SeqCst), 1);
    server.shutdown().await;

    // 2. All upstreams unreachable -> SERVFAIL + Error counter
    let dead_dir = tempfile::tempdir().expect("tempdir dead");
    let mut dead_cfg = Config::default();
    dead_cfg.bootstrap.listen_dns = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    dead_cfg.bootstrap.listen_web = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    dead_cfg.bootstrap.data_dir = dead_dir.path().to_path_buf();
    dead_cfg.upstreams = vec!["udp://127.0.0.1:1".to_string()];
    dead_cfg.cache_size = 128;
    dead_cfg.optimistic_cache = false;
    dead_cfg.upstream_timeout_ms = 200;
    dead_cfg.log_retention_hours = 24;

    let dead_server = spawn_server(dead_cfg).await.expect("spawn dead server");
    let dead_base = format!("http://{}", dead_server.web_addr);
    let err_resp = send_udp_query(
        dead_server.dns_addr,
        &build_query(0x2002, "broken.example.com.", RecordType::A),
    )
    .await;
    assert_eq!(err_resp.id, 0x2002);
    assert_eq!(err_resp.response_code, ResponseCode::ServFail);

    let http = reqwest::Client::new();
    let stats = wait_for_total_queries(&http, &dead_base, 1).await;
    assert_eq!(stats["stats"]["error_queries"].as_u64(), Some(1));

    dead_server.shutdown().await;
}

#[tokio::test]
async fn test_full_chain_config_update_hot_reload_and_restart() {
    let (udp_upstream, udp_hits) = spawn_mock_udp_upstream().await;
    let (tcp_upstream, tcp_hits) = spawn_mock_tcp_upstream().await;
    let data_dir = tempfile::tempdir().expect("tempdir");

    let mut config = Config::default();
    config.bootstrap.listen_dns = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    config.bootstrap.listen_web = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    config.bootstrap.data_dir = data_dir.path().to_path_buf();
    config.upstreams = vec![format!("udp://{udp_upstream}")];
    config.cache_size = 128;
    config.optimistic_cache = true;
    config.upstream_timeout_ms = 1500;
    config.log_retention_hours = 24;

    let server = spawn_server(config.clone()).await.expect("spawn server");
    let http = reqwest::Client::new();
    let base_url = format!("http://{}", server.web_addr);

    // Query goes to UDP upstream initially
    let r1 = send_udp_query(
        server.dns_addr,
        &build_query(0x3001, "cfg-test-1.example.com.", RecordType::A),
    )
    .await;
    assert_eq!(r1.response_code, ResponseCode::NoError);
    assert_eq!(udp_hits.load(Ordering::SeqCst), 1);
    assert_eq!(tcp_hits.load(Ordering::SeqCst), 0);

    // Invalid config (empty upstreams) must return 400 Bad Request
    let bad_resp = put_json(
        &http,
        &format!("{base_url}/api/config"),
        &serde_json::json!({
            "upstreams": [],
            "cache_size": 256,
            "optimistic_cache": false,
            "upstream_timeout_ms": 1000,
            "log_retention_hours": 12
        }),
    )
    .await;
    assert_eq!(bad_resp.status(), reqwest::StatusCode::BAD_REQUEST);

    // Valid PUT /api/config switches upstream to TCP and updates cache/timeout/retention
    let ok_resp = put_json(
        &http,
        &format!("{base_url}/api/config"),
        &serde_json::json!({
            "upstreams": [format!("tcp://{tcp_upstream}")],
            "cache_size": 512,
            "optimistic_cache": false,
            "upstream_timeout_ms": 2500,
            "log_retention_hours": 48
        }),
    )
    .await;
    assert_eq!(ok_resp.status(), reqwest::StatusCode::OK);

    // Next query immediately uses the new TCP upstream (hot-reloaded)
    let r2 = send_udp_query(
        server.dns_addr,
        &build_query(0x3002, "cfg-test-2.example.com.", RecordType::A),
    )
    .await;
    assert_eq!(r2.response_code, ResponseCode::NoError);
    assert_eq!(udp_hits.load(Ordering::SeqCst), 1);
    assert_eq!(tcp_hits.load(Ordering::SeqCst), 1);

    server.shutdown().await;

    // Restart with original UDP config; Fjall persisted config should override to TCP upstream
    let restarted = spawn_server(config).await.expect("restart server");
    let restarted_http = reqwest::Client::new();
    let cfg_json: Value = get_json(
        &restarted_http,
        &format!("http://{}/api/config", restarted.web_addr),
    )
    .await;
    assert_eq!(cfg_json["cache_size"].as_u64(), Some(512));
    assert_eq!(cfg_json["optimistic_cache"].as_bool(), Some(false));
    assert_eq!(cfg_json["log_retention_hours"].as_u64(), Some(48));

    let r3 = send_udp_query(
        restarted.dns_addr,
        &build_query(0x3003, "cfg-test-3.example.com.", RecordType::A),
    )
    .await;
    assert_eq!(r3.response_code, ResponseCode::NoError);
    assert_eq!(tcp_hits.load(Ordering::SeqCst), 2);

    restarted.shutdown().await;
}
