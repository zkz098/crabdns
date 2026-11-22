use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::Router;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use crabdns_core::{Config, FilterAction};
use crabdns_server::spawn_server;
use futures_util::StreamExt;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Notify;
use tokio_tungstenite::connect_async;

fn build_query(id: u16, domain: &str) -> Vec<u8> {
    let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(
        Name::from_ascii(domain).expect("valid domain"),
        RecordType::A,
    ));
    msg.to_vec().expect("encode query")
}

async fn spawn_mock_udp_upstream() -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind mock udp");
    let addr = sock.local_addr().expect("mock addr");
    tokio::spawn(async move {
        let mut buf = [0_u8; 2048];
        while let Ok((len, peer)) = sock.recv_from(&mut buf).await {
            if let Ok(req) = Message::from_vec(&buf[..len]) {
                let mut resp = Message::new(req.id, MessageType::Response, OpCode::Query);
                resp.metadata.recursion_available = true;
                resp.metadata.response_code = ResponseCode::NoError;
                resp.queries.clone_from(&req.queries);
                if let Some(q) = req.queries.first() {
                    resp.add_answer(Record::from_rdata(
                        q.name().clone(),
                        120,
                        RData::A(A(Ipv4Addr::new(93, 184, 216, 34))),
                    ));
                }
                if let Ok(wire) = resp.to_vec() {
                    let _ = sock.send_to(&wire, peer).await;
                }
            }
        }
    });
    addr
}

async fn spawn_mock_subscription_server() -> (SocketAddr, Arc<AtomicUsize>, Arc<Notify>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let notify = Arc::new(Notify::new());
    let hits_bg = Arc::clone(&hits);
    let notify_bg = Arc::clone(&notify);

    let app = Router::new().route(
        "/sub.txt",
        get(move || {
            let hits = Arc::clone(&hits_bg);
            let notify = Arc::clone(&notify_bg);
            async move {
                let n = hits.fetch_add(1, Ordering::SeqCst) + 1;
                notify.notify_waiters();
                if n > 1 && n.is_multiple_of(7) {
                    return (StatusCode::INTERNAL_SERVER_ERROR, "upstream error").into_response();
                }
                let body = if n.is_multiple_of(2) {
                    "||sub-even1.test^\n||sub-even2.test^\n||shared-sub.test^\n"
                } else {
                    "||sub-odd.test^\n||shared-sub.test^\n"
                };
                (StatusCode::OK, body).into_response()
            }
        }),
    );

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock sub");
    let addr = listener.local_addr().expect("sub addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (addr, hits, notify)
}

#[cfg(target_os = "linux")]
fn count_open_fds() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .expect("read /proc/self/fd")
        .filter_map(std::result::Result::ok)
        .count()
}

#[cfg(not(target_os = "linux"))]
fn count_open_fds() -> usize {
    0
}

async fn wait_for_real_hits(hits: &AtomicUsize, target: usize) {
    for _ in 0..500 {
        if hits.load(Ordering::SeqCst) >= target {
            return;
        }
        tokio::task::yield_now().await;
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!(
        "timed out waiting for subscription hits >= {target}, got {}",
        hits.load(Ordering::SeqCst)
    );
}

#[tokio::test(start_paused = true)]
async fn test_virtual_time_long_horizon_background_tasks() {
    let upstream_addr = spawn_mock_udp_upstream().await;
    let (sub_addr, sub_hits, _notify) = spawn_mock_subscription_server().await;

    let dir = tempfile::tempdir().expect("tempdir");
    let hosts_path = dir.path().join("hosts");
    std::fs::write(&hosts_path, "10.0.0.50 virtual.lan\n").expect("write hosts");

    let cfg = Config {
        listen_dns: "127.0.0.1:0".parse().expect("dns addr"),
        listen_web: "127.0.0.1:0".parse().expect("web addr"),
        data_dir: dir.path().to_path_buf(),
        upstreams: vec![format!("udp://{upstream_addr}")],
        cache_size: 128,
        cache_persist_enabled: true,
        log_retention_hours: 1,
        hosts_enabled: true,
        hosts_path: Some(hosts_path.display().to_string()),
        allow_private_subscriptions: true,
        rdns_enabled: false,
        ..Config::default()
    };

    let server = spawn_server(cfg).await.expect("spawn server");
    let client = reqwest::Client::new();
    let base = format!("http://{}", server.web_addr);

    let create_res = client
        .post(format!("{base}/api/subscriptions"))
        .header("content-type", "application/json")
        .body(format!(
            r#"{{"name":"Soak Sub","url":"http://{sub_addr}/sub.txt","enabled":true}}"#
        ))
        .send()
        .await
        .expect("create sub");
    assert_eq!(create_res.status(), StatusCode::CREATED);
    let create_body = create_res.text().await.expect("create sub body");
    assert_eq!(
        sub_hits.load(Ordering::SeqCst),
        1,
        "unexpected initial sub hits; create_subscription body={create_body}"
    );

    let dns_sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
    dns_sock.connect(server.dns_addr).await.expect("connect");

    // Yield once so background intervals complete their initial immediate tick cleanly.
    tokio::task::yield_now().await;
    let baseline_fds = count_open_fds();

    let mut dns_buf = [0_u8; 2048];
    for day in 1_u16..=31 {
        let pkt = build_query(day, &format!("day-{day}.virtual.test."));
        let _ = dns_sock.send(&pkt).await;
        let _ = dns_sock.recv(&mut dns_buf).await;

        tokio::time::advance(Duration::from_hours(24)).await;
        wait_for_real_hits(&sub_hits, usize::from(day) + 1).await;
        tokio::task::yield_now().await;
        std::thread::sleep(Duration::from_millis(5));
        tokio::task::yield_now().await;
    }

    assert!(sub_hits.load(Ordering::SeqCst) >= 32);
    assert_eq!(
        server.pipeline.filter().evaluate("shared-sub.test").action,
        FilterAction::Block
    );

    let end_fds = count_open_fds();
    assert!(
        end_fds <= baseline_fds + 8,
        "FD leak across 31 simulated days: baseline={baseline_fds}, end={end_fds}"
    );

    drop(dns_sock);
    drop(client);
    server.shutdown().await;
}

#[tokio::test]
async fn test_fd_and_inflight_return_to_baseline_after_mixed_bursts() {
    let upstream_addr = spawn_mock_udp_upstream().await;
    let dir = tempfile::tempdir().expect("tempdir");

    let cfg = Config {
        listen_dns: "127.0.0.1:0".parse().expect("dns addr"),
        listen_web: "127.0.0.1:0".parse().expect("web addr"),
        data_dir: dir.path().to_path_buf(),
        upstreams: vec![format!("udp://{upstream_addr}")],
        custom_rules: vec!["||blocked.burst.test^".to_string()],
        tcp_idle_timeout_secs: 1,
        rdns_enabled: false,
        ..Config::default()
    };

    let server = spawn_server(cfg).await.expect("spawn server");
    let http = reqwest::Client::new();
    let base = format!("http://{}", server.web_addr);

    // Warm up lazy connections/pools before capturing FD baseline.
    let warm_udp = UdpSocket::bind("127.0.0.1:0").await.expect("warm udp");
    warm_udp.connect(server.dns_addr).await.expect("connect");
    let mut rbuf = [0_u8; 2048];
    let _ = warm_udp.send(&build_query(1, "warmup.example.test.")).await;
    let _ = warm_udp.recv(&mut rbuf).await;
    drop(warm_udp);
    let _ = http.get(format!("{base}/metrics")).send().await;

    let baseline_fds = count_open_fds();

    // 1. UDP burst (blocked, cached, forwarded)
    let udp_sock = UdpSocket::bind("127.0.0.1:0").await.expect("udp");
    udp_sock.connect(server.dns_addr).await.expect("connect");
    for i in 0_u16..50 {
        let domain = match i % 3 {
            0 => "blocked.burst.test.".to_string(),
            1 => "warmup.example.test.".to_string(),
            _ => format!("burst-{i}.example.test."),
        };
        let _ = udp_sock.send(&build_query(i + 10, &domain)).await;
        let _ = tokio::time::timeout(Duration::from_secs(1), udp_sock.recv(&mut rbuf)).await;
    }
    drop(udp_sock);

    // 2. TCP burst (graceful + idle-timeout connections)
    for i in 0_u16..8 {
        let mut stream = TcpStream::connect(server.dns_addr).await.expect("tcp");
        let pkt = build_query(100 + i, "warmup.example.test.");
        let len_bytes = u16::try_from(pkt.len()).expect("len").to_be_bytes();
        stream.write_all(&len_bytes).await.expect("write len");
        stream.write_all(&pkt).await.expect("write pkt");
        let mut resp_len_buf = [0_u8; 2];
        stream
            .read_exact(&mut resp_len_buf)
            .await
            .expect("read len");
        let resp_len = usize::from(u16::from_be_bytes(resp_len_buf));
        let mut resp = vec![0_u8; resp_len];
        stream.read_exact(&mut resp).await.expect("read resp");
        if i % 2 == 0 {
            drop(stream);
        } else {
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(1200)).await;
                drop(stream);
            });
        }
    }

    // 3. DoH + WebSocket abrupt disconnect burst
    let doh_pkt = build_query(0x5555, "blocked.burst.test.");
    for _ in 0..8 {
        let res = http
            .post(format!("{base}/dns-query"))
            .header("content-type", "application/dns-message")
            .body(doh_pkt.clone())
            .send()
            .await
            .expect("doh");
        assert_eq!(res.status(), StatusCode::OK);
    }

    for _ in 0..4 {
        let ws_url = format!("ws://{}/api/logs/ws", server.web_addr);
        let (mut ws, _) = connect_async(ws_url).await.expect("ws connect");
        let trigger = UdpSocket::bind("127.0.0.1:0").await.expect("trigger");
        trigger.connect(server.dns_addr).await.expect("connect");
        let _ = trigger.send(&doh_pkt).await;
        let _ = trigger.recv(&mut rbuf).await;
        let _ = tokio::time::timeout(Duration::from_secs(1), ws.next()).await;
        drop(ws);
    }

    // Wait for TCP idle timeout (1s) + task cleanup.
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let metrics = server.pipeline.runtime_metrics();
    assert_eq!(metrics.singleflight_inflight, 0);
    assert_eq!(metrics.rdns_inflight, 0);
    assert_eq!(metrics.bg_refresh_inflight, 0);

    let final_fds = count_open_fds();
    assert!(
        final_fds <= baseline_fds + 4,
        "FD count did not return to baseline: baseline={baseline_fds}, final={final_fds}"
    );

    drop(http);
    server.shutdown().await;
}
