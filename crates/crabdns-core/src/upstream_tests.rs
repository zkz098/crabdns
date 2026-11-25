use super::*;
use crate::upstream_health::{
    UNHEALTHY_BASE_COOLDOWN_MS, UNHEALTHY_FAILURE_THRESHOLD, UNHEALTHY_MAX_COOLDOWN_MS,
    compute_backoff_cooldown_ms,
};
use std::sync::atomic::AtomicU32;

#[test]
fn test_parse_upstream_specs() {
    assert!(matches!(
        UpstreamEndpoint::parse("1.1.1.1").expect("valid"),
        UpstreamEndpoint::Udp(_)
    ));
    assert!(matches!(
        UpstreamEndpoint::parse("tcp://8.8.8.8:53").expect("valid"),
        UpstreamEndpoint::Tcp(_)
    ));
    assert!(matches!(
        UpstreamEndpoint::parse("tls://dns.google").expect("valid"),
        UpstreamEndpoint::Dot { .. }
    ));
    assert!(matches!(
        UpstreamEndpoint::parse("https://dns.google/dns-query").expect("valid"),
        UpstreamEndpoint::Doh { .. }
    ));
}

#[tokio::test]
async fn test_parallel_strategy_and_circuit_breaker() {
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind mock");
    let mock_addr = sock.local_addr().expect("addr");
    tokio::spawn(async move {
        let mut buf = [0_u8; 512];
        while let Ok((len, peer)) = sock.recv_from(&mut buf).await {
            let _ = sock.send_to(&buf[..len], peer).await;
        }
    });

    let pool = UpstreamPool::new_with_strategy(
        &[
            "udp://127.0.0.1:1".to_string(),
            format!("udp://{mock_addr}"),
        ],
        500,
        UpstreamStrategy::Parallel,
    )
    .expect("pool");

    let (resp, label) = pool
        .exchange(&[0x12, 0x34, 0, 0])
        .await
        .expect("parallel ok");
    assert_eq!(resp, vec![0x12, 0x34, 0, 0]);
    assert_eq!(label, format!("udp://{mock_addr}"));

    let snap = pool.health_snapshot();
    assert_eq!(snap.len(), 2);
    assert!(snap[1].healthy);
    assert_eq!(snap[1].total_requests, 1);

    // Trigger circuit breaker on dead endpoint
    let dead_pool = UpstreamPool::new(&["udp://127.0.0.1:1".to_string()], 50).expect("dead pool");
    for _ in 0..UNHEALTHY_FAILURE_THRESHOLD {
        assert!(dead_pool.exchange(&[1, 2, 3]).await.is_err());
    }
    let dead_snap = dead_pool.health_snapshot();
    assert!(!dead_snap[0].healthy);
    assert_eq!(
        dead_snap[0].consecutive_failures,
        UNHEALTHY_FAILURE_THRESHOLD
    );
}

#[test]
fn test_bootstrap_endpoint_validation() {
    assert!(
        BootstrapResolver::new(
            &[
                "1.1.1.1".to_string(),
                "udp://8.8.8.8:53".to_string(),
                "tcp://9.9.9.9:53".to_string(),
                "[2606:4700:4700::1111]:53".to_string(),
            ],
            Duration::from_millis(500),
        )
        .is_ok()
    );

    for invalid in [
        "dns.google",
        "tls://dns.google",
        "https://dns.google/dns-query",
    ] {
        assert!(
            BootstrapResolver::new(&[invalid.to_string()], Duration::from_millis(500)).is_err(),
            "expected {invalid} to be rejected"
        );
    }
}

#[tokio::test]
async fn test_bootstrap_resolver_queries_and_caches() {
    use hickory_proto::rr::Record;
    use hickory_proto::rr::rdata::A;
    use std::net::Ipv4Addr;

    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind mock");
    let mock_addr = sock.local_addr().expect("addr");
    let hits = Arc::new(AtomicU32::new(0));
    let hits_clone = Arc::clone(&hits);

    tokio::spawn(async move {
        let mut buf = [0_u8; 512];
        while let Ok((len, peer)) = sock.recv_from(&mut buf).await {
            let req = Message::from_vec(&buf[..len]).expect("valid query");
            let q = req.queries.first().expect("question").clone();
            let mut resp = Message::new(req.id, MessageType::Response, OpCode::Query);
            resp.metadata.recursion_desired = true;
            resp.metadata.recursion_available = true;
            resp.metadata.response_code = ResponseCode::NoError;
            resp.add_query(q.clone());
            if q.query_type == RecordType::A {
                hits_clone.fetch_add(1, Ordering::SeqCst);
                resp.add_answer(Record::from_rdata(
                    q.name,
                    120,
                    RData::A(A(Ipv4Addr::new(127, 0, 0, 10))),
                ));
            }
            let wire = resp.to_vec().expect("encode resp");
            let _ = sock.send_to(&wire, peer).await;
        }
    });

    let resolver =
        BootstrapResolver::new(&[format!("udp://{mock_addr}")], Duration::from_millis(1000))
            .expect("resolver");

    // IP literals bypass DNS queries.
    let literal = resolver.resolve_ips("127.0.0.1").await.expect("literal");
    assert_eq!(literal, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    assert_eq!(hits.load(Ordering::SeqCst), 0);

    // First query hits mock bootstrap server; second hits cache.
    let ips1 = resolver
        .resolve_ips("doh.example.test")
        .await
        .expect("resolve 1");
    assert_eq!(ips1, vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 10))]);
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    let ips2 = resolver
        .resolve_ips("doh.example.test")
        .await
        .expect("resolve 2");
    assert_eq!(ips2, vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 10))]);
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    // reqwest::dns::Resolve trait integration.
    let reqwest_name: reqwest::dns::Name = "doh.example.test".parse().expect("reqwest name");
    let addrs: Vec<SocketAddr> = reqwest::dns::Resolve::resolve(&resolver, reqwest_name)
        .await
        .expect("reqwest resolve")
        .collect();
    assert_eq!(
        addrs,
        vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 10)), 0)]
    );
}

#[test]
fn test_half_open_single_probe_prevents_thundering_herd() {
    let health = EndpointHealth::default();
    let start = 1_000_u64;
    for _ in 0..UNHEALTHY_FAILURE_THRESHOLD {
        health.record_failure(start);
    }
    assert!(!health.is_healthy(start + 1));

    // During cooldown, no request is selected.
    let (ok_during, guard_during) = health.try_select(start + 100);
    assert!(!ok_during);
    assert!(guard_during.is_none());

    // At cooldown expiry, only one concurrent caller wins the half-open probe.
    let half_open_at = health.unhealthy_until_ms.load(Ordering::Relaxed);
    assert!(half_open_at >= start + (UNHEALTHY_BASE_COOLDOWN_MS * 4 / 5));
    assert!(half_open_at <= start + (UNHEALTHY_BASE_COOLDOWN_MS * 6 / 5));
    let (ok1, guard1) = health.try_select(half_open_at);
    assert!(ok1);
    assert!(guard1.is_some());

    let (ok2, guard2) = health.try_select(half_open_at);
    assert!(!ok2);
    assert!(guard2.is_none());

    // Dropping the probe guard (simulating task cancellation) frees the slot.
    drop(guard1);
    let (ok3, guard3) = health.try_select(half_open_at);
    assert!(ok3);
    assert!(guard3.is_some());

    // Completing a probe failure immediately re-arms cooldown with higher exponent.
    if let Some(mut g) = guard3 {
        g.defused = true;
    }
    health.record_failure(half_open_at + 10);
    let second_until = health.unhealthy_until_ms.load(Ordering::Relaxed);
    assert!(!health.is_healthy(half_open_at + 11));
    // Second backoff base is 2x UNHEALTHY_BASE_COOLDOWN_MS (10s ± 20%).
    assert!(second_until >= half_open_at + 10 + (UNHEALTHY_BASE_COOLDOWN_MS * 2 * 4 / 5));
    assert_eq!(health.backoff_exponent.load(Ordering::Relaxed), 2);

    // Recovery resets backoff exponent.
    health.record_success(2_000);
    assert_eq!(health.backoff_exponent.load(Ordering::Relaxed), 0);
    assert!(health.is_healthy(second_until));
}

#[test]
fn test_exponential_backoff_bounds_and_cap() {
    let c0 = compute_backoff_cooldown_ms(0, 42);
    assert!((4_000..=6_000).contains(&c0), "c0={c0}");

    let c1 = compute_backoff_cooldown_ms(1, 42);
    assert!((8_000..=12_000).contains(&c1), "c1={c1}");

    let c_max = compute_backoff_cooldown_ms(20, 99);
    assert!(
        (UNHEALTHY_MAX_COOLDOWN_MS * 4 / 5..=UNHEALTHY_MAX_COOLDOWN_MS).contains(&c_max),
        "c_max={c_max}"
    );
}

#[tokio::test]
async fn test_servfail_failover_and_health_tracking() {
    use hickory_proto::rr::Record;
    use hickory_proto::rr::rdata::A;
    use std::net::Ipv4Addr;

    // Mock 1: always returns SERVFAIL.
    let bad_sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind bad");
    let bad_addr = bad_sock.local_addr().expect("bad addr");
    tokio::spawn(async move {
        let mut buf = [0_u8; 512];
        while let Ok((len, peer)) = bad_sock.recv_from(&mut buf).await {
            let req = Message::from_vec(&buf[..len]).expect("req");
            let mut resp = Message::new(req.id, MessageType::Response, OpCode::Query);
            resp.metadata.response_code = ResponseCode::ServFail;
            if let Some(q) = req.queries.first() {
                resp.add_query(q.clone());
            }
            let _ = bad_sock.send_to(&resp.to_vec().expect("enc"), peer).await;
        }
    });

    // Mock 2: returns NOERROR with 1.2.3.4.
    let good_sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind good");
    let good_addr = good_sock.local_addr().expect("good addr");
    tokio::spawn(async move {
        let mut buf = [0_u8; 512];
        while let Ok((len, peer)) = good_sock.recv_from(&mut buf).await {
            let req = Message::from_vec(&buf[..len]).expect("req");
            let mut resp = Message::new(req.id, MessageType::Response, OpCode::Query);
            resp.metadata.response_code = ResponseCode::NoError;
            if let Some(q) = req.queries.first() {
                resp.add_query(q.clone());
                resp.add_answer(Record::from_rdata(
                    q.name.clone(),
                    60,
                    RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
                ));
            }
            let _ = good_sock.send_to(&resp.to_vec().expect("enc"), peer).await;
        }
    });

    let mut q = Message::new(0x1337, MessageType::Query, OpCode::Query);
    q.add_query(Query::query(
        Name::from_ascii("example.test.").unwrap(),
        RecordType::A,
    ));
    let wire = q.to_vec().unwrap();

    // Failover skips SERVFAIL upstream and succeeds on healthy secondary.
    let pool = UpstreamPool::new_with_strategy(
        &[format!("udp://{bad_addr}"), format!("udp://{good_addr}")],
        500,
        UpstreamStrategy::Failover,
    )
    .expect("pool");
    let (resp_wire, label) = pool.exchange(&wire).await.expect("failover ok");
    let parsed = Message::from_vec(&resp_wire).expect("resp");
    assert_eq!(parsed.response_code, ResponseCode::NoError);
    assert_eq!(label, format!("udp://{good_addr}"));
    let snap = pool.health_snapshot();
    assert_eq!(snap[0].total_failures, 1);
    assert_eq!(snap[0].ewma_latency_ms, 0);
    assert_eq!(snap[1].total_failures, 0);

    // When all upstreams return SERVFAIL, the SERVFAIL packet is still returned (and failures tracked).
    let all_bad = UpstreamPool::new(&[format!("udp://{bad_addr}")], 500).expect("all_bad");
    for _ in 0..UNHEALTHY_FAILURE_THRESHOLD {
        let (resp_wire, _) = all_bad.exchange(&wire).await.expect("servfail returned");
        assert_eq!(
            Message::from_vec(&resp_wire).unwrap().response_code,
            ResponseCode::ServFail
        );
    }
    assert!(!all_bad.health_snapshot()[0].healthy);
}
