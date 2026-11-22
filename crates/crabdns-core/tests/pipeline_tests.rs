use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crabdns_core::PersistedCacheEntry;

use crabdns_core::cache::{CacheKey, DnsCache};
use crabdns_core::config::{BlockMode, UpstreamStrategy};
use crabdns_core::filter::FilterEngine;
use crabdns_core::pipeline::{DnsPipeline, QueryContext, QueryOutcome, QueryProtocol};
use crabdns_core::upstream::UpstreamPool;
use crabdns_core::{ClientGroup, ClientProfile};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, CNAME, SOA};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

fn build_query(id: u16, domain: &str, qtype: RecordType) -> Vec<u8> {
    let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    let name = Name::from_ascii(domain).expect("valid domain");
    msg.add_query(Query::query(name, qtype));
    msg.to_vec().expect("encode query")
}

async fn spawn_mock_udp_upstream(cname_target: Option<&'static str>) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind mock");
    let addr = socket.local_addr().expect("local addr");
    tokio::spawn(async move {
        let mut buf = [0_u8; 2048];
        while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
            let req = Message::from_vec(&buf[..len]).expect("valid req");
            let q = req.queries.first().expect("question");
            let mut resp = Message::new(req.id, MessageType::Response, OpCode::Query);
            resp.metadata.recursion_available = true;
            resp.queries.clone_from(&req.queries);
            if let Some(target) = cname_target {
                let cname = Name::from_ascii(target).expect("valid cname");
                resp.add_answer(Record::from_rdata(
                    q.name().clone(),
                    60,
                    RData::CNAME(CNAME(cname)),
                ));
            } else {
                resp.add_answer(Record::from_rdata(
                    q.name().clone(),
                    120,
                    RData::A(A(Ipv4Addr::new(93, 184, 216, 34))),
                ));
            }
            let bytes = resp.to_vec().expect("encode resp");
            let _ = socket.send_to(&bytes, peer).await;
        }
    });
    addr
}

#[tokio::test]
async fn test_pipeline_block_rewrite_and_invalid() {
    let filter = Arc::new(FilterEngine::new(&[
        "||ads.test^".to_string(),
        "||nas.local^$dnsrewrite=10.0.0.2".to_string(),
    ]));
    let cache = Arc::new(DnsCache::new(64, true));
    let upstream = Arc::new(UpstreamPool::new(&["udp://127.0.0.1:1".to_string()], 200).unwrap());
    let (tx, mut rx) = mpsc::channel(16);
    let pipeline = DnsPipeline::new(filter, cache, upstream, Some(tx));
    let client: SocketAddr = "127.0.0.1:12345".parse().expect("addr");

    let blocked_q = build_query(0x1001, "ads.test.", RecordType::A);
    let resp = Message::from_vec(&pipeline.handle_packet(&blocked_q, client).await.unwrap())
        .expect("decode");
    assert_eq!(resp.answers.len(), 1);
    let ev1 = rx.recv().await.unwrap();
    assert_eq!(ev1.outcome, QueryOutcome::Blocked);
    assert_eq!(ev1.protocol, QueryProtocol::Udp);
    assert_eq!(ev1.matched_list.as_deref(), Some("custom"));
    assert_eq!(ev1.answers, vec!["0.0.0.0"]);

    let blocked_txt = build_query(0x1002, "ads.test.", RecordType::TXT);
    let resp_txt = Message::from_vec(&pipeline.handle_packet(&blocked_txt, client).await.unwrap())
        .expect("decode");
    assert_eq!(resp_txt.response_code, ResponseCode::NXDomain);
    let _ = rx.recv().await;

    let rewrite_q = build_query(0x1003, "nas.local.", RecordType::A);
    let resp_rw = Message::from_vec(&pipeline.handle_packet(&rewrite_q, client).await.unwrap())
        .expect("decode");
    assert_eq!(resp_rw.answers.len(), 1);
    let ev_rw = rx.recv().await.unwrap();
    assert_eq!(ev_rw.outcome, QueryOutcome::Rewritten);
    assert_eq!(ev_rw.answers, vec!["10.0.0.2"]);

    assert!(pipeline.handle_packet(&[0, 1, 2], client).await.is_err());
}

#[tokio::test]
async fn test_pipeline_forward_cache_and_cname_cloaking() {
    let mock_addr = spawn_mock_udp_upstream(None).await;
    let filter = Arc::new(FilterEngine::new(&["||evil-cname.test^".to_string()]));
    let cache = Arc::new(DnsCache::new(64, true));
    let upstream =
        Arc::new(UpstreamPool::new(&[format!("udp://{mock_addr}")], 1000).expect("pool"));
    let (tx, mut rx) = mpsc::channel(16);
    let pipeline = DnsPipeline::new(filter, cache, upstream, Some(tx));
    let client: SocketAddr = "127.0.0.1:54321".parse().expect("addr");

    let q1 = build_query(0x2001, "example.org.", RecordType::A);
    let r1 = Message::from_vec(&pipeline.handle_packet(&q1, client).await.unwrap()).unwrap();
    assert_eq!(r1.id, 0x2001);
    let ev1 = rx.recv().await.unwrap();
    assert_eq!(ev1.outcome, QueryOutcome::Forwarded);
    assert_eq!(ev1.answers, vec!["93.184.216.34"]);

    let q2 = build_query(0x2002, "example.org.", RecordType::A);
    let r2 = Message::from_vec(&pipeline.handle_packet(&q2, client).await.unwrap()).unwrap();
    assert_eq!(r2.id, 0x2002);
    let ev2 = rx.recv().await.unwrap();
    assert_eq!(ev2.outcome, QueryOutcome::Cached);
    assert_eq!(ev2.answers, vec!["93.184.216.34"]);

    let cname_addr = spawn_mock_udp_upstream(Some("evil-cname.test.")).await;
    let upstream2 =
        Arc::new(UpstreamPool::new(&[format!("udp://{cname_addr}")], 1000).expect("pool"));
    let (tx2, mut rx2) = mpsc::channel(16);
    let pipeline2 = DnsPipeline::new(
        Arc::clone(pipeline.filter()),
        Arc::new(DnsCache::new(64, false)),
        upstream2,
        Some(tx2),
    );
    let q3 = build_query(0x3001, "cloaked.example.", RecordType::A);
    let _ = pipeline2.handle_packet(&q3, client).await.unwrap();
    assert_eq!(rx2.recv().await.unwrap().outcome, QueryOutcome::Blocked);
}

#[tokio::test]
async fn test_pipeline_upstream_timeout_servfail() {
    let filter = Arc::new(FilterEngine::new(&[]));
    let cache = Arc::new(DnsCache::new(64, false));
    let upstream = Arc::new(UpstreamPool::new(&["udp://127.0.0.1:1".to_string()], 50).unwrap());
    let pipeline = DnsPipeline::new(filter, cache, upstream, None);
    let client: SocketAddr = "127.0.0.1:9999".parse().expect("addr");

    let q = build_query(0x4001, "unreachable.example.", RecordType::A);
    let resp = Message::from_vec(&pipeline.handle_packet(&q, client).await.unwrap()).unwrap();
    assert_eq!(resp.response_code, ResponseCode::ServFail);
}

#[tokio::test]
async fn test_pipeline_block_modes_rewrites_and_acl() {
    let filter = Arc::new(FilterEngine::new(&[
        "||blocked.test^".to_string(),
        "||alias.test^$dnsrewrite=CNAME;target.test".to_string(),
        "||txt.test^$dnsrewrite=TXT;hello-crabdns".to_string(),
    ]));
    let cache = Arc::new(DnsCache::new(64, false));
    let upstream = Arc::new(UpstreamPool::new(&["udp://127.0.0.1:1".to_string()], 50).unwrap());
    let pipeline = DnsPipeline::new(filter, cache, upstream, None);
    let allowed_client: SocketAddr = "127.0.0.1:5000".parse().expect("addr");

    pipeline.set_block_mode(BlockMode::NxDomain);
    let q_blk = build_query(0x5001, "blocked.test.", RecordType::A);
    let nx_resp = Message::from_vec(
        &pipeline
            .handle_packet(&q_blk, allowed_client)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(nx_resp.response_code, ResponseCode::NXDomain);
    assert_eq!(nx_resp.answers.len(), 0);

    pipeline.set_block_mode(BlockMode::NoData);
    let nodata_resp = Message::from_vec(
        &pipeline
            .handle_packet(&q_blk, allowed_client)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(nodata_resp.response_code, ResponseCode::NoError);
    assert_eq!(nodata_resp.answers.len(), 0);

    let q_cname = build_query(0x5002, "alias.test.", RecordType::A);
    let r_cname = Message::from_vec(
        &pipeline
            .handle_packet(&q_cname, allowed_client)
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(matches!(
        r_cname.answers.first().map(|r| &r.data),
        Some(RData::CNAME(_))
    ));

    let q_txt = build_query(0x5003, "txt.test.", RecordType::TXT);
    let r_txt = Message::from_vec(
        &pipeline
            .handle_packet(&q_txt, allowed_client)
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(matches!(
        r_txt.answers.first().map(|r| &r.data),
        Some(RData::TXT(_))
    ));

    pipeline
        .reload_acl(&["127.0.0.0/8".to_string()], &["127.0.0.99".to_string()], 1)
        .expect("acl");
    let denied_client: SocketAddr = "127.0.0.99:5000".parse().expect("addr");
    let r_denied =
        Message::from_vec(&pipeline.handle_packet(&q_blk, denied_client).await.unwrap()).unwrap();
    assert_eq!(r_denied.response_code, ResponseCode::Refused);

    let r_ok = Message::from_vec(
        &pipeline
            .handle_packet(&q_blk, allowed_client)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(r_ok.response_code, ResponseCode::NoError);
    let r_rl = Message::from_vec(
        &pipeline
            .handle_packet(&q_blk, allowed_client)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(r_rl.response_code, ResponseCode::Refused);
}

#[tokio::test]
async fn test_pipeline_singleflight_coalesces_concurrent_misses() {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_bg = Arc::clone(&hits);

    tokio::spawn(async move {
        let mut buf = [0_u8; 2048];
        while let Ok((len, peer)) = sock.recv_from(&mut buf).await {
            let req = Message::from_vec(&buf[..len]).unwrap();
            let hits_inner = Arc::clone(&hits_bg);
            let sock_ref = &sock;
            hits_inner.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(60)).await;
            let mut resp = Message::new(req.id, MessageType::Response, OpCode::Query);
            resp.metadata.recursion_available = true;
            resp.queries.clone_from(&req.queries);
            if let Some(q) = req.queries.first() {
                resp.add_answer(Record::from_rdata(
                    q.name().clone(),
                    120,
                    RData::A(A(Ipv4Addr::new(93, 184, 216, 34))),
                ));
            }
            let _ = sock_ref.send_to(&resp.to_vec().unwrap(), peer).await;
        }
    });

    let filter = Arc::new(FilterEngine::new(&[]));
    let cache = Arc::new(DnsCache::new(64, false));
    let pool = Arc::new(UpstreamPool::new(&[format!("udp://{addr}")], 2000).unwrap());
    let pipeline = Arc::new(DnsPipeline::new(filter, cache, pool, None));
    let client: SocketAddr = "127.0.0.1:40000".parse().unwrap();

    let mut handles = Vec::new();
    for i in 0_u16..16 {
        let pipe = Arc::clone(&pipeline);
        handles.push(tokio::spawn(async move {
            let tx_id = 0x9000 + i;
            let q = build_query(tx_id, "coalesce.example.org.", RecordType::A);
            let raw = pipe.handle_packet(&q, client).await.unwrap();
            let msg = Message::from_vec(&raw).unwrap();
            (tx_id, msg)
        }));
    }

    for h in handles {
        let (expected_id, msg) = h.await.unwrap();
        assert_eq!(msg.id, expected_id);
        assert_eq!(msg.answers.len(), 1);
    }
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_pipeline_negative_soa_ttl() {
    let sock_default = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let default_addr = sock_default.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0_u8; 2048];
        while let Ok((len, peer)) = sock_default.recv_from(&mut buf).await {
            let req = Message::from_vec(&buf[..len]).unwrap();
            let mut resp = Message::new(req.id, MessageType::Response, OpCode::Query);
            resp.metadata.recursion_available = true;
            resp.queries.clone_from(&req.queries);
            resp.metadata.response_code = ResponseCode::NXDomain;
            resp.add_authority(Record::from_rdata(
                Name::from_ascii("example.").unwrap(),
                300,
                RData::SOA(SOA::new(
                    Name::from_ascii("ns1.example.").unwrap(),
                    Name::from_ascii("hostmaster.example.").unwrap(),
                    1,
                    3600,
                    600,
                    86400,
                    45,
                )),
            ));
            let _ = sock_default.send_to(&resp.to_vec().unwrap(), peer).await;
        }
    });

    let filter = Arc::new(FilterEngine::new(&[]));
    let cache = Arc::new(DnsCache::with_options(64, false, 10, 86_400, false));
    let pool = Arc::new(UpstreamPool::new(&[format!("udp://{default_addr}")], 1000).unwrap());
    let pipeline = DnsPipeline::new(filter, cache, pool, None);

    let client: SocketAddr = "192.168.1.99:5555".parse().unwrap();
    let nx_q = build_query(0x1111, "missing.example.", RecordType::A);
    let nx_r = Message::from_vec(&pipeline.handle_packet(&nx_q, client).await.unwrap()).unwrap();
    assert_eq!(nx_r.response_code, ResponseCode::NXDomain);
    let hit = pipeline
        .cache()
        .get(
            &CacheKey {
                qname: "missing.example.".to_string(),
                qtype: 1,
                qclass: 1,
                ecs_subnet: None,
                dnssec_do: false,
                upstream_scope: None,
            },
            0x1112,
        )
        .expect("nxdomain cached");
    let cached_nx = Message::from_vec(&hit.wire_bytes).unwrap();
    assert_eq!(cached_nx.authorities[0].ttl, 45);
}

#[tokio::test]
async fn test_pipeline_client_policies_and_profiles() {
    let custom_upstream = spawn_mock_udp_upstream(None).await;
    let filter = Arc::new(FilterEngine::new(&["||ads.example.com^".to_string()]));
    let cache = Arc::new(DnsCache::with_options(64, false, 10, 86_400, false));
    let pool = Arc::new(UpstreamPool::new(&["udp://127.0.0.1:1".to_string()], 500).unwrap());
    let (tx, mut rx) = mpsc::channel(32);
    let pipeline = DnsPipeline::new(filter, cache, pool, Some(tx));

    let groups = vec![ClientGroup {
        id: "kids".to_string(),
        name: "Kids".to_string(),
        description: String::new(),
        blocking_enabled: true,
        use_global_rules: true,
        custom_rules: "||tiktok.com^".to_string(),
        upstreams: Vec::new(),
        block_mode: Some(BlockMode::NxDomain),
        cname_cloaking_blocking: None,
        safesearch_enabled: None,
    }];
    let clients = vec![
        ClientProfile {
            id: "vip".to_string(),
            name: "VIP Phone".to_string(),
            identifiers: vec!["192.168.1.10".to_string(), "vip-doh".to_string()],
            group_id: None,
            blocking_enabled: Some(false),
            use_global_rules: Some(true),
            custom_rules: String::new(),
            upstreams: vec![format!("udp://{custom_upstream}")],
            block_mode: None,
            safesearch_enabled: None,
            tags: Vec::new(),
        },
        ClientProfile {
            id: "kid-ipad".to_string(),
            name: "Kid iPad".to_string(),
            identifiers: vec!["192.168.1.20".to_string()],
            group_id: Some("kids".to_string()),
            blocking_enabled: None,
            use_global_rules: None,
            custom_rules: String::new(),
            upstreams: Vec::new(),
            block_mode: None,
            safesearch_enabled: None,
            tags: Vec::new(),
        },
    ];
    pipeline
        .reload_clients(&clients, &groups, 1000, UpstreamStrategy::Failover, &[])
        .unwrap();

    // VIP client by DoH ClientID bypasses global adblock and routes to custom_upstream (93.184.216.34)
    let vip_ctx = QueryContext {
        client_addr: "10.0.0.5:0".parse().unwrap(),
        protocol: QueryProtocol::Doh,
        client_id: Some("vip-doh".to_string()),
    };
    let vip_r = Message::from_vec(
        &pipeline
            .handle_packet_with_context(
                &build_query(0x2222, "ads.example.com.", RecordType::A),
                vip_ctx,
            )
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        vip_r.answers[0].data,
        RData::A(A(Ipv4Addr::new(93, 184, 216, 34)))
    );
    let vip_ev = rx.recv().await.unwrap();
    assert_eq!(vip_ev.client_name.as_deref(), Some("VIP Phone"));
    assert_eq!(vip_ev.protocol, QueryProtocol::Doh);

    // Kid iPad gets group block (NXDOMAIN) on tiktok.com
    let kid_ctx = QueryContext {
        client_addr: "192.168.1.20:1234".parse().unwrap(),
        protocol: QueryProtocol::Udp,
        client_id: None,
    };
    let kid_r = Message::from_vec(
        &pipeline
            .handle_packet_with_context(&build_query(0x3333, "tiktok.com.", RecordType::A), kid_ctx)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(kid_r.response_code, ResponseCode::NXDomain);
    let kid_ev = rx.recv().await.unwrap();
    assert_eq!(kid_ev.client_name.as_deref(), Some("Kid iPad"));
    assert_eq!(kid_ev.matched_list.as_deref(), Some("group:Kids"));
}

async fn wait_for_refresh_idle(pipeline: &DnsPipeline, calls: &AtomicUsize, expected_calls: usize) {
    for _ in 0..100 {
        if calls.load(Ordering::SeqCst) >= expected_calls
            && pipeline.runtime_metrics().bg_refresh_inflight == 0
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(calls.load(Ordering::SeqCst), expected_calls);
}

#[tokio::test]
async fn test_background_refresh_clears_inflight_on_servfail() {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_bg = Arc::clone(&calls);

    tokio::spawn(async move {
        let mut buf = [0_u8; 2048];
        while let Ok((len, peer)) = sock.recv_from(&mut buf).await {
            let req = Message::from_vec(&buf[..len]).unwrap();
            let call_num = calls_bg.fetch_add(1, Ordering::SeqCst) + 1;
            let mut resp = Message::new(req.id, MessageType::Response, OpCode::Query);
            resp.metadata.recursion_available = true;
            resp.queries.clone_from(&req.queries);
            if call_num == 1 {
                resp.metadata.response_code = ResponseCode::ServFail;
            } else if let Some(q) = req.queries.first() {
                resp.metadata.response_code = ResponseCode::NoError;
                resp.add_answer(Record::from_rdata(
                    q.name().clone(),
                    120,
                    RData::A(A(Ipv4Addr::new(5, 6, 7, 8))),
                ));
            }
            let _ = sock.send_to(&resp.to_vec().unwrap(), peer).await;
        }
    });

    let mut cached_resp = Message::new(0x0001, MessageType::Response, OpCode::Query);
    cached_resp.metadata.recursion_available = true;
    cached_resp.metadata.response_code = ResponseCode::NoError;
    let qname = Name::from_ascii("stale-refresh.example.").unwrap();
    cached_resp.add_query(Query::query(qname.clone(), RecordType::A));
    cached_resp.add_answer(Record::from_rdata(
        qname,
        10,
        RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
    ));
    let now_secs = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();

    let cache = Arc::new(DnsCache::with_options(64, true, 10, 86_400, true));
    let imported = cache.import_persisted(
        vec![PersistedCacheEntry {
            qname: "stale-refresh.example.".to_string(),
            qtype: 1,
            qclass: 1,
            ecs_subnet: None,
            dnssec_do: false,
            upstream_scope: None,
            wire_bytes: cached_resp.to_vec().unwrap(),
            expires_at_unix_secs: now_secs - 1,
            ttl_secs: 1,
        }],
        now_secs,
    );
    assert_eq!(imported, 1);

    let filter = Arc::new(FilterEngine::new(&[]));
    let pool = Arc::new(UpstreamPool::new(&[format!("udp://{addr}")], 1000).unwrap());
    let pipeline = DnsPipeline::new(filter, cache, pool, None);
    let client: SocketAddr = "127.0.0.1:42000".parse().unwrap();

    // First stale hit triggers background refresh #1 which gets SERVFAIL.
    let r1 = Message::from_vec(
        &pipeline
            .handle_packet(
                &build_query(0x7001, "stale-refresh.example.", RecordType::A),
                client,
            )
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(r1.answers[0].data, RData::A(A(Ipv4Addr::new(1, 2, 3, 4))));
    wait_for_refresh_idle(&pipeline, &calls, 1).await;

    // Because RefreshGuard cleared inflight after SERVFAIL, second stale hit triggers refresh #2.
    let r2 = Message::from_vec(
        &pipeline
            .handle_packet(
                &build_query(0x7002, "stale-refresh.example.", RecordType::A),
                client,
            )
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(r2.answers[0].data, RData::A(A(Ipv4Addr::new(1, 2, 3, 4))));
    wait_for_refresh_idle(&pipeline, &calls, 2).await;

    // Third hit serves refreshed 5.6.7.8 record from cache.
    let r3 = Message::from_vec(
        &pipeline
            .handle_packet(
                &build_query(0x7003, "stale-refresh.example.", RecordType::A),
                client,
            )
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(r3.answers[0].data, RData::A(A(Ipv4Addr::new(5, 6, 7, 8))));
}

#[tokio::test]
async fn test_log_dropped_metric_and_monotonic_pause() {
    let filter = Arc::new(FilterEngine::new(&["||blocked.test^".to_string()]));
    let cache = Arc::new(DnsCache::new(64, false));
    let upstream = Arc::new(UpstreamPool::new(&["udp://127.0.0.1:1".to_string()], 50).unwrap());
    let (tx, _rx_unpolled) = mpsc::channel(1);
    let pipeline = DnsPipeline::new(filter, cache, upstream, Some(tx));
    let client: SocketAddr = "127.0.0.1:43000".parse().unwrap();

    for i in 0_u16..8 {
        let q = build_query(0x8000 + i, "blocked.test.", RecordType::A);
        let _ = pipeline.handle_packet(&q, client).await.unwrap();
    }
    let metrics = pipeline.runtime_metrics();
    assert!(metrics.log_dropped > 0);
    assert_eq!(metrics.singleflight_inflight, 0);

    pipeline.pause_blocking(Some(60));
    let (paused, rem) = pipeline.blocking_status();
    assert!(paused);
    assert!(rem.is_some_and(|s| s > 0 && s <= 60));
    pipeline.resume_blocking();
    assert_eq!(pipeline.blocking_status(), (false, None));
}
