use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use crabdns_core::{
    Config, DnsCache, DnsPipeline, FilterEngine, SplitDnsRule, UpstreamPool, UpstreamStrategy,
};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, CNAME};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use tokio::net::UdpSocket;

fn build_query(id: u16, domain: &str, qtype: RecordType) -> Vec<u8> {
    let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(Name::from_ascii(domain).unwrap(), qtype));
    msg.to_vec().unwrap()
}

async fn spawn_mock_udp(ip: Ipv4Addr, cname: Option<&'static str>) -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0_u8; 4096];
        while let Ok((len, peer)) = sock.recv_from(&mut buf).await {
            if let Ok(req) = Message::from_vec(&buf[..len]) {
                let mut resp = Message::new(req.id, MessageType::Response, OpCode::Query);
                resp.metadata.recursion_desired = true;
                resp.metadata.recursion_available = true;
                resp.metadata.response_code = ResponseCode::NoError;
                resp.queries.clone_from(&req.queries);
                if let Some(q) = req.queries.first() {
                    if let Some(target) = cname {
                        resp.add_answer(Record::from_rdata(
                            q.name().clone(),
                            60,
                            RData::CNAME(CNAME(Name::from_ascii(target).unwrap())),
                        ));
                    }
                    resp.add_answer(Record::from_rdata(q.name().clone(), 60, RData::A(A(ip))));
                }
                if let Ok(bytes) = resp.to_vec() {
                    let _ = sock.send_to(&bytes, peer).await;
                }
            }
        }
    });
    addr
}

#[tokio::test]
async fn test_split_dns_routing() {
    let default_upstream = spawn_mock_udp(Ipv4Addr::new(1, 1, 1, 1), None).await;
    let corp_upstream = spawn_mock_udp(Ipv4Addr::new(10, 20, 30, 40), None).await;

    let filter = Arc::new(FilterEngine::new(&[]));
    let cache = Arc::new(DnsCache::new(64, true));
    let pool = Arc::new(UpstreamPool::new(&[format!("udp://{default_upstream}")], 1000).unwrap());
    let pipeline = DnsPipeline::new(filter, cache, pool, None);
    pipeline
        .reload_split_dns(
            &[SplitDnsRule {
                domain: "corp.local".to_string(),
                upstreams: vec![format!("udp://{corp_upstream}")],
                fallback_to_default: true,
                ..Default::default()
            }],
            1000,
            UpstreamStrategy::Failover,
        )
        .unwrap();

    let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345);

    let corp_resp = pipeline
        .handle_packet(&build_query(1, "api.corp.local.", RecordType::A), client)
        .await
        .unwrap();
    let corp_msg = Message::from_vec(&corp_resp).unwrap();
    assert_eq!(
        corp_msg.answers[0].data,
        RData::A(A(Ipv4Addr::new(10, 20, 30, 40)))
    );

    let pub_resp = pipeline
        .handle_packet(&build_query(2, "example.com.", RecordType::A), client)
        .await
        .unwrap();
    let pub_msg = Message::from_vec(&pub_resp).unwrap();
    assert_eq!(
        pub_msg.answers[0].data,
        RData::A(A(Ipv4Addr::new(1, 1, 1, 1)))
    );
}

#[tokio::test]
async fn test_pause_blocking_and_cname_cloaking_allowlist() {
    let upstream = spawn_mock_udp(Ipv4Addr::new(93, 184, 216, 34), Some("tracker.evil.com.")).await;
    let filter = Arc::new(FilterEngine::new(&[
        "||ads.example.com^".to_string(),
        "||tracker.evil.com^".to_string(),
        "@@||safe-cname.example.com^".to_string(),
    ]));
    let cache = Arc::new(DnsCache::new(64, false));
    let pool = Arc::new(UpstreamPool::new(&[format!("udp://{upstream}")], 1000).unwrap());
    let pipeline = DnsPipeline::new(filter, cache, pool, None);
    let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345);

    // 1. Blocked normally
    let blocked = Message::from_vec(
        &pipeline
            .handle_packet(&build_query(1, "ads.example.com.", RecordType::A), client)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(blocked.answers[0].data, RData::A(A(Ipv4Addr::UNSPECIFIED)));

    // 2. Explicit allowlist bypasses CNAME cloaking
    let allowed = Message::from_vec(
        &pipeline
            .handle_packet(
                &build_query(2, "safe-cname.example.com.", RecordType::A),
                client,
            )
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(
        allowed
            .answers
            .iter()
            .any(|r| r.data == RData::A(A(Ipv4Addr::new(93, 184, 216, 34))))
    );

    // 3. Pause blocking allows ads.example.com and CNAME-cloaked domain
    pipeline.pause_blocking(Some(60));
    assert!(pipeline.blocking_status().0);
    let unblocked = Message::from_vec(
        &pipeline
            .handle_packet(&build_query(3, "ads.example.com.", RecordType::A), client)
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(
        unblocked
            .answers
            .iter()
            .any(|r| r.data == RData::A(A(Ipv4Addr::new(93, 184, 216, 34))))
    );

    // 4. Resume blocking restores blocking (flush cache first so cached entry isn't served)
    pipeline.resume_blocking();
    pipeline.cache().flush();
    assert!(!pipeline.blocking_status().0);
    let reblocked = Message::from_vec(
        &pipeline
            .handle_packet(&build_query(4, "ads.example.com.", RecordType::A), client)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        reblocked.answers[0].data,
        RData::A(A(Ipv4Addr::UNSPECIFIED))
    );
    let _ = Config::default();
}

#[tokio::test]
async fn test_any_suppression_ddr_and_hosts() {
    use crabdns_core::{DdrConfig, HostsTable};

    let upstream_addr = spawn_mock_udp(Ipv4Addr::new(93, 184, 216, 34), None).await;
    let filter = Arc::new(FilterEngine::new(&[]));
    let cache = Arc::new(DnsCache::new(64, true));
    let pool = Arc::new(UpstreamPool::new(&[format!("udp://{upstream_addr}")], 1000).unwrap());
    let pipeline = DnsPipeline::new(filter, cache, pool, None);
    let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5353);

    // 1. ANY query suppression
    pipeline.set_block_any_queries(true);
    let any_q = build_query(10, "example.com.", RecordType::ANY);
    let any_resp =
        Message::from_vec(&pipeline.handle_packet(&any_q, client).await.unwrap()).unwrap();
    assert_eq!(any_resp.response_code, ResponseCode::NoError);
    assert_eq!(any_resp.answers[0].record_type(), RecordType::HINFO);

    // 2. DDR (_dns.resolver.arpa SVCB)
    pipeline.reload_ddr(DdrConfig {
        enabled: true,
        hostname: Some("dns.home.arpa".to_string()),
        dot_port: Some(853),
        doq_port: None,
        doh_enabled: true,
        doh_port: Some(443),
    });
    let ddr_q = build_query(11, "_dns.resolver.arpa.", RecordType::SVCB);
    let ddr_resp =
        Message::from_vec(&pipeline.handle_packet(&ddr_q, client).await.unwrap()).unwrap();
    assert_eq!(ddr_resp.answers.len(), 2);
    assert_eq!(ddr_resp.answers[0].record_type(), RecordType::SVCB);

    // 3. Hosts table (A & PTR)
    pipeline.set_hosts_enabled(true);
    pipeline.reload_hosts_table(HostsTable::parse("192.168.10.50 printer.lan\n"));
    let host_q = build_query(12, "printer.lan.", RecordType::A);
    let host_resp =
        Message::from_vec(&pipeline.handle_packet(&host_q, client).await.unwrap()).unwrap();
    assert!(matches!(
        host_resp.answers[0].data,
        RData::A(A(ip)) if ip == Ipv4Addr::new(192, 168, 10, 50)
    ));
    let ptr_q = build_query(13, "50.10.168.192.in-addr.arpa.", RecordType::PTR);
    let ptr_resp =
        Message::from_vec(&pipeline.handle_packet(&ptr_q, client).await.unwrap()).unwrap();
    assert_eq!(ptr_resp.answers[0].record_type(), RecordType::PTR);
}

#[tokio::test]
async fn test_private_ptr_and_dns_rebinding_protection() {
    let rebind_upstream = spawn_mock_udp(Ipv4Addr::new(192, 168, 1, 99), None).await;
    let filter = Arc::new(FilterEngine::new(&[]));
    let cache = Arc::new(DnsCache::new(64, true));
    let pool = Arc::new(UpstreamPool::new(&[format!("udp://{rebind_upstream}")], 1000).unwrap());
    let pipeline = DnsPipeline::new(filter, cache, pool, None);
    let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5353);

    // Private PTR with no private_ptr_upstreams returns NXDOMAIN
    pipeline
        .reload_private_ptr(true, &[], 1000, UpstreamStrategy::Failover, &[])
        .unwrap();
    let ptr_q = build_query(20, "1.1.168.192.in-addr.arpa.", RecordType::PTR);
    let ptr_resp =
        Message::from_vec(&pipeline.handle_packet(&ptr_q, client).await.unwrap()).unwrap();
    assert_eq!(ptr_resp.response_code, ResponseCode::NXDomain);

    // DNS Rebinding protection blocks public domain resolving to 192.168.1.99
    pipeline.set_dns_rebinding_protection(true);
    let rebind_q = build_query(21, "evil.example.com.", RecordType::A);
    let rebind_resp =
        Message::from_vec(&pipeline.handle_packet(&rebind_q, client).await.unwrap()).unwrap();
    assert!(matches!(
        rebind_resp.answers[0].data,
        RData::A(A(ip)) if ip == Ipv4Addr::UNSPECIFIED
    ));
}

#[tokio::test]
async fn test_ecs_and_dnssec_do_forwarded_to_upstream() {
    use hickory_proto::rr::rdata::opt::EdnsOption;

    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = sock.local_addr().unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<(bool, Option<(IpAddr, u8)>)>(4);

    tokio::spawn(async move {
        let mut buf = [0_u8; 4096];
        while let Ok((len, peer)) = sock.recv_from(&mut buf).await {
            if let Ok(req) = Message::from_vec(&buf[..len]) {
                let do_bit = req.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok);
                let ecs = req.edns.as_ref().and_then(|e| {
                    e.options().as_ref().iter().find_map(|(_, opt)| match opt {
                        EdnsOption::Subnet(cs) => Some((cs.addr(), cs.source_prefix())),
                        _ => None,
                    })
                });
                let _ = tx.send((do_bit, ecs)).await;

                let mut resp = Message::new(req.id, MessageType::Response, OpCode::Query);
                resp.metadata.recursion_desired = true;
                resp.metadata.recursion_available = true;
                resp.metadata.response_code = ResponseCode::NoError;
                resp.queries.clone_from(&req.queries);
                if let Some(q) = req.queries.first() {
                    resp.add_answer(Record::from_rdata(
                        q.name().clone(),
                        60,
                        RData::A(A(Ipv4Addr::new(93, 184, 216, 34))),
                    ));
                }
                let _ = sock.send_to(&resp.to_vec().unwrap(), peer).await;
            }
        }
    });

    let filter = Arc::new(FilterEngine::new(&[]));
    let cache = Arc::new(DnsCache::new(64, true));
    let pool = Arc::new(UpstreamPool::new(&[format!("udp://{upstream_addr}")], 1000).unwrap());
    let pipeline = DnsPipeline::new(filter, cache, pool, None);
    pipeline.reload_ecs(true, None, 24, 56).unwrap();

    // 1. ECS enabled, DNSSEC disabled -> succeeds and forwards masked ECS subnet
    let public_client = SocketAddr::new("203.0.113.77".parse().unwrap(), 5353);
    let q1 = build_query(30, "ecs-only.example.", RecordType::A);
    let resp1 =
        Message::from_vec(&pipeline.handle_packet(&q1, public_client).await.unwrap()).unwrap();
    assert_eq!(resp1.response_code, ResponseCode::NoError);
    let (saw_do1, saw_ecs1) = rx.recv().await.unwrap();
    assert!(!saw_do1);
    assert_eq!(saw_ecs1, Some(("203.0.113.0".parse().unwrap(), 24)));

    // 2. DNSSEC enabled -> sets DO bit and returns SERVFAIL if upstream has no valid DNSSEC chain
    pipeline.set_dnssec_enabled(true);
    let q2 = build_query(31, "ecs-dnssec.example.", RecordType::A);
    let resp2 =
        Message::from_vec(&pipeline.handle_packet(&q2, public_client).await.unwrap()).unwrap();
    assert_eq!(resp2.response_code, ResponseCode::ServFail);
    let (saw_do2, saw_ecs2) = rx.recv().await.unwrap();
    assert!(saw_do2);
    assert_eq!(saw_ecs2, Some(("203.0.113.0".parse().unwrap(), 24)));
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn test_safesearch_dns64_and_svcb_sanitization_pipeline() {
    use crabdns_core::{ClientProfile, SafeSearchConfig, UpstreamStrategy};
    use hickory_proto::rr::rdata::HTTPS;
    use hickory_proto::rr::rdata::svcb::{
        Alpn, EchConfigList, IpHint, SVCB, SvcParamKey, SvcParamValue,
    };

    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = sock.local_addr().unwrap();

    tokio::spawn(async move {
        let mut buf = [0_u8; 4096];
        while let Ok((len, peer)) = sock.recv_from(&mut buf).await {
            if let Ok(req) = Message::from_vec(&buf[..len])
                && let Some(q) = req.queries.first()
            {
                let mut resp = Message::new(req.id, MessageType::Response, OpCode::Query);
                resp.metadata.recursion_desired = true;
                resp.metadata.recursion_available = true;
                resp.metadata.response_code = ResponseCode::NoError;
                resp.queries.clone_from(&req.queries);

                match q.query_type() {
                    RecordType::A => {
                        resp.add_answer(Record::from_rdata(
                            q.name().clone(),
                            120,
                            RData::A(A(Ipv4Addr::new(93, 184, 216, 34))),
                        ));
                    }
                    RecordType::HTTPS => {
                        let params = vec![
                            (
                                SvcParamKey::Alpn,
                                SvcParamValue::Alpn(Alpn(vec!["h2".to_string()])),
                            ),
                            (
                                SvcParamKey::Ipv4Hint,
                                SvcParamValue::Ipv4Hint(IpHint(vec![
                                    Ipv4Addr::new(93, 184, 216, 34).into(),
                                ])),
                            ),
                            (
                                SvcParamKey::EchConfigList,
                                SvcParamValue::EchConfigList(EchConfigList(vec![1, 2, 3, 4])),
                            ),
                        ];
                        resp.add_answer(Record::from_rdata(
                            q.name().clone(),
                            300,
                            RData::HTTPS(HTTPS(SVCB::new(1, Name::root(), params))),
                        ));
                    }
                    _ => {}
                }
                let _ = sock.send_to(&resp.to_vec().unwrap(), peer).await;
            }
        }
    });

    let filter = Arc::new(FilterEngine::new(&[]));
    let cache = Arc::new(DnsCache::new(64, true));
    let pool = Arc::new(UpstreamPool::new(&[format!("udp://{upstream_addr}")], 1000).unwrap());
    let pipeline = DnsPipeline::new(filter, cache, pool, None);

    // 1. SafeSearch global + per-client override
    pipeline.set_safesearch(SafeSearchConfig {
        enabled: true,
        ..Default::default()
    });
    pipeline
        .reload_clients(
            &[ClientProfile {
                id: "bypass-ss".to_string(),
                name: "Bypass".to_string(),
                identifiers: vec!["192.168.1.99".to_string()],
                group_id: None,
                blocking_enabled: None,
                use_global_rules: None,
                custom_rules: String::new(),
                upstreams: Vec::new(),
                block_mode: None,
                safesearch_enabled: Some(false),
                upstream_policy: Default::default(),
                tags: Vec::new(),
            }],
            &[],
            1000,
            UpstreamStrategy::Failover,
            &[],
        )
        .unwrap();

    let normal_client = SocketAddr::new("192.168.1.10".parse().unwrap(), 5353);
    let bypass_client = SocketAddr::new("192.168.1.99".parse().unwrap(), 5353);

    let q_ss = build_query(101, "www.google.com.", RecordType::A);
    let r_ss =
        Message::from_vec(&pipeline.handle_packet(&q_ss, normal_client).await.unwrap()).unwrap();
    assert_eq!(r_ss.answers.len(), 1);
    assert!(matches!(r_ss.answers[0].data, RData::CNAME(_)));

    let r_bypass =
        Message::from_vec(&pipeline.handle_packet(&q_ss, bypass_client).await.unwrap()).unwrap();
    assert_eq!(r_bypass.answers.len(), 1);
    assert!(matches!(r_bypass.answers[0].data, RData::A(_)));

    // 2. DNS64 synthesis on empty NoError AAAA
    pipeline
        .reload_dns64(true, &["64:ff9b::/96".to_string()])
        .unwrap();
    let q_aaaa = build_query(102, "v4only.example.", RecordType::AAAA);
    let r_aaaa = Message::from_vec(
        &pipeline
            .handle_packet(&q_aaaa, normal_client)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(r_aaaa.response_code, ResponseCode::NoError);
    assert_eq!(r_aaaa.answers.len(), 1);
    assert_eq!(r_aaaa.answers[0].data.to_string(), "64:ff9b::5db8:d822");

    // 3. HTTPS/SVCB sanitization strips ECH + IPv4Hint while preserving ALPN
    pipeline.set_svcb_sanitization(true, true);
    let q_https = build_query(103, "svcb.example.", RecordType::HTTPS);
    let r_https = Message::from_vec(
        &pipeline
            .handle_packet(&q_https, normal_client)
            .await
            .unwrap(),
    )
    .unwrap();
    let RData::HTTPS(https) = &r_https.answers[0].data else {
        panic!("expected HTTPS record");
    };
    assert_eq!(https.0.svc_params.len(), 1);
    assert_eq!(https.0.svc_params[0].0, SvcParamKey::Alpn);
}

#[tokio::test]
async fn test_acme_dns01_local_challenge_response() {
    let filter = Arc::new(FilterEngine::new(&[]));
    let cache = Arc::new(DnsCache::new(64, false));
    let pool = Arc::new(UpstreamPool::new(&["udp://127.0.0.1:9".to_string()], 500).unwrap());
    let pipeline = DnsPipeline::new(filter, cache, pool, None);

    pipeline.set_acme_dns_challenge("_acme-challenge.dns.example.com", "token-123".to_string());
    let q = build_query(201, "_acme-challenge.dns.example.com.", RecordType::TXT);
    let client = SocketAddr::new("127.0.0.1".parse().unwrap(), 12345);
    let resp = Message::from_vec(&pipeline.handle_packet(&q, client).await.unwrap()).unwrap();
    assert_eq!(resp.response_code, ResponseCode::NoError);
    assert_eq!(resp.answers.len(), 1);
    assert!(resp.answers[0].data.to_string().contains("token-123"));

    pipeline.clear_acme_dns_challenges();
}

#[tokio::test]
async fn test_per_group_upstream_policies_split_dns_and_client_group() {
    use crabdns_core::{BlockMode, UpstreamPolicy};
    use hickory_proto::rr::rdata::opt::EdnsOption;
    use std::sync::atomic::{AtomicBool, Ordering};

    async fn spawn_inspecting_upstream(
        reply_ip: Ipv4Addr,
        saw_ecs: Arc<AtomicBool>,
        saw_do: Arc<AtomicBool>,
    ) -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while let Ok((len, peer)) = sock.recv_from(&mut buf).await {
                let req = Message::from_vec(&buf[..len]).unwrap();
                if let Some(edns) = req.edns.as_ref() {
                    if edns.flags().dnssec_ok {
                        saw_do.store(true, Ordering::Relaxed);
                    }
                    if edns
                        .options()
                        .as_ref()
                        .iter()
                        .any(|opt| matches!(opt, (_, EdnsOption::Subnet(_))))
                    {
                        saw_ecs.store(true, Ordering::Relaxed);
                    }
                }
                let q = req.queries[0].clone();
                let mut resp = Message::new(req.id, MessageType::Response, OpCode::Query);
                resp.metadata.recursion_desired = req.recursion_desired;
                resp.metadata.recursion_available = true;
                resp.metadata.response_code = ResponseCode::NoError;
                resp.add_query(q.clone());
                resp.add_answer(Record::from_rdata(
                    q.name().clone(),
                    60,
                    RData::A(A(reply_ip)),
                ));
                let _ = sock.send_to(&resp.to_vec().unwrap(), peer).await;
            }
        });
        addr
    }

    let cn_saw_ecs = Arc::new(AtomicBool::new(false));
    let cn_saw_do = Arc::new(AtomicBool::new(false));
    let cn_addr = spawn_inspecting_upstream(
        Ipv4Addr::new(10, 0, 0, 55),
        Arc::clone(&cn_saw_ecs),
        Arc::clone(&cn_saw_do),
    )
    .await;

    let overseas_saw_ecs = Arc::new(AtomicBool::new(false));
    let overseas_saw_do = Arc::new(AtomicBool::new(false));
    let overseas_addr = spawn_inspecting_upstream(
        Ipv4Addr::new(127, 0, 0, 2),
        Arc::clone(&overseas_saw_ecs),
        Arc::clone(&overseas_saw_do),
    )
    .await;

    let default_saw_ecs = Arc::new(AtomicBool::new(false));
    let default_saw_do = Arc::new(AtomicBool::new(false));
    let default_addr = spawn_inspecting_upstream(
        Ipv4Addr::new(93, 184, 216, 34),
        Arc::clone(&default_saw_ecs),
        Arc::clone(&default_saw_do),
    )
    .await;

    let filter = Arc::new(FilterEngine::new(&[]));
    let cache = Arc::new(DnsCache::new(64, false));
    let pool = Arc::new(UpstreamPool::new(&[format!("udp://{default_addr}")], 1000).unwrap());
    let pipeline = DnsPipeline::new(filter, cache, pool, None);
    pipeline.set_block_mode(BlockMode::NxDomain);

    // Global: DNSSEC off, ECS off, rebinding protection off
    pipeline.set_dnssec_enabled(false);
    pipeline.set_dns_rebinding_protection(false);

    pipeline
        .reload_split_dns(
            &[
                SplitDnsRule {
                    domain: "cn".to_string(),
                    upstreams: vec![format!("udp://{cn_addr}")],
                    fallback_to_default: false,
                    policy: UpstreamPolicy {
                        dnssec_enabled: Some(false),
                        ecs_enabled: Some(false),
                        dns_rebinding_protection: Some(false),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                SplitDnsRule {
                    domain: "overseas.test".to_string(),
                    upstreams: vec![format!("udp://{overseas_addr}")],
                    fallback_to_default: false,
                    policy: UpstreamPolicy {
                        dnssec_enabled: Some(true),
                        ecs_enabled: Some(true),
                        ecs_custom_ip: Some("1.2.3.0/24".to_string()),
                        dns_rebinding_protection: Some(true),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                SplitDnsRule {
                    domain: "rebind.test".to_string(),
                    upstreams: vec![format!("udp://{overseas_addr}")],
                    fallback_to_default: false,
                    policy: UpstreamPolicy {
                        dnssec_enabled: Some(false),
                        dns_rebinding_protection: Some(true),
                        ..Default::default()
                    },
                    ..Default::default()
                },
            ],
            1000,
            UpstreamStrategy::Failover,
        )
        .unwrap();

    let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 12345);

    // 1. Domestic: no ECS, no DO bit, private IP allowed because rebinding protection is off
    let cn_resp = Message::from_vec(
        &pipeline
            .handle_packet(&build_query(1, "example.cn.", RecordType::A), client)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(cn_resp.response_code, ResponseCode::NoError);
    assert_eq!(cn_resp.answers[0].data.to_string(), "10.0.0.55");
    assert!(!cn_saw_ecs.load(Ordering::Relaxed));
    assert!(!cn_saw_do.load(Ordering::Relaxed));

    // 2. Overseas: ECS sent, DO bit sent, and DNSSEC validation rejects unsigned response with SERVFAIL
    let overseas_resp = Message::from_vec(
        &pipeline
            .handle_packet(&build_query(2, "www.overseas.test.", RecordType::A), client)
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(overseas_saw_ecs.load(Ordering::Relaxed));
    assert!(overseas_saw_do.load(Ordering::Relaxed));
    assert_eq!(overseas_resp.response_code, ResponseCode::ServFail);

    // 3. Rebind group: DNSSEC off, rebinding protection on -> blocks 127.0.0.2 with NXDOMAIN
    let rebind_resp = Message::from_vec(
        &pipeline
            .handle_packet(&build_query(3, "a.rebind.test.", RecordType::A), client)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(rebind_resp.response_code, ResponseCode::NXDomain);

    // 3. Invalid policy validation should fail cleanly
    assert!(
        UpstreamPolicy {
            upstream_timeout_ms: Some(0),
            ..Default::default()
        }
        .validate()
        .is_err()
    );
    assert!(
        UpstreamPolicy {
            ecs_ipv4_prefix: Some(33),
            ..Default::default()
        }
        .validate()
        .is_err()
    );
}

#[tokio::test]
async fn test_block_local_domains_and_log_suppression() {
    use crabdns_core::{HostsTable, QueryOutcome, SplitDnsRule, UdpFastOutcome};

    // Mock upstream that always returns 1.2.3.4 (used for split_dns override check)
    let split_upstream_addr = spawn_mock_udp(Ipv4Addr::new(10, 20, 30, 40), None).await;
    // Unreachable/unused default upstream to verify .local never forwards when blocked locally
    let unused_upstream_addr = spawn_mock_udp(Ipv4Addr::new(93, 184, 216, 34), None).await;

    let filter = Arc::new(FilterEngine::new(&[]));
    let cache = Arc::new(DnsCache::new(64, true));
    let pool =
        Arc::new(UpstreamPool::new(&[format!("udp://{unused_upstream_addr}")], 1000).unwrap());
    let (log_tx, mut log_rx) = tokio::sync::mpsc::channel(32);
    let pipeline = DnsPipeline::new(filter, cache, pool, Some(log_tx));
    let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5353);

    // Enable local domain blocking without log suppression
    pipeline.set_block_local_domains(true);
    pipeline.set_suppress_local_domain_logs(false);

    // Fast path must defer .local queries to slow path when block_local_domains is enabled
    let mdns_ptr_q = build_query(101, "_lyra-mdns._udp.local.", RecordType::PTR);
    let mut fast_out = Vec::new();
    assert_eq!(
        pipeline.try_handle_udp_fast(&mdns_ptr_q, client, &mut fast_out),
        UdpFastOutcome::NeedsAsync
    );

    let resp1 =
        Message::from_vec(&pipeline.handle_packet(&mdns_ptr_q, client).await.unwrap()).unwrap();
    assert_eq!(resp1.response_code, ResponseCode::NXDomain);
    let ev1 = log_rx.try_recv().expect("expected blocked log event");
    assert_eq!(ev1.outcome, QueryOutcome::Blocked);
    assert_eq!(ev1.matched_rule.as_deref(), Some("lan:local-mdns"));
    assert_eq!(ev1.domain, "_lyra-mdns._udp.local");

    // Enable log suppression -> NXDOMAIN returned, no log emitted
    pipeline.set_suppress_local_domain_logs(true);
    let apple_q = build_query(102, "Apple-Vision-Pro.local.", RecordType::A);
    let resp2 =
        Message::from_vec(&pipeline.handle_packet(&apple_q, client).await.unwrap()).unwrap();
    assert_eq!(resp2.response_code, ResponseCode::NXDomain);
    assert!(
        log_rx.try_recv().is_err(),
        "expected no log event when suppress_local_domain_logs is enabled"
    );

    // Hosts entries for .local still resolve locally
    pipeline.set_hosts_enabled(true);
    pipeline.reload_hosts_table(HostsTable::parse("192.168.10.50 nas.local\n"));
    let nas_q = build_query(103, "nas.local.", RecordType::A);
    let nas_resp =
        Message::from_vec(&pipeline.handle_packet(&nas_q, client).await.unwrap()).unwrap();
    assert_eq!(nas_resp.response_code, ResponseCode::NoError);
    assert!(matches!(
        nas_resp.answers[0].data,
        RData::A(A(ip)) if ip == Ipv4Addr::new(192, 168, 10, 50)
    ));
    let ev_hosts = log_rx.try_recv().expect("hosts lookup should still log");
    assert_eq!(ev_hosts.outcome, QueryOutcome::Rewritten);

    // Split DNS rules for .local still route to the configured local upstream
    pipeline
        .reload_split_dns(
            &[SplitDnsRule {
                domain: "*.corp.local".to_string(),
                upstreams: vec![format!("udp://{split_upstream_addr}")],
                fallback_to_default: false,
                ..Default::default()
            }],
            1000,
            crabdns_core::UpstreamStrategy::Failover,
        )
        .unwrap();
    let corp_q = build_query(104, "app.corp.local.", RecordType::A);
    let corp_resp =
        Message::from_vec(&pipeline.handle_packet(&corp_q, client).await.unwrap()).unwrap();
    assert_eq!(corp_resp.response_code, ResponseCode::NoError);
    assert!(matches!(
        corp_resp.answers[0].data,
        RData::A(A(ip)) if ip == Ipv4Addr::new(10, 20, 30, 40)
    ));
}
