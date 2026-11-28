#![allow(clippy::too_many_lines)]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use crabdns_core::{
    BlockMode, ClientGroup, ClientProfile, DnsCache, DnsPipeline, FilterEngine, QueryContext,
    QueryOutcome, QueryProtocol, ResponseIpRule, SplitDnsMatchMode, SplitDnsRule,
    SplitUpstreamRouter, UpstreamGroup, UpstreamGroupRegistry, UpstreamPolicy, UpstreamPool,
    UpstreamStrategy,
};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

fn build_query(id: u16, qname: &str, qtype: RecordType) -> Vec<u8> {
    let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(Name::from_ascii(qname).unwrap(), qtype));
    msg.to_vec().unwrap()
}

#[derive(Clone)]
struct MockBehavior {
    rcode: ResponseCode,
    a_ip: Option<Ipv4Addr>,
    aaaa_ip: Option<Ipv6Addr>,
    cname: Option<&'static str>,
    txt: Option<&'static str>,
    delay_ms: u64,
}

impl Default for MockBehavior {
    fn default() -> Self {
        Self {
            rcode: ResponseCode::NoError,
            a_ip: Some(Ipv4Addr::new(93, 184, 216, 34)),
            aaaa_ip: None,
            cname: None,
            txt: None,
            delay_ms: 0,
        }
    }
}

async fn spawn_mock_udp(behavior: MockBehavior) -> (SocketAddr, Arc<AtomicUsize>) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_clone = Arc::clone(&hits);

    tokio::spawn(async move {
        let mut buf = [0_u8; 2048];
        while let Ok((len, peer)) = sock.recv_from(&mut buf).await {
            hits_clone.fetch_add(1, Ordering::Relaxed);
            let req = Message::from_vec(&buf[..len]).unwrap();
            let b = behavior.clone();
            if b.delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(b.delay_ms)).await;
            }
            let mut resp = Message::new(req.id, MessageType::Response, OpCode::Query);
            resp.metadata.recursion_desired = req.recursion_desired;
            resp.metadata.recursion_available = true;
            resp.metadata.response_code = b.rcode;
            if let Some(q) = req.queries.first() {
                resp.add_query(q.clone());
                if b.rcode == ResponseCode::NoError {
                    let name = q.name().clone();
                    if let Some(target) = b.cname {
                        resp.add_answer(Record::from_rdata(
                            name.clone(),
                            60,
                            RData::CNAME(CNAME(Name::from_ascii(target).unwrap())),
                        ));
                    }
                    match q.query_type() {
                        RecordType::A => {
                            if let Some(ip) = b.a_ip {
                                resp.add_answer(Record::from_rdata(name, 60, RData::A(A(ip))));
                            }
                        }
                        RecordType::AAAA => {
                            if let Some(ip) = b.aaaa_ip {
                                resp.add_answer(Record::from_rdata(
                                    name,
                                    60,
                                    RData::AAAA(AAAA(ip)),
                                ));
                            }
                        }
                        RecordType::TXT => {
                            if let Some(txt) = b.txt {
                                resp.add_answer(Record::from_rdata(
                                    name,
                                    60,
                                    RData::TXT(TXT::new(vec![txt.to_string()])),
                                ));
                            }
                        }
                        _ => {}
                    }
                }
            }
            let wire = resp.to_vec().unwrap();
            let _ = sock.send_to(&wire, peer).await;
        }
    });
    (addr, hits)
}

#[tokio::test]
async fn test_runtime_fallback_first_query_servfail_nxdomain_and_group_chain() {
    let (servfail_addr, servfail_hits) = spawn_mock_udp(MockBehavior {
        rcode: ResponseCode::ServFail,
        a_ip: None,
        ..Default::default()
    })
    .await;
    let (nx_addr, nx_hits) = spawn_mock_udp(MockBehavior {
        rcode: ResponseCode::NXDomain,
        a_ip: None,
        ..Default::default()
    })
    .await;
    let (ok_addr, ok_hits) = spawn_mock_udp(MockBehavior {
        a_ip: Some(Ipv4Addr::new(8, 8, 4, 4)),
        ..Default::default()
    })
    .await;

    let filter = Arc::new(FilterEngine::new(&[]));
    let cache = Arc::new(DnsCache::with_options(64, false, 10, 600, false));
    let default_pool = Arc::new(UpstreamPool::new(&[format!("udp://{ok_addr}")], 500).unwrap());
    let pipeline = DnsPipeline::new(filter, cache, default_pool, None);

    let groups = vec![
        UpstreamGroup {
            name: "primary_grp".to_string(),
            upstreams: vec![format!("udp://{servfail_addr}")],
            fallback_groups: vec!["secondary_grp".to_string()],
            ..Default::default()
        },
        UpstreamGroup {
            name: "secondary_grp".to_string(),
            upstreams: vec![format!("udp://{nx_addr}")],
            ..Default::default()
        },
    ];
    let rules = vec![
        SplitDnsRule {
            domain: "failover.test".to_string(),
            upstreams: vec!["@primary_grp".to_string()],
            fallback_to_default: true,
            fallback_on_nxdomain: true,
            ..Default::default()
        },
        SplitDnsRule {
            domain: "strict.test".to_string(),
            upstreams: vec![format!("udp://{servfail_addr}")],
            fallback_to_default: false,
            ..Default::default()
        },
    ];
    pipeline
        .reload_split_dns_full(
            &groups,
            &rules,
            SplitDnsMatchMode::SpecificityFirst,
            500,
            UpstreamStrategy::Failover,
            &[],
            |_| None,
        )
        .unwrap();

    let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5000);

    // Very first query falls back from primary_grp (SERVFAIL) -> secondary_grp (NXDOMAIN) -> default (8.8.4.4)
    let r1 = Message::from_vec(
        &pipeline
            .handle_packet(&build_query(1, "app.failover.test.", RecordType::A), client)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(r1.response_code, ResponseCode::NoError);
    assert_eq!(r1.answers[0].data, RData::A(A(Ipv4Addr::new(8, 8, 4, 4))));
    assert_eq!(servfail_hits.load(Ordering::Relaxed), 1);
    assert_eq!(nx_hits.load(Ordering::Relaxed), 1);
    assert_eq!(ok_hits.load(Ordering::Relaxed), 1);

    // Strict rule does NOT fall back
    let r2 = Message::from_vec(
        &pipeline
            .handle_packet(&build_query(2, "app.strict.test.", RecordType::A), client)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(r2.response_code, ResponseCode::ServFail);
    assert_eq!(ok_hits.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn test_is_local_route_inference_and_rebinding_cache_consistency() {
    // Verify auto-inference on SplitUpstreamRouter directly
    let auto_rules = vec![
        SplitDnsRule {
            domain: "lan.test".to_string(),
            upstreams: vec!["udp://10.0.0.1:53".to_string()],
            ..Default::default()
        },
        SplitDnsRule {
            domain: "cn.test".to_string(),
            upstreams: vec!["https://dns.alidns.com/dns-query".to_string()],
            ..Default::default()
        },
        SplitDnsRule {
            domain: "forced-local.test".to_string(),
            upstreams: vec!["https://dns.alidns.com/dns-query".to_string()],
            is_local: Some(true),
            ..Default::default()
        },
    ];
    let router = SplitUpstreamRouter::new(&auto_rules, 500, UpstreamStrategy::Failover).unwrap();
    assert!(
        router
            .resolve_plan(&crabdns_core::split_dns::SplitQueryContext::domain_only(
                "nas.lan.test"
            ))
            .unwrap()
            .primary
            .is_local_route
    );
    assert!(
        !router
            .resolve_plan(&crabdns_core::split_dns::SplitQueryContext::domain_only(
                "www.cn.test"
            ))
            .unwrap()
            .primary
            .is_local_route
    );
    assert!(
        router
            .resolve_plan(&crabdns_core::split_dns::SplitQueryContext::domain_only(
                "x.forced-local.test"
            ))
            .unwrap()
            .primary
            .is_local_route
    );

    // Full pipeline test: global rebinding protection ON; public split rule (is_local: Some(false))
    // must block private IP 192.168.1.50 AND not poison cache.
    let (rebind_addr, _) = spawn_mock_udp(MockBehavior {
        a_ip: Some(Ipv4Addr::new(192, 168, 1, 50)),
        ..Default::default()
    })
    .await;
    let filter = Arc::new(FilterEngine::new(&[]));
    let cache = Arc::new(DnsCache::with_options(64, false, 10, 600, false));
    let pool = Arc::new(UpstreamPool::new(&[format!("udp://{rebind_addr}")], 500).unwrap());
    let pipeline = DnsPipeline::new(filter, cache, pool, None);
    pipeline.set_block_mode(BlockMode::NxDomain);
    pipeline.set_dns_rebinding_protection(true);

    pipeline
        .reload_split_dns(
            &[
                SplitDnsRule {
                    domain: "public-split.test".to_string(),
                    upstreams: vec![format!("udp://{rebind_addr}")],
                    is_local: Some(false),
                    ..Default::default()
                },
                SplitDnsRule {
                    domain: "intranet-split.test".to_string(),
                    upstreams: vec![format!("udp://{rebind_addr}")],
                    is_local: Some(true),
                    ..Default::default()
                },
            ],
            500,
            UpstreamStrategy::Failover,
        )
        .unwrap();

    let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5001);
    let r_pub = Message::from_vec(
        &pipeline
            .handle_packet(
                &build_query(10, "evil.public-split.test.", RecordType::A),
                client,
            )
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(r_pub.response_code, ResponseCode::NXDomain);
    assert_eq!(pipeline.cache().entry_count(), 0);

    let r_lan = Message::from_vec(
        &pipeline
            .handle_packet(
                &build_query(11, "printer.intranet-split.test.", RecordType::A),
                client,
            )
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(r_lan.response_code, ResponseCode::NoError);
    assert_eq!(
        r_lan.answers[0].data,
        RData::A(A(Ipv4Addr::new(192, 168, 1, 50)))
    );
}

#[tokio::test]
async fn test_match_mode_config_order_and_stable_cache_scope() {
    let rules = vec![
        SplitDnsRule {
            domain: "example.com".to_string(),
            upstreams: vec!["udp://10.0.0.1:53".to_string()],
            ..Default::default()
        },
        SplitDnsRule {
            domain: "sub.example.com".to_string(),
            upstreams: vec!["udp://10.0.0.2:53".to_string()],
            ..Default::default()
        },
    ];
    let groups = UpstreamGroupRegistry::empty();

    let spec_first = SplitUpstreamRouter::new_full(
        &rules,
        &groups,
        SplitDnsMatchMode::SpecificityFirst,
        500,
        UpstreamStrategy::Failover,
        &[],
        |_| None,
    )
    .unwrap();
    let (_, _, scope_spec) = spec_first.resolve_with_policy("a.sub.example.com").unwrap();
    assert_eq!(
        spec_first
            .resolve("a.sub.example.com")
            .unwrap()
            .health_snapshot()[0]
            .endpoint,
        "udp://10.0.0.2:53"
    );

    let cfg_order = SplitUpstreamRouter::new_full(
        &rules,
        &groups,
        SplitDnsMatchMode::ConfigOrder,
        500,
        UpstreamStrategy::Failover,
        &[],
        |_| None,
    )
    .unwrap();
    assert_eq!(
        cfg_order
            .resolve("a.sub.example.com")
            .unwrap()
            .health_snapshot()[0]
            .endpoint,
        "udp://10.0.0.1:53"
    );

    // Reordering rules does not alter the scope fingerprint for the same rule!
    let reordered = vec![rules[1].clone(), rules[0].clone()];
    let spec_reordered = SplitUpstreamRouter::new_full(
        &reordered,
        &groups,
        SplitDnsMatchMode::SpecificityFirst,
        500,
        UpstreamStrategy::Failover,
        &[],
        |_| None,
    )
    .unwrap();
    let (_, _, scope_reordered) = spec_reordered
        .resolve_with_policy("a.sub.example.com")
        .unwrap();
    assert_eq!(scope_spec, scope_reordered);
}

#[tokio::test]
async fn test_client_split_precedence_and_policy_merge() {
    let (client_addr, _) = spawn_mock_udp(MockBehavior {
        a_ip: Some(Ipv4Addr::new(1, 1, 1, 1)),
        ..Default::default()
    })
    .await;
    let (split_addr, _) = spawn_mock_udp(MockBehavior {
        a_ip: Some(Ipv4Addr::new(10, 0, 0, 88)),
        ..Default::default()
    })
    .await;
    let (global_addr, _) = spawn_mock_udp(MockBehavior {
        a_ip: Some(Ipv4Addr::new(9, 9, 9, 9)),
        ..Default::default()
    })
    .await;

    let filter = Arc::new(FilterEngine::new(&[]));
    let cache = Arc::new(DnsCache::with_options(64, false, 10, 600, false));
    let pool = Arc::new(UpstreamPool::new(&[format!("udp://{global_addr}")], 500).unwrap());
    let pipeline = DnsPipeline::new(filter, cache, pool, None);

    pipeline
        .reload_clients(
            &[ClientProfile {
                id: "c1".to_string(),
                name: "Laptop".to_string(),
                identifiers: vec!["192.168.5.5".to_string()],
                group_id: None,
                blocking_enabled: None,
                use_global_rules: None,
                custom_rules: String::new(),
                upstreams: vec![format!("udp://{client_addr}")],
                block_mode: None,
                safesearch_enabled: None,
                blocked_services: None,
                upstream_policy: UpstreamPolicy {
                    disable_ipv6: Some(true),
                    ..Default::default()
                },
                tags: vec!["corp".to_string()],
            }],
            &[],
            500,
            UpstreamStrategy::Failover,
            &[],
        )
        .unwrap();

    pipeline
        .reload_split_dns(
            &[SplitDnsRule {
                domain: "corp.internal".to_string(),
                upstreams: vec![format!("udp://{split_addr}")],
                policy: UpstreamPolicy {
                    disable_ipv6: Some(false),
                    ..Default::default()
                },
                ..Default::default()
            }],
            500,
            UpstreamStrategy::Failover,
        )
        .unwrap();

    let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 5, 5)), 5353);

    // Default (split_dns_before_client_upstreams = false): client upstream wins over split_dns
    let r1 = Message::from_vec(
        &pipeline
            .handle_packet(&build_query(1, "db.corp.internal.", RecordType::A), client)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(r1.answers[0].data, RData::A(A(Ipv4Addr::new(1, 1, 1, 1))));

    // Client policy disable_ipv6 = true returns NOERROR NODATA for AAAA
    let r1_v6 = Message::from_vec(
        &pipeline
            .handle_packet(&build_query(2, "example.org.", RecordType::AAAA), client)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(r1_v6.response_code, ResponseCode::NoError);
    assert_eq!(r1_v6.answers, [] as [Record; 0]);

    // Enable split_dns_before_client_upstreams -> split_dns wins for corp.internal AND overrides disable_ipv6=false
    pipeline.set_split_dns_before_client_upstreams(true);
    let r2 = Message::from_vec(
        &pipeline
            .handle_packet(&build_query(3, "db.corp.internal.", RecordType::A), client)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(r2.answers[0].data, RData::A(A(Ipv4Addr::new(10, 0, 0, 88))));
}

#[tokio::test]
async fn test_response_ip_routing_accept_reject_invert_cname_txt_and_hedged() {
    let (cn_ok_addr, _) = spawn_mock_udp(MockBehavior {
        a_ip: Some(Ipv4Addr::new(1, 0, 1, 5)),
        txt: Some("v=spf1 ~all"),
        ..Default::default()
    })
    .await;
    let (cn_foreign_addr, _) = spawn_mock_udp(MockBehavior {
        a_ip: Some(Ipv4Addr::new(8, 8, 8, 8)),
        ..Default::default()
    })
    .await;
    let (cn_cname_addr, _) = spawn_mock_udp(MockBehavior {
        a_ip: Some(Ipv4Addr::new(8, 8, 8, 8)),
        cname: Some("edge.kunlun.com."),
        ..Default::default()
    })
    .await;
    let (slow_primary_addr, _) = spawn_mock_udp(MockBehavior {
        a_ip: Some(Ipv4Addr::new(1, 0, 1, 9)),
        delay_ms: 400,
        ..Default::default()
    })
    .await;
    let (overseas_addr, _) = spawn_mock_udp(MockBehavior {
        a_ip: Some(Ipv4Addr::new(203, 0, 113, 77)),
        ..Default::default()
    })
    .await;

    let filter = Arc::new(FilterEngine::new(&[]));
    let cache = Arc::new(DnsCache::with_options(64, false, 10, 600, false));
    let default_pool =
        Arc::new(UpstreamPool::new(&[format!("udp://{overseas_addr}")], 1000).unwrap());
    let pipeline = DnsPipeline::new(filter, cache, default_pool, None);

    let rules = vec![
        SplitDnsRule {
            domain: "accept.test".to_string(),
            upstreams: vec![format!("udp://{cn_ok_addr}")],
            response_ip: Some(ResponseIpRule {
                expected_cidrs: vec!["1.0.1.0/24".to_string()],
                fallback_upstreams: vec![format!("udp://{overseas_addr}")],
                fallback_on_empty: true,
                ..Default::default()
            }),
            ..Default::default()
        },
        SplitDnsRule {
            domain: "reject.test".to_string(),
            upstreams: vec![format!("udp://{cn_foreign_addr}")],
            response_ip: Some(ResponseIpRule {
                expected_cidrs: vec!["1.0.1.0/24".to_string()],
                fallback_upstreams: vec![format!("udp://{overseas_addr}")],
                ..Default::default()
            }),
            ..Default::default()
        },
        SplitDnsRule {
            domain: "invert.test".to_string(),
            upstreams: vec![format!("udp://{cn_ok_addr}")],
            response_ip: Some(ResponseIpRule {
                expected_cidrs: vec!["1.0.1.0/24".to_string()],
                invert: true,
                fallback_upstreams: vec![format!("udp://{overseas_addr}")],
                ..Default::default()
            }),
            ..Default::default()
        },
        SplitDnsRule {
            domain: "cname-accept.test".to_string(),
            upstreams: vec![format!("udp://{cn_cname_addr}")],
            response_ip: Some(ResponseIpRule {
                expected_cidrs: vec!["1.0.1.0/24".to_string()],
                match_cname_domains: vec!["kunlun.com".to_string()],
                fallback_upstreams: vec![format!("udp://{overseas_addr}")],
                ..Default::default()
            }),
            ..Default::default()
        },
        SplitDnsRule {
            domain: "hedged.test".to_string(),
            upstreams: vec![format!("udp://{slow_primary_addr}")],
            response_ip: Some(ResponseIpRule {
                expected_cidrs: vec!["1.0.1.0/24".to_string()],
                fallback_upstreams: vec![format!("udp://{overseas_addr}")],
                fallback_delay_ms: Some(30),
                ..Default::default()
            }),
            ..Default::default()
        },
    ];
    pipeline
        .reload_split_dns(&rules, 1000, UpstreamStrategy::Failover)
        .unwrap();

    let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5002);

    // 1. Expected IP accepted directly
    let r_accept = Message::from_vec(
        &pipeline
            .handle_packet(&build_query(1, "a.accept.test.", RecordType::A), client)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        r_accept.answers[0].data,
        RData::A(A(Ipv4Addr::new(1, 0, 1, 5)))
    );

    // 2. Non-IP TXT query on accept.test must NOT falsely trigger fallback_on_empty
    let r_txt = Message::from_vec(
        &pipeline
            .handle_packet(&build_query(2, "a.accept.test.", RecordType::TXT), client)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(r_txt.response_code, ResponseCode::NoError);
    assert_ne!(r_txt.answers, [] as [Record; 0]);

    // 3. Unexpected IP (8.8.8.8) falls back to overseas_addr (203.0.113.77)
    let r_reject = Message::from_vec(
        &pipeline
            .handle_packet(&build_query(3, "a.reject.test.", RecordType::A), client)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        r_reject.answers[0].data,
        RData::A(A(Ipv4Addr::new(203, 0, 113, 77)))
    );

    // 4. Invert=true rejects 1.0.1.5 and falls back to 203.0.113.77
    let r_invert = Message::from_vec(
        &pipeline
            .handle_packet(&build_query(4, "a.invert.test.", RecordType::A), client)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        r_invert.answers[0].data,
        RData::A(A(Ipv4Addr::new(203, 0, 113, 77)))
    );

    // 5. CNAME matching kunlun.com accepts primary even when IP is outside expected_cidrs
    let r_cname = Message::from_vec(
        &pipeline
            .handle_packet(
                &build_query(5, "a.cname-accept.test.", RecordType::A),
                client,
            )
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(
        r_cname
            .answers
            .iter()
            .any(|r| r.data == RData::A(A(Ipv4Addr::new(8, 8, 8, 8))))
    );

    // 6. Hedged fallback after 30ms beats 400ms slow primary
    let r_hedged = Message::from_vec(
        &pipeline
            .handle_packet(&build_query(6, "a.hedged.test.", RecordType::A), client)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        r_hedged.answers[0].data,
        RData::A(A(Ipv4Addr::new(203, 0, 113, 77)))
    );
}

#[tokio::test]
async fn test_multidim_matching_exclusions_keyword_regexp_and_disable_ipv6() {
    let (special_addr, _) = spawn_mock_udp(MockBehavior {
        a_ip: Some(Ipv4Addr::new(10, 99, 0, 1)),
        aaaa_ip: Some("2001:db8::1".parse().unwrap()),
        ..Default::default()
    })
    .await;
    let (default_addr, _) = spawn_mock_udp(MockBehavior {
        a_ip: Some(Ipv4Addr::new(4, 4, 4, 4)),
        aaaa_ip: Some("2001:4860:4860::8888".parse().unwrap()),
        ..Default::default()
    })
    .await;

    let filter = Arc::new(FilterEngine::new(&[]));
    let cache = Arc::new(DnsCache::with_options(64, false, 10, 600, false));
    let pool = Arc::new(UpstreamPool::new(&[format!("udp://{default_addr}")], 500).unwrap());
    let pipeline = DnsPipeline::new(filter, cache, pool, None);

    pipeline
        .reload_clients(
            &[ClientProfile {
                id: "vip-tv".to_string(),
                name: "Apple TV".to_string(),
                identifiers: vec!["192.168.20.10".to_string()],
                group_id: Some("media".to_string()),
                blocking_enabled: None,
                use_global_rules: None,
                custom_rules: String::new(),
                upstreams: Vec::new(),
                block_mode: None,
                safesearch_enabled: None,
                blocked_services: None,
                upstream_policy: UpstreamPolicy::default(),
                tags: vec!["streaming".to_string()],
            }],
            &[ClientGroup {
                id: "media".to_string(),
                name: "Media".to_string(),
                description: String::new(),
                blocking_enabled: true,
                use_global_rules: true,
                custom_rules: String::new(),
                upstreams: Vec::new(),
                block_mode: None,
                cname_cloaking_blocking: None,
                safesearch_enabled: None,
                blocked_services: None,
                upstream_policy: UpstreamPolicy::default(),
            }],
            500,
            UpstreamStrategy::Failover,
            &[],
        )
        .unwrap();

    let rules = vec![SplitDnsRule {
        domain: "keyword:stream, regexp:^cdn[0-9]+\\.video\\.net$, DOMAIN-SUFFIX,play.test"
            .to_string(),
        exclude_domains: vec!["ads.play.test".to_string(), "keyword:tracker".to_string()],
        qtypes: vec!["A".to_string(), "AAAA".to_string()],
        client_cidrs: vec!["192.168.20.0/24".to_string()],
        client_groups: vec!["media".to_string()],
        client_tags: vec!["streaming".to_string()],
        protocols: vec![QueryProtocol::Doh],
        upstreams: vec![format!("udp://{special_addr}")],
        policy: UpstreamPolicy {
            disable_ipv6: Some(true),
            ..Default::default()
        },
        ..Default::default()
    }];
    pipeline
        .reload_split_dns(&rules, 500, UpstreamStrategy::Failover)
        .unwrap();

    let vip_doh = QueryContext {
        client_addr: "192.168.20.10:443".parse().unwrap(),
        protocol: QueryProtocol::Doh,
        client_id: None,
    };
    let vip_udp = QueryContext {
        client_addr: "192.168.20.10:53".parse().unwrap(),
        protocol: QueryProtocol::Udp,
        client_id: None,
    };

    // Matching keyword + DoH + CIDR + group + tag -> special_addr
    let r_hit = Message::from_vec(
        &pipeline
            .handle_packet_with_context(
                &build_query(1, "edge.stream.org.", RecordType::A),
                vip_doh.clone(),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        r_hit.answers[0].data,
        RData::A(A(Ipv4Addr::new(10, 99, 0, 1)))
    );

    // Regex match + disable_ipv6 -> NOERROR NODATA on AAAA
    let r_v6 = Message::from_vec(
        &pipeline
            .handle_packet_with_context(
                &build_query(2, "cdn42.video.net.", RecordType::AAAA),
                vip_doh.clone(),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(r_v6.response_code, ResponseCode::NoError);
    assert_eq!(r_v6.answers, [] as [Record; 0]);

    // Excluded domain goes to default_addr
    let r_excl = Message::from_vec(
        &pipeline
            .handle_packet_with_context(&build_query(3, "ads.play.test.", RecordType::A), vip_doh)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        r_excl.answers[0].data,
        RData::A(A(Ipv4Addr::new(4, 4, 4, 4)))
    );

    // Wrong protocol (UDP instead of DoH) skips split rule and uses default_addr
    let r_proto = Message::from_vec(
        &pipeline
            .handle_packet_with_context(&build_query(4, "edge.stream.org.", RecordType::A), vip_udp)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        r_proto.answers[0].data,
        RData::A(A(Ipv4Addr::new(4, 4, 4, 4)))
    );
}

#[tokio::test]
async fn test_shared_upstream_group_health_and_http_proxy_pool() {
    let dns_tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dns_addr = dns_tcp.local_addr().unwrap();
    let saw_proxied = Arc::new(AtomicBool::new(false));
    let saw_clone = Arc::clone(&saw_proxied);
    tokio::spawn(async move {
        while let Ok((mut s, _)) = dns_tcp.accept().await {
            let mut len_buf = [0_u8; 2];
            if s.read_exact(&mut len_buf).await.is_err() {
                continue;
            }
            let qlen = usize::from(u16::from_be_bytes(len_buf));
            let mut qbuf = vec![0_u8; qlen];
            s.read_exact(&mut qbuf).await.unwrap();
            saw_clone.store(true, Ordering::Relaxed);
            let req = Message::from_vec(&qbuf).unwrap();
            let mut resp = Message::new(req.id, MessageType::Response, OpCode::Query);
            resp.metadata.recursion_desired = true;
            resp.metadata.recursion_available = true;
            resp.metadata.response_code = ResponseCode::NoError;
            let q = req.queries[0].clone();
            resp.add_query(q.clone());
            resp.add_answer(Record::from_rdata(
                q.name().clone(),
                60,
                RData::A(A(Ipv4Addr::new(77, 77, 77, 77))),
            ));
            let wire = resp.to_vec().unwrap();
            let rlen = u16::try_from(wire.len()).unwrap().to_be_bytes();
            s.write_all(&rlen).await.unwrap();
            s.write_all(&wire).await.unwrap();
        }
    });

    let proxy_tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_tcp.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut client, _)) = proxy_tcp.accept().await {
            tokio::spawn(async move {
                let mut buf = [0_u8; 512];
                let _ = client.read(&mut buf).await.unwrap();
                client
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await
                    .unwrap();
                let mut target = tokio::net::TcpStream::connect(dns_addr).await.unwrap();
                let _ = tokio::io::copy_bidirectional(&mut client, &mut target).await;
            });
        }
    });

    let groups = vec![UpstreamGroup {
        name: "proxied_grp".to_string(),
        upstreams: vec![format!("tcp://{dns_addr}")],
        proxy_url: Some(format!("http://{proxy_addr}")),
        ..Default::default()
    }];
    let rules = vec![
        SplitDnsRule {
            domain: "one.test".to_string(),
            upstreams: vec!["@proxied_grp".to_string()],
            ..Default::default()
        },
        SplitDnsRule {
            domain: "two.test".to_string(),
            upstreams: vec!["@proxied_grp".to_string()],
            ..Default::default()
        },
    ];

    let filter = Arc::new(FilterEngine::new(&[]));
    let cache = Arc::new(DnsCache::with_options(64, false, 10, 600, false));
    let default_pool =
        Arc::new(UpstreamPool::new(&["udp://127.0.0.1:1".to_string()], 500).unwrap());
    let (log_tx, mut log_rx) = tokio::sync::mpsc::channel(16);
    let pipeline = DnsPipeline::new(filter, cache, default_pool, Some(log_tx));
    pipeline
        .reload_split_dns_full(
            &groups,
            &rules,
            SplitDnsMatchMode::SpecificityFirst,
            1500,
            UpstreamStrategy::Failover,
            &[],
            |_| None,
        )
        .unwrap();

    // Both split rules share the exact same UpstreamPool instance from UpstreamGroupRegistry
    let split_pools = pipeline.split_router().pools();
    assert_eq!(split_pools.len(), 2);
    assert!(Arc::ptr_eq(&split_pools[0], &split_pools[1]));

    let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5003);
    let r = Message::from_vec(
        &pipeline
            .handle_packet(&build_query(77, "www.one.test.", RecordType::A), client)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        r.answers[0].data,
        RData::A(A(Ipv4Addr::new(77, 77, 77, 77)))
    );
    assert!(saw_proxied.load(Ordering::Relaxed));

    let ev = log_rx.recv().await.unwrap();
    assert_eq!(ev.outcome, QueryOutcome::Forwarded);
}
