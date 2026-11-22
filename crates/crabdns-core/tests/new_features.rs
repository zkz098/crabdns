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
