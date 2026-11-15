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
