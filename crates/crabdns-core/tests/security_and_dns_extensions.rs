use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crabdns_core::cookies::EDNS_OPTION_COOKIE;
use crabdns_core::edns::{
    EDE_BLOCKED, EDE_NO_REACHABLE_AUTHORITY, EDE_PROHIBITED, EDNS_OPTION_EDE,
};
use crabdns_core::upstream::UpstreamEndpoint;
use crabdns_core::{
    DnsCache, DnsPipeline, DnssecValidator, FilterEngine, QueryContext, QueryProtocol, RrlConfig,
    UpstreamPool, ValidationOutcome,
};
use hickory_proto::dnssec::crypto::Ed25519SigningKey;
use hickory_proto::dnssec::rdata::sig::SigInput;
use hickory_proto::dnssec::rdata::{DNSKEY, DNSSECRData, DS, NSEC, RRSIG};
use hickory_proto::dnssec::{Algorithm, DigestType, SigningKey, TBS, TrustAnchors};
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
use hickory_proto::rr::rdata::{SOA, TXT};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType, SerialNumber};
use tokio::net::UdpSocket;

fn build_edns_query(id: u16, domain: &str, qtype: RecordType, max_payload: u16) -> Vec<u8> {
    let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(Name::from_ascii(domain).unwrap(), qtype));
    let mut edns = Edns::new();
    edns.set_max_payload(max_payload);
    msg.edns = Some(edns);
    msg.to_vec().unwrap()
}

fn extract_ede_code(msg: &Message) -> Option<u16> {
    let edns = msg.edns.as_ref()?;
    for (_, opt) in edns.options().as_ref() {
        if let EdnsOption::Unknown(EDNS_OPTION_EDE, data) = opt
            && data.len() >= 2
        {
            return Some(u16::from_be_bytes([data[0], data[1]]));
        }
    }
    None
}

fn extract_cookie_data(msg: &Message) -> Option<&[u8]> {
    let edns = msg.edns.as_ref()?;
    for (code, opt) in edns.options().as_ref() {
        match (code, opt) {
            (EdnsCode::Cookie, EdnsOption::Unknown(_, data))
            | (_, EdnsOption::Unknown(EDNS_OPTION_COOKIE, data)) => return Some(data.as_slice()),
            _ => {}
        }
    }
    None
}

async fn spawn_large_txt_udp() -> SocketAddr {
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
                let mut edns = Edns::new();
                edns.set_max_payload(4096);
                resp.edns = Some(edns);
                if let Some(q) = req.queries.first() {
                    let payload = "x".repeat(235);
                    for i in 0..5 {
                        let s = format!("{i}:{payload}");
                        resp.add_answer(Record::from_rdata(
                            q.name().clone(),
                            60,
                            RData::TXT(TXT::new(vec![s])),
                        ));
                    }
                }
                if let Ok(bytes) = resp.to_vec() {
                    let _ = sock.send_to(&bytes, peer).await;
                }
            }
        }
    });
    addr
}

#[test]
fn test_doq_upstream_parsing() {
    let ep = UpstreamEndpoint::parse("quic://dns.adguard-dns.com").expect("parse doq");
    assert!(matches!(
        ep,
        UpstreamEndpoint::Doq { ref addr, ref server_name }
        if addr == "dns.adguard-dns.com:853" && server_name == "dns.adguard-dns.com"
    ));

    let ep_port = UpstreamEndpoint::parse("quic://1.1.1.1:8853").expect("parse doq port");
    assert!(matches!(
        ep_port,
        UpstreamEndpoint::Doq { ref addr, ref server_name }
        if addr == "1.1.1.1:8853" && server_name == "1.1.1.1"
    ));

    assert!(UpstreamPool::new(&["quic://dns.adguard-dns.com".to_string()], 1000).is_ok());

    let h3_ep = UpstreamEndpoint::parse("h3://dns.google/dns-query").expect("parse doh3");
    assert!(matches!(
        h3_ep,
        UpstreamEndpoint::Doh3 { ref url, ref host, port }
        if url == "https://dns.google/dns-query" && host == "dns.google" && port == 443
    ));
    let h3_default_path = UpstreamEndpoint::parse("h3://1.1.1.1:8443").expect("parse doh3 default");
    assert!(matches!(
        h3_default_path,
        UpstreamEndpoint::Doh3 { ref url, ref host, port }
        if url == "https://1.1.1.1:8443/dns-query" && host == "1.1.1.1" && port == 8443
    ));
    assert!(UpstreamPool::new(&["h3://dns.google/dns-query".to_string()], 1000).is_ok());
}

#[tokio::test]
async fn test_ede_attached_for_blocked_acl_and_upstream_fail() {
    let filter = Arc::new(FilterEngine::new(&["||blocked.test^".to_string()]));
    let cache = Arc::new(DnsCache::new(64, true));
    // Unreachable port to trigger UpstreamFailed
    let pool = Arc::new(UpstreamPool::new(&["udp://127.0.0.1:1".to_string()], 100).unwrap());
    let pipeline = DnsPipeline::new(filter, cache, pool, None);
    let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345);

    // 1. Filter block -> EDE_BLOCKED (15)
    let resp_bytes = pipeline
        .handle_packet(
            &build_edns_query(1, "blocked.test.", RecordType::A, 1232),
            client,
        )
        .await
        .unwrap();
    let resp = Message::from_vec(&resp_bytes).unwrap();
    assert_eq!(extract_ede_code(&resp), Some(EDE_BLOCKED));

    // 2. Upstream failure -> EDE_NO_REACHABLE_AUTHORITY (22)
    let fail_bytes = pipeline
        .handle_packet(
            &build_edns_query(2, "ok.test.", RecordType::A, 1232),
            client,
        )
        .await
        .unwrap();
    let fail_resp = Message::from_vec(&fail_bytes).unwrap();
    assert_eq!(fail_resp.response_code, ResponseCode::ServFail);
    assert_eq!(
        extract_ede_code(&fail_resp),
        Some(EDE_NO_REACHABLE_AUTHORITY)
    );

    // 3. ACL denial -> EDE_PROHIBITED (18)
    pipeline
        .reload_acl(&[], &["127.0.0.1/32".to_string()], 0)
        .unwrap();
    let acl_bytes = pipeline
        .handle_packet(
            &build_edns_query(3, "ok.test.", RecordType::A, 1232),
            client,
        )
        .await
        .unwrap();
    let acl_resp = Message::from_vec(&acl_bytes).unwrap();
    assert_eq!(acl_resp.response_code, ResponseCode::Refused);
    assert_eq!(extract_ede_code(&acl_resp), Some(EDE_PROHIBITED));
}

#[tokio::test]
async fn test_dns_cookies_end_to_end() {
    let filter = Arc::new(FilterEngine::new(&["||ads.test^".to_string()]));
    let cache = Arc::new(DnsCache::new(64, true));
    let pool = Arc::new(UpstreamPool::new(&["udp://127.0.0.1:1".to_string()], 100).unwrap());
    let pipeline = DnsPipeline::new(filter, cache, pool, None);
    pipeline.set_dns_cookies(true, true);

    let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345);
    let client_cookie = [1_u8, 2, 3, 4, 5, 6, 7, 8];

    // Step 1: Client sends only 8-byte client cookie while require_valid=true -> BADCOOKIE + minted server cookie.
    let mut msg = Message::new(10, MessageType::Query, OpCode::Query);
    msg.add_query(Query::query(
        Name::from_ascii("ads.test.").unwrap(),
        RecordType::A,
    ));
    let mut edns = Edns::new();
    edns.options_mut().insert(EdnsOption::Unknown(
        EDNS_OPTION_COOKIE,
        client_cookie.to_vec(),
    ));
    msg.edns = Some(edns);
    let resp1_bytes = pipeline
        .handle_packet(&msg.to_vec().unwrap(), client)
        .await
        .unwrap();
    let resp1 = Message::from_vec(&resp1_bytes).unwrap();
    assert_eq!(resp1.response_code, ResponseCode::BADCOOKIE);
    let minted = extract_cookie_data(&resp1).expect("server cookie attached");
    assert_eq!(minted.len(), 24);
    assert_eq!(&minted[..8], &client_cookie);

    // Step 2: Client retries with the 24-byte cookie -> succeeds with NOERROR.
    let mut msg2 = Message::new(11, MessageType::Query, OpCode::Query);
    msg2.add_query(Query::query(
        Name::from_ascii("ads.test.").unwrap(),
        RecordType::A,
    ));
    let mut edns2 = Edns::new();
    edns2
        .options_mut()
        .insert(EdnsOption::Unknown(EDNS_OPTION_COOKIE, minted.to_vec()));
    msg2.edns = Some(edns2);
    let resp2_bytes = pipeline
        .handle_packet(&msg2.to_vec().unwrap(), client)
        .await
        .unwrap();
    let resp2 = Message::from_vec(&resp2_bytes).unwrap();
    assert_eq!(resp2.response_code, ResponseCode::NoError);
}

#[tokio::test]
async fn test_udp_payload_cap_and_rrl() {
    let upstream_addr = spawn_large_txt_udp().await;
    let filter = Arc::new(FilterEngine::new(&[]));
    let cache = Arc::new(DnsCache::new(64, true));
    let pool = Arc::new(UpstreamPool::new(&[format!("udp://{upstream_addr}")], 1000).unwrap());
    let pipeline = DnsPipeline::new(filter, cache, pool, None);
    pipeline.set_max_udp_payload_size(1232);

    let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 23456);
    let q = build_edns_query(20, "big.example.com.", RecordType::TXT, 4096);

    // Over UDP: capped at <= 1232 bytes with TC=1.
    let udp_resp_bytes = pipeline.handle_packet(&q, client).await.unwrap();
    assert!(
        udp_resp_bytes.len() <= 1232,
        "UDP response {} exceeded 1232",
        udp_resp_bytes.len()
    );
    let udp_resp = Message::from_vec(&udp_resp_bytes).unwrap();
    assert!(
        udp_resp.metadata.truncation,
        "expected TC=1, got len={}, answers={}",
        udp_resp_bytes.len(),
        udp_resp.answers.len()
    );

    // Over TCP: full response (> 1232 bytes) without TC=1.
    let tcp_resp_bytes = pipeline
        .handle_packet_with_context(
            &q,
            QueryContext {
                client_addr: client,
                protocol: QueryProtocol::Tcp,
                client_id: None,
            },
        )
        .await
        .unwrap();
    assert!(tcp_resp_bytes.len() > 1232);
    let tcp_resp = Message::from_vec(&tcp_resp_bytes).unwrap();
    assert!(!tcp_resp.metadata.truncation);

    // Enable RRL: 1 req/s, slip=2.
    pipeline.set_rrl(RrlConfig {
        enabled: true,
        responses_per_second: 1,
        slip: 2,
        window_secs: 1,
    });
    let small_q = build_edns_query(21, "rrl.example.com.", RecordType::A, 1232);
    let r1 = pipeline.handle_packet(&small_q, client).await.unwrap();
    assert!(!r1.is_empty(), "1st response should be allowed");
    let r2 = pipeline.handle_packet(&small_q, client).await.unwrap();
    assert!(!r2.is_empty(), "2nd response should slip with TC=1");
    assert!(Message::from_vec(&r2).unwrap().metadata.truncation);
    let r3 = pipeline.handle_packet(&small_q, client).await.unwrap();
    assert!(r3.is_empty(), "RRL Drop must return empty bytes");
}

fn sign_rrset_for_test(
    key: &Ed25519SigningKey,
    dnskey: &DNSKEY,
    zone: &Name,
    records: &[Record],
    now: u32,
) -> Record {
    let sig_input = SigInput {
        type_covered: records[0].record_type(),
        algorithm: Algorithm::ED25519,
        num_labels: records[0].name.num_labels(),
        original_ttl: 300,
        sig_expiration: SerialNumber::new(now + 3600),
        sig_inception: SerialNumber::new(now - 60),
        key_tag: dnskey.calculate_key_tag().unwrap(),
        signer_name: zone.clone(),
    };
    let tbs = TBS::from_input(&records[0].name, DNSClass::IN, &sig_input, records.iter()).unwrap();
    let sig_bytes = key.sign(&tbs).unwrap();
    let rrsig = RRSIG::from_sig(sig_input, sig_bytes);
    Record::from_rdata(
        records[0].name.clone(),
        300,
        RData::DNSSEC(DNSSECRData::RRSIG(rrsig)),
    )
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn test_dnssec_negative_nsec_validation() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;

    let pkcs8 = Ed25519SigningKey::generate_pkcs8().unwrap();
    let signing_key = Ed25519SigningKey::from_pkcs8(&pkcs8).unwrap();
    let pub_key = signing_key.to_public_key().unwrap();
    let dnskey = DNSKEY::new(true, true, false, pub_key);

    let root = Name::root();
    let zone = Name::from_ascii("test.").unwrap();
    let missing = Name::from_ascii("missing.test.").unwrap();

    let mut anchors = TrustAnchors::empty();
    anchors.insert(&dnskey.public_key().clone());

    let root_key_rec = Record::from_rdata(
        root.clone(),
        300,
        RData::DNSSEC(DNSSECRData::DNSKEY(dnskey.clone())),
    );
    let root_key_sig = sign_rrset_for_test(
        &signing_key,
        &dnskey,
        &root,
        std::slice::from_ref(&root_key_rec),
        now,
    );

    let ds = DS::from_key(dnskey.public_key(), &zone, DigestType::SHA256).unwrap();
    let ds_rec = Record::from_rdata(zone.clone(), 300, RData::DNSSEC(DNSSECRData::DS(ds)));
    let ds_sig = sign_rrset_for_test(
        &signing_key,
        &dnskey,
        &root,
        std::slice::from_ref(&ds_rec),
        now,
    );

    let zone_key_rec = Record::from_rdata(
        zone.clone(),
        300,
        RData::DNSSEC(DNSSECRData::DNSKEY(dnskey.clone())),
    );
    let zone_key_sig = sign_rrset_for_test(
        &signing_key,
        &dnskey,
        &zone,
        std::slice::from_ref(&zone_key_rec),
        now,
    );

    // Mock upstream serving root DNSKEY, zone DS, and zone DNSKEY.
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = sock.local_addr().unwrap();
    let r_recs = (
        root_key_rec,
        root_key_sig,
        ds_rec,
        ds_sig,
        zone_key_rec,
        zone_key_sig,
    );
    tokio::spawn(async move {
        let mut buf = [0_u8; 4096];
        while let Ok((len, peer)) = sock.recv_from(&mut buf).await {
            if let Ok(req) = Message::from_vec(&buf[..len]) {
                let mut resp = Message::new(req.id, MessageType::Response, OpCode::Query);
                resp.queries.clone_from(&req.queries);
                let mut edns = Edns::new();
                edns.set_max_payload(4096);
                resp.edns = Some(edns);
                if let Some(q) = req.queries.first() {
                    if *q.name() == Name::root() && q.query_type() == RecordType::DNSKEY {
                        resp.add_answer(r_recs.0.clone());
                        resp.add_answer(r_recs.1.clone());
                    } else if q.name().to_ascii() == "test." && q.query_type() == RecordType::DS {
                        resp.add_answer(r_recs.2.clone());
                        resp.add_answer(r_recs.3.clone());
                    } else if q.name().to_ascii() == "test." && q.query_type() == RecordType::DNSKEY
                    {
                        resp.add_answer(r_recs.4.clone());
                        resp.add_answer(r_recs.5.clone());
                    }
                }
                let _ = sock.send_to(&resp.to_vec().unwrap(), peer).await;
            }
        }
    });

    let pool = UpstreamPool::new(&[format!("udp://{upstream_addr}")], 1000).unwrap();
    let validator = DnssecValidator::new(anchors);

    // 1. Valid NSEC covering both `missing.example.test.` and `*.example.test.` (wrap-around `example.test.` -> `example.test.`):
    let soa_rec = Record::from_rdata(
        zone.clone(),
        300,
        RData::SOA(SOA::new(zone.clone(), zone.clone(), 1, 60, 60, 60, 60)),
    );
    let soa_sig = sign_rrset_for_test(
        &signing_key,
        &dnskey,
        &zone,
        std::slice::from_ref(&soa_rec),
        now,
    );
    let nsec_rec = Record::from_rdata(
        zone.clone(),
        300,
        RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(
            zone.clone(),
            vec![
                RecordType::SOA,
                RecordType::DNSKEY,
                RecordType::NSEC,
                RecordType::RRSIG,
            ],
        ))),
    );
    let nsec_sig = sign_rrset_for_test(
        &signing_key,
        &dnskey,
        &zone,
        std::slice::from_ref(&nsec_rec),
        now,
    );

    let mut nx_msg = Message::new(100, MessageType::Response, OpCode::Query);
    nx_msg.metadata.response_code = ResponseCode::NXDomain;
    nx_msg.add_query(Query::query(missing.clone(), RecordType::A));
    nx_msg.add_authority(soa_rec.clone());
    nx_msg.add_authority(soa_sig);
    nx_msg.add_authority(nsec_rec);
    nx_msg.add_authority(nsec_sig);

    assert_eq!(
        validator.validate_message(&nx_msg, &pool, now).await,
        ValidationOutcome::Secure
    );

    // 2. Unsigned NXDOMAIN from signed zone -> Bogus!
    let mut spoofed_nx = Message::new(101, MessageType::Response, OpCode::Query);
    spoofed_nx.metadata.response_code = ResponseCode::NXDomain;
    spoofed_nx.add_query(Query::query(missing, RecordType::A));
    spoofed_nx.add_authority(soa_rec);
    assert_eq!(
        validator.validate_message(&spoofed_nx, &pool, now).await,
        ValidationOutcome::Bogus
    );
}
