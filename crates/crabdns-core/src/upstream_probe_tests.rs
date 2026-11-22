use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use super::*;
use crate::upstream_probe_wire::{EDNS_CODE_COOKIE, EDNS_CODE_EDE, EDNS_CODE_PADDING};
use hickory_proto::dnssec::Algorithm;
use hickory_proto::dnssec::rdata::sig::SigInput;
use hickory_proto::dnssec::rdata::{DNSSECRData, RRSIG};
use hickory_proto::op::{Edns, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsCode, EdnsOption, NSIDPayload};
use hickory_proto::rr::rdata::svcb::{Alpn, Unknown};
use hickory_proto::rr::{Name, Record, SerialNumber};
use tokio::net::UdpSocket;

#[allow(clippy::struct_excessive_bools)]
struct MockBehavior {
    support_edns: bool,
    support_dnssec_aware: bool,
    support_dnssec_validating: bool,
    support_ecs: bool,
    hijack_nxdomain: bool,
    support_ddr: bool,
    recursion_available: bool,
    nsid: Option<&'static str>,
    support_cookies: bool,
    support_padding: bool,
    support_ede: bool,
}

fn build_mock_edns(req: &Message, cfg: &MockBehavior) -> Edns {
    let mut edns = Edns::new();
    edns.set_max_payload(1232);
    if let Some(nsid_str) = cfg.nsid
        && req.edns.as_ref().is_some_and(|e| {
            e.options()
                .as_ref()
                .iter()
                .any(|(c, o)| matches!(c, EdnsCode::NSID) || matches!(o, EdnsOption::NSID(_)))
        })
        && let Ok(payload) = NSIDPayload::new(nsid_str.as_bytes().to_vec())
    {
        edns.options_mut().insert(EdnsOption::NSID(payload));
    }
    if cfg.support_cookies
        && let Some(client_bytes) = req.edns.as_ref().and_then(|e| {
            e.options().as_ref().iter().find_map(|(_, o)| match o {
                EdnsOption::Unknown(EDNS_CODE_COOKIE, data) if data.len() >= 8 => {
                    Some(data[..8].to_vec())
                }
                _ => None,
            })
        })
    {
        let mut full_cookie = client_bytes;
        full_cookie.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        edns.options_mut()
            .insert(EdnsOption::Unknown(EDNS_CODE_COOKIE, full_cookie));
    }
    if cfg.support_padding {
        edns.options_mut()
            .insert(EdnsOption::Unknown(EDNS_CODE_PADDING, vec![0; 16]));
    }
    if cfg.support_ecs
        && req.edns.as_ref().is_some_and(|e| {
            e.options()
                .as_ref()
                .iter()
                .any(|(_, o)| matches!(o, EdnsOption::Subnet(_)))
        })
    {
        edns.options_mut()
            .insert(EdnsOption::Subnet(ClientSubnet::new(
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 0)),
                24,
                24,
            )));
    }
    edns
}

fn handle_mock_dnskey(cfg: &MockBehavior, resp: &mut Message) {
    resp.metadata.response_code = ResponseCode::NoError;
    if !cfg.support_dnssec_aware {
        return;
    }
    resp.metadata.authentic_data = cfg.support_dnssec_validating;
    let sig = RRSIG::from_sig(
        SigInput {
            type_covered: RecordType::DNSKEY,
            algorithm: Algorithm::ED25519,
            num_labels: 0,
            original_ttl: 300,
            sig_expiration: SerialNumber::new(2_000_000_000),
            sig_inception: SerialNumber::new(1_000_000_000),
            key_tag: 12345,
            signer_name: Name::root(),
        },
        vec![1, 2, 3, 4],
    );
    resp.add_answer(Record::from_rdata(
        Name::root(),
        300,
        RData::DNSSEC(DNSSECRData::RRSIG(sig)),
    ));
}

fn handle_mock_ddr(q: &Query, cfg: &MockBehavior, resp: &mut Message) {
    resp.metadata.response_code = ResponseCode::NoError;
    if !cfg.support_ddr {
        return;
    }
    let target = Name::from_ascii("dns.example.test.").unwrap();
    let tls_svcb = SVCB::new(
        1,
        target.clone(),
        vec![(
            SvcParamKey::Alpn,
            SvcParamValue::Alpn(Alpn(vec!["dot".to_string()])),
        )],
    );
    let https_svcb = SVCB::new(
        2,
        target,
        vec![
            (
                SvcParamKey::Alpn,
                SvcParamValue::Alpn(Alpn(vec!["h2".to_string()])),
            ),
            (
                SvcParamKey::Unknown(7),
                SvcParamValue::Unknown(Unknown(b"/dns-query{?dns}".to_vec())),
            ),
        ],
    );
    resp.add_answer(Record::from_rdata(
        q.name().clone(),
        300,
        RData::SVCB(tls_svcb),
    ));
    resp.add_answer(Record::from_rdata(
        q.name().clone(),
        300,
        RData::SVCB(https_svcb),
    ));
}

fn apply_mock_query_response(q: &Query, cfg: &MockBehavior, resp: &mut Message) {
    let qname = q.name().to_ascii().to_ascii_lowercase();
    let qtype = q.query_type();

    if qname == "." && qtype == RecordType::DNSKEY {
        handle_mock_dnskey(cfg, resp);
    } else if qname == DNSSEC_BOGUS_DOMAIN {
        if cfg.support_dnssec_validating {
            resp.metadata.response_code = ResponseCode::ServFail;
            if cfg.support_ede
                && let Some(edns) = resp.edns.as_mut()
            {
                let mut ede_data = 6_u16.to_be_bytes().to_vec();
                ede_data.extend_from_slice(b"validation failure");
                edns.options_mut()
                    .insert(EdnsOption::Unknown(EDNS_CODE_EDE, ede_data));
            }
        } else {
            resp.metadata.response_code = ResponseCode::NoError;
            resp.add_answer(Record::from_rdata(
                q.name().clone(),
                60,
                RData::A(A(Ipv4Addr::new(93, 184, 216, 34))),
            ));
        }
    } else if qname.ends_with(".invalid.") {
        if cfg.hijack_nxdomain {
            resp.metadata.response_code = ResponseCode::NoError;
            resp.add_answer(Record::from_rdata(
                q.name().clone(),
                60,
                RData::A(A(Ipv4Addr::new(198, 51, 100, 1))),
            ));
        } else {
            resp.metadata.response_code = ResponseCode::NXDomain;
        }
    } else if qname == DDR_PROBE_DOMAIN && qtype == RecordType::SVCB {
        handle_mock_ddr(q, cfg, resp);
    } else {
        resp.metadata.response_code = ResponseCode::NoError;
        resp.add_answer(Record::from_rdata(
            q.name().clone(),
            60,
            RData::A(A(Ipv4Addr::new(204, 79, 197, 200))),
        ));
    }
}

async fn spawn_mock_dns_server(cfg: MockBehavior) -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind mock");
    let addr = sock.local_addr().expect("addr");
    tokio::spawn(async move {
        let mut buf = [0_u8; 4096];
        while let Ok((len, peer)) = sock.recv_from(&mut buf).await {
            let Ok(req) = Message::from_vec(&buf[..len]) else {
                continue;
            };
            let mut resp = Message::new(req.id, MessageType::Response, OpCode::Query);
            resp.metadata.recursion_desired = req.metadata.recursion_desired;
            resp.metadata.recursion_available = cfg.recursion_available;
            if let Some(q) = req.queries.first() {
                resp.add_query(q.clone());
                if req.edns.is_some() && !cfg.support_edns {
                    resp.metadata.response_code = ResponseCode::FormErr;
                } else {
                    if req.edns.is_some() && cfg.support_edns {
                        resp.edns = Some(build_mock_edns(&req, &cfg));
                    }
                    apply_mock_query_response(q, &cfg, &mut resp);
                }
            }
            if let Ok(wire) = resp.to_vec() {
                let _ = sock.send_to(&wire, peer).await;
            }
        }
    });
    addr
}

#[tokio::test]
async fn test_probe_full_featured_upstream() {
    let addr = spawn_mock_dns_server(MockBehavior {
        support_edns: true,
        support_dnssec_aware: true,
        support_dnssec_validating: true,
        support_ecs: true,
        hijack_nxdomain: false,
        support_ddr: true,
        recursion_available: true,
        nsid: Some("hkg-edge-01"),
        support_cookies: true,
        support_padding: true,
        support_ede: true,
    })
    .await;
    let results = probe_upstreams(&[format!("udp://{addr}")], &[], 2000)
        .await
        .expect("probe");
    assert_eq!(results.len(), 1);
    let cap = &results[0];
    assert_eq!(cap.protocol, UpstreamProtocol::Udp);
    assert!(!cap.encrypted);
    assert!(cap.reachable);
    assert_eq!(cap.recursion_available, Some(true));
    assert_eq!(cap.edns, Some(true));
    assert_eq!(cap.edns_udp_size, Some(1232));
    assert_eq!(cap.dnssec_aware, Some(true));
    assert_eq!(cap.dnssec_validating, Some(true));
    assert_eq!(cap.ecs, Some(true));
    assert_eq!(cap.nxdomain_hijack, Some(false));
    assert_eq!(cap.nsid.as_deref(), Some("hkg-edge-01"));
    assert_eq!(cap.dns_cookies, Some(true));
    assert_eq!(cap.edns_padding, Some(true));
    assert_eq!(cap.ede, Some(true));
    assert_eq!(
        cap.ede_detail.as_deref(),
        Some("6: DNSSEC Bogus (validation failure)")
    );
    assert_eq!(
        cap.ddr_upgrades,
        vec![
            "tls://dns.example.test".to_string(),
            "https://dns.example.test/dns-query".to_string(),
        ]
    );
}

#[tokio::test]
async fn test_probe_legacy_hijacking_non_recursive_upstream() {
    let addr = spawn_mock_dns_server(MockBehavior {
        support_edns: false,
        support_dnssec_aware: false,
        support_dnssec_validating: false,
        support_ecs: false,
        hijack_nxdomain: true,
        support_ddr: false,
        recursion_available: false,
        nsid: None,
        support_cookies: false,
        support_padding: false,
        support_ede: false,
    })
    .await;
    let results = probe_upstreams(&[format!("udp://{addr}")], &[], 2000)
        .await
        .expect("probe");
    let cap = &results[0];
    assert!(cap.reachable);
    assert_eq!(cap.recursion_available, Some(false));
    assert_eq!(cap.edns, Some(false));
    assert_eq!(cap.dnssec_aware, Some(false));
    assert_eq!(cap.dnssec_validating, Some(false));
    assert_eq!(cap.ecs, Some(false));
    assert_eq!(cap.nxdomain_hijack, Some(true));
    assert_eq!(cap.nsid, None);
    assert_eq!(cap.dns_cookies, Some(false));
    assert_eq!(cap.edns_padding, None);
    assert_eq!(cap.ede, None);
    assert_eq!(cap.ddr_upgrades, Vec::<String>::new());
}

#[tokio::test]
async fn test_probe_invalid_and_unreachable_upstreams() {
    let results = probe_upstreams(
        &[
            "not-an-upstream".to_string(),
            "udp://127.0.0.1:1".to_string(),
        ],
        &[],
        300,
    )
    .await
    .expect("probe");
    assert_eq!(results.len(), 2);
    assert!(!results[0].reachable);
    assert!(results[0].error.is_some());
    assert!(!results[1].reachable);
    assert!(results[1].error.is_some());
}
