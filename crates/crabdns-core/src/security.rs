use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::rdata::HINFO;
use hickory_proto::rr::{RData, Record};

use crate::error::{CoreError, Result};
use crate::wire::base_response;

/// Returns `true` if `ip` is private, loopback, link-local, CGNAT, ULA, unspecified, or multicast.
pub fn is_private_or_special_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_or_special_v4(v4),
        IpAddr::V6(v6) => is_private_or_special_v6(v6),
    }
}

fn is_private_or_special_v4(v4: Ipv4Addr) -> bool {
    let octets = v4.octets();
    let is_cgnat = octets[0] == 100 && (octets[1] & 0b1100_0000) == 64; // 100.64.0.0/10
    v4.is_private()
        || v4.is_loopback()
        || v4.is_link_local()
        || v4.is_unspecified()
        || v4.is_broadcast()
        || v4.is_multicast()
        || is_cgnat
}

fn is_private_or_special_v6(v6: Ipv6Addr) -> bool {
    if let Some(v4) = v6.to_ipv4_mapped() {
        return is_private_or_special_v4(v4);
    }
    let seg0 = v6.segments()[0];
    let is_ula = (seg0 & 0xfe00) == 0xfc00; // fc00::/7
    let is_link_local = (seg0 & 0xffc0) == 0xfe80; // fe80::/10
    v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() || is_ula || is_link_local
}

/// Returns `true` if the DNS response contains an `A` or `AAAA` answer pointing to a private/special IP.
pub fn contains_rebinding_ip(resp_bytes: &[u8]) -> bool {
    let Ok(msg) = Message::from_vec(resp_bytes) else {
        return false;
    };
    msg.answers.iter().any(|record| match &record.data {
        RData::A(a) => is_private_or_special_v4(a.0),
        RData::AAAA(aaaa) => is_private_or_special_v6(aaaa.0),
        _ => false,
    })
}

/// Builds an RFC 8482 `HINFO` response to suppress `ANY` queries and prevent DNS amplification.
pub fn build_rfc8482_any_response(request: &Message) -> Result<Vec<u8>> {
    let mut resp = base_response(request, ResponseCode::NoError);
    if let Some(q) = request.queries.first() {
        let hinfo = HINFO::new("ANY obsoleted".to_string(), "See RFC 8482".to_string());
        resp.add_answer(Record::from_rdata(
            q.name().clone(),
            3600,
            RData::HINFO(hinfo),
        ));
    }
    resp.to_vec()
        .map_err(|e| CoreError::Protocol(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, OpCode, Query};
    use hickory_proto::rr::rdata::{A, AAAA};
    use hickory_proto::rr::{Name, RecordType};

    #[test]
    fn test_private_ip_classification() {
        assert!(is_private_or_special_ip("192.168.1.1".parse().unwrap()));
        assert!(is_private_or_special_ip("10.0.0.1".parse().unwrap()));
        assert!(is_private_or_special_ip("172.16.5.4".parse().unwrap()));
        assert!(is_private_or_special_ip("100.64.0.1".parse().unwrap()));
        assert!(is_private_or_special_ip("127.0.0.1".parse().unwrap()));
        assert!(is_private_or_special_ip("169.254.1.1".parse().unwrap()));
        assert!(is_private_or_special_ip("::1".parse().unwrap()));
        assert!(is_private_or_special_ip("fd00::1".parse().unwrap()));
        assert!(is_private_or_special_ip("fe80::1".parse().unwrap()));

        assert!(!is_private_or_special_ip("1.1.1.1".parse().unwrap()));
        assert!(!is_private_or_special_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_private_or_special_ip(
            "2606:4700:4700::1111".parse().unwrap()
        ));
    }

    #[test]
    fn test_contains_rebinding_ip() {
        let mut msg = Message::new(1, MessageType::Response, OpCode::Query);
        let name = Name::from_ascii("rebind.example.com.").unwrap();
        msg.add_query(Query::query(name.clone(), RecordType::A));
        msg.add_answer(Record::from_rdata(
            name.clone(),
            60,
            RData::A(A(Ipv4Addr::new(192, 168, 1, 10))),
        ));
        let wire = msg.to_vec().unwrap();
        assert!(contains_rebinding_ip(&wire));

        let mut pub_msg = Message::new(2, MessageType::Response, OpCode::Query);
        pub_msg.add_query(Query::query(name.clone(), RecordType::AAAA));
        pub_msg.add_answer(Record::from_rdata(
            name,
            60,
            RData::AAAA(AAAA("2606:4700:4700::1111".parse().unwrap())),
        ));
        let pub_wire = pub_msg.to_vec().unwrap();
        assert!(!contains_rebinding_ip(&pub_wire));
    }

    #[test]
    fn test_rfc8482_any_response() {
        let mut req = Message::new(42, MessageType::Query, OpCode::Query);
        req.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::ANY,
        ));
        let wire = build_rfc8482_any_response(&req).unwrap();
        let resp = Message::from_vec(&wire).unwrap();
        assert_eq!(resp.response_code, ResponseCode::NoError);
        assert_eq!(resp.answers.len(), 1);
        assert_eq!(resp.answers[0].record_type(), RecordType::HINFO);
    }
}
