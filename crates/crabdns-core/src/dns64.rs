use std::net::{Ipv4Addr, Ipv6Addr};

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::rdata::AAAA;
use hickory_proto::rr::{Name, RData, Record, RecordType};

use crate::error::{CoreError, Result};
use crate::wire::base_response;

pub const DEFAULT_DNS64_PREFIX: &str = "64:ff9b::/96";
const MAX_SYNTHESIZED_TTL: u32 = 600;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dns64Prefix {
    pub network: Ipv6Addr,
    pub prefix_len: u8,
}

impl Dns64Prefix {
    pub fn parse(raw: &str) -> Result<Self> {
        let trimmed = raw.trim();
        let (addr_str, len_str) = trimmed.split_once('/').ok_or_else(|| {
            CoreError::Config(format!("DNS64 prefix '{trimmed}' must include '/len'"))
        })?;
        let network: Ipv6Addr = addr_str.trim().parse().map_err(|_| {
            CoreError::Config(format!("invalid IPv6 address in DNS64 prefix '{trimmed}'"))
        })?;
        let prefix_len: u8 = len_str.trim().parse().map_err(|_| {
            CoreError::Config(format!("invalid prefix length in DNS64 prefix '{trimmed}'"))
        })?;
        if !matches!(prefix_len, 32 | 40 | 48 | 56 | 64 | 96) {
            return Err(CoreError::Config(format!(
                "DNS64 prefix length must be 32, 40, 48, 56, 64, or 96 (got /{prefix_len})"
            )));
        }
        Ok(Self {
            network,
            prefix_len,
        })
    }

    /// Synthesizes an IPv6 address from `ipv4` according to RFC 6052 §2.2.
    pub fn synthesize(&self, ipv4: Ipv4Addr) -> Ipv6Addr {
        let mut out = self.network.octets();
        let v4 = ipv4.octets();
        match self.prefix_len {
            32 => {
                out[4..8].copy_from_slice(&v4);
                out[8..16].fill(0);
            }
            40 => {
                out[5..8].copy_from_slice(&v4[0..3]);
                out[8] = 0;
                out[9] = v4[3];
                out[10..16].fill(0);
            }
            48 => {
                out[6..8].copy_from_slice(&v4[0..2]);
                out[8] = 0;
                out[9..11].copy_from_slice(&v4[2..4]);
                out[11..16].fill(0);
            }
            56 => {
                out[7] = v4[0];
                out[8] = 0;
                out[9..12].copy_from_slice(&v4[1..4]);
                out[12..16].fill(0);
            }
            64 => {
                out[8] = 0;
                out[9..13].copy_from_slice(&v4);
                out[13..16].fill(0);
            }
            96 => {
                out[12..16].copy_from_slice(&v4);
            }
            _ => {}
        }
        Ipv6Addr::from(out)
    }
}

#[derive(Debug, Clone, Default)]
pub struct Dns64Config {
    pub enabled: bool,
    pub prefixes: Vec<Dns64Prefix>,
}

impl Dns64Config {
    pub fn compile(enabled: bool, raw_prefixes: &[String]) -> Result<Self> {
        if !enabled {
            return Ok(Self {
                enabled: false,
                prefixes: Vec::new(),
            });
        }
        let mut prefixes = Vec::new();
        for raw in raw_prefixes {
            let trimmed = raw.trim();
            if !trimmed.is_empty() {
                prefixes.push(Dns64Prefix::parse(trimmed)?);
            }
        }
        if prefixes.is_empty() {
            prefixes.push(Dns64Prefix::parse(DEFAULT_DNS64_PREFIX)?);
        }
        Ok(Self { enabled, prefixes })
    }
}

/// Returns `Some(target_name)` if `aaaa_msg` is a `NoError` response with no `AAAA` answers
/// and should trigger an `A` lookup for DNS64 synthesis.
pub fn needs_dns64_synthesis(aaaa_msg: &Message) -> Option<Name> {
    if aaaa_msg.response_code != ResponseCode::NoError {
        return None;
    }
    let has_aaaa = aaaa_msg
        .answers
        .iter()
        .any(|r| matches!(r.data, RData::AAAA(_)));
    if has_aaaa {
        return None;
    }
    let mut target = aaaa_msg.queries.first()?.name().clone();
    for _ in 0..8 {
        let next = aaaa_msg.answers.iter().find_map(|r| {
            if r.name == target
                && let RData::CNAME(cname) = &r.data
            {
                return Some(cname.0.clone());
            }
            None
        });
        match next {
            Some(c) if c != target => target = c,
            _ => break,
        }
    }
    Some(target)
}

/// Builds a DNS64-synthesized `AAAA` response from `orig_aaaa_msg` and `a_msg`.
/// Returns `Ok(None)` if `a_msg` contains no synthesizable `A` records.
pub fn build_dns64_response(
    request: &Message,
    orig_aaaa_msg: &Message,
    a_msg: &Message,
    prefixes: &[Dns64Prefix],
) -> Result<Option<Vec<u8>>> {
    if prefixes.is_empty() {
        return Ok(None);
    }

    let mut a_records: Vec<(Name, u32, Ipv4Addr)> = Vec::new();
    for rec in &a_msg.answers {
        if let RData::A(a) = &rec.data {
            let v4 = a.0;
            if !v4.is_unspecified()
                && !v4.is_loopback()
                && !v4.is_multicast()
                && !v4.is_link_local()
            {
                a_records.push((rec.name.clone(), rec.ttl.min(MAX_SYNTHESIZED_TTL), v4));
            }
        }
    }

    if a_records.is_empty() {
        return Ok(None);
    }

    let mut resp = base_response(request, ResponseCode::NoError);
    resp.metadata.recursion_available = orig_aaaa_msg.recursion_available;

    for rec in &orig_aaaa_msg.answers {
        if rec.record_type() != RecordType::RRSIG {
            resp.add_answer(rec.clone());
        }
    }
    for rec in &a_msg.answers {
        if let RData::CNAME(_) = &rec.data
            && !resp.answers.iter().any(|existing| existing == rec)
        {
            resp.add_answer(rec.clone());
        }
    }

    for prefix in prefixes {
        for (name, ttl, v4) in &a_records {
            let v6 = prefix.synthesize(*v4);
            resp.add_answer(Record::from_rdata(
                name.clone(),
                *ttl,
                RData::AAAA(AAAA(v6)),
            ));
        }
    }

    let bytes = resp
        .to_vec()
        .map_err(|e| CoreError::Protocol(e.to_string()))?;
    Ok(Some(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, OpCode, Query};
    use hickory_proto::rr::rdata::{A, CNAME};

    #[test]
    fn test_rfc6052_synthesis() {
        let p96 = Dns64Prefix::parse("64:ff9b::/96").unwrap();
        assert_eq!(
            p96.synthesize("192.0.2.1".parse().unwrap()),
            "64:ff9b::c000:201".parse::<Ipv6Addr>().unwrap()
        );

        let p64 = Dns64Prefix::parse("2001:db8:122:344::/64").unwrap();
        assert_eq!(
            p64.synthesize("192.0.2.33".parse().unwrap()),
            "2001:db8:122:344:c0:2:2100:0".parse::<Ipv6Addr>().unwrap()
        );

        assert!(Dns64Prefix::parse("64:ff9b::/72").is_err());
    }

    #[test]
    fn test_build_dns64_response_with_cname() {
        let qname = Name::from_ascii("ipv4only.example.").unwrap();
        let target = Name::from_ascii("target.example.").unwrap();

        let mut req = Message::new(42, MessageType::Query, OpCode::Query);
        req.add_query(Query::query(qname.clone(), RecordType::AAAA));

        let mut aaaa_resp = base_response(&req, ResponseCode::NoError);
        aaaa_resp.add_answer(Record::from_rdata(
            qname.clone(),
            120,
            RData::CNAME(CNAME(target.clone())),
        ));

        let detected = needs_dns64_synthesis(&aaaa_resp).unwrap();
        assert_eq!(detected, target);

        let mut a_resp = Message::new(42, MessageType::Response, OpCode::Query);
        a_resp.metadata.response_code = ResponseCode::NoError;
        a_resp.add_answer(Record::from_rdata(
            target.clone(),
            300,
            RData::A(A("93.184.216.34".parse().unwrap())),
        ));

        let prefix = Dns64Prefix::parse("64:ff9b::/96").unwrap();
        let synth_bytes = build_dns64_response(&req, &aaaa_resp, &a_resp, &[prefix])
            .unwrap()
            .unwrap();
        let synth = Message::from_vec(&synth_bytes).unwrap();
        assert_eq!(synth.answers.len(), 2);
        assert!(matches!(synth.answers[0].data, RData::CNAME(_)));
        assert_eq!(
            synth.answers[1].data,
            RData::AAAA(AAAA("64:ff9b::5db8:d822".parse().unwrap()))
        );
    }
}
