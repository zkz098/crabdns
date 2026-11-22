use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::Arc;

use foldhash::fast::RandomState;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::rdata::svcb::{Alpn, SVCB, SvcParamKey, SvcParamValue, Unknown};
use hickory_proto::rr::rdata::{A, AAAA, PTR};
use hickory_proto::rr::{Name, RData, Record, RecordType};

use crate::config::UpstreamStrategy;
use crate::error::{CoreError, Result};
use crate::security::is_private_or_special_ip;
use crate::upstream::UpstreamPool;
use crate::wire::base_response;

type FastMap<K, V> = HashMap<K, V, RandomState>;

#[derive(Debug, Clone, Default)]
pub struct HostsTable {
    v4: FastMap<String, Vec<Ipv4Addr>>,
    v6: FastMap<String, Vec<Ipv6Addr>>,
    ptr: FastMap<IpAddr, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostsMatch {
    V4(Vec<Ipv4Addr>),
    V6(Vec<Ipv6Addr>),
    Ptr(String),
}

impl HostsTable {
    pub fn from_file(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Ok(Self::parse(&content))
    }

    pub fn parse(content: &str) -> Self {
        let mut table = Self::default();
        for raw_line in content.lines() {
            let line = raw_line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let mut parts = line.split_whitespace();
            let Some(ip_str) = parts.next() else {
                continue;
            };
            let Ok(ip) = ip_str.parse::<IpAddr>() else {
                continue;
            };
            for host in parts {
                let norm = host.trim_end_matches('.').to_ascii_lowercase();
                if norm.is_empty() {
                    continue;
                }
                match ip {
                    IpAddr::V4(v4) => {
                        let list = table.v4.entry(norm.clone()).or_default();
                        if !list.contains(&v4) {
                            list.push(v4);
                        }
                    }
                    IpAddr::V6(v6) => {
                        let list = table.v6.entry(norm.clone()).or_default();
                        if !list.contains(&v6) {
                            list.push(v6);
                        }
                    }
                }
                table.ptr.entry(ip).or_insert(norm);
            }
        }
        table
    }

    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    pub fn len_entries(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    pub fn lookup(&self, clean_domain: &str, qtype: RecordType) -> Option<HostsMatch> {
        let norm = clean_domain.trim_end_matches('.').to_ascii_lowercase();
        match qtype {
            RecordType::A => self.v4.get(&norm).cloned().map(HostsMatch::V4),
            RecordType::AAAA => self.v6.get(&norm).cloned().map(HostsMatch::V6),
            RecordType::PTR => parse_ptr_ip(&norm)
                .and_then(|ip| self.ptr.get(&ip).cloned())
                .map(HostsMatch::Ptr),
            _ => None,
        }
    }
}

pub fn build_hosts_response(request: &Message, matched: &HostsMatch) -> Result<Vec<u8>> {
    let mut resp = base_response(request, ResponseCode::NoError);
    if let Some(q) = request.queries.first() {
        let name = q.name().clone();
        match matched {
            HostsMatch::V4(ips) => {
                for ip in ips {
                    resp.add_answer(Record::from_rdata(name.clone(), 60, RData::A(A(*ip))));
                }
            }
            HostsMatch::V6(ips) => {
                for ip in ips {
                    resp.add_answer(Record::from_rdata(name.clone(), 60, RData::AAAA(AAAA(*ip))));
                }
            }
            HostsMatch::Ptr(hostname) => {
                let fqdn = format!("{}.", hostname.trim_end_matches('.'));
                if let Ok(ptr_name) = Name::from_ascii(&fqdn) {
                    resp.add_answer(Record::from_rdata(name, 60, RData::PTR(PTR(ptr_name))));
                }
            }
        }
    }
    resp.to_vec()
        .map_err(|e| CoreError::Protocol(e.to_string()))
}

/// Parses an `in-addr.arpa` or `ip6.arpa` domain name into its corresponding `IpAddr`.
pub fn parse_ptr_ip(clean_domain: &str) -> Option<IpAddr> {
    let lower = clean_domain.trim_end_matches('.').to_ascii_lowercase();
    if let Some(prefix) = lower.strip_suffix(".in-addr.arpa") {
        let mut octets = [0_u8; 4];
        let parts: Vec<&str> = prefix.split('.').collect();
        if parts.len() != 4 {
            return None;
        }
        for (i, part) in parts.iter().rev().enumerate() {
            octets[i] = part.parse::<u8>().ok()?;
        }
        return Some(IpAddr::V4(Ipv4Addr::from(octets)));
    }
    if let Some(prefix) = lower.strip_suffix(".ip6.arpa") {
        let nibbles: Vec<&str> = prefix.split('.').collect();
        if nibbles.len() != 32 {
            return None;
        }
        let mut addr_val: u128 = 0;
        for nibble in nibbles.iter().rev() {
            if nibble.len() != 1 {
                return None;
            }
            let val = u8::from_str_radix(nibble, 16).ok()?;
            addr_val = (addr_val << 4) | u128::from(val);
        }
        return Some(IpAddr::V6(Ipv6Addr::from(addr_val)));
    }
    None
}

/// Returns `true` if `clean_domain` is a reverse PTR lookup for a private or special-use IP.
pub fn is_private_ptr_domain(clean_domain: &str) -> bool {
    parse_ptr_ip(clean_domain).is_some_and(is_private_or_special_ip)
}

#[derive(Default)]
pub struct PrivatePtrRouter {
    pub enabled: bool,
    pub pool: Option<Arc<UpstreamPool>>,
}

impl PrivatePtrRouter {
    pub fn new(
        enabled: bool,
        upstreams: &[String],
        timeout_ms: u64,
        strategy: UpstreamStrategy,
        bootstrap_dns: &[String],
    ) -> Result<Self> {
        if !enabled || upstreams.is_empty() {
            return Ok(Self {
                enabled,
                pool: None,
            });
        }
        let pool =
            UpstreamPool::new_with_bootstrap(upstreams, timeout_ms, strategy, bootstrap_dns)?;
        Ok(Self {
            enabled,
            pool: Some(Arc::new(pool)),
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct DdrConfig {
    pub enabled: bool,
    pub hostname: Option<String>,
    pub dot_port: Option<u16>,
    pub doq_port: Option<u16>,
    pub doh_enabled: bool,
    pub doh_port: Option<u16>,
}

/// Returns `true` if the query is an RFC 9462 DDR lookup (`_dns.resolver.arpa` SVCB/HTTPS).
pub fn is_ddr_query(clean_domain: &str, qtype: RecordType) -> bool {
    clean_domain.eq_ignore_ascii_case("_dns.resolver.arpa")
        && matches!(qtype, RecordType::SVCB | RecordType::HTTPS)
}

/// Builds an RFC 9462 DDR `SVCB` response advertising configured DoT/DoH endpoints.
pub fn build_ddr_response(request: &Message, cfg: &DdrConfig) -> Result<Vec<u8>> {
    let mut resp = base_response(request, ResponseCode::NoError);
    let Some(q) = request.queries.first() else {
        return resp
            .to_vec()
            .map_err(|e| CoreError::Protocol(e.to_string()));
    };
    let Some(host) = cfg
        .hostname
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return resp
            .to_vec()
            .map_err(|e| CoreError::Protocol(e.to_string()));
    };
    let fqdn = format!("{}.", host.trim_end_matches('.'));
    let target = Name::from_ascii(&fqdn).map_err(|e| CoreError::Config(e.to_string()))?;
    let owner = q.name().clone();

    if let Some(dot_port) = cfg.dot_port {
        let mut params = vec![(
            SvcParamKey::Alpn,
            SvcParamValue::Alpn(Alpn(vec!["dot".to_string()])),
        )];
        if dot_port != 853 {
            params.push((SvcParamKey::Port, SvcParamValue::Port(dot_port)));
        }
        let svcb = SVCB::new(1, target.clone(), params);
        resp.add_answer(Record::from_rdata(owner.clone(), 300, RData::SVCB(svcb)));
    }

    if let Some(doq_port) = cfg.doq_port {
        let mut params = vec![(
            SvcParamKey::Alpn,
            SvcParamValue::Alpn(Alpn(vec!["doq".to_string()])),
        )];
        if doq_port != 853 {
            params.push((SvcParamKey::Port, SvcParamValue::Port(doq_port)));
        }
        let svcb = SVCB::new(2, target.clone(), params);
        resp.add_answer(Record::from_rdata(owner.clone(), 300, RData::SVCB(svcb)));
    }

    if cfg.doh_enabled {
        let mut params = vec![
            (
                SvcParamKey::Alpn,
                SvcParamValue::Alpn(Alpn(vec!["h2".to_string()])),
            ),
            (
                SvcParamKey::Unknown(7),
                SvcParamValue::Unknown(Unknown(b"/dns-query{?dns}".to_vec())),
            ),
        ];
        if let Some(port) = cfg.doh_port.filter(|&p| p != 443) {
            params.push((SvcParamKey::Port, SvcParamValue::Port(port)));
        }
        let svcb = SVCB::new(3, target, params);
        resp.add_answer(Record::from_rdata(owner, 300, RData::SVCB(svcb)));
    }

    resp.to_vec()
        .map_err(|e| CoreError::Protocol(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, OpCode, Query};

    #[test]
    fn test_hosts_parse_and_lookup() {
        let content = r"
# comment
127.0.0.1 localhost
192.168.1.50 nas.local nas
::1 localhost
fd00::50 nas.local
";
        let table = HostsTable::parse(content);
        assert_eq!(
            table.lookup("nas.local", RecordType::A),
            Some(HostsMatch::V4(vec![Ipv4Addr::new(192, 168, 1, 50)]))
        );
        assert_eq!(
            table.lookup("NAS", RecordType::A),
            Some(HostsMatch::V4(vec![Ipv4Addr::new(192, 168, 1, 50)]))
        );
        assert_eq!(
            table.lookup("nas.local", RecordType::AAAA),
            Some(HostsMatch::V6(vec!["fd00::50".parse().unwrap()]))
        );
        assert_eq!(
            table.lookup("50.1.168.192.in-addr.arpa", RecordType::PTR),
            Some(HostsMatch::Ptr("nas.local".to_string()))
        );
    }

    #[test]
    fn test_private_ptr_detection() {
        assert!(is_private_ptr_domain("1.1.168.192.in-addr.arpa"));
        assert!(is_private_ptr_domain("1.0.0.10.in-addr.arpa"));
        assert!(is_private_ptr_domain("1.0.0.127.in-addr.arpa"));
        assert!(!is_private_ptr_domain("8.8.8.8.in-addr.arpa"));

        assert!(is_private_ptr_domain(
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa"
        ));
    }

    #[test]
    fn test_ddr_response() {
        let mut req = Message::new(7, MessageType::Query, OpCode::Query);
        req.add_query(Query::query(
            Name::from_ascii("_dns.resolver.arpa.").unwrap(),
            RecordType::SVCB,
        ));
        let cfg = DdrConfig {
            enabled: true,
            hostname: Some("dns.home.arpa".to_string()),
            dot_port: Some(853),
            doq_port: None,
            doh_enabled: true,
            doh_port: Some(443),
        };
        let wire = build_ddr_response(&req, &cfg).unwrap();
        let resp = Message::from_vec(&wire).unwrap();
        assert_eq!(resp.answers.len(), 2);
        assert_eq!(resp.answers[0].record_type(), RecordType::SVCB);
    }
}
