use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Instant;

use dashmap::DashMap;

use crate::error::{CoreError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpNet {
    V4 { network: u32, mask: u32 },
    V6 { network: u128, mask: u128 },
}

impl IpNet {
    pub fn parse(raw: &str) -> Result<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(CoreError::Config("empty CIDR entry".to_string()));
        }

        if let Some((ip_str, prefix_str)) = trimmed.split_once('/') {
            let ip: IpAddr = ip_str
                .trim()
                .parse()
                .map_err(|_| CoreError::Config(format!("invalid CIDR IP: {trimmed}")))?;
            let prefix: u8 = prefix_str
                .trim()
                .parse()
                .map_err(|_| CoreError::Config(format!("invalid CIDR prefix: {trimmed}")))?;
            return Self::from_ip_prefix(ip, prefix, trimmed);
        }

        let ip: IpAddr = trimmed
            .parse()
            .map_err(|_| CoreError::Config(format!("invalid IP/CIDR: {trimmed}")))?;
        let prefix = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        Self::from_ip_prefix(ip, prefix, trimmed)
    }

    fn from_ip_prefix(ip: IpAddr, prefix: u8, raw: &str) -> Result<Self> {
        match ip {
            IpAddr::V4(v4) => {
                if prefix > 32 {
                    return Err(CoreError::Config(format!("invalid IPv4 prefix: {raw}")));
                }
                let mask = if prefix == 0 {
                    0
                } else {
                    !0_u32 << (32 - u32::from(prefix))
                };
                let network = u32::from(v4) & mask;
                Ok(Self::V4 { network, mask })
            }
            IpAddr::V6(v6) => {
                if prefix > 128 {
                    return Err(CoreError::Config(format!("invalid IPv6 prefix: {raw}")));
                }
                let mask = if prefix == 0 {
                    0
                } else {
                    !0_u128 << (128 - u32::from(prefix))
                };
                let network = u128::from(v6) & mask;
                Ok(Self::V6 { network, mask })
            }
        }
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (Self::V4 { network, mask }, IpAddr::V4(v4)) => (u32::from(v4) & *mask) == *network,
            (Self::V6 { network, mask }, IpAddr::V6(v6)) => (u128::from(v6) & *mask) == *network,
            (Self::V4 { .. }, IpAddr::V6(v6)) => {
                v6.to_ipv4_mapped().is_some_and(|v4| self.contains_v4(v4))
            }
            (Self::V6 { .. }, IpAddr::V4(v4)) => self.contains_v6(v4.to_ipv6_mapped()),
        }
    }

    fn contains_v4(self, v4: Ipv4Addr) -> bool {
        matches!(self, Self::V4 { network, mask } if (u32::from(v4) & mask) == network)
    }

    fn contains_v6(self, v6: Ipv6Addr) -> bool {
        matches!(self, Self::V6 { network, mask } if (u128::from(v6) & mask) == network)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclDecision {
    Allow,
    DeniedAcl,
    RateLimited,
}

#[derive(Debug, Clone, Copy)]
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

pub struct AccessController {
    allow_cidrs: Vec<IpNet>,
    deny_cidrs: Vec<IpNet>,
    rate_limit_qps: u32,
    buckets: DashMap<IpAddr, TokenBucket>,
}

impl AccessController {
    pub fn new(allow_specs: &[String], deny_specs: &[String], rate_limit_qps: u32) -> Result<Self> {
        let allow_cidrs = parse_cidr_list(allow_specs)?;
        let deny_cidrs = parse_cidr_list(deny_specs)?;
        Ok(Self {
            allow_cidrs,
            deny_cidrs,
            rate_limit_qps,
            buckets: DashMap::new(),
        })
    }

    pub fn check(&self, client_ip: IpAddr) -> AclDecision {
        if self.deny_cidrs.iter().any(|net| net.contains(client_ip)) {
            return AclDecision::DeniedAcl;
        }
        if !self.allow_cidrs.is_empty()
            && !self.allow_cidrs.iter().any(|net| net.contains(client_ip))
        {
            return AclDecision::DeniedAcl;
        }
        if self.rate_limit_qps > 0 && !self.consume_token(client_ip) {
            return AclDecision::RateLimited;
        }
        AclDecision::Allow
    }

    fn consume_token(&self, client_ip: IpAddr) -> bool {
        const MAX_TRACKED_CLIENTS: usize = 65_536;
        if self.buckets.len() > MAX_TRACKED_CLIENTS {
            let now = Instant::now();
            self.buckets
                .retain(|_, b| now.duration_since(b.last_refill).as_secs() < 60);
        }

        let now = Instant::now();
        let rate = f64::from(self.rate_limit_qps);
        let mut entry = self.buckets.entry(client_ip).or_insert(TokenBucket {
            tokens: rate,
            last_refill: now,
        });

        let elapsed = now.duration_since(entry.last_refill).as_secs_f64();
        entry.tokens = (entry.tokens + elapsed * rate).min(rate);
        entry.last_refill = now;

        if entry.tokens >= 1.0 {
            entry.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

pub fn parse_cidr_list(specs: &[String]) -> Result<Vec<IpNet>> {
    specs
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(IpNet::parse)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cidr_parsing_and_matching() {
        let net4 = IpNet::parse("192.168.1.0/24").expect("valid v4 cidr");
        assert!(net4.contains("192.168.1.50".parse().expect("ip")));
        assert!(!net4.contains("192.168.2.1".parse().expect("ip")));

        let single = IpNet::parse("10.0.0.5").expect("valid single ip");
        assert!(single.contains("10.0.0.5".parse().expect("ip")));
        assert!(!single.contains("10.0.0.6".parse().expect("ip")));

        let net6 = IpNet::parse("fd00::/8").expect("valid v6 cidr");
        assert!(net6.contains("fd12:3456::1".parse().expect("ip")));
        assert!(!net6.contains("2001:db8::1".parse().expect("ip")));

        assert!(IpNet::parse("192.168.1.0/33").is_err());
        assert!(IpNet::parse("not-an-ip").is_err());
    }

    #[test]
    fn test_acl_allow_deny_and_ratelimit() {
        let acl = AccessController::new(
            &["192.168.0.0/16".to_string()],
            &["192.168.1.99".to_string()],
            2,
        )
        .expect("valid acl");

        let denied_ip: IpAddr = "192.168.1.99".parse().expect("ip");
        assert_eq!(acl.check(denied_ip), AclDecision::DeniedAcl);

        let outside_ip: IpAddr = "8.8.8.8".parse().expect("ip");
        assert_eq!(acl.check(outside_ip), AclDecision::DeniedAcl);

        let ok_ip: IpAddr = "192.168.1.10".parse().expect("ip");
        assert_eq!(acl.check(ok_ip), AclDecision::Allow);
        assert_eq!(acl.check(ok_ip), AclDecision::Allow);
        assert_eq!(acl.check(ok_ip), AclDecision::RateLimited);
    }
}
