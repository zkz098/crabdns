use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use hickory_proto::op::{Edns, Message};
use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsOption};

use crate::error::{CoreError, Result};
use crate::security::is_private_or_special_ip;

#[derive(Debug, Clone)]
pub struct EcsConfig {
    pub enabled: bool,
    pub custom_subnet: Option<(IpAddr, u8)>,
    pub ipv4_prefix: u8,
    pub ipv6_prefix: u8,
}

impl Default for EcsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            custom_subnet: None,
            ipv4_prefix: 24,
            ipv6_prefix: 56,
        }
    }
}

impl EcsConfig {
    pub fn from_parts(
        enabled: bool,
        custom_ip: Option<&str>,
        ipv4_prefix: u8,
        ipv6_prefix: u8,
    ) -> Result<Self> {
        if ipv4_prefix > 32 {
            return Err(CoreError::Config(format!(
                "invalid ecs_ipv4_prefix: {ipv4_prefix} (must be 0..=32)"
            )));
        }
        if ipv6_prefix > 128 {
            return Err(CoreError::Config(format!(
                "invalid ecs_ipv6_prefix: {ipv6_prefix} (must be 0..=128)"
            )));
        }

        let custom_subnet = match custom_ip.map(str::trim).filter(|s| !s.is_empty()) {
            Some(raw) => Some(parse_ecs_custom(raw, ipv4_prefix, ipv6_prefix)?),
            None => None,
        };

        Ok(Self {
            enabled,
            custom_subnet,
            ipv4_prefix,
            ipv6_prefix,
        })
    }
}

fn parse_ecs_custom(raw: &str, default_v4: u8, default_v6: u8) -> Result<(IpAddr, u8)> {
    if let Some((ip_str, prefix_str)) = raw.split_once('/') {
        let ip: IpAddr = ip_str
            .trim()
            .parse()
            .map_err(|_| CoreError::Config(format!("invalid ecs_custom_ip: {raw}")))?;
        let prefix: u8 = prefix_str
            .trim()
            .parse()
            .map_err(|_| CoreError::Config(format!("invalid ecs_custom_ip prefix: {raw}")))?;
        let max_prefix = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix > max_prefix {
            return Err(CoreError::Config(format!(
                "invalid ecs_custom_ip prefix: {raw}"
            )));
        }
        return Ok((mask_ip(ip, prefix), prefix));
    }

    let ip: IpAddr = raw
        .parse()
        .map_err(|_| CoreError::Config(format!("invalid ecs_custom_ip: {raw}")))?;
    let prefix = match ip {
        IpAddr::V4(_) => default_v4,
        IpAddr::V6(_) => default_v6,
    };
    Ok((mask_ip(ip, prefix), prefix))
}

/// Masks `ip` to `prefix` bits so host bits are zeroed per RFC 7871.
pub fn mask_ip(ip: IpAddr, prefix: u8) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let p = prefix.min(32);
            let mask = if p == 0 {
                0
            } else {
                !0_u32 << (32 - u32::from(p))
            };
            IpAddr::V4(Ipv4Addr::from(u32::from(v4) & mask))
        }
        IpAddr::V6(v6) => {
            let p = prefix.min(128);
            let mask = if p == 0 {
                0
            } else {
                !0_u128 << (128 - u32::from(p))
            };
            IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask))
        }
    }
}

/// Resolves the ECS `(masked_ip, prefix)` to send upstream, or `None` if ECS should not be sent.
pub fn resolve_ecs_subnet(cfg: &EcsConfig, client_ip: IpAddr) -> Option<(IpAddr, u8)> {
    if !cfg.enabled {
        return None;
    }
    if let Some(custom) = cfg.custom_subnet {
        return Some(custom);
    }
    if is_private_or_special_ip(client_ip) {
        return None;
    }
    let prefix = match client_ip {
        IpAddr::V4(_) => cfg.ipv4_prefix,
        IpAddr::V6(_) => cfg.ipv6_prefix,
    };
    Some((mask_ip(client_ip, prefix), prefix))
}

/// Injects or replaces the EDNS0 Client Subnet option in `msg`.
pub fn apply_ecs_to_message(msg: &mut Message, subnet: (IpAddr, u8)) {
    let edns = msg.edns.get_or_insert_with(Edns::new);
    if edns.max_payload() < 1232 {
        edns.set_max_payload(1232);
    }
    edns.options_mut()
        .insert(EdnsOption::Subnet(ClientSubnet::new(subnet.0, subnet.1, 0)));
}

/// Returns `true` if the DNS message has the EDNS0 DNSSEC OK (DO) bit set.
pub fn has_dnssec_ok(msg: &Message) -> bool {
    msg.edns.as_ref().is_some_and(|edns| edns.flags().dnssec_ok)
}

/// Sets the EDNS0 DNSSEC OK (DO) bit on the DNS message.
pub fn set_dnssec_ok(msg: &mut Message) {
    let edns = msg.edns.get_or_insert_with(Edns::new);
    if edns.max_payload() < 1232 {
        edns.set_max_payload(1232);
    }
    edns.set_dnssec_ok(true);
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};

    #[test]
    fn test_mask_ip() {
        assert_eq!(
            mask_ip("203.0.113.195".parse().unwrap(), 24),
            "203.0.113.0".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            mask_ip("2001:db8:1234:5678::1".parse().unwrap(), 56),
            "2001:db8:1234:5600::".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn test_resolve_ecs_subnet() {
        let cfg = EcsConfig::from_parts(true, None, 24, 56).unwrap();
        assert_eq!(
            resolve_ecs_subnet(&cfg, "192.168.1.50".parse().unwrap()),
            None
        );
        assert_eq!(
            resolve_ecs_subnet(&cfg, "203.0.113.45".parse().unwrap()),
            Some(("203.0.113.0".parse().unwrap(), 24))
        );

        let custom_cfg = EcsConfig::from_parts(true, Some("198.51.100.77/25"), 24, 56).unwrap();
        assert_eq!(
            resolve_ecs_subnet(&custom_cfg, "192.168.1.50".parse().unwrap()),
            Some(("198.51.100.0".parse().unwrap(), 25))
        );
    }

    #[test]
    fn test_apply_ecs_and_do() {
        let mut msg = Message::new(1, MessageType::Query, OpCode::Query);
        msg.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));
        assert!(!has_dnssec_ok(&msg));

        apply_ecs_to_message(&mut msg, ("203.0.113.0".parse().unwrap(), 24));
        set_dnssec_ok(&mut msg);

        let wire = msg.to_vec().unwrap();
        let parsed = Message::from_vec(&wire).unwrap();
        assert!(has_dnssec_ok(&parsed));
        let edns = parsed.edns.as_ref().unwrap();
        let subnet = edns.options().as_ref().iter().find_map(|opt| match opt {
            (_, EdnsOption::Subnet(cs)) => Some(cs),
            _ => None,
        });
        let cs = subnet.expect("ECS option present");
        assert_eq!(cs.addr(), "203.0.113.0".parse::<IpAddr>().unwrap());
        assert_eq!(cs.source_prefix(), 24);
    }
}
