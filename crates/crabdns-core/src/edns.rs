use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use hickory_proto::op::{Edns, Message};
use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsCode, EdnsOption};

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

pub(crate) fn parse_ecs_custom(raw: &str, default_v4: u8, default_v6: u8) -> Result<(IpAddr, u8)> {
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

pub const EDNS_OPTION_EDE: u16 = 15;
/// Private/experimental EDNS0 option code used by dnsmasq `--add-mac` to carry the client MAC.
pub const EDNS_OPTION_MAC: u16 = 65001;
pub const EDE_STALE_ANSWER: u16 = 3;
pub const EDE_DNSSEC_BOGUS: u16 = 6;
pub const EDE_BLOCKED: u16 = 15;
pub const EDE_FILTERED: u16 = 17;
pub const EDE_PROHIBITED: u16 = 18;
pub const EDE_NO_REACHABLE_AUTHORITY: u16 = 22;
pub const EDE_NETWORK_ERROR: u16 = 23;
pub const DEFAULT_MAX_UDP_PAYLOAD: u16 = 1232;

/// Attaches an RFC 8914 Extended DNS Error option to `response` if `request` included EDNS0.
pub fn attach_ede_to_message(
    request: &Message,
    response: &mut Message,
    info_code: u16,
    extra_text: Option<&str>,
) {
    if request.edns.is_none() {
        return;
    }
    let mut data = Vec::with_capacity(2 + extra_text.map_or(0, str::len));
    data.extend_from_slice(&info_code.to_be_bytes());
    if let Some(text) = extra_text {
        data.extend_from_slice(text.as_bytes());
    }
    let edns = response.edns.get_or_insert_with(Edns::new);
    if edns.max_payload() < DEFAULT_MAX_UDP_PAYLOAD {
        edns.set_max_payload(DEFAULT_MAX_UDP_PAYLOAD);
    }
    edns.options_mut()
        .insert(EdnsOption::Unknown(EDNS_OPTION_EDE, data));
}

/// Attaches an RFC 8914 Extended DNS Error option to serialized `resp_bytes` if `request` included EDNS0.
pub fn attach_ede_to_wire(
    request: &Message,
    resp_bytes: Vec<u8>,
    info_code: u16,
    extra_text: Option<&str>,
) -> Vec<u8> {
    if request.edns.is_none() {
        return resp_bytes;
    }
    let Ok(mut msg) = Message::from_vec(&resp_bytes) else {
        return resp_bytes;
    };
    attach_ede_to_message(request, &mut msg, info_code, extra_text);
    msg.to_vec().unwrap_or(resp_bytes)
}

/// Computes the effective UDP payload size limit from client EDNS0 and server cap (RFC 9715).
pub fn effective_udp_payload_limit(request: &Message, server_max_udp: u16) -> usize {
    let client_max = request
        .edns
        .as_ref()
        .map_or(512, |e| e.max_payload().max(512));
    let server_cap = server_max_udp.max(512);
    usize::from(client_max.min(server_cap))
}

/// Truncates `resp_bytes` with `TC=1` if it exceeds `max_udp` bytes, or forces `TC=1` truncation.
pub fn truncate_dns_response(
    request: &Message,
    resp_bytes: Vec<u8>,
    max_udp: usize,
    force_tc: bool,
) -> Vec<u8> {
    if !force_tc && resp_bytes.len() <= max_udp {
        return resp_bytes;
    }
    let mut msg = Message::from_vec(&resp_bytes).unwrap_or_else(|_| {
        let mut fallback = Message::new(
            request.id,
            hickory_proto::op::MessageType::Response,
            request.op_code,
        );
        fallback.metadata.recursion_desired = request.recursion_desired;
        fallback.metadata.recursion_available = true;
        fallback.metadata.response_code = hickory_proto::op::ResponseCode::NoError;
        if let Some(q) = request.queries.first() {
            fallback.add_query(q.clone());
        }
        fallback
    });
    msg.metadata.truncation = true;
    msg.additionals.clear();
    if let Ok(wire) = msg.to_vec()
        && wire.len() <= max_udp
    {
        return wire;
    }
    msg.authorities.clear();
    if let Ok(wire) = msg.to_vec()
        && wire.len() <= max_udp
    {
        return wire;
    }
    msg.answers.clear();
    if let Ok(wire) = msg.to_vec()
        && wire.len() <= max_udp
    {
        return wire;
    }
    msg.edns = None;
    msg.to_vec().unwrap_or(resp_bytes)
}

/// Extracts and normalizes a client MAC address from EDNS0 option 65001 (`dnsmasq --add-mac`).
///
/// Supports raw 6-byte binary, text (`aa:bb:cc:dd:ee:ff` / `aa-bb-cc-dd-ee-ff`), and 8-char Base64.
pub fn extract_edns_mac(msg: &Message) -> Option<String> {
    let edns = msg.edns.as_ref()?;
    for (code, opt) in edns.options().as_ref() {
        let data = match (code, opt) {
            (EdnsCode::Unknown(EDNS_OPTION_MAC), EdnsOption::Unknown(_, data))
            | (_, EdnsOption::Unknown(EDNS_OPTION_MAC, data)) => data.as_slice(),
            _ => continue,
        };
        if data.len() == 6 {
            return Some(format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                data[0], data[1], data[2], data[3], data[4], data[5]
            ));
        }
        if let Ok(text) = std::str::from_utf8(data) {
            if let Some(norm) = crate::neighbor::normalize_mac(text) {
                return Some(norm);
            }
            if let Some(bytes) = decode_base64_6bytes(text.trim()) {
                return Some(format!(
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
                ));
            }
        }
    }
    None
}

fn decode_base64_6bytes(input: &str) -> Option<[u8; 6]> {
    let bytes = input.as_bytes();
    if bytes.len() != 8 {
        return None;
    }
    let mut vals = [0_u8; 8];
    for (i, &b) in bytes.iter().enumerate() {
        vals[i] = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
    }
    Some([
        (vals[0] << 2) | (vals[1] >> 4),
        (vals[1] << 4) | (vals[2] >> 2),
        (vals[2] << 6) | vals[3],
        (vals[4] << 2) | (vals[5] >> 4),
        (vals[5] << 4) | (vals[6] >> 2),
        (vals[6] << 6) | vals[7],
    ])
}

/// Extracts a non-unspecified client IP from an EDNS0 Client Subnet (ECS) option.
pub fn extract_edns_client_ip(msg: &Message) -> Option<IpAddr> {
    let edns = msg.edns.as_ref()?;
    for (_, opt) in edns.options().as_ref() {
        if let EdnsOption::Subnet(cs) = opt
            && cs.source_prefix() > 0
            && !cs.addr().is_unspecified()
        {
            return Some(cs.addr());
        }
    }
    None
}

/// Returns `true` if `msg` contains EDNS0 option 65001 (client MAC).
pub fn has_edns_mac(msg: &Message) -> bool {
    msg.edns.as_ref().is_some_and(|edns| {
        edns.options().as_ref().iter().any(|(code, opt)| {
            matches!(code, EdnsCode::Unknown(EDNS_OPTION_MAC))
                || matches!(opt, EdnsOption::Unknown(EDNS_OPTION_MAC, _))
        })
    })
}

/// Returns `true` if `msg` contains an EDNS0 Client Subnet option with a private/special IP.
pub fn has_private_ecs(msg: &Message) -> bool {
    msg.edns.as_ref().is_some_and(|edns| {
        edns.options().as_ref().iter().any(
            |(_, opt)| matches!(opt, EdnsOption::Subnet(cs) if is_private_or_special_ip(cs.addr())),
        )
    })
}

/// Strips EDNS0 option 65001 (and optionally private ECS) before forwarding upstream.
pub fn strip_forwarder_edns_options(msg: &mut Message, strip_private_ecs: bool) {
    let Some(edns) = msg.edns.as_mut() else {
        return;
    };
    edns.options_mut()
        .remove(EdnsCode::Unknown(EDNS_OPTION_MAC));
    if strip_private_ecs {
        let has_priv = edns.options().as_ref().iter().any(
            |(_, opt)| matches!(opt, EdnsOption::Subnet(cs) if is_private_or_special_ip(cs.addr())),
        );
        if has_priv {
            edns.options_mut().remove(EdnsCode::Subnet);
        }
    }
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

    #[test]
    fn test_extract_and_strip_forwarder_edns() {
        let mut msg = Message::new(1, MessageType::Query, OpCode::Query);
        msg.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));
        let mut edns = Edns::new();
        edns.options_mut().insert(EdnsOption::Unknown(
            EDNS_OPTION_MAC,
            vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        ));
        edns.options_mut()
            .insert(EdnsOption::Subnet(ClientSubnet::new(
                "192.168.1.42".parse().unwrap(),
                32,
                0,
            )));
        msg.edns = Some(edns);

        assert!(has_edns_mac(&msg));
        assert!(has_private_ecs(&msg));
        assert_eq!(extract_edns_mac(&msg).as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(
            extract_edns_client_ip(&msg),
            Some("192.168.1.42".parse().unwrap())
        );

        strip_forwarder_edns_options(&mut msg, true);
        assert!(!has_edns_mac(&msg));
        assert!(!has_private_ecs(&msg));
        assert_eq!(extract_edns_mac(&msg), None);
        assert_eq!(extract_edns_client_ip(&msg), None);

        // Text & base64 formats
        let mut text_msg = Message::new(2, MessageType::Query, OpCode::Query);
        let mut text_edns = Edns::new();
        text_edns.options_mut().insert(EdnsOption::Unknown(
            EDNS_OPTION_MAC,
            b"AA-BB-CC-11-22-33".to_vec(),
        ));
        text_msg.edns = Some(text_edns);
        assert_eq!(
            extract_edns_mac(&text_msg).as_deref(),
            Some("aa:bb:cc:11:22:33")
        );

        let mut b64_msg = Message::new(3, MessageType::Query, OpCode::Query);
        let mut b64_edns = Edns::new();
        b64_edns
            .options_mut()
            .insert(EdnsOption::Unknown(EDNS_OPTION_MAC, b"qrvM3e7/".to_vec()));
        b64_msg.edns = Some(b64_edns);
        assert_eq!(
            extract_edns_mac(&b64_msg).as_deref(),
            Some("aa:bb:cc:dd:ee:ff")
        );
    }
}
