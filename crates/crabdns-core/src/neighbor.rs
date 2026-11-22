use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;

use foldhash::fast::RandomState;

pub const PROC_NET_ARP_PATH: &str = "/proc/net/arp";

/// Normalizes a MAC address (`aa:bb:cc:dd:ee:ff`, `aa-bb-cc-dd-ee-ff`, `aabb.ccdd.eeff`)
/// to lowercase colon-separated `aa:bb:cc:dd:ee:ff`.
pub fn normalize_mac(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let bytes = if trimmed.contains(':') {
        parse_separated_mac(trimmed, ':')?
    } else if trimmed.contains('-') {
        parse_separated_mac(trimmed, '-')?
    } else if trimmed.contains('.') {
        parse_dotted_mac(trimmed)?
    } else {
        return None;
    };

    Some(format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    ))
}

fn parse_separated_mac(raw: &str, sep: char) -> Option<[u8; 6]> {
    let mut parts = raw.split(sep);
    let mut out = [0_u8; 6];
    for slot in &mut out {
        let part = parts.next()?;
        if part.len() != 2 || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        *slot = u8::from_str_radix(part, 16).ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(out)
}

fn parse_dotted_mac(raw: &str) -> Option<[u8; 6]> {
    let mut parts = raw.split('.');
    let mut out = [0_u8; 6];
    for idx in 0..3 {
        let part = parts.next()?;
        if part.len() != 4 || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        out[idx * 2] = u8::from_str_radix(&part[0..2], 16).ok()?;
        out[idx * 2 + 1] = u8::from_str_radix(&part[2..4], 16).ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(out)
}

fn is_usable_neighbor_mac(mac: &str) -> bool {
    mac != "00:00:00:00:00:00" && mac != "ff:ff:ff:ff:ff:ff"
}

#[derive(Debug, Clone, Default)]
pub struct NeighborTable {
    entries: HashMap<IpAddr, String, RandomState>,
}

impl NeighborTable {
    pub fn from_proc_arp_file(path: &Path) -> std::io::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Ok(Self::parse_proc_net_arp(&content))
    }

    /// Parses Linux `/proc/net/arp` content.
    pub fn parse_proc_net_arp(content: &str) -> Self {
        let mut entries = HashMap::with_hasher(RandomState::default());
        for (idx, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || (idx == 0 && trimmed.starts_with("IP address")) {
                continue;
            }
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() < 4 {
                continue;
            }
            let Ok(ip) = parts[0].parse::<IpAddr>() else {
                continue;
            };
            // Flags 0x0 means incomplete ARP entry.
            if parts[2] == "0x0" {
                continue;
            }
            if let Some(mac) = normalize_mac(parts[3])
                && is_usable_neighbor_mac(&mac)
            {
                entries.insert(ip, mac);
            }
        }
        Self { entries }
    }

    /// Parses `ip neigh show` output (covers both IPv4 ARP and IPv6 NDP).
    pub fn parse_ip_neigh(content: &str) -> Self {
        let mut entries = HashMap::with_hasher(RandomState::default());
        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }
            let Ok(ip) = parts[0].parse::<IpAddr>() else {
                continue;
            };
            if let Some(lladdr_pos) = parts.iter().position(|&p| p == "lladdr")
                && let Some(raw_mac) = parts.get(lladdr_pos + 1)
                && let Some(mac) = normalize_mac(raw_mac)
                && is_usable_neighbor_mac(&mac)
            {
                entries.insert(ip, mac);
            }
        }
        Self { entries }
    }

    /// Loads system neighbor mappings from `/proc/net/arp` and `ip neigh show` (best-effort).
    pub fn load_system() -> Self {
        let mut table = Self::from_proc_arp_file(Path::new(PROC_NET_ARP_PATH)).unwrap_or_default();
        if let Ok(output) = std::process::Command::new("ip")
            .args(["neigh", "show"])
            .output()
            && output.status.success()
            && let Ok(stdout) = std::str::from_utf8(&output.stdout)
        {
            let neigh = Self::parse_ip_neigh(stdout);
            for (ip, mac) in neigh.entries {
                table.entries.entry(ip).or_insert(mac);
            }
        }
        table
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<&str> {
        self.entries.get(&ip).map(String::as_str)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_mac_formats() {
        assert_eq!(
            normalize_mac("AA:BB:CC:DD:EE:FF"),
            Some("aa:bb:cc:dd:ee:ff".to_string())
        );
        assert_eq!(
            normalize_mac("aa-bb-cc-11-22-33"),
            Some("aa:bb:cc:11:22:33".to_string())
        );
        assert_eq!(
            normalize_mac("AABB.CCDD.EEFF"),
            Some("aa:bb:cc:dd:ee:ff".to_string())
        );
        assert_eq!(normalize_mac("not-a-mac"), None);
        assert_eq!(normalize_mac("living-room-tv"), None);
        assert_eq!(normalize_mac("aa:bb:cc:dd:ee"), None);
    }

    #[test]
    fn test_parse_proc_net_arp() {
        let sample = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.10     0x1         0x2         aa:bb:cc:dd:ee:01     *        eth0
192.168.1.11     0x1         0x0         00:00:00:00:00:00     *        eth0
192.168.1.12     0x1         0x2         ff:ff:ff:ff:ff:ff     *        eth0
";
        let table = NeighborTable::parse_proc_net_arp(sample);
        assert_eq!(
            table.lookup("192.168.1.10".parse().unwrap()),
            Some("aa:bb:cc:dd:ee:01")
        );
        assert_eq!(table.lookup("192.168.1.11".parse().unwrap()), None);
        assert_eq!(table.lookup("192.168.1.12".parse().unwrap()), None);
    }

    #[test]
    fn test_parse_ip_neigh() {
        let sample = "\
192.168.1.20 dev eth0 lladdr AA:BB:CC:11:22:33 REACHABLE
fe80::1234 dev eth0 lladdr aa:bb:cc:44:55:66 STALE
192.168.1.21 dev eth0 FAILED
";
        let table = NeighborTable::parse_ip_neigh(sample);
        assert_eq!(
            table.lookup("192.168.1.20".parse().unwrap()),
            Some("aa:bb:cc:11:22:33")
        );
        assert_eq!(
            table.lookup("fe80::1234".parse().unwrap()),
            Some("aa:bb:cc:44:55:66")
        );
        assert_eq!(table.lookup("192.168.1.21".parse().unwrap()), None);
    }
}
