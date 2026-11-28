use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use foldhash::fast::RandomState;
use hickory_proto::rr::RecordType;

use crate::error::Result;
use crate::lan::{HostsMatch, parse_ptr_ip};
use crate::mdns::clean_hostname;
use crate::neighbor::normalize_mac;

pub const DEFAULT_DHCP_LEASES_PATH: &str = "/var/lib/misc/dnsmasq.leases";
pub const OPENWRT_DHCP_LEASES_PATH: &str = "/tmp/dhcp.leases";

fn is_openwrt_with_dhcp_leases(
    openwrt_release_path: &Path,
    openwrt_version_path: &Path,
    openwrt_leases_path: &Path,
) -> bool {
    (openwrt_release_path.is_file() || openwrt_version_path.is_file())
        && openwrt_leases_path.is_file()
}

/// Returns the default DHCP leases path, preferring `/tmp/dhcp.leases` on `OpenWrt` when present.
pub fn default_dhcp_leases_path() -> &'static str {
    if is_openwrt_with_dhcp_leases(
        Path::new("/etc/openwrt_release"),
        Path::new("/etc/openwrt_version"),
        Path::new(OPENWRT_DHCP_LEASES_PATH),
    ) {
        OPENWRT_DHCP_LEASES_PATH
    } else {
        DEFAULT_DHCP_LEASES_PATH
    }
}

/// Resolves the effective DHCP leases file path from an optional user-configured path.
pub fn resolve_dhcp_leases_path(configured: Option<&str>) -> &str {
    configured
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .unwrap_or_else(|| default_dhcp_leases_path())
}

#[derive(Debug, Clone, Default)]
pub struct DhcpLeaseTable {
    entries: HashMap<IpAddr, String, RandomState>,
    mac_entries: HashMap<IpAddr, String, RandomState>,
    host_v4: HashMap<String, Vec<Ipv4Addr>, RandomState>,
    host_v6: HashMap<String, Vec<Ipv6Addr>, RandomState>,
}

impl DhcpLeaseTable {
    pub fn from_file(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Ok(Self::parse(&content))
    }

    pub fn parse(content: &str) -> Self {
        let trimmed = content.trim_start();
        if trimmed.contains("lease ") && trimmed.contains('{') {
            return Self::parse_isc_dhcpd(content);
        }
        if let Some(first_line) = content.lines().find(|l| !l.trim().is_empty())
            && first_line.contains(',')
            && first_line.to_ascii_lowercase().contains("address")
        {
            return Self::parse_kea_csv(content);
        }
        Self::parse_dnsmasq_or_odhcpd(content)
    }

    fn parse_dnsmasq_or_odhcpd(content: &str) -> Self {
        let mut entries = HashMap::with_hasher(RandomState::default());
        let mut mac_entries = HashMap::with_hasher(RandomState::default());
        for raw_line in content.lines() {
            let line = raw_line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            // dnsmasq: <expiry> <mac> <ip> <hostname> [<client_id>]
            if parts.len() >= 4
                && parts[0].parse::<u64>().is_ok()
                && let Ok(ip) = parts[2].parse::<IpAddr>()
            {
                if let Some(mac) = normalize_mac(parts[1]) {
                    mac_entries.insert(ip, mac);
                }
                if let Some(host) = clean_hostname(parts[3]) {
                    entries.insert(ip, host);
                }
                continue;
            }
            // odhcpd / simple lease line: <ip> <hostname>
            if parts.len() >= 2
                && let Ok(ip) = parts[0].parse::<IpAddr>()
                && let Some(host) = clean_hostname(parts[1])
            {
                entries.insert(ip, host);
            }
        }
        Self::from_maps(entries, mac_entries)
    }

    fn parse_isc_dhcpd(content: &str) -> Self {
        let mut entries = HashMap::with_hasher(RandomState::default());
        let mut mac_entries = HashMap::with_hasher(RandomState::default());
        let mut block = IscLeaseBlock::default();

        for raw_line in content.lines() {
            let line = raw_line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            block.process_line(line, &mut entries, &mut mac_entries);
        }
        Self::from_maps(entries, mac_entries)
    }

    fn parse_kea_csv(content: &str) -> Self {
        let mut entries = HashMap::with_hasher(RandomState::default());
        let mut mac_entries = HashMap::with_hasher(RandomState::default());
        let mut lines = content.lines().filter(|l| !l.trim().is_empty());
        let Some(header) = lines.next() else {
            return Self::default();
        };
        let cols: Vec<String> = header
            .split(',')
            .map(|c| c.trim().to_ascii_lowercase())
            .collect();
        let Some(addr_idx) = cols.iter().position(|c| c == "address") else {
            return Self::default();
        };
        let Some(host_idx) = cols.iter().position(|c| c == "hostname") else {
            return Self::default();
        };
        let hwaddr_idx = cols.iter().position(|c| c == "hwaddr");
        let state_idx = cols.iter().position(|c| c == "state");

        for line in lines {
            let fields: Vec<&str> = line.split(',').collect();
            if let Some(s_idx) = state_idx
                && let Some(state_str) = fields.get(s_idx)
                && state_str.trim() != "0"
            {
                continue;
            }
            let Some(ip_str) = fields.get(addr_idx) else {
                continue;
            };
            let Ok(ip) = ip_str.trim().parse::<IpAddr>() else {
                continue;
            };
            if let Some(hw_idx) = hwaddr_idx
                && let Some(hw_str) = fields.get(hw_idx)
                && let Some(mac) = normalize_mac(hw_str)
            {
                mac_entries.insert(ip, mac);
            }
            if let Some(host_str) = fields.get(host_idx)
                && let Some(host) = clean_hostname(host_str)
            {
                entries.insert(ip, host);
            }
        }
        Self::from_maps(entries, mac_entries)
    }

    fn from_maps(
        entries: HashMap<IpAddr, String, RandomState>,
        mac_entries: HashMap<IpAddr, String, RandomState>,
    ) -> Self {
        let mut host_v4: HashMap<String, Vec<Ipv4Addr>, RandomState> =
            HashMap::with_hasher(RandomState::default());
        let mut host_v6: HashMap<String, Vec<Ipv6Addr>, RandomState> =
            HashMap::with_hasher(RandomState::default());
        for (&ip, host) in &entries {
            let norm = host.trim_end_matches('.').to_ascii_lowercase();
            if norm.is_empty() {
                continue;
            }
            match ip {
                IpAddr::V4(v4) => {
                    let list = host_v4.entry(norm).or_default();
                    if !list.contains(&v4) {
                        list.push(v4);
                    }
                }
                IpAddr::V6(v6) => {
                    let list = host_v6.entry(norm).or_default();
                    if !list.contains(&v6) {
                        list.push(v6);
                    }
                }
            }
        }
        Self {
            entries,
            mac_entries,
            host_v4,
            host_v6,
        }
    }

    /// Resolves a DHCP lease hostname (bare or `<host>.<local_domain>`) or PTR query.
    pub fn lookup_forward(
        &self,
        clean_domain: &str,
        qtype: RecordType,
        local_domain: &str,
    ) -> Option<HostsMatch> {
        let norm = clean_domain
            .trim()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if norm.is_empty() {
            return None;
        }
        let suffix = local_domain.trim().trim_matches('.').to_ascii_lowercase();
        if qtype == RecordType::PTR {
            let ip = parse_ptr_ip(&norm)?;
            let host = self.entries.get(&ip)?.to_ascii_lowercase();
            let fqdn = if suffix.is_empty() || host.contains('.') {
                host
            } else {
                format!("{host}.{suffix}")
            };
            return Some(HostsMatch::Ptr(fqdn));
        }

        let stripped = if suffix.is_empty() {
            None
        } else {
            norm.strip_suffix(&format!(".{suffix}"))
        };
        match qtype {
            RecordType::A => self
                .host_v4
                .get(&norm)
                .or_else(|| stripped.and_then(|label| self.host_v4.get(label)))
                .cloned()
                .map(HostsMatch::V4),
            RecordType::AAAA => self
                .host_v6
                .get(&norm)
                .or_else(|| stripped.and_then(|label| self.host_v6.get(label)))
                .cloned()
                .map(HostsMatch::V6),
            _ => None,
        }
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<&str> {
        self.entries.get(&ip).map(String::as_str)
    }

    pub fn lookup_mac(&self, ip: IpAddr) -> Option<&str> {
        self.mac_entries.get(&ip).map(String::as_str)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

struct IscLeaseBlock {
    ip: Option<IpAddr>,
    host: Option<String>,
    mac: Option<String>,
    active: bool,
}

impl Default for IscLeaseBlock {
    fn default() -> Self {
        Self {
            ip: None,
            host: None,
            mac: None,
            active: true,
        }
    }
}

impl IscLeaseBlock {
    fn reset(&mut self, ip: Option<IpAddr>) {
        self.ip = ip;
        self.host = None;
        self.mac = None;
        self.active = true;
    }

    fn commit(
        &mut self,
        entries: &mut HashMap<IpAddr, String, RandomState>,
        mac_entries: &mut HashMap<IpAddr, String, RandomState>,
    ) {
        if let Some(ip) = self.ip.take() {
            if self.active {
                if let Some(host) = self.host.take() {
                    entries.insert(ip, host);
                }
                if let Some(mac) = self.mac.take() {
                    mac_entries.insert(ip, mac);
                }
            } else {
                entries.remove(&ip);
                mac_entries.remove(&ip);
            }
        }
        self.reset(None);
    }

    fn process_line(
        &mut self,
        line: &str,
        entries: &mut HashMap<IpAddr, String, RandomState>,
        mac_entries: &mut HashMap<IpAddr, String, RandomState>,
    ) {
        if let Some(rest) = line.strip_prefix("lease ") {
            let ip_token = rest.split([' ', '{']).next().unwrap_or("").trim();
            self.reset(ip_token.parse::<IpAddr>().ok());
            return;
        }
        if line.starts_with('}') {
            self.commit(entries, mac_entries);
            return;
        }
        if self.ip.is_none() {
            return;
        }
        if let Some(state_rest) = line
            .strip_prefix("binding state ")
            .or_else(|| line.strip_prefix("BINDING STATE "))
        {
            let state = state_rest.trim_end_matches(';').trim();
            self.active = state.eq_ignore_ascii_case("active");
            return;
        }
        if let Some(hw_rest) = line
            .strip_prefix("hardware ethernet ")
            .or_else(|| line.strip_prefix("HARDWARE ETHERNET "))
        {
            let mac_token = hw_rest.trim_end_matches(';').trim();
            if let Some(mac) = normalize_mac(mac_token) {
                self.mac = Some(mac);
            }
            return;
        }
        if let Some(val) = line
            .strip_prefix("client-hostname ")
            .or_else(|| line.strip_prefix("hostname "))
        {
            let stripped = val.trim().trim_end_matches(';').trim().trim_matches('"');
            if let Some(host) = clean_hostname(stripped) {
                self.host = Some(host);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dnsmasq_leases() {
        let content = r"
1760000000 aa:bb:cc:dd:ee:01 192.168.1.50 macbook-pro 01:aa:bb:cc:dd:ee:01
1760000000 aa:bb:cc:dd:ee:02 192.168.1.51 * *
0 aa:bb:cc:dd:ee:03 fd00::52 nas-v6 *
";
        let table = DhcpLeaseTable::parse(content);
        assert_eq!(
            table.lookup("192.168.1.50".parse().unwrap()),
            Some("macbook-pro")
        );
        assert_eq!(table.lookup("192.168.1.51".parse().unwrap()), None);
        assert_eq!(table.lookup("fd00::52".parse().unwrap()), Some("nas-v6"));
    }

    #[test]
    fn test_parse_isc_dhcpd_and_kea_leases() {
        let isc = r#"
lease 192.168.2.10 {
  starts 4 2026/01/01 00:00:00;
  binding state active;
  client-hostname "living-room-tv";
}
lease 192.168.2.11 {
  binding state free;
  client-hostname "old-device";
}
"#;
        let isc_table = DhcpLeaseTable::parse(isc);
        assert_eq!(
            isc_table.lookup("192.168.2.10".parse().unwrap()),
            Some("living-room-tv")
        );
        assert_eq!(isc_table.lookup("192.168.2.11".parse().unwrap()), None);

        let kea = "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state\n\
10.0.0.25,aa:bb:cc:11:22:33,,3600,1760000000,1,0,0,workstation.lan,0\n\
10.0.0.26,aa:bb:cc:11:22:44,,3600,1760000000,1,0,0,expired-box,2\n";
        let kea_table = DhcpLeaseTable::parse(kea);
        assert_eq!(
            kea_table.lookup("10.0.0.25".parse().unwrap()),
            Some("workstation.lan")
        );
        assert_eq!(kea_table.lookup("10.0.0.26".parse().unwrap()), None);
    }

    #[test]
    fn test_openwrt_dhcp_leases_detection_and_resolution() {
        let dir = tempfile::tempdir().unwrap();
        let release = dir.path().join("openwrt_release");
        let version = dir.path().join("openwrt_version");
        let leases = dir.path().join("dhcp.leases");

        assert!(!is_openwrt_with_dhcp_leases(&release, &version, &leases));

        std::fs::write(&leases, "").unwrap();
        assert!(!is_openwrt_with_dhcp_leases(&release, &version, &leases));

        std::fs::write(&release, "DISTRIB_ID='OpenWrt'\n").unwrap();
        assert!(is_openwrt_with_dhcp_leases(&release, &version, &leases));

        std::fs::remove_file(&release).unwrap();
        std::fs::write(&version, "24.10.0\n").unwrap();
        assert!(is_openwrt_with_dhcp_leases(&release, &version, &leases));

        std::fs::remove_file(&leases).unwrap();
        assert!(!is_openwrt_with_dhcp_leases(&release, &version, &leases));

        assert_eq!(
            resolve_dhcp_leases_path(Some(" /custom/dhcp.leases ")),
            "/custom/dhcp.leases"
        );
        assert_eq!(
            resolve_dhcp_leases_path(Some("   ")),
            default_dhcp_leases_path()
        );
        assert_eq!(resolve_dhcp_leases_path(None), default_dhcp_leases_path());
    }

    #[test]
    fn test_dhcp_lease_forward_and_ptr_lookup() {
        let content = "1710000000 aa:bb:cc:dd:ee:01 192.168.1.50 nas 01:aa\n\
                       1710000000 aa:bb:cc:dd:ee:01 fd00::50 nas 01:aa\n";
        let table = DhcpLeaseTable::parse(content);

        assert_eq!(
            table.lookup_forward("nas.lan", RecordType::A, "lan"),
            Some(HostsMatch::V4(vec![Ipv4Addr::new(192, 168, 1, 50)]))
        );
        assert_eq!(
            table.lookup_forward("nas", RecordType::A, "lan"),
            Some(HostsMatch::V4(vec![Ipv4Addr::new(192, 168, 1, 50)]))
        );
        assert_eq!(
            table.lookup_forward("nas.lan", RecordType::AAAA, "lan"),
            Some(HostsMatch::V6(vec!["fd00::50".parse().unwrap()]))
        );
        assert_eq!(
            table.lookup_forward("50.1.168.192.in-addr.arpa", RecordType::PTR, "lan"),
            Some(HostsMatch::Ptr("nas.lan".to_string()))
        );
        assert!(
            table
                .lookup_forward("other.lan", RecordType::A, "lan")
                .is_none()
        );
    }
}
