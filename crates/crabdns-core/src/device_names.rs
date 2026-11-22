use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use foldhash::fast::RandomState;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use moka::sync::Cache;
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;

use crate::clients::ip_to_ptr_domain;
use crate::error::Result;
use crate::upstream::next_tx_id;

const MDNS_CACHE_CAPACITY: u64 = 4096;
const MDNS_CACHE_TTL: Duration = Duration::from_mins(15);
const MDNS_QUERY_TIMEOUT: Duration = Duration::from_millis(700);
const MAX_INFLIGHT_MDNS: usize = 16;
const MAX_PASSIVE_MDNS_ENTRIES: usize = 4096;
const MDNS_V4_ADDR: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 251), 5353));
const MDNS_V6_ADDR: SocketAddr = SocketAddr::V6(SocketAddrV6::new(
    Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x00fb),
    5353,
    0,
    0,
));

#[derive(Debug, Clone, Default)]
pub struct DhcpLeaseTable {
    entries: HashMap<IpAddr, String, RandomState>,
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
                && let Some(host) = clean_hostname(parts[3])
            {
                entries.insert(ip, host);
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
        Self { entries }
    }

    fn parse_isc_dhcpd(content: &str) -> Self {
        let mut entries = HashMap::with_hasher(RandomState::default());
        let mut block = IscLeaseBlock::default();

        for raw_line in content.lines() {
            let line = raw_line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            block.process_line(line, &mut entries);
        }
        Self { entries }
    }

    fn parse_kea_csv(content: &str) -> Self {
        let mut entries = HashMap::with_hasher(RandomState::default());
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
            let Some(host_str) = fields.get(host_idx) else {
                continue;
            };
            if let Ok(ip) = ip_str.trim().parse::<IpAddr>()
                && let Some(host) = clean_hostname(host_str)
            {
                entries.insert(ip, host);
            }
        }
        Self { entries }
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

struct IscLeaseBlock {
    ip: Option<IpAddr>,
    host: Option<String>,
    active: bool,
}

impl Default for IscLeaseBlock {
    fn default() -> Self {
        Self {
            ip: None,
            host: None,
            active: true,
        }
    }
}

impl IscLeaseBlock {
    fn reset(&mut self, ip: Option<IpAddr>) {
        self.ip = ip;
        self.host = None;
        self.active = true;
    }

    fn commit(&mut self, entries: &mut HashMap<IpAddr, String, RandomState>) {
        if let Some(ip) = self.ip.take() {
            if self.active {
                if let Some(host) = self.host.take() {
                    entries.insert(ip, host);
                }
            } else {
                entries.remove(&ip);
            }
        }
        self.reset(None);
    }

    fn process_line(&mut self, line: &str, entries: &mut HashMap<IpAddr, String, RandomState>) {
        if let Some(rest) = line.strip_prefix("lease ") {
            let ip_token = rest.split([' ', '{']).next().unwrap_or("").trim();
            self.reset(ip_token.parse::<IpAddr>().ok());
            return;
        }
        if line.starts_with('}') {
            self.commit(entries);
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

fn clean_hostname(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_end_matches('.').trim();
    if trimmed.is_empty() || trimmed == "*" || trimmed == "?" {
        return None;
    }
    if trimmed.parse::<IpAddr>().is_ok() {
        return None;
    }
    Some(trimmed.to_string())
}

pub struct MdnsNameResolver {
    passive: Arc<DashMap<IpAddr, String, RandomState>>,
    active_cache: Cache<IpAddr, Option<String>, RandomState>,
    inflight: Arc<DashMap<IpAddr, (), RandomState>>,
    limiter: Arc<Semaphore>,
}

struct MdnsInflightGuard {
    inflight: Arc<DashMap<IpAddr, (), RandomState>>,
    ip: IpAddr,
}

impl Drop for MdnsInflightGuard {
    fn drop(&mut self) {
        self.inflight.remove(&self.ip);
    }
}

impl Default for MdnsNameResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl MdnsNameResolver {
    pub fn new() -> Self {
        let active_cache = Cache::builder()
            .max_capacity(MDNS_CACHE_CAPACITY)
            .time_to_live(MDNS_CACHE_TTL)
            .build_with_hasher(RandomState::default());
        Self {
            passive: Arc::new(DashMap::with_hasher(RandomState::default())),
            active_cache,
            inflight: Arc::new(DashMap::with_hasher(RandomState::default())),
            limiter: Arc::new(Semaphore::new(MAX_INFLIGHT_MDNS)),
        }
    }

    pub fn lookup_cached(&self, ip: IpAddr) -> Option<Option<String>> {
        if let Some(name) = self.passive.get(&ip) {
            return Some(Some(name.value().clone()));
        }
        self.active_cache.get(&ip)
    }

    pub fn record_discovered(&self, ip: IpAddr, hostname: &str) {
        if let Some(clean) = clean_hostname(hostname) {
            if self.passive.len() >= MAX_PASSIVE_MDNS_ENTRIES && !self.passive.contains_key(&ip) {
                return;
            }
            self.passive.insert(ip, clean.clone());
            self.active_cache.insert(ip, Some(clean));
        }
    }

    pub fn ingest_mdns_packet(&self, wire: &[u8]) {
        let Ok(msg) = Message::from_vec(wire) else {
            return;
        };
        for record in msg.answers.iter().chain(msg.additionals.iter()) {
            match &record.data {
                RData::A(a) => {
                    let host = record.name.to_utf8();
                    self.record_discovered(IpAddr::V4(a.0), &host);
                }
                RData::AAAA(aaaa) => {
                    let host = record.name.to_utf8();
                    self.record_discovered(IpAddr::V6(aaaa.0), &host);
                }
                RData::PTR(ptr) => {
                    let owner = record.name.to_utf8();
                    if let Some(ip) = parse_ptr_owner_ip(&owner) {
                        self.record_discovered(ip, &ptr.to_utf8());
                    }
                }
                _ => {}
            }
        }
    }

    pub fn spawn_lookup_if_needed(&self, ip: IpAddr) {
        if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
            return;
        }
        if self.passive.contains_key(&ip) || self.active_cache.contains_key(&ip) {
            return;
        }
        let Ok(permit) = Arc::clone(&self.limiter).try_acquire_owned() else {
            return;
        };
        let Entry::Vacant(vacant) = self.inflight.entry(ip) else {
            return;
        };
        vacant.insert(());

        let cache = self.active_cache.clone();
        let guard = MdnsInflightGuard {
            inflight: Arc::clone(&self.inflight),
            ip,
        };
        tokio::spawn(async move {
            let _permit = permit;
            let _guard = guard;
            let resolved = query_mdns_ptr(ip).await;
            cache.insert(ip, resolved);
        });
    }
}

fn parse_ptr_owner_ip(owner: &str) -> Option<IpAddr> {
    let clean = owner.trim().trim_end_matches('.').to_ascii_lowercase();
    if let Some(v4_part) = clean.strip_suffix(".in-addr.arpa") {
        let parts: Vec<&str> = v4_part.split('.').collect();
        if parts.len() == 4 {
            let d: u8 = parts[0].parse().ok()?;
            let c: u8 = parts[1].parse().ok()?;
            let b: u8 = parts[2].parse().ok()?;
            let a: u8 = parts[3].parse().ok()?;
            return Some(IpAddr::V4(Ipv4Addr::new(a, b, c, d)));
        }
    }
    if let Some(v6_part) = clean.strip_suffix(".ip6.arpa") {
        let nibbles: Vec<&str> = v6_part.split('.').collect();
        if nibbles.len() == 32 {
            let mut bytes = [0_u8; 16];
            for (idx, chunk) in nibbles.rchunks_exact(2).enumerate() {
                let high = u8::from_str_radix(chunk[0], 16).ok()?;
                let low = u8::from_str_radix(chunk[1], 16).ok()?;
                bytes[idx] = (high << 4) | low;
            }
            return Some(IpAddr::V6(Ipv6Addr::from(bytes)));
        }
    }
    None
}

async fn query_mdns_ptr(ip: IpAddr) -> Option<String> {
    let ptr_domain = format!("{}.", ip_to_ptr_domain(ip));
    let name = Name::from_ascii(&ptr_domain).ok()?;
    let tx_id = next_tx_id();
    let mut msg = Message::new(tx_id, MessageType::Query, OpCode::Query);
    msg.add_query(Query::query(name, RecordType::PTR));
    let wire = msg.to_vec().ok()?;

    let (bind_addr, target): (SocketAddr, SocketAddr) = match ip {
        IpAddr::V4(_) => (
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            MDNS_V4_ADDR,
        ),
        IpAddr::V6(_) => (
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
            MDNS_V6_ADDR,
        ),
    };

    let sock = UdpSocket::bind(bind_addr).await.ok()?;
    sock.send_to(&wire, target).await.ok()?;

    let mut buf = [0_u8; 1500];
    let (len, _) = tokio::time::timeout(MDNS_QUERY_TIMEOUT, sock.recv_from(&mut buf))
        .await
        .ok()?
        .ok()?;
    let resp = Message::from_vec(&buf[..len]).ok()?;
    if resp.response_code != ResponseCode::NoError {
        return None;
    }
    for answer in &resp.answers {
        if let RData::PTR(ptr) = &answer.data
            && let Some(host) = clean_hostname(&ptr.to_utf8())
        {
            return Some(host);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::Record;
    use hickory_proto::rr::rdata::{A, PTR};

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
    fn test_mdns_packet_ingestion() {
        let resolver = MdnsNameResolver::new();
        let mut msg = Message::new(0, MessageType::Response, OpCode::Query);
        msg.add_answer(Record::from_rdata(
            Name::from_ascii("printer.local.").unwrap(),
            120,
            RData::A(A(Ipv4Addr::new(192, 168, 1, 88))),
        ));
        msg.add_answer(Record::from_rdata(
            Name::from_ascii("99.1.168.192.in-addr.arpa.").unwrap(),
            120,
            RData::PTR(PTR(Name::from_ascii("apple-tv.local.").unwrap())),
        ));
        let wire = msg.to_vec().unwrap();
        resolver.ingest_mdns_packet(&wire);

        assert_eq!(
            resolver.lookup_cached("192.168.1.88".parse().unwrap()),
            Some(Some("printer.local".to_string()))
        );
        assert_eq!(
            resolver.lookup_cached("192.168.1.99".parse().unwrap()),
            Some(Some("apple-tv.local".to_string()))
        );
    }
}
