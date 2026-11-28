use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
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
use crate::lan::{HostsMatch, is_local_domain, parse_ptr_ip};
use crate::upstream::next_tx_id;

pub(crate) fn clean_hostname(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_end_matches('.').trim();
    if trimmed.is_empty() || trimmed == "*" || trimmed == "?" {
        return None;
    }
    if trimmed.parse::<IpAddr>().is_ok() {
        return None;
    }
    Some(trimmed.to_string())
}

const MDNS_CACHE_CAPACITY: u64 = 4096;
const MDNS_CACHE_TTL: Duration = Duration::from_mins(15);
const MDNS_FORWARD_TTL: Duration = Duration::from_secs(60);
const MDNS_QUERY_TIMEOUT: Duration = Duration::from_millis(700);
const MAX_INFLIGHT_MDNS: usize = 16;
const MAX_PASSIVE_MDNS_ENTRIES: usize = 4096;

pub const MDNS_V4_ADDR: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 251), 5353));
pub const MDNS_V6_ADDR: SocketAddr = SocketAddr::V6(SocketAddrV6::new(
    Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x00fb),
    5353,
    0,
    0,
));

pub struct MdnsNameResolver {
    passive: Arc<DashMap<IpAddr, String, RandomState>>,
    active_cache: Cache<IpAddr, Option<String>, RandomState>,
    forward_v4: Cache<String, Option<Vec<Ipv4Addr>>, RandomState>,
    forward_v6: Cache<String, Option<Vec<Ipv6Addr>>, RandomState>,
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
        let forward_v4 = Cache::builder()
            .max_capacity(MDNS_CACHE_CAPACITY)
            .time_to_live(MDNS_FORWARD_TTL)
            .build_with_hasher(RandomState::default());
        let forward_v6 = Cache::builder()
            .max_capacity(MDNS_CACHE_CAPACITY)
            .time_to_live(MDNS_FORWARD_TTL)
            .build_with_hasher(RandomState::default());
        Self {
            passive: Arc::new(DashMap::with_hasher(RandomState::default())),
            active_cache,
            forward_v4,
            forward_v6,
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
            if self.passive.len() < MAX_PASSIVE_MDNS_ENTRIES || self.passive.contains_key(&ip) {
                self.passive.insert(ip, clean.clone());
            }
            self.active_cache.insert(ip, Some(clean.clone()));
            let lower = clean.to_ascii_lowercase();
            let fqdn = if is_local_domain(&lower) {
                lower
            } else {
                format!("{lower}.local")
            };
            match ip {
                IpAddr::V4(v4) => {
                    let mut list = self.forward_v4.get(&fqdn).flatten().unwrap_or_default();
                    if !list.contains(&v4) {
                        list.push(v4);
                    }
                    self.forward_v4.insert(fqdn, Some(list));
                }
                IpAddr::V6(v6) => {
                    let mut list = self.forward_v6.get(&fqdn).flatten().unwrap_or_default();
                    if !list.contains(&v6) {
                        list.push(v6);
                    }
                    self.forward_v6.insert(fqdn, Some(list));
                }
            }
        }
    }

    /// Looks up a cached `.local` hostname for `A`, `AAAA`, or `PTR` queries.
    pub fn lookup_forward_cached(&self, domain: &str, qtype: RecordType) -> Option<HostsMatch> {
        let norm = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        match qtype {
            RecordType::A if is_local_domain(&norm) => {
                self.forward_v4.get(&norm).flatten().map(HostsMatch::V4)
            }
            RecordType::AAAA if is_local_domain(&norm) => {
                self.forward_v6.get(&norm).flatten().map(HostsMatch::V6)
            }
            RecordType::PTR => parse_ptr_ip(&norm)
                .and_then(|ip| self.lookup_cached(ip).flatten())
                .map(HostsMatch::Ptr),
            _ => None,
        }
    }

    /// Resolves a `.local` hostname via mDNS cache or active multicast query.
    pub async fn resolve_forward(&self, domain: &str, qtype: RecordType) -> Option<HostsMatch> {
        let norm = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if !matches!(qtype, RecordType::A | RecordType::AAAA | RecordType::PTR) {
            return None;
        }
        if qtype != RecordType::PTR && !is_local_domain(&norm) {
            return None;
        }
        match qtype {
            RecordType::A => {
                if let Some(cached) = self.forward_v4.get(&norm) {
                    return cached.map(HostsMatch::V4);
                }
            }
            RecordType::AAAA => {
                if let Some(cached) = self.forward_v6.get(&norm) {
                    return cached.map(HostsMatch::V6);
                }
            }
            RecordType::PTR => {
                if let Some(ip) = parse_ptr_ip(&norm)
                    && let Some(cached) = self.lookup_cached(ip)
                {
                    return cached.map(HostsMatch::Ptr);
                }
            }
            _ => return None,
        }

        let Ok(_permit) = Arc::clone(&self.limiter).try_acquire_owned() else {
            return None;
        };
        if let Some(wire) = query_mdns_raw(&norm, qtype).await {
            self.ingest_mdns_packet(&wire);
        }
        let matched = self.lookup_forward_cached(&norm, qtype);
        if matched.is_none() {
            match qtype {
                RecordType::A => self.forward_v4.insert(norm, None),
                RecordType::AAAA => self.forward_v6.insert(norm, None),
                _ => {}
            }
        }
        matched
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
                    let norm = owner.trim().trim_end_matches('.').to_ascii_lowercase();
                    if let Some(ip) = parse_ptr_ip(&norm) {
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

async fn query_mdns_ptr(ip: IpAddr) -> Option<String> {
    let ptr_domain = ip_to_ptr_domain(ip);
    let wire = query_mdns_raw(&ptr_domain, RecordType::PTR).await?;
    let resp = Message::from_vec(&wire).ok()?;
    for answer in &resp.answers {
        if let RData::PTR(ptr) = &answer.data
            && let Some(host) = clean_hostname(&ptr.to_utf8())
        {
            return Some(host);
        }
    }
    None
}

async fn query_mdns_raw(domain: &str, qtype: RecordType) -> Option<Vec<u8>> {
    let fqdn = format!("{}.", domain.trim_end_matches('.'));
    let name = Name::from_ascii(&fqdn).ok()?;
    let tx_id = next_tx_id();
    let mut msg = Message::new(tx_id, MessageType::Query, OpCode::Query);
    msg.add_query(Query::query(name, qtype));
    let wire = msg.to_vec().ok()?;

    let use_v6 = matches!(qtype, RecordType::AAAA)
        || (qtype == RecordType::PTR && domain.ends_with(".ip6.arpa"));
    let (bind_addr, target): (SocketAddr, SocketAddr) = if use_v6 {
        (
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
            MDNS_V6_ADDR,
        )
    } else {
        (
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            MDNS_V4_ADDR,
        )
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
    Some(buf[..len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::Record;
    use hickory_proto::rr::rdata::{A, PTR};

    #[test]
    fn test_mdns_packet_ingestion_and_forward_lookup() {
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
        assert_eq!(
            resolver.lookup_forward_cached("printer.local", RecordType::A),
            Some(HostsMatch::V4(vec![Ipv4Addr::new(192, 168, 1, 88)]))
        );
    }
}
