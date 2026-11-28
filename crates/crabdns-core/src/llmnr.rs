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
use crate::lan::{HostsMatch, parse_ptr_ip};
use crate::upstream::next_tx_id;

const LLMNR_CACHE_CAPACITY: u64 = 2048;
const LLMNR_CACHE_TTL: Duration = Duration::from_mins(10);
const LLMNR_MISS_TTL: Duration = Duration::from_secs(30);
const LLMNR_QUERY_TIMEOUT: Duration = Duration::from_millis(500);
const MAX_INFLIGHT_LLMNR: usize = 16;
const MAX_PASSIVE_LLMNR_ENTRIES: usize = 2048;

pub const LLMNR_V4_ADDR: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 252), 5355));
pub const LLMNR_V6_ADDR: SocketAddr = SocketAddr::V6(SocketAddrV6::new(
    Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0x0001, 0x0003),
    5355,
    0,
    0,
));

/// Passive and active Link-Local Multicast Name Resolution (LLMNR, RFC 4795) resolver.
pub struct LlmnrNameResolver {
    passive: Arc<DashMap<IpAddr, String, RandomState>>,
    active_cache: Cache<IpAddr, Option<String>, RandomState>,
    forward_v4: Cache<String, Option<Vec<Ipv4Addr>>, RandomState>,
    forward_v6: Cache<String, Option<Vec<Ipv6Addr>>, RandomState>,
    inflight: Arc<DashMap<IpAddr, (), RandomState>>,
    limiter: Arc<Semaphore>,
}

struct LlmnrInflightGuard {
    inflight: Arc<DashMap<IpAddr, (), RandomState>>,
    ip: IpAddr,
}

impl Drop for LlmnrInflightGuard {
    fn drop(&mut self) {
        self.inflight.remove(&self.ip);
    }
}

impl Default for LlmnrNameResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl LlmnrNameResolver {
    pub fn new() -> Self {
        let active_cache = Cache::builder()
            .max_capacity(LLMNR_CACHE_CAPACITY)
            .time_to_live(LLMNR_CACHE_TTL)
            .build_with_hasher(RandomState::default());
        let forward_v4 = Cache::builder()
            .max_capacity(LLMNR_CACHE_CAPACITY)
            .time_to_live(LLMNR_MISS_TTL)
            .build_with_hasher(RandomState::default());
        let forward_v6 = Cache::builder()
            .max_capacity(LLMNR_CACHE_CAPACITY)
            .time_to_live(LLMNR_MISS_TTL)
            .build_with_hasher(RandomState::default());
        Self {
            passive: Arc::new(DashMap::with_hasher(RandomState::default())),
            active_cache,
            forward_v4,
            forward_v6,
            inflight: Arc::new(DashMap::with_hasher(RandomState::default())),
            limiter: Arc::new(Semaphore::new(MAX_INFLIGHT_LLMNR)),
        }
    }

    pub fn lookup_cached(&self, ip: IpAddr) -> Option<Option<String>> {
        if let Some(name) = self.passive.get(&ip) {
            return Some(Some(name.value().clone()));
        }
        self.active_cache.get(&ip)
    }

    pub fn record_discovered(&self, ip: IpAddr, hostname: &str) {
        let Some(clean) = clean_llmnr_hostname(hostname) else {
            return;
        };
        if self.passive.len() < MAX_PASSIVE_LLMNR_ENTRIES || self.passive.contains_key(&ip) {
            self.passive.insert(ip, clean.clone());
        }
        self.active_cache.insert(ip, Some(clean.clone()));
        match ip {
            IpAddr::V4(v4) => {
                let mut list = self.forward_v4.get(&clean).flatten().unwrap_or_default();
                if !list.contains(&v4) {
                    list.push(v4);
                }
                self.forward_v4.insert(clean, Some(list));
            }
            IpAddr::V6(v6) => {
                let mut list = self.forward_v6.get(&clean).flatten().unwrap_or_default();
                if !list.contains(&v6) {
                    list.push(v6);
                }
                self.forward_v6.insert(clean, Some(list));
            }
        }
    }

    pub fn ingest_llmnr_packet(&self, wire: &[u8]) {
        let Ok(msg) = Message::from_vec(wire) else {
            return;
        };
        for record in msg.answers.iter().chain(msg.additionals.iter()) {
            match &record.data {
                RData::A(a) => {
                    self.record_discovered(IpAddr::V4(a.0), &record.name.to_utf8());
                }
                RData::AAAA(aaaa) => {
                    self.record_discovered(IpAddr::V6(aaaa.0), &record.name.to_utf8());
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
        let guard = LlmnrInflightGuard {
            inflight: Arc::clone(&self.inflight),
            ip,
        };
        tokio::spawn(async move {
            let _permit = permit;
            let _guard = guard;
            let resolved = query_llmnr_ptr(ip).await;
            cache.insert(ip, resolved);
        });
    }

    /// Looks up a cached single-label hostname for `A`, `AAAA`, or `PTR` queries.
    pub fn lookup_forward_cached(&self, domain: &str, qtype: RecordType) -> Option<HostsMatch> {
        let norm = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if norm.is_empty() {
            return None;
        }
        match qtype {
            RecordType::A if !norm.contains('.') => {
                self.forward_v4.get(&norm).flatten().map(HostsMatch::V4)
            }
            RecordType::AAAA if !norm.contains('.') => {
                self.forward_v6.get(&norm).flatten().map(HostsMatch::V6)
            }
            RecordType::PTR => parse_ptr_ip(&norm)
                .and_then(|ip| self.lookup_cached(ip).flatten())
                .map(HostsMatch::Ptr),
            _ => None,
        }
    }

    /// Resolves a single-label hostname via LLMNR cache or active multicast query.
    pub async fn resolve_forward(&self, domain: &str, qtype: RecordType) -> Option<HostsMatch> {
        let norm = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if norm.is_empty() || !matches!(qtype, RecordType::A | RecordType::AAAA | RecordType::PTR) {
            return None;
        }
        if qtype != RecordType::PTR && norm.contains('.') {
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
        let resp = query_llmnr_packet(&norm, qtype).await;
        if let Some(ref msg) = resp
            && let Ok(wire) = msg.to_vec()
        {
            self.ingest_llmnr_packet(&wire);
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
}

fn clean_llmnr_hostname(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if trimmed.is_empty() || trimmed == "*" {
        return None;
    }
    Some(trimmed)
}

async fn query_llmnr_ptr(ip: IpAddr) -> Option<String> {
    let ptr_domain = ip_to_ptr_domain(ip);
    let resp = query_llmnr_packet(&ptr_domain, RecordType::PTR).await?;
    for answer in &resp.answers {
        if let RData::PTR(ptr) = &answer.data
            && let Some(host) = clean_llmnr_hostname(&ptr.to_utf8())
        {
            return Some(host);
        }
    }
    None
}

async fn query_llmnr_packet(domain: &str, qtype: RecordType) -> Option<Message> {
    let fqdn = format!("{}.", domain.trim_end_matches('.'));
    let name = Name::from_ascii(&fqdn).ok()?;
    let tx_id = next_tx_id();
    let mut msg = Message::new(tx_id, MessageType::Query, OpCode::Query);
    msg.add_query(Query::query(name, qtype));
    let wire = msg.to_vec().ok()?;

    let use_v6 = matches!(qtype, RecordType::AAAA);
    let (bind_addr, target): (SocketAddr, SocketAddr) = if use_v6 {
        (
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
            LLMNR_V6_ADDR,
        )
    } else {
        (
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            LLMNR_V4_ADDR,
        )
    };

    let sock = UdpSocket::bind(bind_addr).await.ok()?;
    sock.send_to(&wire, target).await.ok()?;

    let mut buf = [0_u8; 1500];
    let (len, _) = tokio::time::timeout(LLMNR_QUERY_TIMEOUT, sock.recv_from(&mut buf))
        .await
        .ok()?
        .ok()?;
    let resp = Message::from_vec(&buf[..len]).ok()?;
    if resp.response_code != ResponseCode::NoError {
        return None;
    }
    Some(resp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::Record;
    use hickory_proto::rr::rdata::A;

    #[test]
    fn test_llmnr_ingest_and_forward_lookup() {
        let resolver = LlmnrNameResolver::new();
        let mut msg = Message::new(42, MessageType::Response, OpCode::Query);
        let name = Name::from_ascii("desktop-win.").expect("valid name");
        msg.add_answer(Record::from_rdata(
            name,
            30,
            RData::A(A(Ipv4Addr::new(192, 168, 1, 88))),
        ));
        let wire = msg.to_vec().expect("encode");
        resolver.ingest_llmnr_packet(&wire);

        assert_eq!(
            resolver.lookup_cached(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 88))),
            Some(Some("desktop-win".to_string()))
        );
        assert_eq!(
            resolver.lookup_forward_cached("desktop-win", RecordType::A),
            Some(HostsMatch::V4(vec![Ipv4Addr::new(192, 168, 1, 88)]))
        );
        assert_eq!(
            resolver.lookup_forward_cached("desktop-win.example.com", RecordType::A),
            None
        );
    }
}
