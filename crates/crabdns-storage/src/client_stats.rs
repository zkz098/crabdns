use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};

use chrono::{DateTime, Utc};
use crabdns_core::{QueryEvent, QueryOutcome, QueryProtocol};
use dashmap::DashMap;
use foldhash::fast::RandomState;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::TopItem;

const MAX_TRACKED_CLIENTS: usize = 4096;
const MAX_TRACKED_PROFILES: usize = 2048;
const MAX_PER_CLIENT_DOMAINS: usize = 64;
const TOP_PER_CLIENT: usize = 5;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ClientProtocolCounts {
    #[ts(type = "number")]
    pub udp: u64,
    #[ts(type = "number")]
    pub tcp: u64,
    #[ts(type = "number")]
    pub dot: u64,
    #[ts(type = "number")]
    pub doq: u64,
    #[ts(type = "number")]
    pub doh: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ClientActivityStats {
    #[ts(type = "number")]
    pub total_queries: u64,
    #[ts(type = "number")]
    pub blocked_queries: u64,
    #[ts(type = "number")]
    pub cached_queries: u64,
    #[ts(type = "number")]
    pub rewritten_queries: u64,
    #[ts(type = "number")]
    pub error_queries: u64,
    pub block_rate: f64,
    pub last_seen: Option<DateTime<Utc>>,
    pub last_client_id: Option<String>,
    pub protocols: ClientProtocolCounts,
    pub top_domains: Vec<TopItem>,
    pub top_blocked: Vec<TopItem>,
}

#[derive(Debug, Clone)]
struct ClientEntry {
    total_queries: u64,
    blocked_queries: u64,
    cached_queries: u64,
    rewritten_queries: u64,
    error_queries: u64,
    last_seen: DateTime<Utc>,
    last_client_id: Option<String>,
    protocols: ClientProtocolCounts,
    domains: HashMap<String, u64, RandomState>,
    blocked_domains: HashMap<String, u64, RandomState>,
}

impl ClientEntry {
    fn new(ts: DateTime<Utc>) -> Self {
        Self {
            total_queries: 0,
            blocked_queries: 0,
            cached_queries: 0,
            rewritten_queries: 0,
            error_queries: 0,
            last_seen: ts,
            last_client_id: None,
            protocols: ClientProtocolCounts::default(),
            domains: HashMap::with_hasher(RandomState::default()),
            blocked_domains: HashMap::with_hasher(RandomState::default()),
        }
    }

    fn record(&mut self, event: &QueryEvent) {
        self.total_queries = self.total_queries.saturating_add(1);
        if event.timestamp > self.last_seen {
            self.last_seen = event.timestamp;
        }
        if let Some(cid) = &event.client_id {
            self.last_client_id = Some(cid.clone());
        }
        match event.outcome {
            QueryOutcome::Blocked => {
                self.blocked_queries = self.blocked_queries.saturating_add(1);
                increment_bounded(&mut self.blocked_domains, &event.domain);
            }
            QueryOutcome::Cached => self.cached_queries = self.cached_queries.saturating_add(1),
            QueryOutcome::Rewritten => {
                self.rewritten_queries = self.rewritten_queries.saturating_add(1);
            }
            QueryOutcome::Error => self.error_queries = self.error_queries.saturating_add(1),
            QueryOutcome::Forwarded => {}
        }
        match event.protocol {
            QueryProtocol::Udp => self.protocols.udp = self.protocols.udp.saturating_add(1),
            QueryProtocol::Tcp => self.protocols.tcp = self.protocols.tcp.saturating_add(1),
            QueryProtocol::Dot => self.protocols.dot = self.protocols.dot.saturating_add(1),
            QueryProtocol::Doq => self.protocols.doq = self.protocols.doq.saturating_add(1),
            QueryProtocol::Doh => self.protocols.doh = self.protocols.doh.saturating_add(1),
        }
        increment_bounded(&mut self.domains, &event.domain);
    }

    fn to_snapshot(&self) -> ClientActivityStats {
        #[allow(clippy::cast_precision_loss)]
        let block_rate = if self.total_queries == 0 {
            0.0
        } else {
            self.blocked_queries as f64 / self.total_queries as f64
        };
        ClientActivityStats {
            total_queries: self.total_queries,
            blocked_queries: self.blocked_queries,
            cached_queries: self.cached_queries,
            rewritten_queries: self.rewritten_queries,
            error_queries: self.error_queries,
            block_rate,
            last_seen: Some(self.last_seen),
            last_client_id: self.last_client_id.clone(),
            protocols: self.protocols.clone(),
            top_domains: top_from_map(&self.domains, TOP_PER_CLIENT),
            top_blocked: top_from_map(&self.blocked_domains, TOP_PER_CLIENT),
        }
    }
}

fn increment_bounded(map: &mut HashMap<String, u64, RandomState>, key: &str) {
    if let Some(count) = map.get_mut(key) {
        *count = count.saturating_add(1);
        return;
    }
    if map.len() >= MAX_PER_CLIENT_DOMAINS {
        map.retain(|_, v| {
            *v /= 2;
            *v > 0
        });
        if map.len() >= MAX_PER_CLIENT_DOMAINS {
            return;
        }
    }
    map.insert(key.to_string(), 1);
}

fn top_from_map(map: &HashMap<String, u64, RandomState>, limit: usize) -> Vec<TopItem> {
    let mut items: Vec<TopItem> = map
        .iter()
        .map(|(k, v)| TopItem {
            name: k.clone(),
            count: *v,
        })
        .collect();
    items.sort_by_key(|a| std::cmp::Reverse(a.count));
    items.truncate(limit);
    items
}

#[derive(Debug, Default)]
pub struct ClientStatsTracker {
    by_ip: DashMap<String, ClientEntry, RandomState>,
    by_profile: DashMap<String, ClientEntry, RandomState>,
    evicting_ip: AtomicBool,
    evicting_profile: AtomicBool,
}

impl ClientStatsTracker {
    pub fn new() -> Self {
        Self {
            by_ip: DashMap::with_hasher(RandomState::default()),
            by_profile: DashMap::with_hasher(RandomState::default()),
            evicting_ip: AtomicBool::new(false),
            evicting_profile: AtomicBool::new(false),
        }
    }

    pub fn record(&self, event: &QueryEvent) {
        record_into_map(
            &self.by_ip,
            &self.evicting_ip,
            MAX_TRACKED_CLIENTS,
            &event.client_ip,
            event,
        );
        if let Some(profile_id) = &event.profile_id {
            record_into_map(
                &self.by_profile,
                &self.evicting_profile,
                MAX_TRACKED_PROFILES,
                profile_id,
                event,
            );
        }
    }

    pub fn list_ip_stats(&self) -> Vec<(String, ClientActivityStats)> {
        let mut out: Vec<(String, ClientActivityStats)> = self
            .by_ip
            .iter()
            .map(|e| (e.key().clone(), e.value().to_snapshot()))
            .collect();
        out.sort_by(|a, b| {
            b.1.last_seen
                .cmp(&a.1.last_seen)
                .then_with(|| b.1.total_queries.cmp(&a.1.total_queries))
        });
        out
    }

    pub fn profile_stats_map(&self) -> HashMap<String, ClientActivityStats> {
        self.by_profile
            .iter()
            .map(|e| (e.key().clone(), e.value().to_snapshot()))
            .collect()
    }
}

fn record_into_map(
    map: &DashMap<String, ClientEntry, RandomState>,
    evicting: &AtomicBool,
    cap: usize,
    key: &str,
    event: &QueryEvent,
) {
    if let Some(mut existing) = map.get_mut(key) {
        existing.record(event);
        return;
    }
    if map.len() >= cap && !evicting.swap(true, Ordering::AcqRel) {
        let mut entries: Vec<(String, DateTime<Utc>)> = map
            .iter()
            .map(|e| (e.key().clone(), e.value().last_seen))
            .collect();
        entries.sort_by_key(|(_, ts)| *ts);
        let remove_count = (entries.len() / 10).max(1);
        for (stale_key, _) in entries.into_iter().take(remove_count) {
            map.remove(&stale_key);
        }
        evicting.store(false, Ordering::Release);
    }
    if map.len() < cap {
        map.entry(key.to_string())
            .and_modify(|e| e.record(event))
            .or_insert_with(|| {
                let mut e = ClientEntry::new(event.timestamp);
                e.record(event);
                e
            });
    }
}
