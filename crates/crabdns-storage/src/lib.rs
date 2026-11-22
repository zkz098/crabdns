use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crabdns_core::{
    ClientGroup, ClientProfile, Config, DnsRewriteEntry, PersistedCacheEntry, QueryEvent,
    QueryOutcome, QueryProtocol,
};

pub mod client_stats;
pub use client_stats::{ClientActivityStats, ClientProtocolCounts, ClientStatsTracker};
use dashmap::DashMap;
use fjall::{Database, Keyspace, KeyspaceCreateOptions};
use foldhash::fast::RandomState;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{Mutex, broadcast, mpsc};
use ts_rs::TS;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("fjall error: {0}")]
    Fjall(#[from] fjall::Error),

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, StorageError>;

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct TopItem {
    pub name: String,
    #[ts(type = "number")]
    pub count: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct TimeSeriesPoint {
    /// Hour bucket start timestamp in Unix milliseconds (UTC).
    #[ts(type = "number")]
    pub timestamp_ms: u64,
    #[ts(type = "number")]
    pub total: u64,
    #[ts(type = "number")]
    pub blocked: u64,
    #[ts(type = "number")]
    pub cached: u64,
    #[ts(type = "number")]
    pub rewritten: u64,
    #[ts(type = "number")]
    pub error: u64,
}

#[derive(Debug, Clone, Default)]
pub struct LogsFilter<'a> {
    pub search: Option<&'a str>,
    pub outcome: Option<&'a str>,
    pub protocol: Option<&'a str>,
    pub qtype: Option<&'a str>,
    pub client: Option<&'a str>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct StatsSnapshot {
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
    pub top_domains: Vec<TopItem>,
    pub top_blocked: Vec<TopItem>,
    pub top_clients: Vec<TopItem>,
    #[serde(default)]
    pub timeseries_24h: Vec<TimeSeriesPoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct FilterSubscription {
    pub id: String,
    pub name: String,
    pub url: String,
    pub enabled: bool,
    pub rule_count: usize,
    pub last_updated: Option<chrono::DateTime<chrono::Utc>>,
    pub last_error: Option<String>,
}

const KEY_CUSTOM_RULES: &[u8] = b"custom_rules";
const KEY_CUSTOM_RULES_ENABLED: &[u8] = b"custom_rules_enabled";
const KEY_SUBSCRIPTIONS: &[u8] = b"subscriptions";
const KEY_COUNTERS: &[u8] = b"counters";
const KEY_TIMESERIES: &[u8] = b"timeseries";
const KEY_RUNTIME_CONFIG: &[u8] = b"runtime_config";
const KEY_CLIENTS: &[u8] = b"clients";
const KEY_CLIENT_GROUPS: &[u8] = b"client_groups";
const KEY_DNS_REWRITES: &[u8] = b"dns_rewrites";

const HOUR_MS: u64 = 3_600_000;
const TIMESERIES_BUCKETS: usize = 24;
const TIMESERIES_RETENTION_MS: u64 = 48 * HOUR_MS;

const FJALL_CACHE_BYTES: u64 = 4 * 1024 * 1024;
const FJALL_MAX_JOURNAL_BYTES: u64 = 64 * 1024 * 1024;
const FJALL_MAX_CACHED_FILES: usize = 64;
const FJALL_WORKER_THREADS: usize = 2;
const FJALL_LOGS_MEMTABLE_BYTES: u64 = 4 * 1024 * 1024;
const FJALL_SMALL_MEMTABLE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_STAT_KEYS: usize = 10_000;
const MAX_LOG_SCAN: usize = 50_000;
const BATCH_CHUNK_SIZE: usize = 1_024;

#[derive(Debug, Default)]
struct BoundedCountMap {
    inner: DashMap<String, u64, RandomState>,
    pruning: AtomicBool,
}

impl BoundedCountMap {
    fn new() -> Self {
        Self {
            inner: DashMap::with_hasher(RandomState::default()),
            pruning: AtomicBool::new(false),
        }
    }

    fn len(&self) -> usize {
        self.inner.len()
    }

    fn clear(&self) {
        self.inner.clear();
        self.inner.shrink_to_fit();
    }

    fn increment(&self, key: &str) {
        if let Some(mut entry) = self.inner.get_mut(key) {
            *entry = entry.saturating_add(1);
            return;
        }
        if self.inner.len() >= MAX_STAT_KEYS {
            self.decay_and_prune();
        }
        if self.inner.len() < MAX_STAT_KEYS {
            self.inner
                .entry(key.to_string())
                .and_modify(|v| *v = v.saturating_add(1))
                .or_insert(1);
        }
    }

    fn decay_and_prune(&self) {
        if self.pruning.swap(true, Ordering::AcqRel) {
            return;
        }
        let before = self.inner.len();
        self.inner.retain(|_, v| *v > 1);
        if self.inner.len() >= (MAX_STAT_KEYS * 9) / 10 {
            self.inner.retain(|_, v| {
                *v /= 2;
                *v > 0
            });
        }
        let after = self.inner.len();
        if after == 0 || after.saturating_mul(4) < before {
            self.inner.shrink_to_fit();
        }
        self.pruning.store(false, Ordering::Release);
    }

    fn top_n(&self, limit: usize) -> Vec<TopItem> {
        let mut items: Vec<TopItem> = self
            .inner
            .iter()
            .map(|entry| TopItem {
                name: entry.key().clone(),
                count: *entry.value(),
            })
            .collect();
        items.sort_by_key(|a| std::cmp::Reverse(a.count));
        items.truncate(limit);
        items
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StorageRuntimeMetrics {
    pub log_batches_written: u64,
    pub log_batch_failures: u64,
    pub log_flush_total_us: u64,
    pub log_pruned_total: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PersistedCounters {
    total: u64,
    blocked: u64,
    cached: u64,
    rewritten: u64,
    error: u64,
}

pub struct StorageEngine {
    db: Database,
    logs: Keyspace,
    meta: Keyspace,
    sub_contents: Keyspace,
    dns_cache: Keyspace,
    seq: AtomicU64,
    total_queries: AtomicU64,
    blocked_queries: AtomicU64,
    cached_queries: AtomicU64,
    rewritten_queries: AtomicU64,
    error_queries: AtomicU64,
    domain_counts: BoundedCountMap,
    blocked_counts: BoundedCountMap,
    client_counts: BoundedCountMap,
    client_stats: ClientStatsTracker,
    hourly_buckets: std::sync::Mutex<HashMap<u64, TimeSeriesPoint>>,
    sub_lock: Mutex<()>,
    client_lock: Mutex<()>,
    config_lock: Mutex<()>,
    rewrite_lock: Mutex<()>,
    log_batches_written: AtomicU64,
    log_batch_failures: AtomicU64,
    log_flush_total_us: AtomicU64,
    log_pruned_total: AtomicU64,
}

impl StorageEngine {
    pub fn open(data_dir: &Path) -> Result<Self> {
        let db = Database::builder(data_dir.join("fjall"))
            .cache_size(FJALL_CACHE_BYTES)
            .max_journaling_size(FJALL_MAX_JOURNAL_BYTES)
            .max_cached_files(Some(FJALL_MAX_CACHED_FILES))
            .worker_threads(FJALL_WORKER_THREADS)
            .open()?;
        let logs = db.keyspace("logs", || {
            KeyspaceCreateOptions::default().max_memtable_size(FJALL_LOGS_MEMTABLE_BYTES)
        })?;
        let meta = db.keyspace("meta", || {
            KeyspaceCreateOptions::default().max_memtable_size(FJALL_SMALL_MEMTABLE_BYTES)
        })?;
        let sub_contents = db.keyspace("sub_contents", || {
            KeyspaceCreateOptions::default().max_memtable_size(FJALL_SMALL_MEMTABLE_BYTES)
        })?;
        let dns_cache = db.keyspace("dns_cache", || {
            KeyspaceCreateOptions::default().max_memtable_size(FJALL_SMALL_MEMTABLE_BYTES)
        })?;

        let persisted = match meta.get(KEY_COUNTERS)? {
            Some(bytes) => serde_json::from_slice::<PersistedCounters>(&bytes).unwrap_or_default(),
            None => PersistedCounters::default(),
        };

        let restored_buckets = match meta.get(KEY_TIMESERIES)? {
            Some(bytes) => serde_json::from_slice::<Vec<TimeSeriesPoint>>(&bytes)
                .unwrap_or_default()
                .into_iter()
                .map(|p| (p.timestamp_ms, p))
                .collect(),
            None => HashMap::new(),
        };

        Ok(Self {
            db,
            logs,
            meta,
            sub_contents,
            dns_cache,
            seq: AtomicU64::new(0),
            total_queries: AtomicU64::new(persisted.total),
            blocked_queries: AtomicU64::new(persisted.blocked),
            cached_queries: AtomicU64::new(persisted.cached),
            rewritten_queries: AtomicU64::new(persisted.rewritten),
            error_queries: AtomicU64::new(persisted.error),
            domain_counts: BoundedCountMap::new(),
            blocked_counts: BoundedCountMap::new(),
            client_counts: BoundedCountMap::new(),
            client_stats: ClientStatsTracker::new(),
            hourly_buckets: std::sync::Mutex::new(restored_buckets),
            sub_lock: Mutex::new(()),
            client_lock: Mutex::new(()),
            config_lock: Mutex::new(()),
            rewrite_lock: Mutex::new(()),
            log_batches_written: AtomicU64::new(0),
            log_batch_failures: AtomicU64::new(0),
            log_flush_total_us: AtomicU64::new(0),
            log_pruned_total: AtomicU64::new(0),
        })
    }

    pub fn runtime_metrics(&self) -> StorageRuntimeMetrics {
        StorageRuntimeMetrics {
            log_batches_written: self.log_batches_written.load(Ordering::Relaxed),
            log_batch_failures: self.log_batch_failures.load(Ordering::Relaxed),
            log_flush_total_us: self.log_flush_total_us.load(Ordering::Relaxed),
            log_pruned_total: self.log_pruned_total.load(Ordering::Relaxed),
        }
    }

    pub fn subscription_lock(&self) -> &Mutex<()> {
        &self.sub_lock
    }

    pub fn client_lock(&self) -> &Mutex<()> {
        &self.client_lock
    }

    pub fn config_lock(&self) -> &Mutex<()> {
        &self.config_lock
    }

    pub fn rewrite_lock(&self) -> &Mutex<()> {
        &self.rewrite_lock
    }

    pub fn record_batch(&self, events: &[QueryEvent]) -> Result<()> {
        if events.is_empty() {
            return Ok(());
        }

        let mut delta_total = 0_u64;
        let mut delta_blocked = 0_u64;
        let mut delta_cached = 0_u64;
        let mut delta_rewritten = 0_u64;
        let mut delta_error = 0_u64;

        let mut batch = self.db.batch();
        for event in events {
            delta_total += 1;
            match event.outcome {
                QueryOutcome::Blocked => delta_blocked += 1,
                QueryOutcome::Cached => delta_cached += 1,
                QueryOutcome::Rewritten => delta_rewritten += 1,
                QueryOutcome::Error => delta_error += 1,
                QueryOutcome::Forwarded => {}
            }
            let ts_ms = event.timestamp.timestamp_millis().max(0).cast_unsigned();
            let seq = self.seq.fetch_add(1, Ordering::Relaxed);
            let key = encode_log_key(ts_ms, seq);
            let value = serde_json::to_vec(event)?;
            batch.insert(&self.logs, key, value);
        }

        let ts_bytes = {
            let mut buckets = self
                .hourly_buckets
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut max_bucket_ms = 0_u64;
            for event in events {
                let ts_ms = event.timestamp.timestamp_millis().max(0).cast_unsigned();
                let bucket_ms = (ts_ms / HOUR_MS) * HOUR_MS;
                max_bucket_ms = max_bucket_ms.max(bucket_ms);
                let point = buckets.entry(bucket_ms).or_insert_with(|| TimeSeriesPoint {
                    timestamp_ms: bucket_ms,
                    ..TimeSeriesPoint::default()
                });
                point.total = point.total.saturating_add(1);
                match event.outcome {
                    QueryOutcome::Blocked => point.blocked = point.blocked.saturating_add(1),
                    QueryOutcome::Cached => point.cached = point.cached.saturating_add(1),
                    QueryOutcome::Rewritten => point.rewritten = point.rewritten.saturating_add(1),
                    QueryOutcome::Error => point.error = point.error.saturating_add(1),
                    QueryOutcome::Forwarded => {}
                }
            }
            let cutoff_ms = max_bucket_ms.saturating_sub(TIMESERIES_RETENTION_MS);
            buckets.retain(|&k, _| k >= cutoff_ms);
            let list: Vec<&TimeSeriesPoint> = buckets.values().collect();
            serde_json::to_vec(&list)?
        };

        let counters = PersistedCounters {
            total: self
                .total_queries
                .load(Ordering::Relaxed)
                .saturating_add(delta_total),
            blocked: self
                .blocked_queries
                .load(Ordering::Relaxed)
                .saturating_add(delta_blocked),
            cached: self
                .cached_queries
                .load(Ordering::Relaxed)
                .saturating_add(delta_cached),
            rewritten: self
                .rewritten_queries
                .load(Ordering::Relaxed)
                .saturating_add(delta_rewritten),
            error: self
                .error_queries
                .load(Ordering::Relaxed)
                .saturating_add(delta_error),
        };
        batch.insert(&self.meta, KEY_COUNTERS, serde_json::to_vec(&counters)?);
        batch.insert(&self.meta, KEY_TIMESERIES, ts_bytes);
        batch.commit()?;

        self.total_queries.fetch_add(delta_total, Ordering::Relaxed);
        self.blocked_queries
            .fetch_add(delta_blocked, Ordering::Relaxed);
        self.cached_queries
            .fetch_add(delta_cached, Ordering::Relaxed);
        self.rewritten_queries
            .fetch_add(delta_rewritten, Ordering::Relaxed);
        self.error_queries.fetch_add(delta_error, Ordering::Relaxed);

        for event in events {
            if event.outcome == QueryOutcome::Blocked {
                self.blocked_counts.increment(&event.domain);
            }
            self.domain_counts.increment(&event.domain);
            self.client_counts.increment(&event.client_ip);
            self.client_stats.record(event);
        }
        Ok(())
    }

    pub fn query_logs(
        &self,
        limit: usize,
        search: Option<&str>,
        outcome_filter: Option<&str>,
    ) -> Result<Vec<QueryEvent>> {
        self.query_logs_filtered(
            limit,
            &LogsFilter {
                search,
                outcome: outcome_filter,
                ..LogsFilter::default()
            },
        )
    }

    pub fn query_logs_filtered(
        &self,
        limit: usize,
        filter: &LogsFilter<'_>,
    ) -> Result<Vec<QueryEvent>> {
        let mut results = Vec::with_capacity(limit.min(500));
        let needle = filter
            .search
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_ascii_lowercase);
        let outcome_expected = filter.outcome.map(str::trim).filter(|s| !s.is_empty());
        let proto_expected = filter
            .protocol
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_ascii_lowercase);
        let qtype_expected = filter
            .qtype
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_ascii_uppercase);
        let client_expected = filter
            .client
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_ascii_lowercase);

        for (scanned, guard) in self.logs.iter().rev().enumerate() {
            if scanned >= MAX_LOG_SCAN {
                break;
            }
            let val = guard.value()?;
            let Ok(event) = serde_json::from_slice::<QueryEvent>(&val) else {
                continue;
            };
            if let Some(ref q) = needle
                && !event_matches_search(&event, q)
            {
                continue;
            }
            if let Some(expected) = outcome_expected
                && outcome_label(&event.outcome) != expected
            {
                continue;
            }
            if let Some(ref proto) = proto_expected
                && protocol_label(event.protocol) != proto
            {
                continue;
            }
            if let Some(ref qt) = qtype_expected
                && !event.qtype.eq_ignore_ascii_case(qt)
            {
                continue;
            }
            if let Some(ref cli) = client_expected
                && !event_matches_client(&event, cli)
            {
                continue;
            }
            results.push(event);
            if results.len() >= limit {
                break;
            }
        }
        Ok(results)
    }

    pub fn clear_logs(&self) -> Result<usize> {
        const CHUNK_SIZE: usize = 4096;
        let mut removed = 0_usize;
        loop {
            let mut keys = Vec::new();
            for guard in self.logs.iter() {
                keys.push(guard.key()?);
                if keys.len() >= CHUNK_SIZE {
                    break;
                }
            }
            if keys.is_empty() {
                break;
            }
            let chunk_len = keys.len();
            let mut batch = self.db.batch();
            for k in keys {
                batch.remove(&self.logs, k);
            }
            batch.commit()?;
            removed += chunk_len;
            if chunk_len < CHUNK_SIZE {
                break;
            }
        }
        if removed > 0 {
            self.log_pruned_total.fetch_add(
                u64::try_from(removed).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
        }
        Ok(removed)
    }

    pub fn reset_stats(&self) -> Result<()> {
        let mut batch = self.db.batch();
        let zero_counters = PersistedCounters::default();
        batch.insert(
            &self.meta,
            KEY_COUNTERS,
            serde_json::to_vec(&zero_counters)?,
        );
        batch.remove(&self.meta, KEY_TIMESERIES);
        batch.commit()?;

        self.total_queries.store(0, Ordering::Relaxed);
        self.blocked_queries.store(0, Ordering::Relaxed);
        self.cached_queries.store(0, Ordering::Relaxed);
        self.rewritten_queries.store(0, Ordering::Relaxed);
        self.error_queries.store(0, Ordering::Relaxed);
        self.domain_counts.clear();
        self.blocked_counts.clear();
        self.client_counts.clear();
        self.client_stats.clear();
        self.hourly_buckets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        Ok(())
    }

    pub fn timeseries_24h_snapshot(&self, now_ms: u64) -> Vec<TimeSeriesPoint> {
        let current_hour_ms = (now_ms / HOUR_MS) * HOUR_MS;
        let buckets = self
            .hourly_buckets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut points = Vec::with_capacity(TIMESERIES_BUCKETS);
        for offset in (0..TIMESERIES_BUCKETS).rev() {
            let bucket_ms =
                current_hour_ms.saturating_sub(u64::try_from(offset).unwrap_or(0) * HOUR_MS);
            if let Some(existing) = buckets.get(&bucket_ms) {
                points.push(existing.clone());
            } else {
                points.push(TimeSeriesPoint {
                    timestamp_ms: bucket_ms,
                    ..TimeSeriesPoint::default()
                });
            }
        }
        points
    }

    pub fn stats_snapshot(&self) -> StatsSnapshot {
        let now_ms = chrono::Utc::now().timestamp_millis().max(0).cast_unsigned();
        StatsSnapshot {
            total_queries: self.total_queries.load(Ordering::Relaxed),
            blocked_queries: self.blocked_queries.load(Ordering::Relaxed),
            cached_queries: self.cached_queries.load(Ordering::Relaxed),
            rewritten_queries: self.rewritten_queries.load(Ordering::Relaxed),
            error_queries: self.error_queries.load(Ordering::Relaxed),
            top_domains: self.domain_counts.top_n(10),
            top_blocked: self.blocked_counts.top_n(10),
            top_clients: self.client_counts.top_n(10),
            timeseries_24h: self.timeseries_24h_snapshot(now_ms),
        }
    }

    pub fn tracked_stat_entries(&self) -> (usize, usize, usize) {
        (
            self.domain_counts.len(),
            self.blocked_counts.len(),
            self.client_counts.len(),
        )
    }

    pub fn save_custom_rules(&self, rules_text: &str) -> Result<()> {
        self.meta.insert(KEY_CUSTOM_RULES, rules_text.as_bytes())?;
        Ok(())
    }

    pub fn load_custom_rules(&self) -> Result<Option<String>> {
        match self.meta.get(KEY_CUSTOM_RULES)? {
            Some(bytes) => Ok(Some(String::from_utf8_lossy(&bytes).into_owned())),
            None => Ok(None),
        }
    }

    pub fn save_custom_rules_enabled(&self, enabled: bool) -> Result<()> {
        let byte = [u8::from(enabled)];
        self.meta.insert(KEY_CUSTOM_RULES_ENABLED, byte)?;
        Ok(())
    }

    pub fn load_custom_rules_enabled(&self) -> Result<bool> {
        match self.meta.get(KEY_CUSTOM_RULES_ENABLED)? {
            Some(bytes) => Ok(bytes.first().copied().unwrap_or(1) != 0),
            None => Ok(true),
        }
    }

    pub fn list_subscriptions(&self) -> Result<Vec<FilterSubscription>> {
        match self.meta.get(KEY_SUBSCRIPTIONS)? {
            Some(bytes) => Ok(serde_json::from_slice(&bytes)?),
            None => Ok(Vec::new()),
        }
    }

    pub fn save_subscriptions(&self, subs: &[FilterSubscription]) -> Result<()> {
        let bytes = serde_json::to_vec(subs)?;
        self.meta.insert(KEY_SUBSCRIPTIONS, bytes)?;
        Ok(())
    }

    pub fn save_subscription_content(&self, id: &str, content: &str) -> Result<()> {
        self.sub_contents
            .insert(id.as_bytes(), content.as_bytes())?;
        Ok(())
    }

    pub fn load_subscription_content(&self, id: &str) -> Result<Option<String>> {
        match self.sub_contents.get(id.as_bytes())? {
            Some(bytes) => Ok(Some(String::from_utf8_lossy(&bytes).into_owned())),
            None => Ok(None),
        }
    }

    pub fn delete_subscription_content(&self, id: &str) -> Result<()> {
        self.sub_contents.remove(id.as_bytes())?;
        Ok(())
    }

    pub fn load_enabled_subscription_contents(&self) -> Result<Vec<String>> {
        let named = self.load_enabled_named_subscription_contents()?;
        Ok(named.into_iter().map(|(_, text)| text).collect())
    }

    pub fn load_enabled_named_subscription_contents(&self) -> Result<Vec<(String, String)>> {
        let subs = self.list_subscriptions()?;
        let mut contents = Vec::new();
        for sub in subs {
            if sub.enabled
                && let Some(text) = self.load_subscription_content(&sub.id)?
            {
                contents.push((sub.name, text));
            }
        }
        Ok(contents)
    }

    pub fn list_clients(&self) -> Result<Vec<ClientProfile>> {
        match self.meta.get(KEY_CLIENTS)? {
            Some(bytes) => Ok(serde_json::from_slice(&bytes)?),
            None => Ok(Vec::new()),
        }
    }

    pub fn save_clients(&self, clients: &[ClientProfile]) -> Result<()> {
        let bytes = serde_json::to_vec(clients)?;
        self.meta.insert(KEY_CLIENTS, bytes)?;
        Ok(())
    }

    pub fn list_client_groups(&self) -> Result<Vec<ClientGroup>> {
        match self.meta.get(KEY_CLIENT_GROUPS)? {
            Some(bytes) => Ok(serde_json::from_slice(&bytes)?),
            None => Ok(Vec::new()),
        }
    }

    pub fn save_client_groups(&self, groups: &[ClientGroup]) -> Result<()> {
        let bytes = serde_json::to_vec(groups)?;
        self.meta.insert(KEY_CLIENT_GROUPS, bytes)?;
        Ok(())
    }

    pub fn list_dns_rewrites(&self) -> Result<Vec<DnsRewriteEntry>> {
        match self.meta.get(KEY_DNS_REWRITES)? {
            Some(bytes) => Ok(serde_json::from_slice(&bytes)?),
            None => Ok(Vec::new()),
        }
    }

    pub fn save_dns_rewrites(&self, rewrites: &[DnsRewriteEntry]) -> Result<()> {
        let bytes = serde_json::to_vec(rewrites)?;
        self.meta.insert(KEY_DNS_REWRITES, bytes)?;
        Ok(())
    }

    pub fn client_activity_list(&self) -> Vec<(String, ClientActivityStats)> {
        self.client_stats.list_ip_stats()
    }

    pub fn profile_activity_map(&self) -> HashMap<String, ClientActivityStats> {
        self.client_stats.profile_stats_map()
    }

    pub fn client_query_counts(&self) -> Vec<(String, u64)> {
        let mut out: Vec<(String, u64)> = self
            .client_counts
            .inner
            .iter()
            .map(|e| (e.key().clone(), *e.value()))
            .collect();
        out.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
        out
    }

    pub fn save_config(&self, config: &Config) -> Result<()> {
        let bytes = serde_json::to_vec(config)?;
        self.meta.insert(KEY_RUNTIME_CONFIG, bytes)?;
        Ok(())
    }

    pub fn load_config(&self) -> Result<Option<Config>> {
        match self.meta.get(KEY_RUNTIME_CONFIG)? {
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            None => Ok(None),
        }
    }

    pub fn prune_older_than(&self, cutoff_ms: u64) -> Result<usize> {
        const CHUNK_SIZE: usize = 4096;
        let end_key = encode_log_key(cutoff_ms, 0);
        let mut removed = 0_usize;
        loop {
            let mut keys = Vec::new();
            for guard in self.logs.range(..end_key) {
                keys.push(guard.key()?);
                if keys.len() >= CHUNK_SIZE {
                    break;
                }
            }
            let chunk_len = keys.len();
            if chunk_len == 0 {
                break;
            }
            let mut batch = self.db.batch();
            for k in keys {
                batch.remove(&self.logs, k);
            }
            batch.commit()?;
            removed += chunk_len;
            if chunk_len < CHUNK_SIZE {
                break;
            }
        }
        if removed > 0 {
            self.log_pruned_total.fetch_add(
                u64::try_from(removed).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
        }
        Ok(removed)
    }

    pub fn prune_oversized_logs(&self, max_disk_bytes: u64) -> Result<usize> {
        const PRUNE_CHUNK: usize = 4096;
        if self.logs.disk_space() <= max_disk_bytes {
            return Ok(0);
        }
        let mut removed = 0_usize;
        while self.logs.disk_space() > max_disk_bytes {
            let mut keys = Vec::new();
            for guard in self.logs.iter() {
                keys.push(guard.key()?);
                if keys.len() >= PRUNE_CHUNK {
                    break;
                }
            }
            if keys.is_empty() {
                break;
            }
            let chunk_len = keys.len();
            let mut batch = self.db.batch();
            for k in keys {
                batch.remove(&self.logs, k);
            }
            batch.commit()?;
            removed += chunk_len;
            if chunk_len < PRUNE_CHUNK {
                break;
            }
        }
        if removed > 0 {
            self.log_pruned_total.fetch_add(
                u64::try_from(removed).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
        }
        Ok(removed)
    }

    pub fn clear_subscription_contents(&self) -> Result<()> {
        loop {
            let mut keys = Vec::new();
            for guard in self.sub_contents.iter() {
                keys.push(guard.key()?);
                if keys.len() >= BATCH_CHUNK_SIZE {
                    break;
                }
            }
            if keys.is_empty() {
                break;
            }
            let chunk_len = keys.len();
            let mut batch = self.db.batch();
            for key in keys {
                batch.remove(&self.sub_contents, key);
            }
            batch.commit()?;
            if chunk_len < BATCH_CHUNK_SIZE {
                break;
            }
        }
        Ok(())
    }

    pub fn clear_dns_cache(&self) -> Result<()> {
        loop {
            let mut keys = Vec::new();
            for guard in self.dns_cache.iter() {
                keys.push(guard.key()?);
                if keys.len() >= BATCH_CHUNK_SIZE {
                    break;
                }
            }
            if keys.is_empty() {
                break;
            }
            let chunk_len = keys.len();
            let mut batch = self.db.batch();
            for key in keys {
                batch.remove(&self.dns_cache, key);
            }
            batch.commit()?;
            if chunk_len < BATCH_CHUNK_SIZE {
                break;
            }
        }
        Ok(())
    }

    pub fn save_dns_cache(&self, entries: &[PersistedCacheEntry]) -> Result<usize> {
        self.clear_dns_cache()?;
        let mut saved: usize = 0;
        for chunk in entries.chunks(BATCH_CHUNK_SIZE) {
            let mut batch = self.db.batch();
            for entry in chunk {
                let key = saved.to_be_bytes();
                let val = serde_json::to_vec(entry)?;
                batch.insert(&self.dns_cache, key, val);
                saved += 1;
            }
            batch.commit()?;
        }
        Ok(saved)
    }

    pub fn load_dns_cache(
        &self,
        now_unix_secs: i64,
        stale_grace_secs: i64,
    ) -> Result<Vec<PersistedCacheEntry>> {
        let mut entries = Vec::new();
        for guard in self.dns_cache.iter() {
            let val = guard.value()?;
            if let Ok(entry) = serde_json::from_slice::<PersistedCacheEntry>(&val)
                && entry.expires_at_unix_secs + stale_grace_secs > now_unix_secs
            {
                entries.push(entry);
            }
        }
        Ok(entries)
    }
}

fn encode_log_key(ts_ms: u64, seq: u64) -> [u8; 16] {
    let mut key = [0_u8; 16];
    key[0..8].copy_from_slice(&ts_ms.to_be_bytes());
    key[8..16].copy_from_slice(&seq.to_be_bytes());
    key
}

fn protocol_label(protocol: QueryProtocol) -> &'static str {
    match protocol {
        QueryProtocol::Udp => "udp",
        QueryProtocol::Tcp => "tcp",
        QueryProtocol::Dot => "dot",
        QueryProtocol::Doq => "doq",
        QueryProtocol::Doh => "doh",
    }
}

fn event_matches_search(event: &QueryEvent, needle: &str) -> bool {
    event.domain.to_ascii_lowercase().contains(needle)
        || event.client_ip.contains(needle)
        || event
            .client_name
            .as_deref()
            .is_some_and(|n| n.to_ascii_lowercase().contains(needle))
        || event
            .matched_list
            .as_deref()
            .is_some_and(|l| l.to_ascii_lowercase().contains(needle))
        || event
            .answers
            .iter()
            .any(|a| a.to_ascii_lowercase().contains(needle))
        || protocol_label(event.protocol).contains(needle)
}

fn event_matches_client(event: &QueryEvent, client_needle: &str) -> bool {
    event.client_ip.to_ascii_lowercase().contains(client_needle)
        || event
            .client_name
            .as_deref()
            .is_some_and(|n| n.to_ascii_lowercase().contains(client_needle))
        || event
            .client_id
            .as_deref()
            .is_some_and(|id| id.to_ascii_lowercase().contains(client_needle))
}

fn outcome_label(outcome: &QueryOutcome) -> &'static str {
    match outcome {
        QueryOutcome::Forwarded => "forwarded",
        QueryOutcome::Cached => "cached",
        QueryOutcome::Blocked => "blocked",
        QueryOutcome::Rewritten => "rewritten",
        QueryOutcome::Error => "error",
    }
}

pub fn spawn_log_sink(
    storage: Arc<StorageEngine>,
    mut rx: mpsc::Receiver<QueryEvent>,
    live_tx: broadcast::Sender<QueryEvent>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut buffer = Vec::with_capacity(256);
        let mut interval = tokio::time::interval(Duration::from_millis(250));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                maybe_event = rx.recv() => {
                    if let Some(event) = maybe_event {
                        let _ = live_tx.send(event.clone());
                        buffer.push(event);
                        if buffer.len() >= 256 {
                            flush_buffer(&storage, &mut buffer).await;
                        }
                    } else {
                        flush_buffer(&storage, &mut buffer).await;
                        break;
                    }
                }
                _ = interval.tick() => {
                    flush_buffer(&storage, &mut buffer).await;
                }
            }
        }
    })
}

async fn flush_buffer(storage: &Arc<StorageEngine>, buffer: &mut Vec<QueryEvent>) {
    if buffer.is_empty() {
        return;
    }
    let batch = std::mem::replace(buffer, Vec::with_capacity(256));
    let st = Arc::clone(storage);
    let start = Instant::now();
    let res = tokio::task::spawn_blocking(move || st.record_batch(&batch)).await;
    let elapsed_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
    storage
        .log_flush_total_us
        .fetch_add(elapsed_us, Ordering::Relaxed);
    match res {
        Ok(Ok(())) => {
            storage.log_batches_written.fetch_add(1, Ordering::Relaxed);
        }
        Ok(Err(err)) => {
            storage.log_batch_failures.fetch_add(1, Ordering::Relaxed);
            tracing::error!(error = %err, "failed to flush query logs to fjall");
        }
        Err(err) => {
            storage.log_batch_failures.fetch_add(1, Ordering::Relaxed);
            tracing::error!(error = %err, "query log flush task panicked");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_fjall_storage_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = StorageEngine::open(dir.path()).expect("open fjall");

        let events = vec![
            QueryEvent {
                timestamp: Utc::now(),
                client_ip: "127.0.0.1".to_string(),
                client_name: None,
                client_id: None,
                profile_id: None,
                protocol: QueryProtocol::Udp,
                domain: "ads.example.com".to_string(),
                qtype: "A".to_string(),
                outcome: QueryOutcome::Blocked,
                matched_rule: Some("||ads.example.com^".to_string()),
                matched_list: Some("custom".to_string()),
                upstream: None,
                elapsed_us: 42,
                rcode: "NOERROR".to_string(),
                answers: vec!["0.0.0.0".to_string()],
            },
            QueryEvent {
                timestamp: Utc::now(),
                client_ip: "127.0.0.1".to_string(),
                client_name: Some("nas-box".to_string()),
                client_id: None,
                profile_id: None,
                protocol: QueryProtocol::Doh,
                domain: "rust-lang.org".to_string(),
                qtype: "AAAA".to_string(),
                outcome: QueryOutcome::Forwarded,
                matched_rule: None,
                matched_list: None,
                upstream: Some("udp://1.1.1.1:53".to_string()),
                elapsed_us: 1200,
                rcode: "NOERROR".to_string(),
                answers: vec!["2606:4700::1".to_string()],
            },
        ];

        storage.record_batch(&events).expect("record batch");
        let logs = storage.query_logs(10, None, None).expect("query logs");
        assert_eq!(logs.len(), 2);

        let blocked = storage
            .query_logs(10, None, Some("blocked"))
            .expect("filter blocked");
        assert_eq!(blocked.len(), 1);
        assert_eq!(blocked[0].domain, "ads.example.com");

        let stats = storage.stats_snapshot();
        assert_eq!(stats.total_queries, 2);
        assert_eq!(stats.blocked_queries, 1);

        storage
            .save_custom_rules("||test.com^\n")
            .expect("save rules");
        assert_eq!(
            storage.load_custom_rules().expect("load rules").as_deref(),
            Some("||test.com^\n")
        );

        let future_cutoff = Utc::now().timestamp_millis().cast_unsigned() + 60_000;
        let pruned = storage.prune_older_than(future_cutoff).expect("prune");
        assert_eq!(pruned, 2);
        assert!(
            storage
                .query_logs(10, None, None)
                .expect("empty")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn test_spawn_log_sink_batches_and_broadcasts() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Arc::new(StorageEngine::open(dir.path()).expect("open fjall"));
        let (tx, rx) = mpsc::channel(16);
        let (live_tx, mut live_rx) = broadcast::channel(16);
        let handle = spawn_log_sink(Arc::clone(&storage), rx, live_tx);

        tx.send(QueryEvent {
            timestamp: Utc::now(),
            client_ip: "10.0.0.5".to_string(),
            client_name: None,
            client_id: None,
            profile_id: None,
            protocol: QueryProtocol::Udp,
            domain: "sink.example.com".to_string(),
            qtype: "A".to_string(),
            outcome: QueryOutcome::Cached,
            matched_rule: None,
            matched_list: None,
            upstream: Some("cache".to_string()),
            elapsed_us: 10,
            rcode: "NOERROR".to_string(),
            answers: vec!["1.2.3.4".to_string()],
        })
        .await
        .expect("send");

        let live_ev = live_rx.recv().await.expect("live broadcast");
        assert_eq!(live_ev.domain, "sink.example.com");

        drop(tx);
        handle.await.expect("sink join");
        let logs = storage.query_logs(10, Some("sink"), None).expect("logs");
        assert_eq!(logs.len(), 1);
    }

    #[test]
    fn test_clients_groups_persistence_and_selective_pruning() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = StorageEngine::open(dir.path()).expect("open fjall");

        let groups = vec![ClientGroup {
            id: "grp-1".to_string(),
            name: "Family".to_string(),
            description: "Home devices".to_string(),
            blocking_enabled: true,
            use_global_rules: true,
            custom_rules: "||ads.test^".to_string(),
            upstreams: vec![],
            block_mode: None,
            cname_cloaking_blocking: None,
        }];
        let clients = vec![ClientProfile {
            id: "cli-1".to_string(),
            name: "Living Room TV".to_string(),
            identifiers: vec!["192.168.1.55".to_string()],
            group_id: Some("grp-1".to_string()),
            blocking_enabled: None,
            use_global_rules: None,
            custom_rules: String::new(),
            upstreams: vec![],
            block_mode: None,
            tags: vec!["tv".to_string()],
        }];
        storage.save_client_groups(&groups).expect("save groups");
        storage.save_clients(&clients).expect("save clients");
        assert_eq!(storage.list_client_groups().unwrap(), groups);
        assert_eq!(storage.list_clients().unwrap(), clients);

        let now = Utc::now();
        let old_event = QueryEvent {
            timestamp: now - chrono::TimeDelta::hours(48),
            client_ip: "192.168.1.55".to_string(),
            client_name: Some("Living Room TV".to_string()),
            client_id: None,
            profile_id: Some("cli-1".to_string()),
            protocol: QueryProtocol::Udp,
            domain: "old.example.com".to_string(),
            qtype: "A".to_string(),
            outcome: QueryOutcome::Forwarded,
            matched_rule: None,
            matched_list: None,
            upstream: None,
            elapsed_us: 100,
            rcode: "NOERROR".to_string(),
            answers: vec!["93.184.216.34".to_string()],
        };
        let fresh_event = QueryEvent {
            timestamp: now - chrono::TimeDelta::hours(1),
            domain: "fresh.example.com".to_string(),
            ..old_event.clone()
        };
        storage
            .record_batch(&[old_event, fresh_event])
            .expect("record");

        let cutoff_ms = (now - chrono::TimeDelta::hours(24))
            .timestamp_millis()
            .max(0)
            .cast_unsigned();
        let pruned = storage.prune_older_than(cutoff_ms).expect("prune");
        assert_eq!(pruned, 1);

        let remaining = storage.query_logs(10, None, None).expect("logs");
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].domain, "fresh.example.com");
    }

    #[test]
    fn test_bounded_count_map_decays_and_admits_new_hot_keys() {
        let map = BoundedCountMap::new();
        for _ in 0..50 {
            map.increment("hot-old.test");
        }
        for i in 0..MAX_STAT_KEYS {
            map.increment(&format!("cold-{i}.test"));
        }
        assert!(map.len() <= MAX_STAT_KEYS);
        for _ in 0..30 {
            map.increment("hot-new.test");
        }
        assert!(map.len() <= MAX_STAT_KEYS);
        let top = map.top_n(5);
        assert!(top.iter().any(|item| item.name == "hot-old.test"));
        assert!(top.iter().any(|item| item.name == "hot-new.test"));
    }
}
