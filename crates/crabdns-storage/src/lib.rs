use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crabdns_core::{
    ClientGroup, ClientProfile, DnsRewriteEntry, PersistedCacheEntry, QueryEvent, QueryOutcome,
    RuntimeConfig, StorageProfile,
};

pub mod client_stats;
pub mod config_history;
mod log_sink;
mod models;
pub use client_stats::{ClientActivityStats, ClientProtocolCounts, ClientStatsTracker};
pub use config_history::{ConfigSnapshotMeta, SplitDnsListMeta};
use fjall::{Database, Keyspace, KeyspaceCreateOptions};
pub use log_sink::spawn_log_sink;
use models::{
    BATCH_CHUNK_SIZE, BoundedCountMap, FjallPreset, HOUR_MS, KEY_CLIENT_GROUPS, KEY_CLIENTS,
    KEY_COUNTERS, KEY_CUSTOM_RULES, KEY_CUSTOM_RULES_ENABLED, KEY_DNS_REWRITES, KEY_RUNTIME_CONFIG,
    KEY_SUBSCRIPTIONS, KEY_TIMESERIES, MAX_LOG_SCAN, PersistedCounters, TIMESERIES_BUCKETS,
    TIMESERIES_RETENTION_MS, available_disk_bytes,
};
pub use models::{
    CompiledLogsFilter, FilterSubscription, LogsFilter, Result, StatsSnapshot, StorageError,
    StorageRuntimeMetrics, TimeSeriesPoint, TopItem,
};
use tokio::sync::Mutex;
pub struct StorageEngine {
    data_dir: PathBuf,
    effective_profile: StorageProfile,
    db: Database,
    logs: Keyspace,
    meta: Keyspace,
    sub_contents: Keyspace,
    dns_cache: Keyspace,
    seq: AtomicU64,
    pub(crate) total_queries: AtomicU64,
    pub(crate) blocked_queries: AtomicU64,
    pub(crate) cached_queries: AtomicU64,
    pub(crate) rewritten_queries: AtomicU64,
    pub(crate) error_queries: AtomicU64,
    pub(crate) domain_counts: BoundedCountMap,
    pub(crate) blocked_counts: BoundedCountMap,
    pub(crate) client_counts: BoundedCountMap,
    pub(crate) client_stats: ClientStatsTracker,
    pub(crate) hourly_buckets: std::sync::Mutex<HashMap<u64, TimeSeriesPoint>>,
    sub_lock: Mutex<()>,
    client_lock: Mutex<()>,
    config_lock: Mutex<()>,
    rewrite_lock: Mutex<()>,
    pub(crate) log_batches_written: AtomicU64,
    pub(crate) log_batch_failures: AtomicU64,
    pub(crate) log_batches_retried: AtomicU64,
    pub(crate) log_batches_degraded_dropped: AtomicU64,
    pub(crate) log_disk_degraded: AtomicBool,
    pub(crate) disk_pressure_active: AtomicBool,
    pub(crate) log_flush_total_us: AtomicU64,
    log_pruned_total: AtomicU64,
}

impl StorageEngine {
    pub fn open(data_dir: &Path) -> Result<Self> {
        Self::open_with_profile(data_dir, StorageProfile::Auto)
    }

    pub fn open_with_profile(data_dir: &Path, profile: StorageProfile) -> Result<Self> {
        let preset = FjallPreset::from_profile(profile);
        let db = Database::builder(data_dir.join("fjall"))
            .cache_size(preset.cache_bytes)
            .max_journaling_size(preset.max_journal_bytes)
            .max_cached_files(Some(preset.max_cached_files))
            .worker_threads(preset.worker_threads)
            .open()?;
        let logs = db.keyspace("logs", || {
            KeyspaceCreateOptions::default().max_memtable_size(preset.logs_memtable_bytes)
        })?;
        let meta = db.keyspace("meta", || {
            KeyspaceCreateOptions::default().max_memtable_size(preset.small_memtable_bytes)
        })?;
        let sub_contents = db.keyspace("sub_contents", || {
            KeyspaceCreateOptions::default().max_memtable_size(preset.small_memtable_bytes)
        })?;
        let dns_cache = db.keyspace("dns_cache", || {
            KeyspaceCreateOptions::default().max_memtable_size(preset.small_memtable_bytes)
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
            data_dir: data_dir.to_path_buf(),
            effective_profile: preset.effective_profile,
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
            log_batches_retried: AtomicU64::new(0),
            log_batches_degraded_dropped: AtomicU64::new(0),
            log_disk_degraded: AtomicBool::new(false),
            disk_pressure_active: AtomicBool::new(false),
            log_flush_total_us: AtomicU64::new(0),
            log_pruned_total: AtomicU64::new(0),
        })
    }

    #[must_use]
    pub fn effective_storage_profile(&self) -> StorageProfile {
        self.effective_profile
    }

    #[must_use]
    pub fn is_disk_pressure_active(&self) -> bool {
        self.disk_pressure_active.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn available_disk_bytes(&self) -> Option<u64> {
        available_disk_bytes(&self.data_dir)
    }

    pub fn runtime_metrics(&self) -> StorageRuntimeMetrics {
        StorageRuntimeMetrics {
            log_batches_written: self.log_batches_written.load(Ordering::Relaxed),
            log_batch_failures: self.log_batch_failures.load(Ordering::Relaxed),
            log_batches_retried: self.log_batches_retried.load(Ordering::Relaxed),
            log_batches_degraded_dropped: self.log_batches_degraded_dropped.load(Ordering::Relaxed),
            log_disk_degraded: self.log_disk_degraded.load(Ordering::Relaxed),
            disk_pressure_active: self.disk_pressure_active.load(Ordering::Relaxed),
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

        self.apply_in_memory_stats_without_buckets(
            events,
            (
                delta_total,
                delta_blocked,
                delta_cached,
                delta_rewritten,
                delta_error,
            ),
        );
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
        let compiled = filter.compile();

        for (scanned, guard) in self.logs.iter().rev().enumerate() {
            if scanned >= MAX_LOG_SCAN {
                break;
            }
            let val = guard.value()?;
            let Ok(event) = serde_json::from_slice::<QueryEvent>(&val) else {
                continue;
            };
            if !compiled.matches(&event) {
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

    pub fn save_config(&self, config: &RuntimeConfig) -> Result<()> {
        let bytes = serde_json::to_vec(config)?;
        self.meta.insert(KEY_RUNTIME_CONFIG, bytes)?;
        Ok(())
    }

    pub fn load_config(&self) -> Result<Option<RuntimeConfig>> {
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

    /// Evaluates both the configured `max_disk_bytes` cap and filesystem free space (`min_free_bytes`).
    /// When available disk space drops below `min_free_bytes`, activates disk pressure mode and
    /// aggressively tightens the log quota by half until space recovers or logs are drained.
    pub fn prune_with_disk_quota(&self, max_disk_bytes: u64, min_free_bytes: u64) -> Result<usize> {
        let mut effective_cap = max_disk_bytes;
        if min_free_bytes > 0
            && let Some(free) = self.available_disk_bytes()
        {
            if free < min_free_bytes {
                self.disk_pressure_active.store(true, Ordering::Relaxed);
                let current_logs = self.logs.disk_space();
                let deficit = min_free_bytes.saturating_sub(free);
                let target = current_logs.saturating_sub(deficit).min(current_logs / 2);
                effective_cap = effective_cap.min(target);
                tracing::warn!(
                    free_bytes = free,
                    min_free_bytes,
                    effective_cap,
                    "low disk space detected; tightening log quota and pausing non-essential log writes"
                );
            } else {
                self.disk_pressure_active.store(false, Ordering::Relaxed);
            }
        }
        self.prune_oversized_logs(effective_cap)
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

#[cfg(test)]
#[path = "storage_tests.rs"]
mod tests;
