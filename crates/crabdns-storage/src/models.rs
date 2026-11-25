use std::sync::atomic::{AtomicBool, Ordering};

use dashmap::DashMap;
use foldhash::fast::RandomState;
use serde::{Deserialize, Serialize};
use thiserror::Error;
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

pub(crate) const KEY_CUSTOM_RULES: &[u8] = b"custom_rules";
pub(crate) const KEY_CUSTOM_RULES_ENABLED: &[u8] = b"custom_rules_enabled";
pub(crate) const KEY_SUBSCRIPTIONS: &[u8] = b"subscriptions";
pub(crate) const KEY_COUNTERS: &[u8] = b"counters";
pub(crate) const KEY_TIMESERIES: &[u8] = b"timeseries";
pub(crate) const KEY_RUNTIME_CONFIG: &[u8] = b"runtime_config";
pub(crate) const KEY_CLIENTS: &[u8] = b"clients";
pub(crate) const KEY_CLIENT_GROUPS: &[u8] = b"client_groups";
pub(crate) const KEY_DNS_REWRITES: &[u8] = b"dns_rewrites";

pub(crate) const HOUR_MS: u64 = 3_600_000;
pub(crate) const TIMESERIES_BUCKETS: usize = 24;
pub(crate) const TIMESERIES_RETENTION_MS: u64 = 48 * HOUR_MS;

pub(crate) const FJALL_CACHE_BYTES: u64 = 4 * 1024 * 1024;
pub(crate) const FJALL_MAX_JOURNAL_BYTES: u64 = 64 * 1024 * 1024;
pub(crate) const FJALL_MAX_CACHED_FILES: usize = 64;
pub(crate) const FJALL_WORKER_THREADS: usize = 2;
pub(crate) const FJALL_LOGS_MEMTABLE_BYTES: u64 = 4 * 1024 * 1024;
pub(crate) const FJALL_SMALL_MEMTABLE_BYTES: u64 = 2 * 1024 * 1024;
pub(crate) const MAX_STAT_KEYS: usize = 10_000;
pub(crate) const MAX_LOG_SCAN: usize = 50_000;
pub(crate) const BATCH_CHUNK_SIZE: usize = 1_024;

#[derive(Debug, Default)]
pub(crate) struct BoundedCountMap {
    pub(crate) inner: DashMap<String, u64, RandomState>,
    pruning: AtomicBool,
}

impl BoundedCountMap {
    pub(crate) fn new() -> Self {
        Self {
            inner: DashMap::with_hasher(RandomState::default()),
            pruning: AtomicBool::new(false),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.inner.len()
    }

    pub(crate) fn clear(&self) {
        self.inner.clear();
        self.inner.shrink_to_fit();
    }

    pub(crate) fn increment(&self, key: &str) {
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

    pub(crate) fn top_n(&self, limit: usize) -> Vec<TopItem> {
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
    pub log_batches_retried: u64,
    pub log_batches_degraded_dropped: u64,
    pub log_disk_degraded: bool,
    pub log_flush_total_us: u64,
    pub log_pruned_total: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct PersistedCounters {
    pub(crate) total: u64,
    pub(crate) blocked: u64,
    pub(crate) cached: u64,
    pub(crate) rewritten: u64,
    pub(crate) error: u64,
}
