use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use foldhash::fast::RandomState;
use moka::sync::Cache;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

pub const DEFAULT_MIN_TTL_SECS: u32 = 10;
pub const DEFAULT_MAX_TTL_SECS: u32 = 86_400;
const PREFETCH_MIN_HITS: u32 = 2;
const PREFETCH_ELAPSED_RATIO: f64 = 0.85;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct CacheKey {
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
    pub ecs_subnet: Option<(IpAddr, u8)>,
    pub dnssec_do: bool,
}

#[derive(Debug, Clone)]
pub struct CachedEntry {
    pub wire_bytes: Vec<u8>,
    pub inserted_at: Instant,
    pub ttl: Duration,
    pub hit_count: Arc<AtomicU32>,
    pub refresh_inflight: Arc<AtomicBool>,
}

#[derive(Debug, Clone)]
pub struct CacheHit {
    pub wire_bytes: Vec<u8>,
    pub is_stale: bool,
    pub needs_refresh: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedCacheEntry {
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
    pub ecs_subnet: Option<(IpAddr, u8)>,
    pub dnssec_do: bool,
    pub wire_bytes: Vec<u8>,
    pub expires_at_unix_secs: i64,
    pub ttl_secs: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct CacheStats {
    #[ts(type = "number")]
    pub entries: u64,
    #[ts(type = "number")]
    pub hits: u64,
    #[ts(type = "number")]
    pub optimistic_hits: u64,
    #[ts(type = "number")]
    pub prefetches: u64,
    #[ts(type = "number")]
    pub misses: u64,
    pub hit_rate: f64,
}

pub struct DnsCache {
    inner: Cache<CacheKey, CachedEntry, RandomState>,
    optimistic: bool,
    min_ttl_secs: u32,
    max_ttl_secs: u32,
    prefetch_enabled: bool,
    stale_grace: Duration,
    hits: AtomicU64,
    optimistic_hits: AtomicU64,
    prefetches: AtomicU64,
    misses: AtomicU64,
}

impl DnsCache {
    pub fn new(max_capacity: u64, optimistic: bool) -> Self {
        Self::with_options(
            max_capacity,
            optimistic,
            DEFAULT_MIN_TTL_SECS,
            DEFAULT_MAX_TTL_SECS,
            true,
        )
    }

    pub fn with_options(
        max_capacity: u64,
        optimistic: bool,
        min_ttl_secs: u32,
        max_ttl_secs: u32,
        prefetch_enabled: bool,
    ) -> Self {
        let clamped_min = min_ttl_secs.max(1);
        let clamped_max = max_ttl_secs.max(clamped_min);
        let ttl_window = if optimistic {
            Duration::from_hours(24).max(Duration::from_secs(u64::from(clamped_max)))
        } else {
            Duration::from_secs(u64::from(clamped_max)).max(Duration::from_hours(1))
        };

        let inner = Cache::builder()
            .max_capacity(max_capacity)
            .time_to_live(ttl_window)
            .build_with_hasher(RandomState::default());

        Self {
            inner,
            optimistic,
            min_ttl_secs: clamped_min,
            max_ttl_secs: clamped_max,
            prefetch_enabled,
            stale_grace: Duration::from_hours(24),
            hits: AtomicU64::new(0),
            optimistic_hits: AtomicU64::new(0),
            prefetches: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    pub fn stale_grace_secs(&self) -> i64 {
        i64::try_from(self.stale_grace.as_secs()).unwrap_or(86_400)
    }

    pub fn get(&self, key: &CacheKey, query_id: u16) -> Option<CacheHit> {
        let Some(entry) = self.inner.get(key) else {
            self.misses.fetch_add(1, Ordering::Relaxed);
            return None;
        };
        let elapsed = entry.inserted_at.elapsed();

        if elapsed <= entry.ttl {
            self.hits.fetch_add(1, Ordering::Relaxed);
            let hits = entry.hit_count.fetch_add(1, Ordering::Relaxed) + 1;
            let mut needs_refresh = false;
            if self.prefetch_enabled
                && hits >= PREFETCH_MIN_HITS
                && elapsed >= entry.ttl.mul_f64(PREFETCH_ELAPSED_RATIO)
                && entry
                    .refresh_inflight
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok()
            {
                needs_refresh = true;
                self.prefetches.fetch_add(1, Ordering::Relaxed);
            }
            let mut bytes = entry.wire_bytes;
            patch_tx_id(&mut bytes, query_id);
            return Some(CacheHit {
                wire_bytes: bytes,
                is_stale: false,
                needs_refresh,
            });
        }

        if self.optimistic && elapsed <= entry.ttl.saturating_add(self.stale_grace) {
            self.hits.fetch_add(1, Ordering::Relaxed);
            self.optimistic_hits.fetch_add(1, Ordering::Relaxed);
            let needs_refresh = entry
                .refresh_inflight
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok();
            let mut bytes = entry.wire_bytes;
            patch_tx_id(&mut bytes, query_id);
            return Some(CacheHit {
                wire_bytes: bytes,
                is_stale: true,
                needs_refresh,
            });
        }

        self.inner.invalidate(key);
        self.misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    pub fn insert(&self, key: CacheKey, wire_bytes: Vec<u8>, ttl_secs: u32) {
        let clamped_ttl = u64::from(ttl_secs.clamp(self.min_ttl_secs, self.max_ttl_secs));
        self.inner.insert(
            key,
            CachedEntry {
                wire_bytes,
                inserted_at: Instant::now(),
                ttl: Duration::from_secs(clamped_ttl),
                hit_count: Arc::new(AtomicU32::new(0)),
                refresh_inflight: Arc::new(AtomicBool::new(false)),
            },
        );
    }

    pub fn clear_refresh_inflight(&self, key: &CacheKey) {
        if let Some(entry) = self.inner.get(key) {
            entry.refresh_inflight.store(false, Ordering::Release);
        }
    }

    pub fn export_persisted(&self, now_unix_secs: i64) -> Vec<PersistedCacheEntry> {
        let stale_secs = self.stale_grace_secs();
        let mut out = Vec::new();
        for (key, entry) in &self.inner {
            let elapsed_secs = i64::try_from(entry.inserted_at.elapsed().as_secs()).unwrap_or(0);
            let ttl_secs = u32::try_from(entry.ttl.as_secs()).unwrap_or(self.max_ttl_secs);
            let expires_at = now_unix_secs + i64::from(ttl_secs) - elapsed_secs;
            if expires_at + stale_secs <= now_unix_secs {
                continue;
            }
            if !self.optimistic && expires_at <= now_unix_secs {
                continue;
            }
            out.push(PersistedCacheEntry {
                qname: key.qname.clone(),
                qtype: key.qtype,
                qclass: key.qclass,
                ecs_subnet: key.ecs_subnet,
                dnssec_do: key.dnssec_do,
                wire_bytes: entry.wire_bytes.clone(),
                expires_at_unix_secs: expires_at,
                ttl_secs,
            });
        }
        out
    }

    pub fn import_persisted(&self, entries: Vec<PersistedCacheEntry>, now_unix_secs: i64) -> usize {
        let stale_secs = self.stale_grace_secs();
        let mut imported = 0;
        for item in entries {
            if item.expires_at_unix_secs + stale_secs <= now_unix_secs {
                continue;
            }
            if !self.optimistic && item.expires_at_unix_secs <= now_unix_secs {
                continue;
            }
            let remaining = item.expires_at_unix_secs - now_unix_secs;
            let ttl = Duration::from_secs(u64::from(item.ttl_secs.max(1)));
            let inserted_at = if remaining >= 0 {
                let rem_dur = Duration::from_secs(remaining.cast_unsigned());
                let elapsed = ttl.saturating_sub(rem_dur);
                Instant::now()
                    .checked_sub(elapsed)
                    .unwrap_or_else(Instant::now)
            } else {
                let stale_elapsed = Duration::from_secs((-remaining).cast_unsigned());
                let total_elapsed = ttl.saturating_add(stale_elapsed);
                Instant::now()
                    .checked_sub(total_elapsed)
                    .unwrap_or_else(Instant::now)
            };
            let key = CacheKey {
                qname: item.qname,
                qtype: item.qtype,
                qclass: item.qclass,
                ecs_subnet: item.ecs_subnet,
                dnssec_do: item.dnssec_do,
            };
            self.inner.insert(
                key,
                CachedEntry {
                    wire_bytes: item.wire_bytes,
                    inserted_at,
                    ttl,
                    hit_count: Arc::new(AtomicU32::new(0)),
                    refresh_inflight: Arc::new(AtomicBool::new(false)),
                },
            );
            imported += 1;
        }
        imported
    }

    pub fn flush(&self) {
        self.inner.invalidate_all();
        self.inner.run_pending_tasks();
    }

    pub fn entry_count(&self) -> u64 {
        self.inner.entry_count()
    }

    pub fn stats(&self) -> CacheStats {
        let hits = self.hits.load(Ordering::Relaxed);
        let optimistic_hits = self.optimistic_hits.load(Ordering::Relaxed);
        let prefetches = self.prefetches.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total = hits + misses;
        #[allow(clippy::cast_precision_loss)]
        let hit_rate = if total == 0 {
            0.0
        } else {
            hits as f64 / total as f64
        };
        CacheStats {
            entries: self.entry_count(),
            hits,
            optimistic_hits,
            prefetches,
            misses,
            hit_rate,
        }
    }
}

pub fn patch_tx_id(wire: &mut [u8], query_id: u16) {
    if wire.len() >= 2 {
        let id_bytes = query_id.to_be_bytes();
        wire[0] = id_bytes[0];
        wire[1] = id_bytes[1];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_hit_and_tx_id_patch() {
        let cache = DnsCache::new(100, true);
        let key = CacheKey {
            qname: "example.com.".to_string(),
            qtype: 1,
            qclass: 1,
            ecs_subnet: None,
            dnssec_do: false,
        };
        cache.insert(key.clone(), vec![0x00, 0x01, 0x81, 0x80], 60);

        let hit = cache.get(&key, 0xABCD).expect("cache hit");
        assert!(!hit.is_stale);
        assert!(!hit.needs_refresh);
        assert_eq!(&hit.wire_bytes[0..2], &[0xAB, 0xCD]);
        assert!(cache.entry_count() <= 1);
    }

    #[test]
    fn test_cache_stale_optimistic_vs_strict() {
        let key = CacheKey {
            qname: "stale.example.".to_string(),
            qtype: 1,
            qclass: 1,
            ecs_subnet: None,
            dnssec_do: false,
        };
        let expired = CachedEntry {
            wire_bytes: vec![0x00, 0x01, 0x81, 0x80],
            inserted_at: Instant::now()
                .checked_sub(Duration::from_secs(120))
                .expect("valid instant"),
            ttl: Duration::from_secs(30),
            hit_count: Arc::new(AtomicU32::new(0)),
            refresh_inflight: Arc::new(AtomicBool::new(false)),
        };

        let opt_cache = DnsCache::new(10, true);
        opt_cache.inner.insert(key.clone(), expired.clone());
        let hit1 = opt_cache.get(&key, 0x1122).expect("optimistic stale hit");
        assert!(hit1.is_stale);
        assert!(hit1.needs_refresh);
        assert_eq!(&hit1.wire_bytes[0..2], &[0x11, 0x22]);

        // Second stale hit while refresh is inflight should deduplicate refresh
        let hit2 = opt_cache.get(&key, 0x3344).expect("optimistic stale hit 2");
        assert!(hit2.is_stale);
        assert!(!hit2.needs_refresh);

        let strict_cache = DnsCache::new(10, false);
        strict_cache.inner.insert(key.clone(), expired);
        assert!(strict_cache.get(&key, 0x1122).is_none());
    }

    #[test]
    fn test_cache_ttl_clamping_and_prefetch() {
        let cache = DnsCache::with_options(100, true, 30, 120, true);
        let key = CacheKey {
            qname: "hot.example.".to_string(),
            qtype: 1,
            qclass: 1,
            ecs_subnet: None,
            dnssec_do: false,
        };
        // TTL below min (5s -> clamped to 30s)
        cache.insert(key.clone(), vec![0x00, 0x01, 0x81, 0x80], 5);
        let entry = cache.inner.get(&key).unwrap();
        assert_eq!(entry.ttl, Duration::from_secs(30));

        // Simulate 90% elapsed (27s of 30s)
        cache.inner.insert(
            key.clone(),
            CachedEntry {
                wire_bytes: vec![0x00, 0x01, 0x81, 0x80],
                inserted_at: Instant::now()
                    .checked_sub(Duration::from_secs(27))
                    .expect("valid instant"),
                ttl: Duration::from_secs(30),
                hit_count: Arc::new(AtomicU32::new(1)),
                refresh_inflight: Arc::new(AtomicBool::new(false)),
            },
        );

        let hit1 = cache.get(&key, 0x0002).expect("prefetch hit");
        assert!(!hit1.is_stale);
        assert!(hit1.needs_refresh);
        assert_eq!(cache.stats().prefetches, 1);

        // Next hit while inflight does not re-trigger prefetch
        let hit2 = cache.get(&key, 0x0003).expect("dedup hit");
        assert!(!hit2.needs_refresh);
    }

    #[test]
    fn test_cache_persist_export_import_roundtrip() {
        let cache1 = DnsCache::new(100, true);
        let key = CacheKey {
            qname: "persist.example.".to_string(),
            qtype: 1,
            qclass: 1,
            ecs_subnet: None,
            dnssec_do: false,
        };
        cache1.insert(key.clone(), vec![0x12, 0x34, 0x81, 0x80], 120);
        let exported = cache1.export_persisted(1_700_000_000);
        assert_eq!(exported.len(), 1);

        let cache2 = DnsCache::new(100, true);
        let imported = cache2.import_persisted(exported, 1_700_000_010);
        assert_eq!(imported, 1);
        let hit = cache2.get(&key, 0x9999).expect("restored hit");
        assert!(!hit.is_stale);
        assert_eq!(&hit.wire_bytes[0..2], &[0x99, 0x99]);
    }
}
