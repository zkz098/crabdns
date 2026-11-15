use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use moka::sync::Cache;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct CacheKey {
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug, Clone)]
pub struct CachedEntry {
    pub wire_bytes: Vec<u8>,
    pub inserted_at: Instant,
    pub ttl: Duration,
}

#[derive(Debug, Clone)]
pub struct CacheHit {
    pub wire_bytes: Vec<u8>,
    pub is_stale: bool,
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
    pub misses: u64,
    pub hit_rate: f64,
}

pub struct DnsCache {
    inner: Cache<CacheKey, CachedEntry>,
    optimistic: bool,
    stale_grace: Duration,
    hits: AtomicU64,
    optimistic_hits: AtomicU64,
    misses: AtomicU64,
}

impl DnsCache {
    pub fn new(max_capacity: u64, optimistic: bool) -> Self {
        let ttl_window = if optimistic {
            Duration::from_hours(24)
        } else {
            Duration::from_hours(1)
        };

        let inner = Cache::builder()
            .max_capacity(max_capacity)
            .time_to_live(ttl_window)
            .build();

        Self {
            inner,
            optimistic,
            stale_grace: Duration::from_hours(24),
            hits: AtomicU64::new(0),
            optimistic_hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    pub fn get(&self, key: &CacheKey, query_id: u16) -> Option<CacheHit> {
        let Some(entry) = self.inner.get(key) else {
            self.misses.fetch_add(1, Ordering::Relaxed);
            return None;
        };
        let elapsed = entry.inserted_at.elapsed();

        if elapsed <= entry.ttl {
            self.hits.fetch_add(1, Ordering::Relaxed);
            let mut bytes = entry.wire_bytes;
            patch_tx_id(&mut bytes, query_id);
            return Some(CacheHit {
                wire_bytes: bytes,
                is_stale: false,
            });
        }

        if self.optimistic && elapsed <= entry.ttl.saturating_add(self.stale_grace) {
            self.hits.fetch_add(1, Ordering::Relaxed);
            self.optimistic_hits.fetch_add(1, Ordering::Relaxed);
            let mut bytes = entry.wire_bytes;
            patch_tx_id(&mut bytes, query_id);
            return Some(CacheHit {
                wire_bytes: bytes,
                is_stale: true,
            });
        }

        self.inner.invalidate(key);
        self.misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    pub fn insert(&self, key: CacheKey, wire_bytes: Vec<u8>, ttl_secs: u32) {
        let clamped_ttl = u64::from(ttl_secs.clamp(10, 86_400));
        self.inner.insert(
            key,
            CachedEntry {
                wire_bytes,
                inserted_at: Instant::now(),
                ttl: Duration::from_secs(clamped_ttl),
            },
        );
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
        };
        cache.insert(key.clone(), vec![0x00, 0x01, 0x81, 0x80], 60);

        let hit = cache.get(&key, 0xABCD).expect("cache hit");
        assert!(!hit.is_stale);
        assert_eq!(&hit.wire_bytes[0..2], &[0xAB, 0xCD]);
        assert!(cache.entry_count() <= 1);
    }

    #[test]
    fn test_cache_stale_optimistic_vs_strict() {
        let key = CacheKey {
            qname: "stale.example.".to_string(),
            qtype: 1,
            qclass: 1,
        };
        let expired = CachedEntry {
            wire_bytes: vec![0x00, 0x01, 0x81, 0x80],
            inserted_at: Instant::now()
                .checked_sub(Duration::from_secs(120))
                .expect("valid instant"),
            ttl: Duration::from_secs(30),
        };

        let opt_cache = DnsCache::new(10, true);
        opt_cache.inner.insert(key.clone(), expired.clone());
        let hit = opt_cache.get(&key, 0x1122).expect("optimistic stale hit");
        assert!(hit.is_stale);
        assert_eq!(&hit.wire_bytes[0..2], &[0x11, 0x22]);

        let strict_cache = DnsCache::new(10, false);
        strict_cache.inner.insert(key.clone(), expired);
        assert!(strict_cache.get(&key, 0x1122).is_none());
    }
}
