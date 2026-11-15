use std::time::{Duration, Instant};

use moka::sync::Cache;

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

pub struct DnsCache {
    inner: Cache<CacheKey, CachedEntry>,
    optimistic: bool,
    stale_grace: Duration,
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
        }
    }

    pub fn get(&self, key: &CacheKey, query_id: u16) -> Option<CacheHit> {
        let entry = self.inner.get(key)?;
        let elapsed = entry.inserted_at.elapsed();

        if elapsed <= entry.ttl {
            let mut bytes = entry.wire_bytes;
            patch_tx_id(&mut bytes, query_id);
            return Some(CacheHit {
                wire_bytes: bytes,
                is_stale: false,
            });
        }

        if self.optimistic && elapsed <= entry.ttl.saturating_add(self.stale_grace) {
            let mut bytes = entry.wire_bytes;
            patch_tx_id(&mut bytes, query_id);
            return Some(CacheHit {
                wire_bytes: bytes,
                is_stale: true,
            });
        }

        self.inner.invalidate(key);
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

    pub fn entry_count(&self) -> u64 {
        self.inner.entry_count()
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
    }
}
