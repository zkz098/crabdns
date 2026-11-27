use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use foldhash::fast::RandomState;
use hickory_proto::op::Message;
use hickory_proto::rr::RData;
use moka::sync::Cache;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::security::contains_rebinding_ip_msg;
use crate::wire::{extract_answer_summaries_msg, patch_wire_ttls, scan_rr_ttl_offsets};

pub const DEFAULT_MIN_TTL_SECS: u32 = 10;
pub const DEFAULT_MAX_TTL_SECS: u32 = 86_400;
const PREFETCH_MIN_HITS: u32 = 2;
const PREFETCH_ELAPSED_RATIO: f64 = 0.85;
const STALE_RESPONSE_TTL_SECS: u32 = 30;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct CacheKey {
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
    pub ecs_subnet: Option<(IpAddr, u8)>,
    pub dnssec_do: bool,
    pub upstream_scope: Option<String>,
}

#[derive(Debug)]
pub struct CachedEntry {
    pub wire_bytes: Box<[u8]>,
    pub inserted_at: Instant,
    pub ttl: Duration,
    pub ttl_offsets: Box<[(usize, u32)]>,
    pub answer_summaries: Box<[String]>,
    pub cname_targets: Box<[Box<str>]>,
    pub rcode_str: &'static str,
    pub has_rebinding_ip: bool,
    pub hit_count: AtomicU32,
    pub refresh_inflight: AtomicBool,
}

fn rcode_from_wire(wire: &[u8]) -> &'static str {
    if wire.len() < 4 {
        return "NOERROR";
    }
    match wire[3] & 0x0F {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "OTHER",
    }
}

struct ExtractedMeta {
    answer_summaries: Box<[String]>,
    cname_targets: Box<[Box<str>]>,
    rcode_str: &'static str,
    has_rebinding_ip: bool,
}

fn extract_cached_meta(wire: &[u8]) -> ExtractedMeta {
    let rcode_str = rcode_from_wire(wire);
    let Ok(msg) = Message::from_vec(wire) else {
        return ExtractedMeta {
            answer_summaries: Box::from([]),
            cname_targets: Box::from([]),
            rcode_str,
            has_rebinding_ip: false,
        };
    };
    let answer_summaries = extract_answer_summaries_msg(&msg).into_boxed_slice();
    let mut cnames = Vec::new();
    for answer in &msg.answers {
        if let RData::CNAME(cname) = &answer.data {
            let target = cname.to_utf8();
            let clean = target.trim_end_matches('.');
            if !clean.is_empty() {
                cnames.push(clean.to_string().into_boxed_str());
            }
        }
    }
    let has_rebinding_ip = contains_rebinding_ip_msg(&msg);
    ExtractedMeta {
        answer_summaries,
        cname_targets: cnames.into_boxed_slice(),
        rcode_str,
        has_rebinding_ip,
    }
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
    #[serde(default)]
    pub upstream_scope: Option<String>,
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
    inner: Cache<CacheKey, Arc<CachedEntry>, RandomState>,
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
        let mut wire_bytes = Vec::new();
        let (is_stale, needs_refresh) = self.get_into(key, query_id, &mut wire_bytes)?;
        Some(CacheHit {
            wire_bytes,
            is_stale,
            needs_refresh,
        })
    }

    /// Looks up a cached entry and writes the patched wire response into `out`,
    /// returning `(is_stale, needs_refresh)` on hit.
    pub fn get_into(
        &self,
        key: &CacheKey,
        query_id: u16,
        out: &mut Vec<u8>,
    ) -> Option<(bool, bool)> {
        let (_entry, is_stale, needs_refresh) = self.get_entry_into(key, query_id, out)?;
        Some((is_stale, needs_refresh))
    }

    /// Looks up a cached entry, writes the patched wire response into `out`,
    /// and returns `(entry, is_stale, needs_refresh)` for zero-parse metadata access.
    pub fn get_entry_into(
        &self,
        key: &CacheKey,
        query_id: u16,
        out: &mut Vec<u8>,
    ) -> Option<(Arc<CachedEntry>, bool, bool)> {
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
            out.clear();
            out.extend_from_slice(&entry.wire_bytes);
            patch_tx_id(out, query_id);
            let elapsed_secs = u32::try_from(elapsed.as_secs()).unwrap_or(u32::MAX);
            patch_wire_ttls(out, &entry.ttl_offsets, elapsed_secs, None);
            return Some((entry, false, needs_refresh));
        }

        if self.optimistic && elapsed <= entry.ttl.saturating_add(self.stale_grace) {
            self.hits.fetch_add(1, Ordering::Relaxed);
            self.optimistic_hits.fetch_add(1, Ordering::Relaxed);
            let needs_refresh = entry
                .refresh_inflight
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok();
            out.clear();
            out.extend_from_slice(&entry.wire_bytes);
            patch_tx_id(out, query_id);
            patch_wire_ttls(out, &entry.ttl_offsets, 0, Some(STALE_RESPONSE_TTL_SECS));
            return Some((entry, true, needs_refresh));
        }

        if elapsed <= entry.ttl.saturating_add(self.stale_grace) {
            // Keep expired entries within `stale_grace` so RFC 8767 serve-stale can
            // fall back to them when all upstream servers fail.
            self.misses.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        self.inner.invalidate(key);
        self.misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// RFC 8767 serve-stale fallback: returns a stale cached response (with TTL clamped to
    /// `STALE_RESPONSE_TTL_SECS`) if the entry is still within `stale_grace`, regardless of
    /// whether optimistic caching is enabled.
    pub fn get_stale_fallback(&self, key: &CacheKey, query_id: u16) -> Option<Vec<u8>> {
        let entry = self.inner.get(key)?;
        let elapsed = entry.inserted_at.elapsed();
        if elapsed > entry.ttl.saturating_add(self.stale_grace) {
            self.inner.invalidate(key);
            return None;
        }
        self.hits.fetch_add(1, Ordering::Relaxed);
        self.optimistic_hits.fetch_add(1, Ordering::Relaxed);
        let mut out = Vec::with_capacity(entry.wire_bytes.len());
        out.extend_from_slice(&entry.wire_bytes);
        patch_tx_id(&mut out, query_id);
        patch_wire_ttls(
            &mut out,
            &entry.ttl_offsets,
            0,
            Some(STALE_RESPONSE_TTL_SECS),
        );
        Some(out)
    }

    pub fn insert(&self, key: CacheKey, wire_bytes: Vec<u8>, ttl_secs: u32) {
        let clamped_ttl = ttl_secs.clamp(self.min_ttl_secs, self.max_ttl_secs);
        let ttl_offsets: Box<[(usize, u32)]> =
            scan_rr_ttl_offsets(&wire_bytes, self.min_ttl_secs, clamped_ttl).into_boxed_slice();
        let meta = extract_cached_meta(&wire_bytes);
        self.inner.insert(
            key,
            Arc::new(CachedEntry {
                wire_bytes: wire_bytes.into_boxed_slice(),
                inserted_at: Instant::now(),
                ttl: Duration::from_secs(u64::from(clamped_ttl)),
                ttl_offsets,
                answer_summaries: meta.answer_summaries,
                cname_targets: meta.cname_targets,
                rcode_str: meta.rcode_str,
                has_rebinding_ip: meta.has_rebinding_ip,
                hit_count: AtomicU32::new(0),
                refresh_inflight: AtomicBool::new(false),
            }),
        );
    }

    pub fn clear_refresh_inflight(&self, key: &CacheKey) {
        if let Some(entry) = self.inner.get(key) {
            entry.refresh_inflight.store(false, Ordering::Release);
        }
    }

    pub fn export_persisted(&self, now_unix_secs: i64) -> Vec<PersistedCacheEntry> {
        let stale_secs = self.stale_grace_secs();
        let cap = usize::try_from(self.inner.entry_count()).unwrap_or(0);
        let mut out = Vec::with_capacity(cap);
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
                upstream_scope: key.upstream_scope.clone(),
                wire_bytes: entry.wire_bytes.to_vec(),
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
                upstream_scope: item.upstream_scope,
            };
            let effective_ttl = item.ttl_secs.max(1);
            let ttl_offsets: Box<[(usize, u32)]> = scan_rr_ttl_offsets(
                &item.wire_bytes,
                self.min_ttl_secs.min(effective_ttl),
                effective_ttl,
            )
            .into_boxed_slice();
            let meta = extract_cached_meta(&item.wire_bytes);
            self.inner.insert(
                key,
                Arc::new(CachedEntry {
                    wire_bytes: item.wire_bytes.into_boxed_slice(),
                    inserted_at,
                    ttl,
                    ttl_offsets,
                    answer_summaries: meta.answer_summaries,
                    cname_targets: meta.cname_targets,
                    rcode_str: meta.rcode_str,
                    has_rebinding_ip: meta.has_rebinding_ip,
                    hit_count: AtomicU32::new(0),
                    refresh_inflight: AtomicBool::new(false),
                }),
            );
            imported += 1;
        }
        imported
    }

    pub fn flush(&self) {
        self.inner.invalidate_all();
        self.inner.run_pending_tasks();
    }

    pub fn run_pending_tasks(&self) {
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
            upstream_scope: None,
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
            upstream_scope: None,
        };
        let expired = Arc::new(CachedEntry {
            wire_bytes: vec![0x00, 0x01, 0x81, 0x80].into_boxed_slice(),
            inserted_at: Instant::now()
                .checked_sub(Duration::from_secs(120))
                .expect("valid instant"),
            ttl: Duration::from_secs(30),
            ttl_offsets: Box::from([]),
            answer_summaries: Box::from([]),
            cname_targets: Box::from([]),
            rcode_str: "NOERROR",
            has_rebinding_ip: false,
            hit_count: AtomicU32::new(0),
            refresh_inflight: AtomicBool::new(false),
        });

        let opt_cache = DnsCache::new(10, true);
        opt_cache.inner.insert(key.clone(), Arc::clone(&expired));
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
            upstream_scope: None,
        };
        // TTL below min (5s -> clamped to 30s)
        cache.insert(key.clone(), vec![0x00, 0x01, 0x81, 0x80], 5);
        let entry = cache.inner.get(&key).unwrap();
        assert_eq!(entry.ttl, Duration::from_secs(30));

        // Simulate 90% elapsed (27s of 30s)
        cache.inner.insert(
            key.clone(),
            Arc::new(CachedEntry {
                wire_bytes: vec![0x00, 0x01, 0x81, 0x80].into_boxed_slice(),
                inserted_at: Instant::now()
                    .checked_sub(Duration::from_secs(27))
                    .expect("valid instant"),
                ttl: Duration::from_secs(30),
                ttl_offsets: Box::from([]),
                answer_summaries: Box::from([]),
                cname_targets: Box::from([]),
                rcode_str: "NOERROR",
                has_rebinding_ip: false,
                hit_count: AtomicU32::new(1),
                refresh_inflight: AtomicBool::new(false),
            }),
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
            upstream_scope: None,
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

    #[test]
    fn test_cache_ttl_decrement_opt_preservation_and_soa_negative_ttl() {
        use std::net::Ipv4Addr;

        use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query};
        use hickory_proto::rr::rdata::A;
        use hickory_proto::rr::{Name, RData, Record, RecordType};

        let name = Name::from_ascii("ttl.example.com.").unwrap();
        let mut msg = Message::new(0x1111, MessageType::Response, OpCode::Query);
        msg.metadata.recursion_desired = true;
        msg.metadata.recursion_available = true;
        msg.add_query(Query::query(name.clone(), RecordType::A));
        msg.add_answer(Record::from_rdata(
            name.clone(),
            120,
            RData::A(A(Ipv4Addr::new(93, 184, 216, 34))),
        ));
        let mut edns = Edns::new();
        edns.set_max_payload(1232);
        edns.set_dnssec_ok(true);
        msg.edns = Some(edns);
        let wire = msg.to_vec().unwrap();

        let cache = DnsCache::with_options(64, true, 10, 86_400, false);
        let key = CacheKey {
            qname: "ttl.example.com.".to_string(),
            qtype: 1,
            qclass: 1,
            ecs_subnet: None,
            dnssec_do: true,
            upstream_scope: None,
        };
        let offsets: Box<[(usize, u32)]> =
            scan_rr_ttl_offsets(&wire, 10, 86_400).into_boxed_slice();
        assert_eq!(offsets.len(), 1);
        cache.inner.insert(
            key.clone(),
            Arc::new(CachedEntry {
                wire_bytes: wire.clone().into_boxed_slice(),
                inserted_at: Instant::now().checked_sub(Duration::from_secs(40)).unwrap(),
                ttl: Duration::from_secs(120),
                ttl_offsets: offsets.clone(),
                answer_summaries: Box::from([]),
                cname_targets: Box::from([]),
                rcode_str: "NOERROR",
                has_rebinding_ip: false,
                hit_count: AtomicU32::new(0),
                refresh_inflight: AtomicBool::new(false),
            }),
        );

        let hit = cache.get(&key, 0x2222).unwrap();
        assert!(!hit.is_stale);
        let parsed_hit = Message::from_vec(&hit.wire_bytes).unwrap();
        assert_eq!(parsed_hit.id, 0x2222);
        assert!(parsed_hit.answers[0].ttl <= 80 && parsed_hit.answers[0].ttl >= 79);
        assert!(
            parsed_hit
                .edns
                .as_ref()
                .is_some_and(|e| e.flags().dnssec_ok)
        );

        // Stale hit returns RFC 8767 fixed stale TTL = 30
        cache.inner.insert(
            key.clone(),
            Arc::new(CachedEntry {
                wire_bytes: wire.into_boxed_slice(),
                inserted_at: Instant::now()
                    .checked_sub(Duration::from_secs(200))
                    .unwrap(),
                ttl: Duration::from_secs(120),
                ttl_offsets: offsets,
                answer_summaries: Box::from([]),
                cname_targets: Box::from([]),
                rcode_str: "NOERROR",
                has_rebinding_ip: false,
                hit_count: AtomicU32::new(0),
                refresh_inflight: AtomicBool::new(false),
            }),
        );
        let stale_hit = cache.get(&key, 0x3333).unwrap();
        assert!(stale_hit.is_stale);
        let parsed_stale = Message::from_vec(&stale_hit.wire_bytes).unwrap();
        assert_eq!(parsed_stale.answers[0].ttl, 30);
    }

    #[test]
    fn test_cache_soa_negative_ttl() {
        use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
        use hickory_proto::rr::rdata::SOA;
        use hickory_proto::rr::{Name, RData, Record};

        use crate::wire::compute_response_cache_ttl;

        // RFC 2308 negative caching SOA minimum TTL
        let mut nx_msg = Message::new(1, MessageType::Response, OpCode::Query);
        nx_msg.metadata.response_code = ResponseCode::NXDomain;
        nx_msg.add_authority(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            300,
            RData::SOA(SOA::new(
                Name::from_ascii("ns1.example.com.").unwrap(),
                Name::from_ascii("hostmaster.example.com.").unwrap(),
                1,
                3600,
                600,
                86400,
                45,
            )),
        ));
        assert_eq!(compute_response_cache_ttl(&nx_msg), Some(45));

        let mut nodata_msg = Message::new(2, MessageType::Response, OpCode::Query);
        nodata_msg.metadata.response_code = ResponseCode::NoError;
        nodata_msg.add_authority(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            25,
            RData::SOA(SOA::new(
                Name::from_ascii("ns1.example.com.").unwrap(),
                Name::from_ascii("hostmaster.example.com.").unwrap(),
                1,
                3600,
                600,
                86400,
                90,
            )),
        ));
        assert_eq!(compute_response_cache_ttl(&nodata_msg), Some(25));
    }

    #[test]
    fn test_serve_stale_fallback_when_optimistic_disabled() {
        let cache = DnsCache::with_options(16, false, 1, 300, false);
        let key = CacheKey {
            qname: "fallback.example.".to_string(),
            qtype: 1,
            qclass: 1,
            ecs_subnet: None,
            dnssec_do: false,
            upstream_scope: None,
        };
        use hickory_proto::op::{MessageType, OpCode, Query};
        use hickory_proto::rr::rdata::A;
        use hickory_proto::rr::{Name, RData, Record, RecordType};

        let mut msg = Message::new(0x1111, MessageType::Response, OpCode::Query);
        let name = Name::from_ascii("fallback.example.").unwrap();
        msg.add_query(Query::query(name.clone(), RecordType::A));
        msg.add_answer(Record::from_rdata(
            name,
            1,
            RData::A(A(std::net::Ipv4Addr::new(93, 184, 216, 34))),
        ));
        let wire = msg.to_vec().unwrap();
        cache.insert(key.clone(), wire, 1);

        std::thread::sleep(Duration::from_millis(1150));
        // Strict cache lookup returns None when optimistic is false
        assert!(cache.get(&key, 0x4444).is_none());
        // RFC 8767 serve-stale fallback still serves the entry with STALE_RESPONSE_TTL_SECS (30)
        let stale_wire = cache
            .get_stale_fallback(&key, 0x5555)
            .expect("stale fallback should exist within grace window");
        let parsed = Message::from_vec(&stale_wire).unwrap();
        assert_eq!(parsed.id, 0x5555);
        assert_eq!(parsed.answers[0].ttl, 30);
    }
}
