use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use ts_rs::TS;

pub(crate) const UNHEALTHY_FAILURE_THRESHOLD: u32 = 3;
pub(crate) const UNHEALTHY_BASE_COOLDOWN_MS: u64 = 5_000;
pub(crate) const UNHEALTHY_MAX_COOLDOWN_MS: u64 = 120_000;
const MAX_BACKOFF_EXPONENT: u32 = 6;

pub(crate) fn compute_backoff_cooldown_ms(exponent: u32, entropy: u64) -> u64 {
    let shift = exponent.min(MAX_BACKOFF_EXPONENT);
    let base = UNHEALTHY_BASE_COOLDOWN_MS
        .saturating_mul(1_u64 << shift)
        .min(UNHEALTHY_MAX_COOLDOWN_MS);
    let jitter_span = base / 5;
    if jitter_span == 0 {
        return base;
    }
    // SplitMix64 finalizer for fast, safe ±20% jitter.
    let mut x = entropy.wrapping_add(0x9E37_79B9_7F4A_7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^= x >> 31;
    let window = jitter_span.saturating_mul(2).saturating_add(1);
    let offset = x % window;
    base.saturating_sub(jitter_span)
        .saturating_add(offset)
        .clamp(1_000, UNHEALTHY_MAX_COOLDOWN_MS)
}

/// Returns true if the DNS wire header carries an upstream server error RCODE
/// (`FORMERR=1`, `SERVFAIL=2`, `NOTIMP=4`, `REFUSED=5`).
pub(crate) fn is_upstream_error_rcode(resp: &[u8]) -> bool {
    resp.len() >= 12 && matches!(resp[3] & 0x0F, 1 | 2 | 4 | 5)
}

pub(crate) fn wire_rcode(resp: &[u8]) -> u8 {
    if resp.len() >= 4 { resp[3] & 0x0F } else { 0 }
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct UpstreamStatus {
    pub endpoint: String,
    pub healthy: bool,
    pub consecutive_failures: u32,
    #[ts(type = "number")]
    pub ewma_latency_ms: u64,
    #[ts(type = "number")]
    pub total_requests: u64,
    #[ts(type = "number")]
    pub total_failures: u64,
}

#[derive(Debug, Default)]
pub(crate) struct EndpointHealth {
    pub(crate) consecutive_failures: AtomicU32,
    pub(crate) unhealthy_until_ms: AtomicU64,
    pub(crate) backoff_exponent: AtomicU32,
    pub(crate) probe_inflight: AtomicBool,
    pub(crate) ewma_latency_us: AtomicU64,
    pub(crate) total_requests: AtomicU64,
    pub(crate) total_failures: AtomicU64,
}

pub(crate) struct ProbeGuard<'a> {
    pub(crate) health: &'a EndpointHealth,
    pub(crate) defused: bool,
}

impl Drop for ProbeGuard<'_> {
    fn drop(&mut self) {
        if !self.defused {
            self.health.probe_inflight.store(false, Ordering::Release);
        }
    }
}

impl EndpointHealth {
    pub(crate) fn is_healthy(&self, now_ms: u64) -> bool {
        let until = self.unhealthy_until_ms.load(Ordering::Relaxed);
        until == 0 || now_ms >= until
    }

    pub(crate) fn try_select(&self, now_ms: u64) -> (bool, Option<ProbeGuard<'_>>) {
        let until = self.unhealthy_until_ms.load(Ordering::Relaxed);
        if until == 0 {
            return (true, None);
        }
        if now_ms < until {
            return (false, None);
        }
        if self
            .probe_inflight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            return (
                true,
                Some(ProbeGuard {
                    health: self,
                    defused: false,
                }),
            );
        }
        (false, None)
    }

    pub(crate) fn record_success(&self, elapsed_us: u64) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.consecutive_failures.store(0, Ordering::Relaxed);
        self.unhealthy_until_ms.store(0, Ordering::Relaxed);
        self.backoff_exponent.store(0, Ordering::Relaxed);
        self.probe_inflight.store(false, Ordering::Release);

        let prev = self.ewma_latency_us.load(Ordering::Relaxed);
        let next = if prev == 0 {
            elapsed_us.max(1)
        } else {
            (prev * 7 + elapsed_us.max(1)) / 8
        };
        self.ewma_latency_us.store(next, Ordering::Relaxed);
    }

    pub(crate) fn record_failure(&self, now_ms: u64) {
        let reqs = self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.total_failures.fetch_add(1, Ordering::Relaxed);
        let fails = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        let was_open = self.unhealthy_until_ms.load(Ordering::Relaxed) != 0;
        if was_open || fails >= UNHEALTHY_FAILURE_THRESHOLD {
            let exp = self
                .backoff_exponent
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |cur| {
                    Some(cur.saturating_add(1).min(MAX_BACKOFF_EXPONENT))
                })
                .unwrap_or(0);
            let cooldown = compute_backoff_cooldown_ms(exp, now_ms ^ reqs);
            self.unhealthy_until_ms
                .store(now_ms.saturating_add(cooldown), Ordering::Relaxed);
        }
        self.probe_inflight.store(false, Ordering::Release);
    }

    pub(crate) fn record_error_response(&self, now_ms: u64) {
        self.record_failure(now_ms);
    }

    pub(crate) fn snapshot(&self, label: String, now_ms: u64) -> UpstreamStatus {
        UpstreamStatus {
            endpoint: label,
            healthy: self.is_healthy(now_ms),
            consecutive_failures: self.consecutive_failures.load(Ordering::Relaxed),
            ewma_latency_ms: self.ewma_latency_us.load(Ordering::Relaxed) / 1000,
            total_requests: self.total_requests.load(Ordering::Relaxed),
            total_failures: self.total_failures.load(Ordering::Relaxed),
        }
    }
}
