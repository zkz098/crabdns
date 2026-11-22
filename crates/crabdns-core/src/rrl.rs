use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use arc_swap::ArcSwap;
use dashmap::DashMap;
use foldhash::fast::RandomState;
use hickory_proto::op::{Message, ResponseCode};

use crate::clock::monotonic_now_ms;

const MAX_RRL_ENTRIES: usize = 32_768;
const RRL_STALE_SECS: u64 = 60;
const RRL_PRUNE_COOLDOWN_MS: u64 = 5_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RrlConfig {
    pub enabled: bool,
    pub responses_per_second: u32,
    pub slip: u32,
    pub window_secs: u64,
}

impl Default for RrlConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            responses_per_second: 10,
            slip: 2,
            window_secs: 15,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RrlCategory {
    Normal,
    NxDomain,
    NoData,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RrlDecision {
    Allow,
    Slip,
    Drop,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RrlKey {
    subnet: IpAddr,
    category: RrlCategory,
    domain: String,
}

#[derive(Debug, Clone, Copy)]
struct RrlBucket {
    tokens: f64,
    last_refill: Instant,
}

pub struct ResponseRateLimiter {
    config: ArcSwap<RrlConfig>,
    buckets: DashMap<RrlKey, RrlBucket, RandomState>,
    last_prune_ms: AtomicU64,
    slip_seq: AtomicU64,
}

impl Default for ResponseRateLimiter {
    fn default() -> Self {
        Self::new(RrlConfig::default())
    }
}

impl ResponseRateLimiter {
    pub fn new(config: RrlConfig) -> Self {
        Self {
            config: ArcSwap::from_pointee(config),
            buckets: DashMap::with_hasher(RandomState::default()),
            last_prune_ms: AtomicU64::new(0),
            slip_seq: AtomicU64::new(0),
        }
    }

    pub fn update_config(&self, config: RrlConfig) {
        self.config.store(std::sync::Arc::new(config));
    }

    pub fn config(&self) -> RrlConfig {
        **self.config.load()
    }

    pub fn check(&self, client_ip: IpAddr, domain: &str, category: RrlCategory) -> RrlDecision {
        let cfg = **self.config.load();
        if !cfg.enabled || cfg.responses_per_second == 0 {
            return RrlDecision::Allow;
        }

        let key = RrlKey {
            subnet: mask_client_subnet(client_ip),
            category,
            domain: domain.to_ascii_lowercase(),
        };

        let now = Instant::now();
        let rate = f64::from(cfg.responses_per_second);
        let burst = rate * f64::from(u32::try_from(cfg.window_secs.clamp(1, 5)).unwrap_or(5));

        if let Some(mut entry) = self.buckets.get_mut(&key) {
            if consume_rrl_token(&mut entry, now, rate, burst) {
                return RrlDecision::Allow;
            }
            return self.decide_limit_action(cfg.slip);
        }

        if self.buckets.len() >= MAX_RRL_ENTRIES {
            let now_ms = monotonic_now_ms();
            let prev = self.last_prune_ms.load(Ordering::Relaxed);
            if now_ms.saturating_sub(prev) >= RRL_PRUNE_COOLDOWN_MS
                && self
                    .last_prune_ms
                    .compare_exchange(prev, now_ms, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok()
            {
                self.prune_stale();
            }
            if self.buckets.len() >= MAX_RRL_ENTRIES {
                return self.decide_limit_action(cfg.slip);
            }
        }

        let mut entry = self.buckets.entry(key).or_insert(RrlBucket {
            tokens: burst,
            last_refill: now,
        });
        if consume_rrl_token(&mut entry, now, rate, burst) {
            RrlDecision::Allow
        } else {
            self.decide_limit_action(cfg.slip)
        }
    }

    fn decide_limit_action(&self, slip: u32) -> RrlDecision {
        if slip > 0 {
            let seq = self.slip_seq.fetch_add(1, Ordering::Relaxed);
            if seq.is_multiple_of(u64::from(slip)) {
                return RrlDecision::Slip;
            }
        }
        RrlDecision::Drop
    }

    pub fn prune_stale(&self) {
        let before = self.buckets.len();
        let now = Instant::now();
        self.buckets
            .retain(|_, b| now.duration_since(b.last_refill).as_secs() < RRL_STALE_SECS);
        let after = self.buckets.len();
        if after == 0 || after.saturating_mul(4) < before {
            self.buckets.shrink_to_fit();
        }
    }
}

pub fn classify_response_category(resp_bytes: &[u8]) -> RrlCategory {
    let Ok(msg) = Message::from_vec(resp_bytes) else {
        return RrlCategory::Error;
    };
    match msg.response_code {
        ResponseCode::NoError => {
            if msg.answers.is_empty() {
                RrlCategory::NoData
            } else {
                RrlCategory::Normal
            }
        }
        ResponseCode::NXDomain => RrlCategory::NxDomain,
        _ => RrlCategory::Error,
    }
}

fn consume_rrl_token(bucket: &mut RrlBucket, now: Instant, rate: f64, burst: f64) -> bool {
    let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
    bucket.tokens = (bucket.tokens + elapsed * rate).min(burst);
    bucket.last_refill = now;
    if bucket.tokens >= 1.0 {
        bucket.tokens -= 1.0;
        true
    } else {
        false
    }
}

fn mask_client_subnet(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], 0))
        }
        IpAddr::V6(v6) => {
            let raw = u128::from(v6);
            let mask = !0_u128 << (128 - 56);
            IpAddr::V6(Ipv6Addr::from(raw & mask))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rrl_allows_burst_then_slips_and_drops() {
        let limiter = ResponseRateLimiter::new(RrlConfig {
            enabled: true,
            responses_per_second: 1,
            slip: 2,
            window_secs: 1,
        });
        let ip: IpAddr = "198.51.100.42".parse().unwrap();

        // First response allowed (burst = 1.0).
        assert_eq!(
            limiter.check(ip, "example.com", RrlCategory::NxDomain),
            RrlDecision::Allow
        );
        // Subsequent immediate responses hit limit: slip=2 alternates Slip and Drop.
        assert_eq!(
            limiter.check(ip, "example.com", RrlCategory::NxDomain),
            RrlDecision::Slip
        );
        assert_eq!(
            limiter.check(ip, "example.com", RrlCategory::NxDomain),
            RrlDecision::Drop
        );
        assert_eq!(
            limiter.check(ip, "example.com", RrlCategory::NxDomain),
            RrlDecision::Slip
        );
    }
}
