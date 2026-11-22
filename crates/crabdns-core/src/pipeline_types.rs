use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use chrono::{DateTime, Utc};
use hickory_proto::rr::RecordType;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Clone)]
pub(crate) struct LogMeta {
    pub client_addr: SocketAddr,
    pub client_name: Option<String>,
    pub client_id: Option<String>,
    pub profile_id: Option<String>,
    pub protocol: QueryProtocol,
    pub domain: String,
    pub qtype: RecordType,
    pub start: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum QueryOutcome {
    Forwarded,
    Cached,
    Blocked,
    Rewritten,
    Error,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum QueryProtocol {
    #[default]
    Udp,
    Tcp,
    Dot,
    Doq,
    Doh,
}

#[derive(Debug, Clone)]
pub struct QueryContext {
    pub client_addr: SocketAddr,
    pub protocol: QueryProtocol,
    pub client_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct QueryEvent {
    pub timestamp: DateTime<Utc>,
    pub client_ip: String,
    #[serde(default)]
    pub client_name: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub profile_id: Option<String>,
    #[serde(default)]
    pub protocol: QueryProtocol,
    pub domain: String,
    pub qtype: String,
    pub outcome: QueryOutcome,
    pub matched_rule: Option<String>,
    #[serde(default)]
    pub matched_list: Option<String>,
    pub upstream: Option<String>,
    #[ts(type = "number")]
    pub elapsed_us: u64,
    pub rcode: String,
    #[serde(default)]
    pub answers: Vec<String>,
}

pub(crate) const MAX_BG_REFRESHES: usize = 64;
const LATENCY_BUCKET_BOUNDS_US: [u64; 14] = [
    500, 1_000, 2_000, 5_000, 10_000, 25_000, 50_000, 100_000, 250_000, 500_000, 1_000_000,
    2_500_000, 5_000_000, 10_000_000,
];

#[derive(Debug, Default)]
pub(crate) struct QueryLatencyHistogram {
    buckets: [AtomicU64; 14],
    inf_bucket: AtomicU64,
    sum_us: AtomicU64,
    count: AtomicU64,
}

impl QueryLatencyHistogram {
    pub(crate) fn record(&self, elapsed_us: u64) {
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum_us.fetch_add(elapsed_us, Ordering::Relaxed);
        if let Some(idx) = LATENCY_BUCKET_BOUNDS_US
            .iter()
            .position(|&bound| elapsed_us <= bound)
        {
            self.buckets[idx].fetch_add(1, Ordering::Relaxed);
        } else {
            self.inf_bucket.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn snapshot(&self) -> LatencyHistogramSnapshot {
        let mut cumulative = 0_u64;
        let mut buckets = Vec::with_capacity(LATENCY_BUCKET_BOUNDS_US.len());
        for (idx, bound_us) in LATENCY_BUCKET_BOUNDS_US.iter().enumerate() {
            cumulative = cumulative.saturating_add(self.buckets[idx].load(Ordering::Relaxed));
            #[allow(clippy::cast_precision_loss)]
            let bound_secs = *bound_us as f64 / 1_000_000.0;
            buckets.push((bound_secs, cumulative));
        }
        let inf = cumulative.saturating_add(self.inf_bucket.load(Ordering::Relaxed));
        let sum_us = self.sum_us.load(Ordering::Relaxed);
        let count = self.count.load(Ordering::Relaxed);
        #[allow(clippy::cast_precision_loss)]
        let sum_secs = sum_us as f64 / 1_000_000.0;
        LatencyHistogramSnapshot {
            buckets,
            inf_count: inf,
            sum_secs,
            count,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct LatencyHistogramSnapshot {
    pub buckets: Vec<(f64, u64)>,
    pub inf_count: u64,
    pub sum_secs: f64,
    pub count: u64,
}

#[derive(Debug, Default)]
pub(crate) struct ServerRuntimeCounters {
    pub(crate) udp_dropped_inflight: AtomicU64,
    pub(crate) tcp_active_connections: AtomicU64,
    pub(crate) tcp_rejected_connections: AtomicU64,
    pub(crate) dot_active_connections: AtomicU64,
    pub(crate) dot_rejected_connections: AtomicU64,
    pub(crate) doq_active_connections: AtomicU64,
    pub(crate) doq_rejected_connections: AtomicU64,
    pub(crate) web_active_connections: AtomicU64,
    pub(crate) web_rejected_connections: AtomicU64,
    pub(crate) doh_rejected_inflight: AtomicU64,
    pub(crate) doh_timed_out: AtomicU64,
    pub(crate) filter_reloads: AtomicU64,
    pub(crate) filter_last_reload_ms: AtomicU64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PipelineRuntimeMetrics {
    pub log_dropped: u64,
    pub singleflight_inflight: usize,
    pub rdns_inflight: usize,
    pub acl_tracked_clients: usize,
    pub bg_refresh_inflight: usize,
    pub udp_dropped_inflight: u64,
    pub tcp_active_connections: u64,
    pub tcp_rejected_connections: u64,
    pub dot_active_connections: u64,
    pub dot_rejected_connections: u64,
    pub doq_active_connections: u64,
    pub doq_rejected_connections: u64,
    pub web_active_connections: u64,
    pub web_rejected_connections: u64,
    pub doh_rejected_inflight: u64,
    pub doh_timed_out: u64,
    pub filter_reloads: u64,
    pub filter_last_reload_ms: u64,
}
