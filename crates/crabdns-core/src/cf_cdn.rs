use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use hickory_proto::op::Message;
use hickory_proto::rr::rdata::svcb::{SVCB, SvcParamKey, SvcParamValue};
use hickory_proto::rr::rdata::{A, AAAA, HTTPS};
use hickory_proto::rr::{RData, Record, RecordType};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio::time::timeout;
use ts_rs::TS;

/// Static fallback list of Cloudflare IPv4 CIDR ranges.
/// Source: <https://www.cloudflare.com/ips-v4>
pub const CLOUDFLARE_IPV4_RANGES: &[&str] = &[
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
];

/// Static fallback list of Cloudflare IPv6 CIDR ranges.
/// Source: <https://www.cloudflare.com/ips-v6>
pub const CLOUDFLARE_IPV6_RANGES: &[&str] = &[
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
];

const CF_IPS_V4_URL: &str = "https://www.cloudflare.com/ips-v4";
const CF_IPS_V6_URL: &str = "https://www.cloudflare.com/ips-v6";
pub const DEFAULT_SPEEDTEST_URL: &str = "https://speed.cloudflare.com/__down?bytes=99999999";

const FETCH_TIMEOUT: Duration = Duration::from_secs(10);
const TCP_PROBE_TIMEOUT: Duration = Duration::from_secs(3);
const THROUGHPUT_SEND_TIMEOUT: Duration = Duration::from_secs(8);
const THROUGHPUT_STREAM_DURATION: Duration = Duration::from_secs(5);

const fn default_true() -> bool {
    true
}

const fn default_interval_secs() -> u64 {
    1800
}

fn default_speedtest_url() -> String {
    DEFAULT_SPEEDTEST_URL.to_string()
}

const fn default_concurrency() -> usize {
    50
}

const fn default_top_n() -> usize {
    3
}

const fn default_samples_per_cidr() -> usize {
    3
}

const fn default_ttl_secs() -> u32 {
    60
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
pub struct CfCdnConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub ipv6_enabled: bool,
    #[serde(default = "default_interval_secs")]
    #[ts(type = "number")]
    pub interval_secs: u64,
    #[serde(default = "default_speedtest_url")]
    pub speedtest_url: String,
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
    #[serde(default = "default_top_n")]
    pub top_n: usize,
    #[serde(default = "default_samples_per_cidr")]
    pub samples_per_cidr: usize,
    #[serde(default = "default_ttl_secs")]
    pub ttl_secs: u32,
    #[serde(default)]
    pub excluded_domains: Vec<String>,
    #[serde(default)]
    pub custom_ipv4_cidrs: Vec<String>,
    #[serde(default)]
    pub custom_ipv6_cidrs: Vec<String>,
}

impl Default for CfCdnConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ipv6_enabled: true,
            interval_secs: default_interval_secs(),
            speedtest_url: default_speedtest_url(),
            concurrency: default_concurrency(),
            top_n: default_top_n(),
            samples_per_cidr: default_samples_per_cidr(),
            ttl_secs: default_ttl_secs(),
            excluded_domains: Vec::new(),
            custom_ipv4_cidrs: Vec::new(),
            custom_ipv6_cidrs: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct CfSpeedTestNode {
    pub ip: String,
    pub latency_ms: f64,
    pub throughput_mbps: Option<f64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct CfCdnStatus {
    pub enabled: bool,
    pub ipv6_enabled: bool,
    pub testing: bool,
    #[ts(type = "number | null")]
    pub last_run_unix_ms: Option<u64>,
    pub last_error: Option<String>,
    pub best_ipv4: Option<String>,
    pub best_ipv4_latency_ms: Option<f64>,
    pub best_ipv4_throughput_mbps: Option<f64>,
    pub best_ipv6: Option<String>,
    pub best_ipv6_latency_ms: Option<f64>,
    pub best_ipv6_throughput_mbps: Option<f64>,
    pub ipv4_cidr_count: usize,
    pub ipv6_cidr_count: usize,
    pub candidates_v4: Vec<CfSpeedTestNode>,
    pub candidates_v6: Vec<CfSpeedTestNode>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Cidr {
    network: u32,
    mask: u32,
    prefix: u8,
}

impl Ipv4Cidr {
    pub fn parse(cidr: &str) -> Option<Self> {
        let (ip_str, prefix_str) = cidr.trim().split_once('/')?;
        let prefix: u8 = prefix_str.parse().ok()?;
        if prefix > 32 {
            return None;
        }
        let ip: Ipv4Addr = ip_str.parse().ok()?;
        let mask = if prefix == 0 {
            0u32
        } else {
            !0u32 << (32 - prefix)
        };
        Some(Self {
            network: u32::from(ip) & mask,
            mask,
            prefix,
        })
    }

    pub const fn contains(self, ip: Ipv4Addr) -> bool {
        (u32::from_be_bytes(ip.octets()) & self.mask) == self.network
    }

    pub fn sample(self, count: usize) -> Vec<Ipv4Addr> {
        let total = if self.prefix >= 32 {
            0u32
        } else {
            1u32 << (32 - self.prefix)
        };
        let max_offset = total.saturating_sub(1);
        let take = u32::try_from(count).unwrap_or(u32::MAX).min(max_offset);
        (1..=take)
            .map(|offset| Ipv4Addr::from(self.network + offset))
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Cidr {
    network: u128,
    mask: u128,
    prefix: u8,
}

impl Ipv6Cidr {
    pub fn parse(cidr: &str) -> Option<Self> {
        let (ip_str, prefix_str) = cidr.trim().split_once('/')?;
        let prefix: u8 = prefix_str.parse().ok()?;
        if prefix > 128 {
            return None;
        }
        let ip: Ipv6Addr = ip_str.parse().ok()?;
        let mask = if prefix == 0 {
            0u128
        } else {
            !0u128 << (128 - prefix)
        };
        Some(Self {
            network: u128::from(ip) & mask,
            mask,
            prefix,
        })
    }

    pub const fn contains(self, ip: Ipv6Addr) -> bool {
        (u128::from_be_bytes(ip.octets()) & self.mask) == self.network
    }

    pub fn sample(self, count: usize) -> Vec<Ipv6Addr> {
        let total = if self.prefix >= 128 {
            0u128
        } else {
            1u128 << (128 - self.prefix)
        };
        let max_offset = total.saturating_sub(1);
        let take = (count as u128).min(max_offset);
        (1..=take)
            .map(|offset| Ipv6Addr::from(self.network + offset))
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct CfCdnRuntime {
    pub config: CfCdnConfig,
    pub excluded_domains: Vec<String>,
    pub ipv4_cidrs: Vec<Ipv4Cidr>,
    pub ipv6_cidrs: Vec<Ipv6Cidr>,
    pub best_ipv4: Option<Ipv4Addr>,
    pub best_ipv6: Option<Ipv6Addr>,
    pub status: CfCdnStatus,
}

impl Default for CfCdnRuntime {
    fn default() -> Self {
        let config = CfCdnConfig::default();
        let ipv4_cidrs = parse_v4_cidrs(CLOUDFLARE_IPV4_RANGES.iter().copied());
        let ipv6_cidrs = parse_v6_cidrs(CLOUDFLARE_IPV6_RANGES.iter().copied());
        let status = CfCdnStatus {
            enabled: config.enabled,
            ipv6_enabled: config.ipv6_enabled,
            ipv4_cidr_count: ipv4_cidrs.len(),
            ipv6_cidr_count: ipv6_cidrs.len(),
            ..CfCdnStatus::default()
        };
        Self {
            config,
            excluded_domains: Vec::new(),
            ipv4_cidrs,
            ipv6_cidrs,
            best_ipv4: None,
            best_ipv6: None,
            status,
        }
    }
}

pub struct CfCdnManager {
    runtime: ArcSwap<CfCdnRuntime>,
    testing: AtomicBool,
    run_lock: tokio::sync::Mutex<()>,
    status_tx: tokio::sync::watch::Sender<u64>,
}

impl Default for CfCdnManager {
    fn default() -> Self {
        Self::new()
    }
}

impl CfCdnManager {
    pub fn new() -> Self {
        let (status_tx, _) = tokio::sync::watch::channel(0);
        Self {
            runtime: ArcSwap::from_pointee(CfCdnRuntime::default()),
            testing: AtomicBool::new(false),
            run_lock: tokio::sync::Mutex::new(()),
            status_tx,
        }
    }

    pub fn subscribe_status(&self) -> tokio::sync::watch::Receiver<u64> {
        self.status_tx.subscribe()
    }

    fn notify_status_changed(&self) {
        self.status_tx.send_modify(|rev| *rev = rev.wrapping_add(1));
    }

    pub fn is_enabled(&self) -> bool {
        self.runtime.load().config.enabled
    }

    pub fn is_testing(&self) -> bool {
        self.testing.load(Ordering::SeqCst)
    }

    pub fn status(&self) -> CfCdnStatus {
        let mut status = self.runtime.load().status.clone();
        status.testing = self.is_testing();
        status
    }

    pub fn reload_config(&self, config: CfCdnConfig) {
        let current = self.runtime.load_full();
        let excluded_domains = normalize_excluded_domains(&config.excluded_domains);

        let ipv4_cidrs = if config.custom_ipv4_cidrs.is_empty() {
            if current.config.custom_ipv4_cidrs.is_empty() && !current.ipv4_cidrs.is_empty() {
                current.ipv4_cidrs.clone()
            } else {
                parse_v4_cidrs(CLOUDFLARE_IPV4_RANGES.iter().copied())
            }
        } else {
            parse_v4_cidrs(config.custom_ipv4_cidrs.iter().map(String::as_str))
        };

        let ipv6_cidrs = if config.custom_ipv6_cidrs.is_empty() {
            if current.config.custom_ipv6_cidrs.is_empty() && !current.ipv6_cidrs.is_empty() {
                current.ipv6_cidrs.clone()
            } else {
                parse_v6_cidrs(CLOUDFLARE_IPV6_RANGES.iter().copied())
            }
        } else {
            parse_v6_cidrs(config.custom_ipv6_cidrs.iter().map(String::as_str))
        };

        let mut status = current.status.clone();
        status.enabled = config.enabled;
        status.ipv6_enabled = config.ipv6_enabled;
        status.ipv4_cidr_count = ipv4_cidrs.len();
        status.ipv6_cidr_count = ipv6_cidrs.len();

        let next = CfCdnRuntime {
            config,
            excluded_domains,
            ipv4_cidrs,
            ipv6_cidrs,
            best_ipv4: current.best_ipv4,
            best_ipv6: current.best_ipv6,
            status,
        };
        self.runtime.store(Arc::new(next));
        self.notify_status_changed();
    }

    /// Runs the two-phase Cloudflare CDN speed test (IPv4, and IPv6 if enabled)
    /// and atomically updates the active optimal IPs.
    pub async fn run_speedtest(&self) -> CfCdnStatus {
        let _guard = self.run_lock.lock().await;
        self.testing.store(true, Ordering::SeqCst);
        self.notify_status_changed();

        let res = self.run_speedtest_inner().await;

        self.testing.store(false, Ordering::SeqCst);
        self.notify_status_changed();
        res
    }

    async fn run_speedtest_inner(&self) -> CfCdnStatus {
        let rt_snapshot = self.runtime.load_full();
        let cfg = rt_snapshot.config.clone();

        let (ipv4_cidrs, ipv6_cidrs, fetch_err) = resolve_cidrs(&cfg).await;

        let samples_per_cidr = cfg.samples_per_cidr.clamp(1, 32);
        let concurrency = cfg.concurrency.clamp(1, 200);
        let top_n = cfg.top_n.clamp(1, 10);

        let v4_candidates: Vec<IpAddr> = ipv4_cidrs
            .iter()
            .flat_map(|c| c.sample(samples_per_cidr))
            .map(IpAddr::V4)
            .collect();

        let (best_v4_node, candidates_v4) =
            speedtest_family(&v4_candidates, concurrency, top_n, &cfg.speedtest_url).await;

        let (best_v6_node, candidates_v6) = if cfg.ipv6_enabled {
            let v6_candidates: Vec<IpAddr> = ipv6_cidrs
                .iter()
                .flat_map(|c| c.sample(samples_per_cidr))
                .map(IpAddr::V6)
                .collect();
            speedtest_family(&v6_candidates, concurrency, top_n, &cfg.speedtest_url).await
        } else {
            (None, Vec::new())
        };

        let best_ipv4 = best_v4_node
            .as_ref()
            .and_then(|n| n.ip.parse::<Ipv4Addr>().ok());
        let best_ipv6 = best_v6_node
            .as_ref()
            .and_then(|n| n.ip.parse::<Ipv6Addr>().ok());

        let last_error = if best_ipv4.is_none() && (!cfg.ipv6_enabled || best_ipv6.is_none()) {
            fetch_err.or_else(|| Some("No reachable Cloudflare CDN IPs found".to_string()))
        } else {
            fetch_err
        };

        let status = CfCdnStatus {
            enabled: cfg.enabled,
            ipv6_enabled: cfg.ipv6_enabled,
            testing: false,
            last_run_unix_ms: Some(current_unix_ms()),
            last_error,
            best_ipv4: best_ipv4.map(|ip| ip.to_string()),
            best_ipv4_latency_ms: best_v4_node.as_ref().map(|n| n.latency_ms),
            best_ipv4_throughput_mbps: best_v4_node.as_ref().and_then(|n| n.throughput_mbps),
            best_ipv6: best_ipv6.map(|ip| ip.to_string()),
            best_ipv6_latency_ms: best_v6_node.as_ref().map(|n| n.latency_ms),
            best_ipv6_throughput_mbps: best_v6_node.as_ref().and_then(|n| n.throughput_mbps),
            ipv4_cidr_count: ipv4_cidrs.len(),
            ipv6_cidr_count: ipv6_cidrs.len(),
            candidates_v4,
            candidates_v6,
        };

        let next = CfCdnRuntime {
            config: cfg,
            excluded_domains: rt_snapshot.excluded_domains.clone(),
            ipv4_cidrs,
            ipv6_cidrs,
            best_ipv4,
            best_ipv6,
            status: status.clone(),
        };
        self.runtime.store(Arc::new(next));
        status
    }

    /// Rewrites DNS `A`, `AAAA`, and `HTTPS`/`SVCB` hint records in `msg` if the
    /// response contains Cloudflare CDN IPs and optimal IP(s) are available.
    ///
    /// Returns `true` if `msg` was modified.
    pub fn rewrite_message_if_cloudflare(&self, domain: &str, msg: &mut Message) -> bool {
        let rt = self.runtime.load();
        if !rt.config.enabled {
            return false;
        }
        if is_domain_excluded(domain, &rt.excluded_domains) {
            return false;
        }

        let ttl = rt.config.ttl_secs.max(1);
        let best_v4 = rt.best_ipv4;
        let best_v6 = if rt.config.ipv6_enabled {
            rt.best_ipv6
        } else {
            None
        };

        let mut modified = false;

        if let Some(target_v4) = best_v4 {
            modified |= rewrite_a_records(&mut msg.answers, &rt.ipv4_cidrs, target_v4, ttl);
            modified |= rewrite_a_records(&mut msg.additionals, &rt.ipv4_cidrs, target_v4, ttl);
        }

        if let Some(target_v6) = best_v6 {
            modified |= rewrite_aaaa_records(&mut msg.answers, &rt.ipv6_cidrs, target_v6, ttl);
            modified |= rewrite_aaaa_records(&mut msg.additionals, &rt.ipv6_cidrs, target_v6, ttl);
        }

        modified |= rewrite_svcb_hints(
            &mut msg.answers,
            &rt.ipv4_cidrs,
            &rt.ipv6_cidrs,
            best_v4,
            best_v6,
        );
        modified |= rewrite_svcb_hints(
            &mut msg.additionals,
            &rt.ipv4_cidrs,
            &rt.ipv6_cidrs,
            best_v4,
            best_v6,
        );

        if modified {
            msg.answers
                .retain(|rec| rec.record_type() != RecordType::RRSIG);
            msg.additionals
                .retain(|rec| rec.record_type() != RecordType::RRSIG);
        }

        modified
    }
}

fn rewrite_a_records(
    records: &mut Vec<Record>,
    cidrs: &[Ipv4Cidr],
    best_v4: Ipv4Addr,
    ttl: u32,
) -> bool {
    let has_cf = records
        .iter()
        .any(|rec| matches!(rec.data, RData::A(A(ip)) if cidrs.iter().any(|c| c.contains(ip))));
    if !has_cf {
        return false;
    }

    let mut replaced_first = false;
    let mut next = Vec::with_capacity(records.len());
    for mut rec in records.drain(..) {
        if let RData::A(A(ip)) = rec.data
            && cidrs.iter().any(|c| c.contains(ip))
        {
            if !replaced_first {
                rec.data = RData::A(A(best_v4));
                rec.ttl = ttl;
                next.push(rec);
                replaced_first = true;
            }
            continue;
        }
        next.push(rec);
    }
    *records = next;
    true
}

fn rewrite_aaaa_records(
    records: &mut Vec<Record>,
    cidrs: &[Ipv6Cidr],
    best_v6: Ipv6Addr,
    ttl: u32,
) -> bool {
    let has_cf = records.iter().any(
        |rec| matches!(rec.data, RData::AAAA(AAAA(ip)) if cidrs.iter().any(|c| c.contains(ip))),
    );
    if !has_cf {
        return false;
    }

    let mut replaced_first = false;
    let mut next = Vec::with_capacity(records.len());
    for mut rec in records.drain(..) {
        if let RData::AAAA(AAAA(ip)) = rec.data
            && cidrs.iter().any(|c| c.contains(ip))
        {
            if !replaced_first {
                rec.data = RData::AAAA(AAAA(best_v6));
                rec.ttl = ttl;
                next.push(rec);
                replaced_first = true;
            }
            continue;
        }
        next.push(rec);
    }
    *records = next;
    true
}

fn rewrite_svcb_inner(
    svcb: &SVCB,
    v4_cidrs: &[Ipv4Cidr],
    v6_cidrs: &[Ipv6Cidr],
    best_v4: Option<Ipv4Addr>,
    best_v6: Option<Ipv6Addr>,
) -> Option<SVCB> {
    let mut changed = false;
    let mut next_params = Vec::with_capacity(svcb.svc_params.len());

    for (key, val) in &svcb.svc_params {
        match (key, val) {
            (SvcParamKey::Ipv4Hint, SvcParamValue::Ipv4Hint(hint))
                if hint
                    .0
                    .iter()
                    .any(|a| v4_cidrs.iter().any(|c| c.contains(a.0))) =>
            {
                changed = true;
                if let Some(v4) = best_v4 {
                    next_params.push((
                        *key,
                        SvcParamValue::Ipv4Hint(hickory_proto::rr::rdata::svcb::IpHint(vec![A(
                            v4,
                        )])),
                    ));
                }
            }
            (SvcParamKey::Ipv6Hint, SvcParamValue::Ipv6Hint(hint))
                if hint
                    .0
                    .iter()
                    .any(|a| v6_cidrs.iter().any(|c| c.contains(a.0))) =>
            {
                changed = true;
                if let Some(v6) = best_v6 {
                    next_params.push((
                        *key,
                        SvcParamValue::Ipv6Hint(hickory_proto::rr::rdata::svcb::IpHint(vec![
                            AAAA(v6),
                        ])),
                    ));
                }
            }
            _ => next_params.push((*key, val.clone())),
        }
    }

    if !changed {
        return None;
    }

    Some(SVCB::new(
        svcb.svc_priority,
        svcb.target_name.clone(),
        next_params,
    ))
}

fn rewrite_svcb_hints(
    records: &mut [Record],
    v4_cidrs: &[Ipv4Cidr],
    v6_cidrs: &[Ipv6Cidr],
    best_v4: Option<Ipv4Addr>,
    best_v6: Option<Ipv6Addr>,
) -> bool {
    let mut changed = false;
    for rec in records.iter_mut() {
        match &rec.data {
            RData::SVCB(svcb) => {
                if let Some(next) = rewrite_svcb_inner(svcb, v4_cidrs, v6_cidrs, best_v4, best_v6) {
                    rec.data = RData::SVCB(next);
                    changed = true;
                }
            }
            RData::HTTPS(https) => {
                if let Some(next) =
                    rewrite_svcb_inner(&https.0, v4_cidrs, v6_cidrs, best_v4, best_v6)
                {
                    rec.data = RData::HTTPS(HTTPS(next));
                    changed = true;
                }
            }
            _ => {}
        }
    }
    changed
}

fn parse_v4_cidrs<'a>(iter: impl IntoIterator<Item = &'a str>) -> Vec<Ipv4Cidr> {
    iter.into_iter().filter_map(Ipv4Cidr::parse).collect()
}

fn parse_v6_cidrs<'a>(iter: impl IntoIterator<Item = &'a str>) -> Vec<Ipv6Cidr> {
    iter.into_iter().filter_map(Ipv6Cidr::parse).collect()
}

fn normalize_excluded_domains(domains: &[String]) -> Vec<String> {
    domains
        .iter()
        .map(|d| d.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|d| !d.is_empty())
        .collect()
}

fn is_domain_excluded(domain: &str, excluded: &[String]) -> bool {
    if excluded.is_empty() {
        return false;
    }
    let clean = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    excluded.iter().any(|rule| {
        clean == *rule
            || (clean.len() > rule.len()
                && clean.ends_with(rule)
                && clean.as_bytes()[clean.len() - rule.len() - 1] == b'.')
    })
}

async fn fetch_cidr_text(client: &reqwest::Client, url: &str) -> Result<String, String> {
    let resp = timeout(FETCH_TIMEOUT, client.get(url).send())
        .await
        .map_err(|_| format!("fetch {url} timed out"))?
        .map_err(|e| format!("fetch {url} failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("fetch {url} returned HTTP {}", resp.status()));
    }
    resp.text()
        .await
        .map_err(|e| format!("read {url} body failed: {e}"))
}

async fn resolve_cidrs(cfg: &CfCdnConfig) -> (Vec<Ipv4Cidr>, Vec<Ipv6Cidr>, Option<String>) {
    let has_custom_v4 = !cfg.custom_ipv4_cidrs.is_empty();
    let has_custom_v6 = !cfg.custom_ipv6_cidrs.is_empty();

    let mut ipv4_cidrs = if has_custom_v4 {
        parse_v4_cidrs(cfg.custom_ipv4_cidrs.iter().map(String::as_str))
    } else {
        Vec::new()
    };

    let mut ipv6_cidrs = if has_custom_v6 {
        parse_v6_cidrs(cfg.custom_ipv6_cidrs.iter().map(String::as_str))
    } else {
        Vec::new()
    };

    let mut fetch_err = None;
    if !has_custom_v4 || (cfg.ipv6_enabled && !has_custom_v6) {
        if let Ok(client) = reqwest::Client::builder().timeout(FETCH_TIMEOUT).build() {
            if !has_custom_v4 {
                match fetch_cidr_text(&client, CF_IPS_V4_URL).await {
                    Ok(body) => {
                        ipv4_cidrs = parse_v4_cidrs(body.lines());
                    }
                    Err(err) => {
                        tracing::warn!(error = %err, "failed to fetch Cloudflare IPv4 CIDRs, using fallback");
                        fetch_err = Some(err);
                    }
                }
            }
            if cfg.ipv6_enabled && !has_custom_v6 {
                match fetch_cidr_text(&client, CF_IPS_V6_URL).await {
                    Ok(body) => {
                        ipv6_cidrs = parse_v6_cidrs(body.lines());
                    }
                    Err(err) => {
                        tracing::warn!(error = %err, "failed to fetch Cloudflare IPv6 CIDRs, using fallback");
                        if fetch_err.is_none() {
                            fetch_err = Some(err);
                        }
                    }
                }
            }
        }
    }

    if ipv4_cidrs.is_empty() {
        ipv4_cidrs = parse_v4_cidrs(CLOUDFLARE_IPV4_RANGES.iter().copied());
    }
    if ipv6_cidrs.is_empty() {
        ipv6_cidrs = parse_v6_cidrs(CLOUDFLARE_IPV6_RANGES.iter().copied());
    }

    (ipv4_cidrs, ipv6_cidrs, fetch_err)
}

async fn measure_tcp_latency(addr: SocketAddr, connect_timeout: Duration) -> Option<Duration> {
    let start = Instant::now();
    match timeout(connect_timeout, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => {
            drop(stream);
            Some(start.elapsed())
        }
        _ => None,
    }
}

async fn screen_candidates(
    ips: &[IpAddr],
    concurrency: usize,
    connect_timeout: Duration,
) -> Vec<(IpAddr, f64)> {
    let mut join_set = JoinSet::new();
    let mut results = Vec::new();
    let mut ip_iter = ips.iter().copied();

    for _ in 0..concurrency {
        let Some(ip) = ip_iter.next() else {
            break;
        };
        join_set.spawn(async move {
            let latency = measure_tcp_latency(SocketAddr::new(ip, 443), connect_timeout).await;
            (ip, latency)
        });
    }

    while let Some(res) = join_set.join_next().await {
        if let Ok((ip, Some(latency))) = res {
            results.push((ip, latency.as_secs_f64() * 1000.0));
        }
        if let Some(ip) = ip_iter.next() {
            join_set.spawn(async move {
                let latency = measure_tcp_latency(SocketAddr::new(ip, 443), connect_timeout).await;
                (ip, latency)
            });
        }
    }

    results.sort_by(|a, b| a.1.total_cmp(&b.1));
    results
}

async fn measure_throughput(ip: IpAddr, speedtest_url: &str) -> Result<f64, String> {
    let parsed =
        reqwest::Url::parse(speedtest_url).map_err(|e| format!("invalid speedtest URL: {e}"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| "speedtest URL has no host".to_string())?;
    let port = parsed.port_or_known_default().unwrap_or(443);

    let client = reqwest::Client::builder()
        .resolve_to_addrs(host, &[SocketAddr::new(ip, port)])
        .connect_timeout(Duration::from_secs(5))
        .user_agent("crabdns-cf-speedtest/1.0")
        .build()
        .map_err(|e| format!("build client failed: {e}"))?;

    let start = Instant::now();
    let resp = timeout(THROUGHPUT_SEND_TIMEOUT, client.get(speedtest_url).send())
        .await
        .map_err(|_| "HTTP request timed out".to_string())?
        .map_err(|e| format!("HTTP request failed: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }

    let mut resp = resp;
    let bytes = Arc::new(AtomicU64::new(0));
    let bytes_ref = Arc::clone(&bytes);
    let download = async move {
        while let Ok(Some(data)) = resp.chunk().await {
            bytes_ref.fetch_add(data.len() as u64, Ordering::Relaxed);
        }
    };

    let _ = timeout(THROUGHPUT_STREAM_DURATION, download).await;
    let elapsed_secs = start.elapsed().as_secs_f64();
    let total_bytes = bytes.load(Ordering::Relaxed) as f64;

    if elapsed_secs <= 0.0 || total_bytes <= 0.0 {
        return Err("no bytes received".to_string());
    }

    Ok((total_bytes / elapsed_secs) / 1_000_000.0)
}

async fn speedtest_family(
    ips: &[IpAddr],
    concurrency: usize,
    top_n: usize,
    speedtest_url: &str,
) -> (Option<CfSpeedTestNode>, Vec<CfSpeedTestNode>) {
    if ips.is_empty() {
        return (None, Vec::new());
    }

    let screened = screen_candidates(ips, concurrency, TCP_PROBE_TIMEOUT).await;
    if screened.is_empty() {
        return (None, Vec::new());
    }

    let mut nodes = Vec::with_capacity(top_n.min(screened.len()));
    for &(ip, latency_ms) in screened.iter().take(top_n) {
        let (throughput_mbps, error) = match measure_throughput(ip, speedtest_url).await {
            Ok(mbps) => (Some((mbps * 100.0).round() / 100.0), None),
            Err(err) => (None, Some(err)),
        };
        nodes.push(CfSpeedTestNode {
            ip: ip.to_string(),
            latency_ms: (latency_ms * 100.0).round() / 100.0,
            throughput_mbps,
            error,
        });
    }

    // Prefer the highest throughput node; if all throughput tests failed, fall back to lowest latency.
    nodes.sort_by(|a, b| match (a.throughput_mbps, b.throughput_mbps) {
        (Some(ta), Some(tb)) => tb.total_cmp(&ta),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => a.latency_ms.total_cmp(&b.latency_ms),
    });

    let best = nodes.first().cloned();
    (best, nodes)
}

fn current_unix_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, OpCode, Query};
    use hickory_proto::rr::Name;
    use hickory_proto::rr::rdata::svcb::IpHint;

    #[test]
    fn cidr_parsing_and_matching_v4_and_v6() {
        let v4 = Ipv4Cidr::parse("104.16.0.0/13").unwrap();
        assert!(v4.contains(Ipv4Addr::new(104, 16, 0, 1)));
        assert!(v4.contains(Ipv4Addr::new(104, 23, 255, 254)));
        assert!(!v4.contains(Ipv4Addr::new(1, 1, 1, 1)));

        let v6 = Ipv6Cidr::parse("2606:4700::/32").unwrap();
        assert!(v6.contains("2606:4700::1".parse().unwrap()));
        assert!(v6.contains("2606:4700:4700::1111".parse().unwrap()));
        assert!(!v6.contains("2001:4860:4860::8888".parse().unwrap()));

        assert_eq!(v4.sample(3).len(), 3);
        assert_eq!(v6.sample(3).len(), 3);
    }

    #[test]
    fn rewrite_a_and_aaaa_replaces_cf_ips_and_preserves_non_cf() {
        let mgr = CfCdnManager::new();
        let mut rt = CfCdnRuntime::default();
        rt.config.enabled = true;
        rt.config.ipv6_enabled = true;
        rt.config.ttl_secs = 45;
        rt.excluded_domains = vec!["workers.dev".to_string()];
        rt.best_ipv4 = Some(Ipv4Addr::new(104, 16, 123, 45));
        rt.best_ipv6 = Some("2606:4700::9999".parse().unwrap());
        mgr.runtime.store(Arc::new(rt));

        // 1. A record with two Cloudflare IPs -> collapsed to best_ipv4
        let name = Name::from_ascii("example.com.").unwrap();
        let mut msg = Message::new(1, MessageType::Response, OpCode::Query);
        msg.add_query(Query::query(name.clone(), RecordType::A));
        msg.add_answer(Record::from_rdata(
            name.clone(),
            300,
            RData::A(A(Ipv4Addr::new(104, 21, 1, 1))),
        ));
        msg.add_answer(Record::from_rdata(
            name.clone(),
            300,
            RData::A(A(Ipv4Addr::new(172, 67, 1, 2))),
        ));
        assert!(mgr.rewrite_message_if_cloudflare("example.com", &mut msg));
        assert_eq!(msg.answers.len(), 1);
        assert_eq!(msg.answers[0].ttl, 45);
        assert_eq!(
            msg.answers[0].data,
            RData::A(A(Ipv4Addr::new(104, 16, 123, 45)))
        );

        // 2. AAAA record with Cloudflare IPv6 -> replaced with best_ipv6
        let mut msg_v6 = Message::new(2, MessageType::Response, OpCode::Query);
        msg_v6.add_query(Query::query(name.clone(), RecordType::AAAA));
        msg_v6.add_answer(Record::from_rdata(
            name.clone(),
            300,
            RData::AAAA(AAAA("2606:4700:3031::6815:101".parse().unwrap())),
        ));
        assert!(mgr.rewrite_message_if_cloudflare("example.com", &mut msg_v6));
        assert_eq!(msg_v6.answers.len(), 1);
        assert_eq!(
            msg_v6.answers[0].data,
            RData::AAAA(AAAA("2606:4700::9999".parse().unwrap()))
        );

        // 3. Excluded domain -> untouched
        let mut msg_excl = Message::new(3, MessageType::Response, OpCode::Query);
        let excl_name = Name::from_ascii("app.workers.dev.").unwrap();
        msg_excl.add_answer(Record::from_rdata(
            excl_name,
            300,
            RData::A(A(Ipv4Addr::new(104, 21, 1, 1))),
        ));
        assert!(!mgr.rewrite_message_if_cloudflare("app.workers.dev", &mut msg_excl));
        assert_eq!(
            msg_excl.answers[0].data,
            RData::A(A(Ipv4Addr::new(104, 21, 1, 1)))
        );

        // 4. Non-Cloudflare IP -> untouched
        let mut msg_other = Message::new(4, MessageType::Response, OpCode::Query);
        msg_other.add_answer(Record::from_rdata(
            name,
            300,
            RData::A(A(Ipv4Addr::new(93, 184, 216, 34))),
        ));
        assert!(!mgr.rewrite_message_if_cloudflare("example.com", &mut msg_other));
    }

    #[test]
    fn rewrite_https_hints_updates_v4_and_v6() {
        let mgr = CfCdnManager::new();
        let mut rt = CfCdnRuntime::default();
        rt.config.enabled = true;
        rt.config.ipv6_enabled = true;
        rt.best_ipv4 = Some(Ipv4Addr::new(104, 16, 123, 45));
        rt.best_ipv6 = Some("2606:4700::9999".parse().unwrap());
        mgr.runtime.store(Arc::new(rt));

        let name = Name::from_ascii("example.com.").unwrap();
        let mut msg = Message::new(5, MessageType::Response, OpCode::Query);
        msg.add_answer(Record::from_rdata(
            name,
            300,
            RData::HTTPS(HTTPS(SVCB::new(
                1,
                Name::root(),
                vec![
                    (
                        SvcParamKey::Ipv4Hint,
                        SvcParamValue::Ipv4Hint(IpHint(vec![A(Ipv4Addr::new(104, 21, 1, 1))])),
                    ),
                    (
                        SvcParamKey::Ipv6Hint,
                        SvcParamValue::Ipv6Hint(IpHint(vec![AAAA(
                            "2606:4700:3031::1".parse().unwrap(),
                        )])),
                    ),
                ],
            ))),
        ));

        assert!(mgr.rewrite_message_if_cloudflare("example.com", &mut msg));
        let RData::HTTPS(https) = &msg.answers[0].data else {
            panic!("expected HTTPS record");
        };
        assert_eq!(
            https.0.svc_params[0],
            (
                SvcParamKey::Ipv4Hint,
                SvcParamValue::Ipv4Hint(IpHint(vec![A(Ipv4Addr::new(104, 16, 123, 45))])),
            )
        );
        assert_eq!(
            https.0.svc_params[1],
            (
                SvcParamKey::Ipv6Hint,
                SvcParamValue::Ipv6Hint(IpHint(vec![AAAA("2606:4700::9999".parse().unwrap())])),
            )
        );
    }
}
