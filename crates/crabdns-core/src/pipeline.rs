use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use hickory_proto::rr::RecordType;
use serde::{Deserialize, Serialize};
use tokio::sync::{Semaphore, mpsc};
use ts_rs::TS;

use crate::acl::AccessController;
use crate::cache::{CacheKey, DnsCache};
use crate::clients::{
    ClientGroup, ClientNameResolver, ClientProfile, ClientRegistry, ResolvedClientPolicy,
    ip_to_ptr_domain,
};
use crate::clock::monotonic_now_ms;
use crate::config::{BlockMode, SplitDnsRule, UpstreamStrategy};
use crate::dnssec::DnssecValidator;
use crate::edns::EcsConfig;
use crate::error::Result;
use crate::filter::{FilterDecision, FilterEngine};
use crate::lan::{DdrConfig, HostsMatch, HostsTable, PrivatePtrRouter, is_private_ptr_domain};
use crate::security::is_private_or_special_ip;
use crate::singleflight::Singleflight;
use crate::split_dns::SplitUpstreamRouter;
use crate::upstream::UpstreamPool;

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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PipelineRuntimeMetrics {
    pub log_dropped: u64,
    pub singleflight_inflight: usize,
    pub rdns_inflight: usize,
    pub acl_tracked_clients: usize,
    pub bg_refresh_inflight: usize,
}

pub struct DnsPipeline {
    pub(crate) filter: Arc<FilterEngine>,
    pub(crate) cache: ArcSwap<DnsCache>,
    pub(crate) upstream: ArcSwap<UpstreamPool>,
    pub(crate) split_router: ArcSwap<SplitUpstreamRouter>,
    pub(crate) acl: ArcSwap<AccessController>,
    pub(crate) clients: ArcSwap<ClientRegistry>,
    pub(crate) name_resolver: Arc<ClientNameResolver>,
    pub(crate) rdns_enabled: AtomicBool,
    pub(crate) inflight: Arc<Singleflight<CacheKey, (Vec<u8>, String)>>,
    pub(crate) refresh_limiter: Arc<Semaphore>,
    pub(crate) block_mode: AtomicU8,
    pub(crate) cname_cloaking: AtomicBool,
    pub(crate) pause_until_ms: AtomicU64,
    pub(crate) log_tx: Option<mpsc::Sender<QueryEvent>>,
    pub(crate) log_dropped: AtomicU64,
    pub(crate) ecs_config: ArcSwap<EcsConfig>,
    pub(crate) dnssec_enabled: AtomicBool,
    pub(crate) dnssec_validator: Arc<DnssecValidator>,
    pub(crate) hosts_enabled: AtomicBool,
    pub(crate) hosts_table: ArcSwap<HostsTable>,
    pub(crate) private_ptr_router: ArcSwap<PrivatePtrRouter>,
    pub(crate) ddr_config: ArcSwap<DdrConfig>,
    pub(crate) dns_rebinding_protection: AtomicBool,
    pub(crate) block_any_queries: AtomicBool,
}

fn block_mode_to_u8(mode: BlockMode) -> u8 {
    match mode {
        BlockMode::ZeroIp => 0,
        BlockMode::NxDomain => 1,
        BlockMode::NoData => 2,
    }
}

fn u8_to_block_mode(val: u8) -> BlockMode {
    match val {
        1 => BlockMode::NxDomain,
        2 => BlockMode::NoData,
        _ => BlockMode::ZeroIp,
    }
}

impl DnsPipeline {
    pub fn new(
        filter: Arc<FilterEngine>,
        cache: Arc<DnsCache>,
        upstream: Arc<UpstreamPool>,
        log_tx: Option<mpsc::Sender<QueryEvent>>,
    ) -> Self {
        let default_acl = AccessController::new(&[], &[], 0).expect("empty acl is valid");
        Self {
            filter,
            cache: ArcSwap::from(cache),
            upstream: ArcSwap::from(upstream),
            split_router: ArcSwap::from_pointee(SplitUpstreamRouter::empty()),
            acl: ArcSwap::from_pointee(default_acl),
            clients: ArcSwap::from_pointee(ClientRegistry::empty()),
            name_resolver: Arc::new(ClientNameResolver::new()),
            rdns_enabled: AtomicBool::new(true),
            inflight: Arc::new(Singleflight::new()),
            refresh_limiter: Arc::new(Semaphore::new(MAX_BG_REFRESHES)),
            block_mode: AtomicU8::new(block_mode_to_u8(BlockMode::ZeroIp)),
            cname_cloaking: AtomicBool::new(true),
            pause_until_ms: AtomicU64::new(0),
            log_tx,
            log_dropped: AtomicU64::new(0),
            ecs_config: ArcSwap::from_pointee(EcsConfig::default()),
            dnssec_enabled: AtomicBool::new(false),
            dnssec_validator: Arc::new(DnssecValidator::default()),
            hosts_enabled: AtomicBool::new(false),
            hosts_table: ArcSwap::from_pointee(HostsTable::default()),
            private_ptr_router: ArcSwap::from_pointee(PrivatePtrRouter::default()),
            ddr_config: ArcSwap::from_pointee(DdrConfig::default()),
            dns_rebinding_protection: AtomicBool::new(false),
            block_any_queries: AtomicBool::new(false),
        }
    }

    pub fn filter(&self) -> &Arc<FilterEngine> {
        &self.filter
    }

    pub fn cache(&self) -> Arc<DnsCache> {
        self.cache.load_full()
    }

    pub fn upstream(&self) -> Arc<UpstreamPool> {
        self.upstream.load_full()
    }

    pub fn block_mode(&self) -> BlockMode {
        u8_to_block_mode(self.block_mode.load(Ordering::Relaxed))
    }

    pub fn set_block_mode(&self, mode: BlockMode) {
        self.block_mode
            .store(block_mode_to_u8(mode), Ordering::Relaxed);
    }

    pub fn reload_acl(
        &self,
        allow_cidrs: &[String],
        deny_cidrs: &[String],
        rate_limit_qps: u32,
    ) -> Result<()> {
        let next = AccessController::new(allow_cidrs, deny_cidrs, rate_limit_qps)?;
        self.swap_acl(next);
        Ok(())
    }

    pub fn swap_acl(&self, next: AccessController) {
        self.acl.store(Arc::new(next));
    }

    pub fn reload_clients(
        &self,
        clients: &[ClientProfile],
        groups: &[ClientGroup],
        timeout_ms: u64,
        strategy: UpstreamStrategy,
        bootstrap_dns: &[String],
    ) -> Result<()> {
        let next = ClientRegistry::compile(clients, groups, timeout_ms, strategy, bootstrap_dns)?;
        self.swap_clients(next);
        Ok(())
    }

    pub fn swap_clients(&self, next: ClientRegistry) {
        self.clients.store(Arc::new(next));
    }

    pub fn set_rdns_enabled(&self, enabled: bool) {
        self.rdns_enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn resolve_client_display_name(
        &self,
        ip: IpAddr,
        client_id: Option<&str>,
    ) -> (Option<String>, &'static str) {
        if let Some(policy) = self.clients.load().match_client(ip, client_id) {
            return (Some(policy.client_name.clone()), "profile");
        }
        self.resolve_unconfigured_client_name(ip)
    }

    pub fn match_client_summary(&self, ip: IpAddr) -> Option<(String, String, Option<String>)> {
        self.clients.load().match_client(ip, None).map(|p| {
            (
                p.profile_id.clone(),
                p.client_name.clone(),
                p.group_id.clone(),
            )
        })
    }

    pub(crate) fn resolve_unconfigured_client_name(
        &self,
        ip: IpAddr,
    ) -> (Option<String>, &'static str) {
        if self.hosts_enabled.load(Ordering::Relaxed)
            && let Some(HostsMatch::Ptr(name)) = self
                .hosts_table
                .load()
                .lookup(&ip_to_ptr_domain(ip), RecordType::PTR)
        {
            return (Some(name), "hosts");
        }

        match self.name_resolver.lookup_cached(ip) {
            Some(Some(name)) => return (Some(name), "rdns"),
            Some(None) => return (None, "unknown"),
            None => {}
        }

        if self.rdns_enabled.load(Ordering::Relaxed)
            && let Some(pool) = self.rdns_upstream_for(ip)
        {
            self.name_resolver.spawn_rdns_if_needed(ip, pool);
        }
        (None, "unknown")
    }

    fn rdns_upstream_for(&self, ip: IpAddr) -> Option<Arc<UpstreamPool>> {
        if !is_private_or_special_ip(ip)
            || ip.is_loopback()
            || ip.is_unspecified()
            || ip.is_multicast()
        {
            return None;
        }
        let ptr_router = self.private_ptr_router.load();
        if let Some(pool) = &ptr_router.pool {
            return Some(Arc::clone(pool));
        }
        if ptr_router.enabled {
            return None;
        }
        let upstream = self.upstream.load_full();
        upstream.has_private_endpoint().then_some(upstream)
    }

    pub fn evaluate_filter_for_client(
        &self,
        domain: &str,
        ip: Option<IpAddr>,
        client_id: Option<&str>,
    ) -> FilterDecision {
        let registry = self.clients.load();
        let policy = match (ip, client_id) {
            (Some(addr), cid) => registry.match_client(addr, cid),
            (None, Some(cid)) => registry.match_client_id(cid),
            (None, None) => None,
        };
        ClientRegistry::evaluate_domain(policy.as_deref(), &self.filter, domain)
    }

    pub fn reload_upstream(&self, specs: &[String], timeout_ms: u64) -> Result<()> {
        let strategy = self.upstream.load().strategy();
        self.reload_upstream_with_strategy(specs, timeout_ms, strategy)
    }

    pub fn reload_upstream_with_strategy(
        &self,
        specs: &[String],
        timeout_ms: u64,
        strategy: UpstreamStrategy,
    ) -> Result<()> {
        self.reload_upstream_with_options(specs, timeout_ms, strategy, &[])
    }

    pub fn reload_upstream_with_options(
        &self,
        specs: &[String],
        timeout_ms: u64,
        strategy: UpstreamStrategy,
        bootstrap_dns: &[String],
    ) -> Result<()> {
        let next = UpstreamPool::new_with_bootstrap(specs, timeout_ms, strategy, bootstrap_dns)?;
        self.swap_upstream(next);
        Ok(())
    }

    pub fn swap_upstream(&self, next: UpstreamPool) {
        self.upstream.store(Arc::new(next));
    }

    pub fn reload_cache(&self, max_capacity: u64, optimistic: bool) {
        self.cache
            .store(Arc::new(DnsCache::new(max_capacity, optimistic)));
    }

    pub fn reload_cache_with_options(
        &self,
        max_capacity: u64,
        optimistic: bool,
        min_ttl_secs: u32,
        max_ttl_secs: u32,
        prefetch_enabled: bool,
    ) {
        let next = DnsCache::with_options(
            max_capacity,
            optimistic,
            min_ttl_secs,
            max_ttl_secs,
            prefetch_enabled,
        );
        let prev = self.cache.load_full();
        if prev.entry_count() > 0 && max_capacity > 0 {
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
            let mut entries = prev.export_persisted(now_secs);
            let limit = usize::try_from(max_capacity).unwrap_or(usize::MAX);
            if entries.len() > limit {
                entries.sort_by_key(|e| std::cmp::Reverse(e.expires_at_unix_secs));
                entries.truncate(limit);
            }
            let _ = next.import_persisted(entries, now_secs);
        }
        self.cache.store(Arc::new(next));
    }

    pub fn reload_split_dns(
        &self,
        rules: &[SplitDnsRule],
        timeout_ms: u64,
        strategy: UpstreamStrategy,
    ) -> Result<()> {
        self.reload_split_dns_with_bootstrap(rules, timeout_ms, strategy, &[])
    }

    pub fn reload_split_dns_with_bootstrap(
        &self,
        rules: &[SplitDnsRule],
        timeout_ms: u64,
        strategy: UpstreamStrategy,
        bootstrap_dns: &[String],
    ) -> Result<()> {
        let router =
            SplitUpstreamRouter::new_with_bootstrap(rules, timeout_ms, strategy, bootstrap_dns)?;
        self.swap_split_dns(router);
        Ok(())
    }

    pub fn swap_split_dns(&self, router: SplitUpstreamRouter) {
        self.split_router.store(Arc::new(router));
    }

    pub fn set_cname_cloaking(&self, enabled: bool) {
        self.cname_cloaking.store(enabled, Ordering::Relaxed);
    }

    pub fn cname_cloaking(&self) -> bool {
        self.cname_cloaking.load(Ordering::Relaxed)
    }

    pub fn reload_ecs(
        &self,
        enabled: bool,
        custom_ip: Option<&str>,
        ipv4_prefix: u8,
        ipv6_prefix: u8,
    ) -> Result<()> {
        let cfg = EcsConfig::from_parts(enabled, custom_ip, ipv4_prefix, ipv6_prefix)?;
        self.swap_ecs(cfg);
        Ok(())
    }

    pub fn swap_ecs(&self, cfg: EcsConfig) {
        self.ecs_config.store(Arc::new(cfg));
    }

    pub fn set_dnssec_enabled(&self, enabled: bool) {
        self.dnssec_enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn set_hosts_enabled(&self, enabled: bool) {
        self.hosts_enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn reload_hosts_table(&self, table: HostsTable) {
        self.hosts_table.store(Arc::new(table));
    }

    pub fn reload_hosts_from_path(&self, path: &std::path::Path) -> Result<usize> {
        let table = HostsTable::from_file(path)?;
        let count = table.len_entries();
        self.hosts_table.store(Arc::new(table));
        Ok(count)
    }

    pub fn reload_private_ptr(
        &self,
        enabled: bool,
        upstreams: &[String],
        timeout_ms: u64,
        strategy: UpstreamStrategy,
        bootstrap_dns: &[String],
    ) -> Result<()> {
        let router =
            PrivatePtrRouter::new(enabled, upstreams, timeout_ms, strategy, bootstrap_dns)?;
        self.swap_private_ptr(router);
        Ok(())
    }

    pub fn swap_private_ptr(&self, router: PrivatePtrRouter) {
        self.private_ptr_router.store(Arc::new(router));
    }

    pub fn reload_ddr(&self, cfg: DdrConfig) {
        self.ddr_config.store(Arc::new(cfg));
    }

    pub fn set_dns_rebinding_protection(&self, enabled: bool) {
        self.dns_rebinding_protection
            .store(enabled, Ordering::Relaxed);
    }

    pub fn set_block_any_queries(&self, enabled: bool) {
        self.block_any_queries.store(enabled, Ordering::Relaxed);
    }

    pub fn runtime_metrics(&self) -> PipelineRuntimeMetrics {
        PipelineRuntimeMetrics {
            log_dropped: self.log_dropped.load(Ordering::Relaxed),
            singleflight_inflight: self.inflight.inflight_count(),
            rdns_inflight: self.name_resolver.inflight_count(),
            acl_tracked_clients: self.acl.load().tracked_clients(),
            bg_refresh_inflight: MAX_BG_REFRESHES
                .saturating_sub(self.refresh_limiter.available_permits()),
        }
    }

    pub fn pause_blocking(&self, duration_secs: Option<u64>) {
        let until = match duration_secs {
            Some(secs) => monotonic_now_ms()
                .saturating_add(secs.saturating_mul(1000))
                .min(u64::MAX - 1),
            None => u64::MAX,
        };
        self.pause_until_ms.store(until, Ordering::Relaxed);
    }

    pub fn resume_blocking(&self) {
        self.pause_until_ms.store(0, Ordering::Relaxed);
    }

    pub fn blocking_status(&self) -> (bool, Option<u64>) {
        let until = self.pause_until_ms.load(Ordering::Relaxed);
        if until == 0 {
            return (false, None);
        }
        if until == u64::MAX {
            return (true, None);
        }
        let now = monotonic_now_ms();
        if now >= until {
            self.pause_until_ms.store(0, Ordering::Relaxed);
            return (false, None);
        }
        (true, Some((until - now).div_ceil(1000)))
    }

    pub(crate) fn is_blocking_paused(&self) -> bool {
        self.blocking_status().0
    }

    pub(crate) fn resolve_upstream_for_query(
        &self,
        policy: Option<&ResolvedClientPolicy>,
        domain: &str,
        qtype: RecordType,
    ) -> (Arc<UpstreamPool>, Option<String>, bool) {
        if let Some((scope, pool)) = policy.and_then(|p| p.upstream_pool.as_ref()) {
            return (Arc::clone(pool), Some(scope.clone()), false);
        }
        if qtype == RecordType::PTR && is_private_ptr_domain(domain) {
            let ptr_router = self.private_ptr_router.load();
            if let Some(pool) = &ptr_router.pool {
                return (Arc::clone(pool), None, true);
            }
        }
        if let Some(pool) = self.split_router.load().resolve(domain) {
            return (pool, None, true);
        }
        (self.upstream.load_full(), None, false)
    }
}
