use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU16, AtomicU64, Ordering};

use arc_swap::ArcSwap;
use hickory_proto::rr::RecordType;
use tokio::sync::{Notify, Semaphore, mpsc};

use crate::acl::AccessController;
use crate::cache::{CacheKey, DnsCache};
use crate::clients::{
    ClientGroup, ClientNameResolver, ClientProfile, ClientRegistry, ResolvedClientPolicy,
    ip_to_ptr_domain,
};
use crate::clock::monotonic_now_ms;
use crate::config::{BlockMode, SplitDnsRule, UpstreamStrategy};
use crate::cookies::DnsCookieEngine;
use crate::device_names::{DhcpLeaseTable, MdnsNameResolver};
use crate::dns64::Dns64Config;
use crate::dnssec::DnssecValidator;
use crate::edns::{DEFAULT_MAX_UDP_PAYLOAD, EcsConfig};
use crate::error::Result;
use crate::filter::{FilterDecision, FilterEngine};
use crate::filter_rules::FilterQueryContext;
use crate::lan::{DdrConfig, HostsMatch, HostsTable, PrivatePtrRouter, is_private_ptr_domain};
use crate::rrl::{ResponseRateLimiter, RrlConfig};
use crate::safesearch::SafeSearchConfig;
use crate::security::is_private_or_special_ip;
use crate::singleflight::Singleflight;
use crate::split_dns::SplitUpstreamRouter;
use crate::svcb::SvcbSanitizeOptions;
use crate::upstream::UpstreamPool;

pub use crate::pipeline_types::{
    LatencyHistogramSnapshot, PipelineRuntimeMetrics, QueryContext, QueryEvent, QueryOutcome,
    QueryProtocol,
};
pub(crate) use crate::pipeline_types::{
    MAX_BG_REFRESHES, QueryLatencyHistogram, ServerRuntimeCounters,
};

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
    pub(crate) dhcp_leases_enabled: AtomicBool,
    pub(crate) dhcp_leases: ArcSwap<DhcpLeaseTable>,
    pub(crate) mdns_enabled: AtomicBool,
    pub(crate) mdns_resolver: Arc<MdnsNameResolver>,
    pub(crate) mdns_notify: Arc<Notify>,
    pub(crate) private_ptr_router: ArcSwap<PrivatePtrRouter>,
    pub(crate) ddr_config: ArcSwap<DdrConfig>,
    pub(crate) dns_rebinding_protection: AtomicBool,
    pub(crate) block_any_queries: AtomicBool,
    pub(crate) safesearch: ArcSwap<SafeSearchConfig>,
    pub(crate) dns64: ArcSwap<Dns64Config>,
    pub(crate) svcb_strip_ech: AtomicBool,
    pub(crate) svcb_strip_hints: AtomicBool,
    pub(crate) ede_enabled: AtomicBool,
    pub(crate) dns_cookies: DnsCookieEngine,
    pub(crate) max_udp_payload_size: AtomicU16,
    pub(crate) rrl: ResponseRateLimiter,
    pub(crate) latency: QueryLatencyHistogram,
    counters: ServerRuntimeCounters,
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
            dhcp_leases_enabled: AtomicBool::new(false),
            dhcp_leases: ArcSwap::from_pointee(DhcpLeaseTable::default()),
            mdns_enabled: AtomicBool::new(false),
            mdns_resolver: Arc::new(MdnsNameResolver::new()),
            mdns_notify: Arc::new(Notify::new()),
            private_ptr_router: ArcSwap::from_pointee(PrivatePtrRouter::default()),
            ddr_config: ArcSwap::from_pointee(DdrConfig::default()),
            dns_rebinding_protection: AtomicBool::new(false),
            block_any_queries: AtomicBool::new(false),
            safesearch: ArcSwap::from_pointee(SafeSearchConfig::default()),
            dns64: ArcSwap::from_pointee(Dns64Config::default()),
            svcb_strip_ech: AtomicBool::new(false),
            svcb_strip_hints: AtomicBool::new(false),
            ede_enabled: AtomicBool::new(true),
            dns_cookies: DnsCookieEngine::new(),
            max_udp_payload_size: AtomicU16::new(DEFAULT_MAX_UDP_PAYLOAD),
            rrl: ResponseRateLimiter::default(),
            latency: QueryLatencyHistogram::default(),
            counters: ServerRuntimeCounters::default(),
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

        if self.dhcp_leases_enabled.load(Ordering::Relaxed)
            && let Some(name) = self.dhcp_leases.load().lookup(ip)
        {
            return (Some(name.to_string()), "dhcp");
        }

        if self.mdns_enabled.load(Ordering::Relaxed) {
            match self.mdns_resolver.lookup_cached(ip) {
                Some(Some(name)) => return (Some(name), "mdns"),
                Some(None) => {}
                None => {
                    if is_private_or_special_ip(ip) {
                        self.mdns_resolver.spawn_lookup_if_needed(ip);
                    }
                }
            }
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
        self.evaluate_filter_for_client_with_qtype(domain, None, ip, client_id)
    }

    pub fn evaluate_filter_for_client_with_qtype(
        &self,
        domain: &str,
        qtype: Option<RecordType>,
        ip: Option<IpAddr>,
        client_id: Option<&str>,
    ) -> FilterDecision {
        let registry = self.clients.load();
        let policy = match (ip, client_id) {
            (Some(addr), cid) => registry.match_client(addr, cid),
            (None, Some(cid)) => registry.match_client_id(cid),
            (None, None) => None,
        };
        let empty_tags: &[String] = &[];
        let ctx = FilterQueryContext {
            domain,
            qtype,
            client_ip: ip,
            client_id,
            client_name: policy.as_deref().map(|p| p.client_name.as_str()),
            client_tags: policy.as_deref().map_or(empty_tags, |p| p.tags.as_slice()),
        };
        ClientRegistry::evaluate_domain_with_context(policy.as_deref(), &self.filter, &ctx)
    }

    pub fn evaluate_filter_for_client_with_qtype_str(
        &self,
        domain: &str,
        qtype_str: Option<&str>,
        ip: Option<IpAddr>,
        client_id: Option<&str>,
    ) -> Result<FilterDecision> {
        let parsed_qtype =
            match qtype_str.map(str::trim).filter(|s| !s.is_empty()) {
                Some(raw) => Some(raw.to_ascii_uppercase().parse::<RecordType>().map_err(
                    |_| crate::error::CoreError::Config(format!("invalid qtype '{raw}'")),
                )?),
                None => None,
            };
        Ok(self.evaluate_filter_for_client_with_qtype(domain, parsed_qtype, ip, client_id))
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

    pub fn set_dhcp_leases_enabled(&self, enabled: bool) {
        self.dhcp_leases_enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn reload_dhcp_leases_table(&self, table: DhcpLeaseTable) {
        self.dhcp_leases.store(Arc::new(table));
    }

    pub fn reload_dhcp_leases_from_path(&self, path: &std::path::Path) -> Result<usize> {
        let table = DhcpLeaseTable::from_file(path)?;
        let count = table.len();
        self.dhcp_leases.store(Arc::new(table));
        Ok(count)
    }

    pub fn set_mdns_enabled(&self, enabled: bool) {
        self.mdns_enabled.store(enabled, Ordering::Relaxed);
        self.mdns_notify.notify_waiters();
    }

    pub fn mdns_notify(&self) -> Arc<Notify> {
        Arc::clone(&self.mdns_notify)
    }

    pub fn mdns_resolver(&self) -> Arc<MdnsNameResolver> {
        Arc::clone(&self.mdns_resolver)
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

    pub fn set_safesearch(&self, config: SafeSearchConfig) {
        self.safesearch.store(Arc::new(config));
    }

    pub fn reload_dns64(&self, enabled: bool, prefixes: &[String]) -> Result<()> {
        let compiled = Dns64Config::compile(enabled, prefixes)?;
        self.dns64.store(Arc::new(compiled));
        Ok(())
    }

    pub fn set_svcb_sanitization(&self, strip_ech: bool, strip_hints: bool) {
        self.svcb_strip_ech.store(strip_ech, Ordering::Relaxed);
        self.svcb_strip_hints.store(strip_hints, Ordering::Relaxed);
    }

    pub fn set_ede_enabled(&self, enabled: bool) {
        self.ede_enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn set_dns_cookies(&self, enabled: bool, require_valid: bool) {
        self.dns_cookies.set_enabled(enabled);
        self.dns_cookies.set_require_valid(require_valid);
    }

    pub fn set_max_udp_payload_size(&self, max_bytes: u16) {
        self.max_udp_payload_size
            .store(max_bytes.max(512), Ordering::Relaxed);
    }

    pub fn set_rrl(&self, cfg: RrlConfig) {
        self.rrl.update_config(cfg);
    }

    pub(crate) fn svcb_sanitize_options(&self) -> SvcbSanitizeOptions {
        SvcbSanitizeOptions {
            strip_ech: self.svcb_strip_ech.load(Ordering::Relaxed),
            strip_hints: self.svcb_strip_hints.load(Ordering::Relaxed),
        }
    }

    pub fn record_udp_dropped(&self) {
        self.counters
            .udp_dropped_inflight
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_tcp_active(&self) {
        self.counters
            .tcp_active_connections
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_tcp_active(&self) {
        self.counters
            .tcp_active_connections
            .fetch_sub(1, Ordering::Relaxed);
    }

    pub fn record_tcp_rejected(&self) {
        self.counters
            .tcp_rejected_connections
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_dot_active(&self) {
        self.counters
            .dot_active_connections
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_dot_active(&self) {
        self.counters
            .dot_active_connections
            .fetch_sub(1, Ordering::Relaxed);
    }

    pub fn record_dot_rejected(&self) {
        self.counters
            .dot_rejected_connections
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_doq_active(&self) {
        self.counters
            .doq_active_connections
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_doq_active(&self) {
        self.counters
            .doq_active_connections
            .fetch_sub(1, Ordering::Relaxed);
    }

    pub fn record_doq_rejected(&self) {
        self.counters
            .doq_rejected_connections
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_web_active(&self) {
        self.counters
            .web_active_connections
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_web_active(&self) {
        self.counters
            .web_active_connections
            .fetch_sub(1, Ordering::Relaxed);
    }

    pub fn record_web_rejected(&self) {
        self.counters
            .web_rejected_connections
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_doh_rejected(&self) {
        self.counters
            .doh_rejected_inflight
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_doh_timeout(&self) {
        self.counters.doh_timed_out.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_filter_reload(&self, elapsed_ms: u64) {
        self.counters.filter_reloads.fetch_add(1, Ordering::Relaxed);
        self.counters
            .filter_last_reload_ms
            .store(elapsed_ms, Ordering::Relaxed);
    }

    pub fn latency_snapshot(&self) -> LatencyHistogramSnapshot {
        self.latency.snapshot()
    }

    pub fn runtime_metrics(&self) -> PipelineRuntimeMetrics {
        PipelineRuntimeMetrics {
            log_dropped: self.log_dropped.load(Ordering::Relaxed),
            singleflight_inflight: self.inflight.inflight_count(),
            rdns_inflight: self.name_resolver.inflight_count(),
            acl_tracked_clients: self.acl.load().tracked_clients(),
            bg_refresh_inflight: MAX_BG_REFRESHES
                .saturating_sub(self.refresh_limiter.available_permits()),
            udp_dropped_inflight: self.counters.udp_dropped_inflight.load(Ordering::Relaxed),
            tcp_active_connections: self.counters.tcp_active_connections.load(Ordering::Relaxed),
            tcp_rejected_connections: self
                .counters
                .tcp_rejected_connections
                .load(Ordering::Relaxed),
            dot_active_connections: self.counters.dot_active_connections.load(Ordering::Relaxed),
            dot_rejected_connections: self
                .counters
                .dot_rejected_connections
                .load(Ordering::Relaxed),
            doq_active_connections: self.counters.doq_active_connections.load(Ordering::Relaxed),
            doq_rejected_connections: self
                .counters
                .doq_rejected_connections
                .load(Ordering::Relaxed),
            web_active_connections: self.counters.web_active_connections.load(Ordering::Relaxed),
            web_rejected_connections: self
                .counters
                .web_rejected_connections
                .load(Ordering::Relaxed),
            doh_rejected_inflight: self.counters.doh_rejected_inflight.load(Ordering::Relaxed),
            doh_timed_out: self.counters.doh_timed_out.load(Ordering::Relaxed),
            filter_reloads: self.counters.filter_reloads.load(Ordering::Relaxed),
            filter_last_reload_ms: self.counters.filter_last_reload_ms.load(Ordering::Relaxed),
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
