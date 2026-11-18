use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{RData, RecordType};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use ts_rs::TS;

use crate::acl::{AccessController, AclDecision};
use crate::cache::{CacheKey, DnsCache};
use crate::config::{BlockMode, SplitDnsRule, UpstreamStrategy};
use crate::dnssec::DnssecValidator;
use crate::edns::{
    EcsConfig, apply_ecs_to_message, has_dnssec_ok, resolve_ecs_subnet, set_dnssec_ok,
};
use crate::error::{CoreError, Result};
use crate::filter::{FilterAction, FilterEngine};
use crate::lan::{
    DdrConfig, HostsTable, PrivatePtrRouter, build_ddr_response, build_hosts_response,
    is_ddr_query, is_private_ptr_domain,
};
use crate::security::{build_rfc8482_any_response, contains_rebinding_ip};
use crate::split_dns::SplitUpstreamRouter;
use crate::upstream::UpstreamPool;
use crate::wire::{build_blocked_response, build_error_response, build_rewrite_response};

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

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct QueryEvent {
    pub timestamp: DateTime<Utc>,
    pub client_ip: String,
    pub domain: String,
    pub qtype: String,
    pub outcome: QueryOutcome,
    pub matched_rule: Option<String>,
    pub upstream: Option<String>,
    #[ts(type = "number")]
    pub elapsed_us: u64,
    pub rcode: String,
}

pub struct DnsPipeline {
    filter: Arc<FilterEngine>,
    cache: ArcSwap<DnsCache>,
    upstream: ArcSwap<UpstreamPool>,
    split_router: ArcSwap<SplitUpstreamRouter>,
    acl: ArcSwap<AccessController>,
    block_mode: AtomicU8,
    cname_cloaking: AtomicBool,
    pause_until_ms: AtomicU64,
    log_tx: Option<mpsc::Sender<QueryEvent>>,
    ecs_config: ArcSwap<EcsConfig>,
    dnssec_enabled: AtomicBool,
    dnssec_validator: Arc<DnssecValidator>,
    hosts_enabled: AtomicBool,
    hosts_table: ArcSwap<HostsTable>,
    private_ptr_router: ArcSwap<PrivatePtrRouter>,
    ddr_config: ArcSwap<DdrConfig>,
    dns_rebinding_protection: AtomicBool,
    block_any_queries: AtomicBool,
}

#[derive(Clone, Copy)]
#[allow(clippy::struct_excessive_bools)]
struct ForwardFlags {
    paused: bool,
    explicitly_allowed: bool,
    dnssec_on: bool,
    client_wants_do: bool,
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
            block_mode: AtomicU8::new(block_mode_to_u8(BlockMode::ZeroIp)),
            cname_cloaking: AtomicBool::new(true),
            pause_until_ms: AtomicU64::new(0),
            log_tx,
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
        self.acl.store(Arc::new(next));
        Ok(())
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
        self.upstream.store(Arc::new(next));
        Ok(())
    }

    pub fn reload_cache(&self, max_capacity: u64, optimistic: bool) {
        self.cache
            .store(Arc::new(DnsCache::new(max_capacity, optimistic)));
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
        self.split_router.store(Arc::new(router));
        Ok(())
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
        self.ecs_config.store(Arc::new(cfg));
        Ok(())
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
        self.private_ptr_router.store(Arc::new(router));
        Ok(())
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

    pub fn pause_blocking(&self, duration_secs: Option<u64>) {
        let until = match duration_secs {
            Some(secs) => now_epoch_ms().saturating_add(secs.saturating_mul(1000)),
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
        let now = now_epoch_ms();
        if now >= until {
            self.pause_until_ms.store(0, Ordering::Relaxed);
            return (false, None);
        }
        (true, Some((until - now).div_ceil(1000)))
    }

    fn is_blocking_paused(&self) -> bool {
        self.blocking_status().0
    }

    fn resolve_upstream_with_source(
        &self,
        domain: &str,
        qtype: RecordType,
    ) -> (Arc<UpstreamPool>, bool) {
        if qtype == RecordType::PTR && is_private_ptr_domain(domain) {
            let ptr_router = self.private_ptr_router.load();
            if let Some(pool) = &ptr_router.pool {
                return (Arc::clone(pool), true);
            }
        }
        if let Some(pool) = self.split_router.load().resolve(domain) {
            return (pool, true);
        }
        (self.upstream.load_full(), false)
    }

    fn resolve_upstream(&self, domain: &str) -> Arc<UpstreamPool> {
        self.split_router
            .load()
            .resolve(domain)
            .unwrap_or_else(|| self.upstream.load_full())
    }

    fn check_local_interceptors(
        &self,
        request: &Message,
        client_addr: SocketAddr,
        clean_domain: &str,
        qtype: RecordType,
        start: Instant,
    ) -> Result<Option<Vec<u8>>> {
        if self.block_any_queries.load(Ordering::Relaxed) && qtype == RecordType::ANY {
            let resp = build_rfc8482_any_response(request)?;
            self.emit_log(
                client_addr,
                clean_domain.to_string(),
                qtype,
                QueryOutcome::Blocked,
                Some("security:any-query".to_string()),
                None,
                start,
                "NOERROR",
            );
            return Ok(Some(resp));
        }

        let ddr = self.ddr_config.load();
        if ddr.enabled && is_ddr_query(clean_domain, qtype) {
            let resp = build_ddr_response(request, &ddr)?;
            self.emit_log(
                client_addr,
                clean_domain.to_string(),
                qtype,
                QueryOutcome::Rewritten,
                Some("ddr:resolver".to_string()),
                None,
                start,
                "NOERROR",
            );
            return Ok(Some(resp));
        }

        if self.hosts_enabled.load(Ordering::Relaxed)
            && let Some(matched) = self.hosts_table.load().lookup(clean_domain, qtype)
        {
            let resp = build_hosts_response(request, &matched)?;
            self.emit_log(
                client_addr,
                clean_domain.to_string(),
                qtype,
                QueryOutcome::Rewritten,
                Some("hosts:local".to_string()),
                None,
                start,
                "NOERROR",
            );
            return Ok(Some(resp));
        }

        Ok(None)
    }

    #[allow(clippy::too_many_lines)]
    pub async fn handle_packet(
        &self,
        raw_query: &[u8],
        client_addr: SocketAddr,
    ) -> Result<Vec<u8>> {
        let start = Instant::now();
        let request = Message::from_vec(raw_query)
            .map_err(|e| CoreError::Protocol(format!("invalid DNS packet: {e}")))?;

        let Some(question) = request.queries.first().cloned() else {
            return build_error_response(&request, ResponseCode::FormErr);
        };

        let qname = question.name().to_utf8();
        let clean_domain = qname.trim_end_matches('.').to_string();
        let qtype = question.query_type();
        let qclass = u16::from(question.query_class());

        if let Some(refused) =
            self.enforce_acl(&request, client_addr, &clean_domain, qtype, start)?
        {
            return Ok(refused);
        }

        if let Some(local_resp) =
            self.check_local_interceptors(&request, client_addr, &clean_domain, qtype, start)?
        {
            return Ok(local_resp);
        }

        let mode = self.block_mode();
        let paused = self.is_blocking_paused();
        let decision = self.filter.evaluate(&clean_domain);
        let explicitly_allowed =
            decision.action == FilterAction::Allow && decision.matched_rule.is_some();
        match decision.action {
            FilterAction::Block if !paused => {
                let (resp, rcode) = build_blocked_response(&request, qtype, mode)?;
                self.emit_log(
                    client_addr,
                    clean_domain,
                    qtype,
                    QueryOutcome::Blocked,
                    decision.matched_rule,
                    None,
                    start,
                    rcode,
                );
                return Ok(resp);
            }
            FilterAction::Rewrite(ref rewrite) => {
                let resp = build_rewrite_response(&request, qtype, rewrite)?;
                self.emit_log(
                    client_addr,
                    clean_domain,
                    qtype,
                    QueryOutcome::Rewritten,
                    decision.matched_rule,
                    None,
                    start,
                    "NOERROR",
                );
                return Ok(resp);
            }
            FilterAction::Block | FilterAction::Allow => {}
        }

        if qtype == RecordType::PTR && is_private_ptr_domain(&clean_domain) {
            let ptr_router = self.private_ptr_router.load();
            if ptr_router.enabled && ptr_router.pool.is_none() {
                let resp = build_error_response(&request, ResponseCode::NXDomain)?;
                self.emit_log(
                    client_addr,
                    clean_domain,
                    qtype,
                    QueryOutcome::Blocked,
                    Some("lan:private-ptr".to_string()),
                    None,
                    start,
                    "NXDOMAIN",
                );
                return Ok(resp);
            }
        }

        let ecs_subnet = resolve_ecs_subnet(&self.ecs_config.load(), client_addr.ip());
        let dnssec_on = self.dnssec_enabled.load(Ordering::Relaxed);
        let client_wants_do = has_dnssec_ok(&request);

        let cache_key = CacheKey {
            qname: qname.to_ascii_lowercase(),
            qtype: u16::from(qtype),
            qclass,
            ecs_subnet,
            dnssec_do: dnssec_on && client_wants_do,
        };

        let cache = self.cache.load();
        if let Some(hit) = cache.get(&cache_key, request.id) {
            if hit.is_stale {
                let refresh_wire =
                    Self::build_upstream_query(&request, raw_query, ecs_subnet, dnssec_on);
                self.spawn_background_refresh(refresh_wire, cache_key.clone());
            }
            self.emit_log(
                client_addr,
                clean_domain,
                qtype,
                QueryOutcome::Cached,
                decision.matched_rule,
                Some("cache".to_string()),
                start,
                "NOERROR",
            );
            return Ok(hit.wire_bytes);
        }

        let upstream_query = Self::build_upstream_query(&request, raw_query, ecs_subnet, dnssec_on);
        let flags = ForwardFlags {
            paused,
            explicitly_allowed,
            dnssec_on,
            client_wants_do,
        };

        self.forward_to_upstream(
            &request,
            &upstream_query,
            client_addr,
            clean_domain,
            qtype,
            cache_key,
            decision.matched_rule,
            flags,
            start,
        )
        .await
    }

    fn enforce_acl(
        &self,
        request: &Message,
        client_addr: SocketAddr,
        clean_domain: &str,
        qtype: RecordType,
        start: Instant,
    ) -> Result<Option<Vec<u8>>> {
        let rule = match self.acl.load().check(client_addr.ip()) {
            AclDecision::Allow => return Ok(None),
            AclDecision::DeniedAcl => "acl:denied",
            AclDecision::RateLimited => "acl:ratelimit",
        };
        self.emit_log(
            client_addr,
            clean_domain.to_string(),
            qtype,
            QueryOutcome::Blocked,
            Some(rule.to_string()),
            None,
            start,
            "REFUSED",
        );
        build_error_response(request, ResponseCode::Refused).map(Some)
    }

    fn build_upstream_query(
        request: &Message,
        raw_query: &[u8],
        ecs_subnet: Option<(std::net::IpAddr, u8)>,
        dnssec_on: bool,
    ) -> Vec<u8> {
        if ecs_subnet.is_none() && !dnssec_on {
            return raw_query.to_vec();
        }
        let mut msg = request.clone();
        if let Some(subnet) = ecs_subnet {
            apply_ecs_to_message(&mut msg, subnet);
        }
        if dnssec_on {
            set_dnssec_ok(&mut msg);
        }
        msg.to_vec().unwrap_or_else(|_| raw_query.to_vec())
    }

    #[allow(clippy::too_many_arguments)]
    async fn forward_to_upstream(
        &self,
        request: &Message,
        upstream_query: &[u8],
        client_addr: SocketAddr,
        clean_domain: String,
        qtype: RecordType,
        cache_key: CacheKey,
        matched_rule: Option<String>,
        flags: ForwardFlags,
        start: Instant,
    ) -> Result<Vec<u8>> {
        let (upstream, is_local_route) = self.resolve_upstream_with_source(&clean_domain, qtype);
        match upstream.exchange(upstream_query).await {
            Ok((mut resp_bytes, upstream_label)) => {
                if flags.dnssec_on {
                    match self
                        .dnssec_validator
                        .validate_and_process(&resp_bytes, &upstream, flags.client_wants_do)
                        .await
                    {
                        Ok(processed) => resp_bytes = processed,
                        Err(err) => {
                            tracing::warn!(domain = %clean_domain, error = %err, "DNSSEC validation failed");
                            self.emit_log(
                                client_addr,
                                clean_domain,
                                qtype,
                                QueryOutcome::Error,
                                Some("dnssec:bogus".to_string()),
                                Some(upstream_label),
                                start,
                                "SERVFAIL",
                            );
                            return build_error_response(request, ResponseCode::ServFail);
                        }
                    }
                }

                if !flags.paused
                    && !flags.explicitly_allowed
                    && !is_local_route
                    && self.dns_rebinding_protection.load(Ordering::Relaxed)
                    && contains_rebinding_ip(&resp_bytes)
                {
                    let (blocked_bytes, rcode) =
                        build_blocked_response(request, qtype, self.block_mode())?;
                    self.emit_log(
                        client_addr,
                        clean_domain,
                        qtype,
                        QueryOutcome::Blocked,
                        Some("security:dns-rebinding".to_string()),
                        Some(upstream_label),
                        start,
                        rcode,
                    );
                    return Ok(blocked_bytes);
                }

                if !flags.paused
                    && !flags.explicitly_allowed
                    && self.cname_cloaking()
                    && let Some((blocked_bytes, rule, rcode)) =
                        self.check_cname_cloaking(request, &resp_bytes, qtype)?
                {
                    self.emit_log(
                        client_addr,
                        clean_domain,
                        qtype,
                        QueryOutcome::Blocked,
                        Some(rule),
                        Some(upstream_label),
                        start,
                        rcode,
                    );
                    return Ok(blocked_bytes);
                }

                let cache = self.cache.load();
                let rcode_str = cache_upstream_response(&cache, cache_key, &resp_bytes);
                self.emit_log(
                    client_addr,
                    clean_domain,
                    qtype,
                    QueryOutcome::Forwarded,
                    matched_rule,
                    Some(upstream_label),
                    start,
                    &rcode_str,
                );
                Ok(resp_bytes)
            }
            Err(err) => {
                tracing::warn!(domain = %clean_domain, error = %err, "all upstreams failed");
                self.emit_log(
                    client_addr,
                    clean_domain,
                    qtype,
                    QueryOutcome::Error,
                    None,
                    None,
                    start,
                    "SERVFAIL",
                );
                build_error_response(request, ResponseCode::ServFail)
            }
        }
    }

    fn check_cname_cloaking(
        &self,
        request: &Message,
        resp_bytes: &[u8],
        qtype: RecordType,
    ) -> Result<Option<(Vec<u8>, String, &'static str)>> {
        let Ok(resp_msg) = Message::from_vec(resp_bytes) else {
            return Ok(None);
        };
        for answer in &resp_msg.answers {
            if let RData::CNAME(cname) = &answer.data {
                let target = cname.to_utf8();
                let target_clean = target.trim_end_matches('.');
                let decision = self.filter.evaluate(target_clean);
                if decision.action == FilterAction::Block {
                    let (blocked_bytes, rcode) =
                        build_blocked_response(request, qtype, self.block_mode())?;
                    let rule = decision
                        .matched_rule
                        .unwrap_or_else(|| format!("cname:{target_clean}"));
                    return Ok(Some((blocked_bytes, rule, rcode)));
                }
            }
        }
        Ok(None)
    }

    fn spawn_background_refresh(&self, query_wire: Vec<u8>, key: CacheKey) {
        let upstream = self.resolve_upstream(&key.qname);
        let cache = self.cache.load_full();
        tokio::spawn(async move {
            if let Ok((resp_bytes, _)) = upstream.exchange(&query_wire).await {
                let _ = cache_upstream_response(&cache, key, &resp_bytes);
            }
        });
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_log(
        &self,
        client_addr: SocketAddr,
        domain: String,
        qtype: RecordType,
        outcome: QueryOutcome,
        matched_rule: Option<String>,
        upstream: Option<String>,
        start: Instant,
        rcode: &str,
    ) {
        let Some(tx) = &self.log_tx else {
            return;
        };
        let elapsed_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
        let event = QueryEvent {
            timestamp: Utc::now(),
            client_ip: client_addr.ip().to_string(),
            domain,
            qtype: qtype.to_string(),
            outcome,
            matched_rule,
            upstream,
            elapsed_us,
            rcode: rcode.to_string(),
        };
        let _ = tx.try_send(event);
    }
}

fn now_epoch_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}

fn cache_upstream_response(cache: &DnsCache, key: CacheKey, resp_bytes: &[u8]) -> String {
    let Ok(msg) = Message::from_vec(resp_bytes) else {
        return "UNKNOWN".to_string();
    };
    let rcode = msg.response_code;
    if rcode == ResponseCode::NoError || rcode == ResponseCode::NXDomain {
        let min_ttl = msg.answers.iter().map(|r| r.ttl).min().unwrap_or(60);
        cache.insert(key, resp_bytes.to_vec(), min_ttl);
    }
    rcode.to_string()
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use hickory_proto::op::{MessageType, OpCode, Query};
    use hickory_proto::rr::rdata::{A, CNAME};
    use hickory_proto::rr::{Name, Record};
    use tokio::net::UdpSocket;

    fn build_query(id: u16, domain: &str, qtype: RecordType) -> Vec<u8> {
        let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
        msg.metadata.recursion_desired = true;
        let name = Name::from_ascii(domain).expect("valid domain");
        msg.add_query(Query::query(name, qtype));
        msg.to_vec().expect("encode query")
    }

    async fn spawn_mock_udp_upstream(cname_target: Option<&'static str>) -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind mock");
        let addr = socket.local_addr().expect("local addr");
        tokio::spawn(async move {
            let mut buf = [0_u8; 2048];
            while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
                let req = Message::from_vec(&buf[..len]).expect("valid req");
                let q = req.queries.first().expect("question");
                let mut resp = Message::new(req.id, MessageType::Response, OpCode::Query);
                resp.metadata.recursion_available = true;
                resp.queries.clone_from(&req.queries);
                if let Some(target) = cname_target {
                    let cname = Name::from_ascii(target).expect("valid cname");
                    resp.add_answer(Record::from_rdata(
                        q.name().clone(),
                        60,
                        RData::CNAME(CNAME(cname)),
                    ));
                } else {
                    resp.add_answer(Record::from_rdata(
                        q.name().clone(),
                        120,
                        RData::A(A(Ipv4Addr::new(93, 184, 216, 34))),
                    ));
                }
                let bytes = resp.to_vec().expect("encode resp");
                let _ = socket.send_to(&bytes, peer).await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn test_pipeline_block_rewrite_and_invalid() {
        let filter = Arc::new(FilterEngine::new(&[
            "||ads.test^".to_string(),
            "||nas.local^$dnsrewrite=10.0.0.2".to_string(),
        ]));
        let cache = Arc::new(DnsCache::new(64, true));
        let upstream =
            Arc::new(UpstreamPool::new(&["udp://127.0.0.1:1".to_string()], 200).unwrap());
        let (tx, mut rx) = mpsc::channel(16);
        let pipeline = DnsPipeline::new(filter, cache, upstream, Some(tx));
        let client: SocketAddr = "127.0.0.1:12345".parse().expect("addr");

        let blocked_q = build_query(0x1001, "ads.test.", RecordType::A);
        let resp = Message::from_vec(&pipeline.handle_packet(&blocked_q, client).await.unwrap())
            .expect("decode");
        assert_eq!(resp.answers.len(), 1);
        assert_eq!(rx.recv().await.unwrap().outcome, QueryOutcome::Blocked);

        let blocked_txt = build_query(0x1002, "ads.test.", RecordType::TXT);
        let resp_txt =
            Message::from_vec(&pipeline.handle_packet(&blocked_txt, client).await.unwrap())
                .expect("decode");
        assert_eq!(resp_txt.response_code, ResponseCode::NXDomain);
        let _ = rx.recv().await;

        let rewrite_q = build_query(0x1003, "nas.local.", RecordType::A);
        let resp_rw = Message::from_vec(&pipeline.handle_packet(&rewrite_q, client).await.unwrap())
            .expect("decode");
        assert_eq!(resp_rw.answers.len(), 1);
        assert_eq!(rx.recv().await.unwrap().outcome, QueryOutcome::Rewritten);

        assert!(pipeline.handle_packet(&[0, 1, 2], client).await.is_err());
    }

    #[tokio::test]
    async fn test_pipeline_forward_cache_and_cname_cloaking() {
        let mock_addr = spawn_mock_udp_upstream(None).await;
        let filter = Arc::new(FilterEngine::new(&["||evil-cname.test^".to_string()]));
        let cache = Arc::new(DnsCache::new(64, true));
        let upstream =
            Arc::new(UpstreamPool::new(&[format!("udp://{mock_addr}")], 1000).expect("pool"));
        let (tx, mut rx) = mpsc::channel(16);
        let pipeline = DnsPipeline::new(filter, cache, upstream, Some(tx));
        let client: SocketAddr = "127.0.0.1:54321".parse().expect("addr");

        let q1 = build_query(0x2001, "example.org.", RecordType::A);
        let r1 = Message::from_vec(&pipeline.handle_packet(&q1, client).await.unwrap()).unwrap();
        assert_eq!(r1.id, 0x2001);
        assert_eq!(rx.recv().await.unwrap().outcome, QueryOutcome::Forwarded);

        let q2 = build_query(0x2002, "example.org.", RecordType::A);
        let r2 = Message::from_vec(&pipeline.handle_packet(&q2, client).await.unwrap()).unwrap();
        assert_eq!(r2.id, 0x2002);
        assert_eq!(rx.recv().await.unwrap().outcome, QueryOutcome::Cached);

        let cname_addr = spawn_mock_udp_upstream(Some("evil-cname.test.")).await;
        let upstream2 =
            Arc::new(UpstreamPool::new(&[format!("udp://{cname_addr}")], 1000).expect("pool"));
        let (tx2, mut rx2) = mpsc::channel(16);
        let pipeline2 = DnsPipeline::new(
            Arc::clone(pipeline.filter()),
            Arc::new(DnsCache::new(64, false)),
            upstream2,
            Some(tx2),
        );
        let q3 = build_query(0x3001, "cloaked.example.", RecordType::A);
        let _ = pipeline2.handle_packet(&q3, client).await.unwrap();
        assert_eq!(rx2.recv().await.unwrap().outcome, QueryOutcome::Blocked);
    }

    #[tokio::test]
    async fn test_pipeline_upstream_timeout_servfail() {
        let filter = Arc::new(FilterEngine::new(&[]));
        let cache = Arc::new(DnsCache::new(64, false));
        let upstream = Arc::new(UpstreamPool::new(&["udp://127.0.0.1:1".to_string()], 50).unwrap());
        let pipeline = DnsPipeline::new(filter, cache, upstream, None);
        let client: SocketAddr = "127.0.0.1:9999".parse().expect("addr");

        let q = build_query(0x4001, "unreachable.example.", RecordType::A);
        let resp = Message::from_vec(&pipeline.handle_packet(&q, client).await.unwrap()).unwrap();
        assert_eq!(resp.response_code, ResponseCode::ServFail);
    }

    #[tokio::test]
    async fn test_pipeline_block_modes_rewrites_and_acl() {
        let filter = Arc::new(FilterEngine::new(&[
            "||blocked.test^".to_string(),
            "||alias.test^$dnsrewrite=CNAME;target.test".to_string(),
            "||txt.test^$dnsrewrite=TXT;hello-crabdns".to_string(),
        ]));
        let cache = Arc::new(DnsCache::new(64, false));
        let upstream = Arc::new(UpstreamPool::new(&["udp://127.0.0.1:1".to_string()], 50).unwrap());
        let pipeline = DnsPipeline::new(filter, cache, upstream, None);
        let allowed_client: SocketAddr = "127.0.0.1:5000".parse().expect("addr");

        // BlockMode::NxDomain
        pipeline.set_block_mode(BlockMode::NxDomain);
        let q_blk = build_query(0x5001, "blocked.test.", RecordType::A);
        let nx_resp = Message::from_vec(
            &pipeline
                .handle_packet(&q_blk, allowed_client)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(nx_resp.response_code, ResponseCode::NXDomain);
        assert_eq!(nx_resp.answers.len(), 0);

        // BlockMode::NoData
        pipeline.set_block_mode(BlockMode::NoData);
        let nodata_resp = Message::from_vec(
            &pipeline
                .handle_packet(&q_blk, allowed_client)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(nodata_resp.response_code, ResponseCode::NoError);
        assert_eq!(nodata_resp.answers.len(), 0);

        // CNAME and TXT rewrites
        let q_cname = build_query(0x5002, "alias.test.", RecordType::A);
        let r_cname = Message::from_vec(
            &pipeline
                .handle_packet(&q_cname, allowed_client)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(matches!(
            r_cname.answers.first().map(|r| &r.data),
            Some(RData::CNAME(_))
        ));

        let q_txt = build_query(0x5003, "txt.test.", RecordType::TXT);
        let r_txt = Message::from_vec(
            &pipeline
                .handle_packet(&q_txt, allowed_client)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(matches!(
            r_txt.answers.first().map(|r| &r.data),
            Some(RData::TXT(_))
        ));

        // ACL deny & rate limit
        pipeline
            .reload_acl(&["127.0.0.0/8".to_string()], &["127.0.0.99".to_string()], 1)
            .expect("acl");
        let denied_client: SocketAddr = "127.0.0.99:5000".parse().expect("addr");
        let r_denied =
            Message::from_vec(&pipeline.handle_packet(&q_blk, denied_client).await.unwrap())
                .unwrap();
        assert_eq!(r_denied.response_code, ResponseCode::Refused);

        // First query within rate limit succeeds, second is refused
        let r_ok = Message::from_vec(
            &pipeline
                .handle_packet(&q_blk, allowed_client)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(r_ok.response_code, ResponseCode::NoError);
        let r_rl = Message::from_vec(
            &pipeline
                .handle_packet(&q_blk, allowed_client)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(r_rl.response_code, ResponseCode::Refused);
    }
}
