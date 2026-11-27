use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

use hickory_proto::op::Message;
use hickory_proto::rr::RecordType;

use crate::acl::AclDecision;
use crate::cache::{CacheKey, CachedEntry};
use crate::clients::{ClientRegistry, ResolvedClientPolicy};
use crate::config::BlockMode;
use crate::edns::resolve_ecs_subnet;
use crate::filter::{FilterAction, FilterDecision};
use crate::filter_rules::FilterQueryContext;
use crate::lan::{is_ddr_query, is_local_domain, is_private_ptr_domain};
use crate::pipeline::{DnsPipeline, QueryOutcome, QueryProtocol};
use crate::pipeline_types::LogMeta;
use crate::rrl::{RrlDecision, classify_response_category};
use crate::safesearch::match_safesearch;
use crate::upstream::UpstreamPool;
use crate::wire::extract_answer_summaries;
use crate::wire_fast::{
    FastQuery, apply_udp_tc_in_place, parse_fast_query, write_blocked_wire_response,
    write_refused_wire_response,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpFastOutcome {
    Handled,
    NeedsAsync,
}

impl DnsPipeline {
    /// Attempts to handle a UDP DNS query synchronously on the fast path without
    /// spawning a Tokio task or constructing `hickory_proto::op::Message`.
    ///
    /// Returns [`UdpFastOutcome::Handled`] when the response has been written into `out`
    /// (which may be empty if dropped by RRL), or [`UdpFastOutcome::NeedsAsync`] when
    /// full async processing is required.
    pub fn try_handle_udp_fast(
        &self,
        raw_query: &[u8],
        client_addr: SocketAddr,
        out: &mut Vec<u8>,
    ) -> UdpFastOutcome {
        if self.fast_path_bypassed() {
            return UdpFastOutcome::NeedsAsync;
        }
        let Some(q) = parse_fast_query(raw_query) else {
            return UdpFastOutcome::NeedsAsync;
        };
        if self.query_requires_slow_path(&q) {
            return UdpFastOutcome::NeedsAsync;
        }

        let start = Instant::now();
        let clean_domain = q.clean_domain();
        let qtype = RecordType::from(q.qtype);

        let (policy, meta) = self.build_fast_meta(client_addr, clean_domain, qtype, start);

        if self.try_fast_acl(raw_query, &q, &meta, out) {
            self.record_fast_latency(start);
            return UdpFastOutcome::Handled;
        }

        let blocking_disabled =
            self.is_blocking_paused() || policy.as_deref().is_some_and(|p| !p.blocking_enabled);
        let decision = self.evaluate_fast_filter(
            clean_domain,
            qtype,
            client_addr.ip(),
            &meta,
            policy.as_deref(),
        );
        let explicitly_allowed =
            decision.action == FilterAction::Allow && decision.matched_rule.is_some();

        match &decision.action {
            FilterAction::Block if !blocking_disabled => {
                let block_mode = policy
                    .as_deref()
                    .and_then(|p| p.block_mode)
                    .unwrap_or_else(|| self.block_mode());
                let rcode = write_blocked_wire_response(
                    raw_query,
                    &q,
                    block_mode,
                    self.ede_enabled.load(Ordering::Relaxed),
                    out,
                );
                self.emit_log(
                    &meta,
                    QueryOutcome::Blocked,
                    decision.matched_rule,
                    decision.matched_list,
                    None,
                    rcode,
                    extract_answer_summaries(out),
                );
                self.finalize_udp_fast_out(client_addr.ip(), clean_domain, &q, out);
                self.record_fast_latency(start);
                return UdpFastOutcome::Handled;
            }
            FilterAction::Rewrite(_) => return UdpFastOutcome::NeedsAsync,
            FilterAction::Block | FilterAction::Allow => {}
        }

        if self.fast_interceptor_applies(
            clean_domain,
            qtype,
            policy.as_deref(),
            blocking_disabled,
            explicitly_allowed,
        ) {
            return UdpFastOutcome::NeedsAsync;
        }

        if self.try_fast_cache(
            raw_query,
            &q,
            &meta,
            policy.as_deref(),
            &decision,
            blocking_disabled,
            explicitly_allowed,
            out,
        ) {
            self.record_fast_latency(start);
            return UdpFastOutcome::Handled;
        }

        UdpFastOutcome::NeedsAsync
    }

    #[inline]
    fn fast_path_bypassed(&self) -> bool {
        self.dns_cookies.is_enabled()
            || self.dns_cookies.require_valid()
            || self.dnssec_enabled.load(Ordering::Relaxed)
            || self.dns64.load().enabled
    }

    fn query_requires_slow_path(&self, q: &FastQuery) -> bool {
        if q.cd {
            return true;
        }
        if matches!(q.qtype, 64 | 65)
            && (self.svcb_strip_ech.load(Ordering::Relaxed)
                || self.svcb_strip_hints.load(Ordering::Relaxed))
        {
            return true;
        }
        if self.cf_cdn.is_enabled() && matches!(q.qtype, 1 | 28 | 64 | 65) {
            return true;
        }
        if self.block_any_queries.load(Ordering::Relaxed) && q.qtype == 255 {
            return true;
        }
        let qtype = RecordType::from(q.qtype);
        let clean = q.clean_domain();
        if self.ddr_config.load().enabled && is_ddr_query(clean, qtype) {
            return true;
        }
        if self.hosts_enabled.load(Ordering::Relaxed)
            && self.hosts_table.load().lookup(clean, qtype).is_some()
        {
            return true;
        }
        if self.dhcp_leases_enabled.load(Ordering::Relaxed)
            && self.dhcp_leases_forward_enabled.load(Ordering::Relaxed)
            && self
                .dhcp_leases
                .load()
                .lookup_forward(clean, qtype, &self.dhcp_leases_domain.load())
                .is_some()
        {
            return true;
        }
        if self.block_local_domains.load(Ordering::Relaxed) && is_local_domain(clean) {
            return true;
        }
        false
    }

    #[inline]
    fn record_fast_latency(&self, start: Instant) {
        let elapsed_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
        self.latency.record(elapsed_us);
    }

    fn build_fast_meta(
        &self,
        client_addr: SocketAddr,
        clean_domain: &str,
        qtype: RecordType,
        start: Instant,
    ) -> (Option<Arc<ResolvedClientPolicy>>, LogMeta) {
        let policy = self.match_client_policy(client_addr.ip(), None);
        let client_name = match &policy {
            Some(p) => Some(p.client_name.clone()),
            None => self.resolve_unconfigured_client_name(client_addr.ip()).0,
        };
        let meta = LogMeta {
            client_addr,
            client_name,
            client_id: None,
            profile_id: policy.as_deref().map(|p| p.profile_id.clone()),
            protocol: QueryProtocol::Udp,
            domain: clean_domain.to_string(),
            qtype,
            start,
        };
        (policy, meta)
    }

    fn try_fast_acl(
        &self,
        raw_query: &[u8],
        q: &FastQuery,
        meta: &LogMeta,
        out: &mut Vec<u8>,
    ) -> bool {
        let decision = self.acl.load().check(meta.client_addr.ip());
        let reason = match decision {
            AclDecision::Allow => return false,
            AclDecision::DeniedAcl => "acl",
            AclDecision::RateLimited => "rate_limit",
        };
        write_refused_wire_response(raw_query, q, out);
        self.emit_log(
            meta,
            QueryOutcome::Blocked,
            Some(format!("acl:{reason}")),
            Some("acl".to_string()),
            None,
            "REFUSED",
            Vec::new(),
        );
        self.finalize_udp_fast_out(meta.client_addr.ip(), q.clean_domain(), q, out);
        true
    }

    fn evaluate_fast_filter(
        &self,
        clean_domain: &str,
        qtype: RecordType,
        client_ip: IpAddr,
        meta: &LogMeta,
        policy: Option<&ResolvedClientPolicy>,
    ) -> FilterDecision {
        let empty_tags: &[String] = &[];
        let filter_ctx = FilterQueryContext {
            domain: clean_domain,
            qtype: Some(qtype),
            client_ip: Some(client_ip),
            client_id: None,
            client_name: meta.client_name.as_deref(),
            client_tags: policy.map_or(empty_tags, |p| p.tags.as_slice()),
        };
        ClientRegistry::evaluate_domain_with_context(policy, &self.filter, &filter_ctx)
    }

    fn fast_interceptor_applies(
        &self,
        clean_domain: &str,
        qtype: RecordType,
        policy: Option<&ResolvedClientPolicy>,
        blocking_disabled: bool,
        explicitly_allowed: bool,
    ) -> bool {
        if !explicitly_allowed
            && !blocking_disabled
            && matches!(
                qtype,
                RecordType::A
                    | RecordType::AAAA
                    | RecordType::CNAME
                    | RecordType::HTTPS
                    | RecordType::SVCB
            )
        {
            let cfg = self.safesearch.load();
            let client_override = policy.and_then(|p| p.safesearch_enabled);
            if match_safesearch(&cfg, clean_domain, client_override).is_some() {
                return true;
            }
        }
        if qtype == RecordType::TXT && !self.acme_dns_challenges.is_empty() {
            return true;
        }
        if qtype == RecordType::PTR && is_private_ptr_domain(clean_domain) {
            let ptr_router = self.private_ptr_router.load();
            if ptr_router.enabled && ptr_router.pool.is_none() {
                return true;
            }
        }
        false
    }

    #[allow(clippy::too_many_arguments)]
    fn try_fast_cache(
        &self,
        raw_query: &[u8],
        q: &FastQuery,
        meta: &LogMeta,
        policy: Option<&ResolvedClientPolicy>,
        decision: &FilterDecision,
        blocking_disabled: bool,
        explicitly_allowed: bool,
        out: &mut Vec<u8>,
    ) -> bool {
        let route = self.resolve_upstream_for_query(
            Some(meta.client_addr.ip()),
            Some(QueryProtocol::Udp),
            policy,
            &meta.domain,
            meta.qtype,
        );
        if let Some(up) = route.upstream_policy.as_deref()
            && (up.dnssec_enabled == Some(true)
                || (up.disable_ipv6 == Some(true) && q.qtype == 28)
                || (up.dns64_enabled == Some(true) && q.qtype == 28)
                || (matches!(q.qtype, 64 | 65)
                    && (up.svcb_strip_ech == Some(true) || up.svcb_strip_hints == Some(true)))
                || (up.cf_cdn_enabled == Some(true) && matches!(q.qtype, 1 | 28 | 64 | 65)))
        {
            return false;
        }
        let global_ecs = self.ecs_config.load();
        let ecs_cfg = route
            .upstream_policy
            .as_deref()
            .map(|p| p.resolve_ecs_config(&global_ecs));
        let ecs_subnet = resolve_ecs_subnet(
            ecs_cfg.as_ref().unwrap_or(&global_ecs),
            meta.client_addr.ip(),
        );
        let upstream = route.pool;
        let dns_rebinding_on = route
            .upstream_policy
            .as_deref()
            .and_then(|p| p.dns_rebinding_protection)
            .unwrap_or_else(|| {
                !route.is_local_route && self.dns_rebinding_protection.load(Ordering::Relaxed)
            });
        let cache_key = CacheKey {
            qname: q.qname_fqdn().to_string(),
            qtype: q.qtype,
            qclass: q.qclass,
            ecs_subnet,
            dnssec_do: false,
            upstream_scope: route.cache_scope,
        };

        let cache = self.cache.load();
        let Some((entry, _is_stale, needs_refresh)) =
            cache.get_entry_into(&cache_key, q.tx_id, out)
        else {
            return false;
        };

        if needs_refresh {
            self.trigger_fast_background_refresh(raw_query, ecs_subnet, &upstream, cache_key);
        }

        let block_mode = policy
            .and_then(|p| p.block_mode)
            .unwrap_or_else(|| self.block_mode());

        if self.check_fast_cache_security(
            raw_query,
            q,
            meta,
            policy,
            &entry,
            blocking_disabled,
            explicitly_allowed,
            dns_rebinding_on,
            block_mode,
            out,
        ) {
            self.finalize_udp_fast_out(meta.client_addr.ip(), q.clean_domain(), q, out);
            return true;
        }

        self.emit_log(
            meta,
            QueryOutcome::Cached,
            decision.matched_rule.clone(),
            decision.matched_list.clone(),
            Some("cache".to_string()),
            entry.rcode_str,
            entry.answer_summaries.to_vec(),
        );
        self.finalize_udp_fast_out(meta.client_addr.ip(), q.clean_domain(), q, out);
        true
    }

    fn trigger_fast_background_refresh(
        &self,
        raw_query: &[u8],
        ecs_subnet: Option<(IpAddr, u8)>,
        upstream: &Arc<UpstreamPool>,
        cache_key: CacheKey,
    ) {
        let refresh_wire = if let Some(subnet) = ecs_subnet {
            if let Ok(req) = Message::from_vec(raw_query) {
                Self::build_upstream_query(&req, raw_query, Some(subnet), false)
            } else {
                raw_query.to_vec()
            }
        } else {
            raw_query.to_vec()
        };
        self.spawn_background_refresh(Arc::clone(upstream), refresh_wire, cache_key, false, false);
    }

    #[allow(clippy::too_many_arguments)]
    fn check_fast_cache_security(
        &self,
        raw_query: &[u8],
        q: &FastQuery,
        meta: &LogMeta,
        policy: Option<&ResolvedClientPolicy>,
        entry: &CachedEntry,
        blocking_disabled: bool,
        explicitly_allowed: bool,
        dns_rebinding_on: bool,
        block_mode: BlockMode,
        out: &mut Vec<u8>,
    ) -> bool {
        if blocking_disabled || explicitly_allowed {
            return false;
        }

        if dns_rebinding_on && entry.has_rebinding_ip {
            let rcode = write_blocked_wire_response(
                raw_query,
                q,
                block_mode,
                self.ede_enabled.load(Ordering::Relaxed),
                out,
            );
            self.emit_log(
                meta,
                QueryOutcome::Blocked,
                Some("security:dns-rebinding".to_string()),
                Some("security".to_string()),
                Some("cache".to_string()),
                rcode,
                extract_answer_summaries(out),
            );
            return true;
        }

        let cname_cloaking_on = policy
            .and_then(|p| p.cname_cloaking_blocking)
            .unwrap_or_else(|| self.cname_cloaking());
        if cname_cloaking_on && !entry.cname_targets.is_empty() {
            let empty_tags: &[String] = &[];
            for target in &entry.cname_targets {
                let ctx = FilterQueryContext {
                    domain: target,
                    qtype: Some(meta.qtype),
                    client_ip: Some(meta.client_addr.ip()),
                    client_id: None,
                    client_name: meta.client_name.as_deref(),
                    client_tags: policy.map_or(empty_tags, |p| p.tags.as_slice()),
                };
                let dec = ClientRegistry::evaluate_domain_with_context(policy, &self.filter, &ctx);
                if dec.action == FilterAction::Block {
                    let rcode = write_blocked_wire_response(
                        raw_query,
                        q,
                        block_mode,
                        self.ede_enabled.load(Ordering::Relaxed),
                        out,
                    );
                    let rule = dec
                        .matched_rule
                        .unwrap_or_else(|| format!("cname:{target}"));
                    self.emit_log(
                        meta,
                        QueryOutcome::Blocked,
                        Some(rule),
                        dec.matched_list,
                        Some("cache".to_string()),
                        rcode,
                        extract_answer_summaries(out),
                    );
                    return true;
                }
            }
        }
        false
    }

    fn finalize_udp_fast_out(
        &self,
        client_ip: IpAddr,
        clean_domain: &str,
        q: &FastQuery,
        out: &mut Vec<u8>,
    ) {
        let category = classify_response_category(out);
        let mut force_tc = false;
        match self.rrl.check(client_ip, clean_domain, category) {
            RrlDecision::Drop => {
                out.clear();
                return;
            }
            RrlDecision::Slip => force_tc = true,
            RrlDecision::Allow => {}
        }
        let server_cap = self.max_udp_payload_size.load(Ordering::Relaxed).max(512);
        let client_max = if q.has_edns {
            q.edns_udp_payload.max(512)
        } else {
            512
        };
        let max_udp = usize::from(client_max.min(server_cap));
        apply_udp_tc_in_place(out, max_udp, force_tc);
    }
}
