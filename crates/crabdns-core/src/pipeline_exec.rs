use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::RecordType;

use crate::acl::AclDecision;
use crate::cache::{CacheKey, patch_tx_id};
use crate::clients::{ClientRegistry, ResolvedClientPolicy};
use crate::config::BlockMode;
use crate::edns::{apply_ecs_to_message, has_dnssec_ok, resolve_ecs_subnet, set_dnssec_ok};
use crate::error::{CoreError, Result};
use crate::filter::{FilterAction, FilterDecision};
use crate::filter_rules::FilterQueryContext;
use crate::lan::{build_ddr_response, build_hosts_response, is_ddr_query, is_private_ptr_domain};
use crate::pipeline::{DnsPipeline, QueryContext, QueryOutcome, QueryProtocol};
use crate::pipeline_cache::cache_upstream_response_msg;
use crate::pipeline_types::LogMeta;
use crate::security::{build_rfc8482_any_response, contains_rebinding_ip_msg};
use crate::singleflight::{FlightGuard, FlightReceiver, FlightRole, wait_follower};
use crate::upstream::UpstreamPool;
use crate::wire::{
    build_blocked_response, build_error_response, build_rewrite_response, extract_answer_summaries,
    extract_answer_summaries_msg,
};

#[derive(Clone, Copy)]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct PolicyFlags {
    pub blocking_disabled: bool,
    pub explicitly_allowed: bool,
    pub cname_cloaking_on: bool,
    pub block_mode: BlockMode,
    pub dnssec_on: bool,
    pub client_wants_do: bool,
}

enum ExchangeError {
    DnssecBogus(String),
    UpstreamFailed(String),
}

struct LatencyRecorder<'a> {
    hist: &'a crate::pipeline::QueryLatencyHistogram,
    start: Instant,
}

impl Drop for LatencyRecorder<'_> {
    fn drop(&mut self) {
        let elapsed_us = u64::try_from(self.start.elapsed().as_micros()).unwrap_or(u64::MAX);
        self.hist.record(elapsed_us);
    }
}

impl DnsPipeline {
    pub async fn handle_packet(
        &self,
        raw_query: &[u8],
        client_addr: SocketAddr,
    ) -> Result<Vec<u8>> {
        self.handle_packet_with_context(
            raw_query,
            QueryContext {
                client_addr,
                protocol: QueryProtocol::Udp,
                client_id: None,
            },
        )
        .await
    }

    pub async fn handle_packet_with_context(
        &self,
        raw_query: &[u8],
        ctx: QueryContext,
    ) -> Result<Vec<u8>> {
        let start = Instant::now();
        let _latency_recorder = LatencyRecorder {
            hist: &self.latency,
            start,
        };
        let request = Message::from_vec(raw_query)
            .map_err(|e| CoreError::Protocol(format!("invalid DNS packet: {e}")))?;

        let Some(question) = request.queries.first().cloned() else {
            return build_error_response(&request, ResponseCode::FormErr);
        };

        let qname = question.name().to_utf8();
        let clean_domain = qname.trim_end_matches('.').to_string();
        let qtype = question.query_type();
        let qclass = u16::from(question.query_class());

        let policy = self
            .clients
            .load()
            .match_client(ctx.client_addr.ip(), ctx.client_id.as_deref());
        let client_name = match &policy {
            Some(p) => Some(p.client_name.clone()),
            None => {
                self.resolve_unconfigured_client_name(ctx.client_addr.ip())
                    .0
            }
        };
        let meta = LogMeta {
            client_addr: ctx.client_addr,
            client_name: client_name.clone(),
            client_id: ctx.client_id.clone(),
            profile_id: policy.as_deref().map(|p| p.profile_id.clone()),
            protocol: ctx.protocol,
            domain: clean_domain,
            qtype,
            start,
        };

        if let Some(resp) = self.check_pre_routing(&request, &meta)? {
            return Ok(resp);
        }

        let flags = self.build_policy_flags(&request, policy.as_deref());
        let decision = self.evaluate_request_filter(&meta, &ctx, policy.as_deref());
        let explicitly_allowed =
            decision.action == FilterAction::Allow && decision.matched_rule.is_some();
        let flags = PolicyFlags {
            explicitly_allowed,
            ..flags
        };

        if let Some(resp) = self.handle_filter_decision(&request, &meta, &decision, flags)? {
            return Ok(resp);
        }

        if let Some(resp) = self.check_private_ptr_block(&request, &meta)? {
            return Ok(resp);
        }

        let ecs_subnet = resolve_ecs_subnet(&self.ecs_config.load(), ctx.client_addr.ip());
        let (upstream, upstream_scope, is_local_route) =
            self.resolve_upstream_for_query(policy.as_deref(), &meta.domain, qtype);
        let cache_key = CacheKey {
            qname: qname.to_ascii_lowercase(),
            qtype: u16::from(qtype),
            qclass,
            ecs_subnet,
            dnssec_do: flags.dnssec_on && flags.client_wants_do,
            upstream_scope,
        };

        if let Some(resp) = self.try_serve_from_cache(
            &request,
            raw_query,
            &meta,
            policy.as_deref(),
            &upstream,
            &cache_key,
            &decision,
            flags,
        )? {
            return Ok(resp);
        }

        let upstream_query =
            Self::build_upstream_query(&request, raw_query, ecs_subnet, flags.dnssec_on);
        self.forward_with_singleflight(
            &request,
            &upstream_query,
            &meta,
            policy.as_deref(),
            &upstream,
            is_local_route,
            cache_key,
            &decision,
            flags,
        )
        .await
    }

    fn evaluate_request_filter(
        &self,
        meta: &LogMeta,
        ctx: &QueryContext,
        policy: Option<&ResolvedClientPolicy>,
    ) -> FilterDecision {
        let empty_tags: &[String] = &[];
        let filter_ctx = FilterQueryContext {
            domain: &meta.domain,
            qtype: Some(meta.qtype),
            client_ip: Some(ctx.client_addr.ip()),
            client_id: ctx.client_id.as_deref(),
            client_name: meta.client_name.as_deref(),
            client_tags: policy.map_or(empty_tags, |p| p.tags.as_slice()),
        };
        ClientRegistry::evaluate_domain_with_context(policy, &self.filter, &filter_ctx)
    }

    fn build_policy_flags(
        &self,
        request: &Message,
        policy: Option<&ResolvedClientPolicy>,
    ) -> PolicyFlags {
        PolicyFlags {
            blocking_disabled: self.is_blocking_paused()
                || policy.is_some_and(|p| !p.blocking_enabled),
            explicitly_allowed: false,
            cname_cloaking_on: policy
                .and_then(|p| p.cname_cloaking_blocking)
                .unwrap_or_else(|| self.cname_cloaking()),
            block_mode: policy
                .and_then(|p| p.block_mode)
                .unwrap_or_else(|| self.block_mode()),
            dnssec_on: self.dnssec_enabled.load(Ordering::Relaxed),
            client_wants_do: has_dnssec_ok(request),
        }
    }

    fn check_pre_routing(&self, request: &Message, meta: &LogMeta) -> Result<Option<Vec<u8>>> {
        if let Some(refused) = self.enforce_acl(request, meta)? {
            return Ok(Some(refused));
        }
        self.check_local_interceptors(request, meta)
    }

    fn check_private_ptr_block(
        &self,
        request: &Message,
        meta: &LogMeta,
    ) -> Result<Option<Vec<u8>>> {
        if meta.qtype == RecordType::PTR && is_private_ptr_domain(&meta.domain) {
            let ptr_router = self.private_ptr_router.load();
            if ptr_router.enabled && ptr_router.pool.is_none() {
                let resp = build_error_response(request, ResponseCode::NXDomain)?;
                self.emit_log(
                    meta,
                    QueryOutcome::Blocked,
                    Some("lan:private-ptr".to_string()),
                    Some("lan".to_string()),
                    None,
                    "NXDOMAIN",
                    Vec::new(),
                );
                return Ok(Some(resp));
            }
        }
        Ok(None)
    }

    fn check_local_interceptors(
        &self,
        request: &Message,
        meta: &LogMeta,
    ) -> Result<Option<Vec<u8>>> {
        if self.block_any_queries.load(Ordering::Relaxed) && meta.qtype == RecordType::ANY {
            let resp = build_rfc8482_any_response(request)?;
            self.emit_log(
                meta,
                QueryOutcome::Blocked,
                Some("security:any-query".to_string()),
                Some("security".to_string()),
                None,
                "NOERROR",
                extract_answer_summaries(&resp),
            );
            return Ok(Some(resp));
        }

        let ddr = self.ddr_config.load();
        if ddr.enabled && is_ddr_query(&meta.domain, meta.qtype) {
            let resp = build_ddr_response(request, &ddr)?;
            self.emit_log(
                meta,
                QueryOutcome::Rewritten,
                Some("ddr:resolver".to_string()),
                Some("ddr".to_string()),
                None,
                "NOERROR",
                extract_answer_summaries(&resp),
            );
            return Ok(Some(resp));
        }

        if self.hosts_enabled.load(Ordering::Relaxed)
            && let Some(matched) = self.hosts_table.load().lookup(&meta.domain, meta.qtype)
        {
            let resp = build_hosts_response(request, &matched)?;
            self.emit_log(
                meta,
                QueryOutcome::Rewritten,
                Some("hosts:local".to_string()),
                Some("hosts".to_string()),
                None,
                "NOERROR",
                extract_answer_summaries(&resp),
            );
            return Ok(Some(resp));
        }

        Ok(None)
    }

    fn handle_filter_decision(
        &self,
        request: &Message,
        meta: &LogMeta,
        decision: &FilterDecision,
        flags: PolicyFlags,
    ) -> Result<Option<Vec<u8>>> {
        match &decision.action {
            FilterAction::Block if !flags.blocking_disabled => {
                let (resp, rcode) = build_blocked_response(request, meta.qtype, flags.block_mode)?;
                self.emit_log(
                    meta,
                    QueryOutcome::Blocked,
                    decision.matched_rule.clone(),
                    decision.matched_list.clone(),
                    None,
                    rcode,
                    extract_answer_summaries(&resp),
                );
                Ok(Some(resp))
            }
            FilterAction::Rewrite(rewrite) => {
                let resp = build_rewrite_response(request, meta.qtype, rewrite)?;
                self.emit_log(
                    meta,
                    QueryOutcome::Rewritten,
                    decision.matched_rule.clone(),
                    decision.matched_list.clone(),
                    None,
                    "NOERROR",
                    extract_answer_summaries(&resp),
                );
                Ok(Some(resp))
            }
            FilterAction::Block | FilterAction::Allow => Ok(None),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn try_serve_from_cache(
        &self,
        request: &Message,
        raw_query: &[u8],
        meta: &LogMeta,
        policy: Option<&ResolvedClientPolicy>,
        upstream: &Arc<UpstreamPool>,
        cache_key: &CacheKey,
        decision: &FilterDecision,
        flags: PolicyFlags,
    ) -> Result<Option<Vec<u8>>> {
        let cache = self.cache.load();
        let Some(hit) = cache.get(cache_key, request.id) else {
            return Ok(None);
        };

        if hit.needs_refresh {
            let refresh_wire = Self::build_upstream_query(
                request,
                raw_query,
                cache_key.ecs_subnet,
                flags.dnssec_on,
            );
            self.spawn_background_refresh(
                Arc::clone(upstream),
                refresh_wire,
                cache_key.clone(),
                flags.dnssec_on,
                flags.client_wants_do,
            );
        }

        let parsed_hit = Message::from_vec(&hit.wire_bytes).ok();

        if !flags.blocking_disabled
            && !flags.explicitly_allowed
            && flags.cname_cloaking_on
            && let Some(ref resp_msg) = parsed_hit
            && let Some(blk) =
                self.check_cname_cloaking_msg(policy, meta, request, resp_msg, flags.block_mode)?
        {
            self.emit_log(
                meta,
                QueryOutcome::Blocked,
                Some(blk.rule),
                blk.list,
                Some("cache".to_string()),
                blk.rcode,
                extract_answer_summaries(&blk.bytes),
            );
            return Ok(Some(blk.bytes));
        }

        let (rcode_str, answers) = match parsed_hit.as_ref() {
            Some(msg) => (
                msg.response_code.to_string(),
                extract_answer_summaries_msg(msg),
            ),
            None => ("UNKNOWN".to_string(), Vec::new()),
        };

        self.emit_log(
            meta,
            QueryOutcome::Cached,
            decision.matched_rule.clone(),
            decision.matched_list.clone(),
            Some("cache".to_string()),
            &rcode_str,
            answers,
        );
        Ok(Some(hit.wire_bytes))
    }

    fn enforce_acl(&self, request: &Message, meta: &LogMeta) -> Result<Option<Vec<u8>>> {
        let rule = match self.acl.load().check(meta.client_addr.ip()) {
            AclDecision::Allow => return Ok(None),
            AclDecision::DeniedAcl => "acl:denied",
            AclDecision::RateLimited => "acl:ratelimit",
        };
        self.emit_log(
            meta,
            QueryOutcome::Blocked,
            Some(rule.to_string()),
            Some("acl".to_string()),
            None,
            "REFUSED",
            Vec::new(),
        );
        build_error_response(request, ResponseCode::Refused).map(Some)
    }

    fn build_upstream_query(
        request: &Message,
        raw_query: &[u8],
        ecs_subnet: Option<(IpAddr, u8)>,
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

    async fn exchange_and_validate(
        &self,
        upstream: &UpstreamPool,
        upstream_query: &[u8],
        clean_domain: &str,
        flags: PolicyFlags,
    ) -> std::result::Result<(Vec<u8>, String), ExchangeError> {
        let (mut resp_bytes, upstream_label) = upstream
            .exchange(upstream_query)
            .await
            .map_err(|e| ExchangeError::UpstreamFailed(e.to_string()))?;

        if flags.dnssec_on {
            match self
                .dnssec_validator
                .validate_and_process(&resp_bytes, upstream, flags.client_wants_do)
                .await
            {
                Ok(processed) => resp_bytes = processed,
                Err(err) => {
                    tracing::warn!(domain = %clean_domain, error = %err, "DNSSEC validation failed");
                    return Err(ExchangeError::DnssecBogus(upstream_label));
                }
            }
        }
        Ok((resp_bytes, upstream_label))
    }

    #[allow(clippy::too_many_arguments)]
    async fn forward_with_singleflight(
        &self,
        request: &Message,
        upstream_query: &[u8],
        meta: &LogMeta,
        policy: Option<&ResolvedClientPolicy>,
        upstream: &Arc<UpstreamPool>,
        is_local_route: bool,
        cache_key: CacheKey,
        decision: &FilterDecision,
        flags: PolicyFlags,
    ) -> Result<Vec<u8>> {
        let query_budget = upstream.query_budget();
        let (resp_bytes, upstream_label, parsed_msg) =
            match self.inflight.acquire(cache_key.clone()) {
                FlightRole::Leader(guard) => {
                    match self
                        .run_singleflight_leader(
                            guard,
                            request,
                            upstream_query,
                            meta,
                            policy,
                            upstream,
                            is_local_route,
                            cache_key,
                            flags,
                            query_budget,
                        )
                        .await
                    {
                        Ok(res) => res,
                        Err(err_resp) => return err_resp,
                    }
                }
                FlightRole::Follower(rx) => {
                    match self
                        .await_singleflight_follower(request, meta, rx, query_budget)
                        .await
                    {
                        Ok(res) => res,
                        Err(err_resp) => return err_resp,
                    }
                }
            };

        self.finalize_upstream_response(
            request,
            meta,
            policy,
            is_local_route,
            decision,
            flags,
            resp_bytes,
            upstream_label,
            parsed_msg.as_ref(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_singleflight_leader(
        &self,
        guard: FlightGuard<CacheKey, (Vec<u8>, String)>,
        request: &Message,
        upstream_query: &[u8],
        meta: &LogMeta,
        policy: Option<&ResolvedClientPolicy>,
        upstream: &Arc<UpstreamPool>,
        is_local_route: bool,
        cache_key: CacheKey,
        flags: PolicyFlags,
        query_budget: Duration,
    ) -> std::result::Result<(Vec<u8>, String, Option<Message>), Result<Vec<u8>>> {
        let exchange_res = match tokio::time::timeout(
            query_budget,
            self.exchange_and_validate(upstream, upstream_query, &meta.domain, flags),
        )
        .await
        {
            Ok(res) => res,
            Err(_) => Err(ExchangeError::UpstreamFailed(
                "upstream query deadline exceeded".to_string(),
            )),
        };

        match exchange_res {
            Ok((resp_bytes, upstream_label)) => {
                let parsed = Message::from_vec(&resp_bytes).ok();
                let rebinding_hit = !is_local_route
                    && self.dns_rebinding_protection.load(Ordering::Relaxed)
                    && parsed.as_ref().is_some_and(contains_rebinding_ip_msg);
                let cname_hit = if !flags.blocking_disabled
                    && !flags.explicitly_allowed
                    && flags.cname_cloaking_on
                    && let Some(ref msg) = parsed
                {
                    match self.check_cname_cloaking_msg(
                        policy,
                        meta,
                        request,
                        msg,
                        flags.block_mode,
                    ) {
                        Ok(hit) => hit.is_some(),
                        Err(err) => return Err(Err(err)),
                    }
                } else {
                    false
                };
                if !rebinding_hit
                    && !cname_hit
                    && let Some(ref msg) = parsed
                {
                    let cache = self.cache.load();
                    let _ = cache_upstream_response_msg(&cache, cache_key, &resp_bytes, msg);
                }
                guard.complete(Ok((resp_bytes.clone(), upstream_label.clone())));
                Ok((resp_bytes, upstream_label, parsed))
            }
            Err(ExchangeError::DnssecBogus(label)) => {
                guard.complete(Err(format!("dnssec:bogus:{label}")));
                self.emit_log(
                    meta,
                    QueryOutcome::Error,
                    Some("dnssec:bogus".to_string()),
                    Some("dnssec".to_string()),
                    Some(label),
                    "SERVFAIL",
                    Vec::new(),
                );
                Err(build_error_response(request, ResponseCode::ServFail))
            }
            Err(ExchangeError::UpstreamFailed(err)) => {
                tracing::warn!(domain = %meta.domain, error = %err, "all upstreams failed");
                guard.complete(Err(err));
                self.emit_log(
                    meta,
                    QueryOutcome::Error,
                    None,
                    None,
                    None,
                    "SERVFAIL",
                    Vec::new(),
                );
                Err(build_error_response(request, ResponseCode::ServFail))
            }
        }
    }

    async fn await_singleflight_follower(
        &self,
        request: &Message,
        meta: &LogMeta,
        rx: FlightReceiver<(Vec<u8>, String)>,
        query_budget: Duration,
    ) -> std::result::Result<(Vec<u8>, String, Option<Message>), Result<Vec<u8>>> {
        let wait_budget = query_budget.saturating_add(Duration::from_secs(1));
        let wait_res = match tokio::time::timeout(wait_budget, wait_follower(rx)).await {
            Ok(res) => res,
            Err(_) => Err("singleflight wait deadline exceeded".to_string()),
        };
        match wait_res {
            Ok((mut bytes, label)) => {
                patch_tx_id(&mut bytes, request.id);
                let parsed = Message::from_vec(&bytes).ok();
                Ok((bytes, label, parsed))
            }
            Err(err_msg) => {
                let (matched_rule, matched_list, upstream_opt) =
                    if let Some(label) = err_msg.strip_prefix("dnssec:bogus:") {
                        (
                            Some("dnssec:bogus".to_string()),
                            Some("dnssec".to_string()),
                            Some(label.to_string()),
                        )
                    } else {
                        (None, None, None)
                    };
                self.emit_log(
                    meta,
                    QueryOutcome::Error,
                    matched_rule,
                    matched_list,
                    upstream_opt,
                    "SERVFAIL",
                    Vec::new(),
                );
                Err(build_error_response(request, ResponseCode::ServFail))
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn finalize_upstream_response(
        &self,
        request: &Message,
        meta: &LogMeta,
        policy: Option<&ResolvedClientPolicy>,
        is_local_route: bool,
        decision: &FilterDecision,
        flags: PolicyFlags,
        resp_bytes: Vec<u8>,
        upstream_label: String,
        parsed_msg: Option<&Message>,
    ) -> Result<Vec<u8>> {
        if !flags.blocking_disabled
            && !flags.explicitly_allowed
            && !is_local_route
            && self.dns_rebinding_protection.load(Ordering::Relaxed)
            && parsed_msg.is_some_and(contains_rebinding_ip_msg)
        {
            let (blocked_bytes, rcode) =
                build_blocked_response(request, meta.qtype, flags.block_mode)?;
            self.emit_log(
                meta,
                QueryOutcome::Blocked,
                Some("security:dns-rebinding".to_string()),
                Some("security".to_string()),
                Some(upstream_label),
                rcode,
                extract_answer_summaries(&blocked_bytes),
            );
            return Ok(blocked_bytes);
        }

        if !flags.blocking_disabled
            && !flags.explicitly_allowed
            && flags.cname_cloaking_on
            && let Some(msg) = parsed_msg
            && let Some(blk) =
                self.check_cname_cloaking_msg(policy, meta, request, msg, flags.block_mode)?
        {
            self.emit_log(
                meta,
                QueryOutcome::Blocked,
                Some(blk.rule),
                blk.list,
                Some(upstream_label),
                blk.rcode,
                extract_answer_summaries(&blk.bytes),
            );
            return Ok(blk.bytes);
        }

        let (rcode_str, answers) = match parsed_msg {
            Some(msg) => (
                msg.response_code.to_string(),
                extract_answer_summaries_msg(msg),
            ),
            None => ("UNKNOWN".to_string(), Vec::new()),
        };
        self.emit_log(
            meta,
            QueryOutcome::Forwarded,
            decision.matched_rule.clone(),
            decision.matched_list.clone(),
            Some(upstream_label),
            &rcode_str,
            answers,
        );
        Ok(resp_bytes)
    }
}
