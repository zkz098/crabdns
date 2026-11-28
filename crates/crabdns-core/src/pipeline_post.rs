use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::TXT;
use hickory_proto::rr::{RData, Record, RecordType};

use crate::clients::ResolvedClientPolicy;
use crate::cookies::CookieCheck;
use crate::dns64::{build_dns64_response, needs_dns64_synthesis};
use crate::edns::{
    EDE_PROHIBITED, attach_ede_to_wire, effective_udp_payload_limit, truncate_dns_response,
};
use crate::error::Result;
use crate::filter::FilterDecision;
use crate::filter_rules::RewriteAction;
use crate::pipeline::{DnsPipeline, QueryContext, QueryOutcome, QueryProtocol};
use crate::pipeline_exec::PolicyFlags;
use crate::pipeline_types::LogMeta;
use crate::rrl::{RrlDecision, classify_response_category};
use crate::safesearch::match_safesearch;
use crate::security::contains_rebinding_ip_msg;
use crate::svcb::sanitize_svcb_bytes;
use crate::upstream::UpstreamPool;
use crate::wire::{
    build_blocked_response, build_rewrite_response, extract_answer_summaries,
    extract_answer_summaries_msg,
};

impl DnsPipeline {
    pub fn resolve_client_mac(&self, ip: IpAddr) -> Option<String> {
        if let Some(mac) = self.neighbor_table.load().lookup(ip) {
            return Some(mac.to_string());
        }
        if self.dhcp_leases_enabled.load(Ordering::Relaxed)
            && let Some(mac) = self.dhcp_leases.load().lookup_mac(ip)
        {
            return Some(mac.to_string());
        }
        None
    }

    pub(crate) fn match_client_policy(
        &self,
        ip: IpAddr,
        client_id: Option<&str>,
    ) -> Option<Arc<ResolvedClientPolicy>> {
        let registry = self.clients.load();
        let mac = if registry.has_mac_rules() {
            self.resolve_client_mac(ip)
        } else {
            None
        };
        registry.match_client_with_mac(ip, client_id, mac.as_deref())
    }

    pub fn set_acme_dns_challenge(&self, fqdn: &str, value: String) {
        let key = fqdn.trim().trim_end_matches('.').to_ascii_lowercase();
        let mut entry = self.acme_dns_challenges.entry(key).or_default();
        if !entry.contains(&value) {
            entry.push(value);
        }
    }

    pub fn clear_acme_dns_challenges(&self) {
        self.acme_dns_challenges.clear();
    }

    pub(crate) fn check_acme_dns_challenge(
        &self,
        request: &Message,
        meta: &LogMeta,
    ) -> Result<Option<Vec<u8>>> {
        if meta.qtype != RecordType::TXT || self.acme_dns_challenges.is_empty() {
            return Ok(None);
        }
        let key = meta.domain.trim_end_matches('.').to_ascii_lowercase();
        let Some(values) = self.acme_dns_challenges.get(&key) else {
            return Ok(None);
        };
        let Some(question) = request.queries.first() else {
            return Ok(None);
        };
        let mut resp = Message::new(request.id, MessageType::Response, OpCode::Query);
        resp.metadata.recursion_desired = request.recursion_desired;
        resp.metadata.recursion_available = true;
        resp.metadata.authoritative = true;
        resp.metadata.response_code = ResponseCode::NoError;
        resp.add_query(question.clone());
        for val in values.iter() {
            resp.add_answer(Record::from_rdata(
                question.name().clone(),
                60,
                RData::TXT(TXT::new(vec![val.clone()])),
            ));
        }
        let wire = resp
            .to_vec()
            .map_err(|e| crate::error::CoreError::Protocol(e.to_string()))?;
        self.emit_log(
            meta,
            QueryOutcome::Rewritten,
            Some("acme:dns-01".to_string()),
            Some("acme".to_string()),
            None,
            "NOERROR",
            extract_answer_summaries(&wire),
        );
        Ok(Some(wire))
    }

    pub(crate) fn check_safesearch_interceptor(
        &self,
        request: &Message,
        meta: &LogMeta,
        policy: Option<&ResolvedClientPolicy>,
        blocking_disabled: bool,
    ) -> Result<Option<Vec<u8>>> {
        if blocking_disabled
            || !matches!(
                meta.qtype,
                RecordType::A
                    | RecordType::AAAA
                    | RecordType::CNAME
                    | RecordType::HTTPS
                    | RecordType::SVCB
            )
        {
            return Ok(None);
        }

        let cfg = self.safesearch.load();
        let client_override = policy.and_then(|p| p.safesearch_enabled);
        let Some((engine, target)) = match_safesearch(&cfg, &meta.domain, client_override) else {
            return Ok(None);
        };

        let rewrite = RewriteAction::Cname(target.to_string());
        let resp = build_rewrite_response(request, meta.qtype, &rewrite)?;
        self.emit_log(
            meta,
            QueryOutcome::Rewritten,
            Some(format!("safesearch:{engine}->{target}")),
            Some("safesearch".to_string()),
            None,
            "NOERROR",
            extract_answer_summaries(&resp),
        );
        Ok(Some(resp))
    }

    #[allow(clippy::unused_self)]
    pub(crate) fn maybe_sanitize_svcb(
        &self,
        qtype: RecordType,
        opts: crate::svcb::SvcbSanitizeOptions,
        resp_bytes: Vec<u8>,
        parsed_msg: Option<Message>,
    ) -> (Vec<u8>, Option<Message>) {
        if !matches!(qtype, RecordType::HTTPS | RecordType::SVCB) {
            return (resp_bytes, parsed_msg);
        }
        if let Some(updated) = sanitize_svcb_bytes(&resp_bytes, opts) {
            let parsed = Message::from_vec(&updated).ok();
            return (updated, parsed);
        }
        (resp_bytes, parsed_msg)
    }

    pub(crate) async fn maybe_synthesize_dns64(
        &self,
        request: &Message,
        meta: &LogMeta,
        upstream: &UpstreamPool,
        dns64_on: bool,
        resp_bytes: Vec<u8>,
        parsed_msg: Option<Message>,
    ) -> Result<(Vec<u8>, Option<Message>, bool)> {
        if meta.qtype != RecordType::AAAA {
            return Ok((resp_bytes, parsed_msg, false));
        }
        let dns64 = self.dns64.load();
        if !dns64_on || dns64.prefixes.is_empty() {
            return Ok((resp_bytes, parsed_msg, false));
        }
        let Some(ref orig_msg) = parsed_msg else {
            return Ok((resp_bytes, parsed_msg, false));
        };
        let Some(target_name) = needs_dns64_synthesis(orig_msg) else {
            return Ok((resp_bytes, parsed_msg, false));
        };

        let mut a_req = Message::new(
            request.id.wrapping_add(1),
            MessageType::Query,
            OpCode::Query,
        );
        a_req.metadata.recursion_desired = request.recursion_desired;
        a_req.add_query(Query::query(target_name, RecordType::A));
        let Ok(a_query_bytes) = a_req.to_vec() else {
            return Ok((resp_bytes, parsed_msg, false));
        };

        let budget = upstream.query_budget();
        let Ok(Ok((a_resp_bytes, _))) =
            tokio::time::timeout(budget, upstream.exchange(&a_query_bytes)).await
        else {
            return Ok((resp_bytes, parsed_msg, false));
        };
        let Ok(a_msg) = Message::from_vec(&a_resp_bytes) else {
            return Ok((resp_bytes, parsed_msg, false));
        };

        if let Some(synth_bytes) = build_dns64_response(request, orig_msg, &a_msg, &dns64.prefixes)?
        {
            let synth_parsed = Message::from_vec(&synth_bytes).ok();
            return Ok((synth_bytes, synth_parsed, true));
        }
        Ok((resp_bytes, parsed_msg, false))
    }

    pub(crate) fn dns64_enabled(&self) -> bool {
        self.dns64.load().enabled
    }

    pub(crate) fn maybe_accelerate_cf_cdn(
        &self,
        domain: &str,
        qtype: RecordType,
        cf_cdn_on: bool,
        resp_bytes: Vec<u8>,
        parsed_msg: Option<Message>,
    ) -> (Vec<u8>, Option<Message>, bool) {
        if !cf_cdn_on
            || !self.cf_cdn.is_enabled()
            || !matches!(
                qtype,
                RecordType::A | RecordType::AAAA | RecordType::HTTPS | RecordType::SVCB
            )
        {
            return (resp_bytes, parsed_msg, false);
        }

        let mut msg = match parsed_msg {
            Some(m) => m,
            None => match Message::from_vec(&resp_bytes) {
                Ok(m) => m,
                Err(_) => return (resp_bytes, None, false),
            },
        };

        if !self.cf_cdn.rewrite_message_if_cloudflare(domain, &mut msg) {
            return (resp_bytes, Some(msg), false);
        }

        match msg.to_vec() {
            Ok(updated) => (updated, Some(msg), true),
            Err(_) => (resp_bytes, Some(msg), false),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn post_process_and_log(
        &self,
        request: &Message,
        meta: &LogMeta,
        upstream: &UpstreamPool,
        flags: PolicyFlags,
        resp_bytes: Vec<u8>,
        parsed_msg: Option<Message>,
        base_outcome: QueryOutcome,
        matched_rule: Option<String>,
        matched_list: Option<String>,
        upstream_source: String,
    ) -> Result<Vec<u8>> {
        let (resp_bytes, parsed_msg, cf_accelerated) = self.maybe_accelerate_cf_cdn(
            &meta.domain,
            meta.qtype,
            flags.cf_cdn_on,
            resp_bytes,
            parsed_msg,
        );
        let (resp_bytes, parsed_msg) = if flags.svcb_strip_ech || flags.svcb_strip_hints {
            let opts = crate::svcb::SvcbSanitizeOptions {
                strip_ech: flags.svcb_strip_ech,
                strip_hints: flags.svcb_strip_hints,
            };
            self.maybe_sanitize_svcb(meta.qtype, opts, resp_bytes, parsed_msg)
        } else {
            (resp_bytes, parsed_msg)
        };
        let (resp_bytes, parsed_msg, dns64_synth) =
            if flags.dns64_on && meta.qtype == RecordType::AAAA {
                self.maybe_synthesize_dns64(
                    request,
                    meta,
                    upstream,
                    flags.dns64_on,
                    resp_bytes,
                    parsed_msg,
                )
                .await?
            } else {
                (resp_bytes, parsed_msg, false)
            };

        let (rcode_str, answers) = match parsed_msg.as_ref() {
            Some(msg) => (
                msg.response_code.to_string(),
                extract_answer_summaries_msg(msg),
            ),
            None => ("UNKNOWN".to_string(), Vec::new()),
        };

        let (final_outcome, final_rule, final_list) = if dns64_synth {
            (
                QueryOutcome::Rewritten,
                Some("dns64:synth".to_string()),
                Some("dns64".to_string()),
            )
        } else if cf_accelerated {
            (
                QueryOutcome::Rewritten,
                Some("cf_cdn:accelerate".to_string()),
                Some("cloudflare_cdn".to_string()),
            )
        } else {
            (base_outcome, matched_rule, matched_list)
        };

        self.emit_log(
            meta,
            final_outcome,
            final_rule,
            final_list,
            Some(upstream_source),
            &rcode_str,
            answers,
        );
        Ok(resp_bytes)
    }

    pub(crate) fn maybe_attach_ede(
        &self,
        request: &Message,
        resp_bytes: Vec<u8>,
        info_code: u16,
        extra_text: Option<&str>,
    ) -> Vec<u8> {
        if !self.ede_enabled.load(Ordering::Relaxed) {
            return resp_bytes;
        }
        attach_ede_to_wire(request, resp_bytes, info_code, extra_text)
    }

    pub(crate) fn finalize_protocol_response(
        &self,
        request: &Message,
        ctx: &QueryContext,
        meta: &LogMeta,
        cookie_check: CookieCheck,
        mut resp_bytes: Vec<u8>,
    ) -> Vec<u8> {
        match cookie_check {
            CookieCheck::Valid { client_cookie }
            | CookieCheck::NeedsServerCookie { client_cookie } => {
                resp_bytes = self.dns_cookies.attach_cookie_to_wire(
                    resp_bytes,
                    client_cookie,
                    ctx.client_addr.ip(),
                );
            }
            CookieCheck::None | CookieCheck::Malformed => {}
        }

        if ctx.protocol == QueryProtocol::Udp {
            let category = classify_response_category(&resp_bytes);
            let mut force_tc = false;
            match self.rrl.check(ctx.client_addr.ip(), &meta.domain, category) {
                RrlDecision::Drop => return Vec::new(),
                RrlDecision::Slip => force_tc = true,
                RrlDecision::Allow => {}
            }
            let max_udp = effective_udp_payload_limit(
                request,
                self.max_udp_payload_size.load(Ordering::Relaxed),
            );
            resp_bytes = truncate_dns_response(request, resp_bytes, max_udp, force_tc);
        }

        resp_bytes
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn finalize_upstream_response(
        &self,
        request: &Message,
        meta: &LogMeta,
        policy: Option<&ResolvedClientPolicy>,
        upstream: &UpstreamPool,
        _is_local_route: bool,
        decision: &FilterDecision,
        flags: PolicyFlags,
        resp_bytes: Vec<u8>,
        upstream_label: String,
        parsed_msg: Option<Message>,
    ) -> Result<Vec<u8>> {
        if !flags.blocking_disabled
            && !flags.explicitly_allowed
            && flags.dns_rebinding_on
            && parsed_msg.as_ref().is_some_and(contains_rebinding_ip_msg)
        {
            let (blocked_bytes, rcode) =
                build_blocked_response(request, meta.qtype, flags.block_mode)?;
            let blocked_bytes = self.maybe_attach_ede(
                request,
                blocked_bytes,
                EDE_PROHIBITED,
                Some("DNS rebinding protection"),
            );
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
            && let Some(ref msg) = parsed_msg
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

        self.post_process_and_log(
            request,
            meta,
            upstream,
            flags,
            resp_bytes,
            parsed_msg,
            QueryOutcome::Forwarded,
            decision.matched_rule.clone(),
            decision.matched_list.clone(),
            upstream_label,
        )
        .await
    }
}
