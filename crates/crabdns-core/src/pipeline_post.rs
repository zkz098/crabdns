use std::sync::atomic::Ordering;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::RecordType;

use crate::clients::ResolvedClientPolicy;
use crate::dns64::{build_dns64_response, needs_dns64_synthesis};
use crate::error::Result;
use crate::filter_rules::RewriteAction;
use crate::pipeline::{DnsPipeline, QueryOutcome};
use crate::pipeline_types::LogMeta;
use crate::safesearch::match_safesearch;
use crate::svcb::sanitize_svcb_bytes;
use crate::upstream::UpstreamPool;
use crate::wire::{build_rewrite_response, extract_answer_summaries, extract_answer_summaries_msg};

impl DnsPipeline {
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

    pub(crate) fn maybe_sanitize_svcb(
        &self,
        qtype: RecordType,
        resp_bytes: Vec<u8>,
        parsed_msg: Option<Message>,
    ) -> (Vec<u8>, Option<Message>) {
        if !matches!(qtype, RecordType::HTTPS | RecordType::SVCB) {
            return (resp_bytes, parsed_msg);
        }
        let opts = self.svcb_sanitize_options();
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
        resp_bytes: Vec<u8>,
        parsed_msg: Option<Message>,
    ) -> Result<(Vec<u8>, Option<Message>, bool)> {
        if meta.qtype != RecordType::AAAA {
            return Ok((resp_bytes, parsed_msg, false));
        }
        let dns64 = self.dns64.load();
        if !dns64.enabled || dns64.prefixes.is_empty() {
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

    pub(crate) fn svcb_sanitization_enabled(&self) -> bool {
        self.svcb_strip_ech.load(Ordering::Relaxed) || self.svcb_strip_hints.load(Ordering::Relaxed)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn post_process_and_log(
        &self,
        request: &Message,
        meta: &LogMeta,
        upstream: &UpstreamPool,
        resp_bytes: Vec<u8>,
        parsed_msg: Option<Message>,
        base_outcome: QueryOutcome,
        matched_rule: Option<String>,
        matched_list: Option<String>,
        upstream_source: String,
    ) -> Result<Vec<u8>> {
        let (resp_bytes, parsed_msg) = if self.svcb_sanitization_enabled() {
            self.maybe_sanitize_svcb(meta.qtype, resp_bytes, parsed_msg)
        } else {
            (resp_bytes, parsed_msg)
        };
        let (resp_bytes, parsed_msg, dns64_synth) =
            if self.dns64_enabled() && meta.qtype == RecordType::AAAA {
                self.maybe_synthesize_dns64(request, meta, upstream, resp_bytes, parsed_msg)
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

        self.emit_log(
            meta,
            if dns64_synth {
                QueryOutcome::Rewritten
            } else {
                base_outcome
            },
            if dns64_synth {
                Some("dns64:synth".to_string())
            } else {
                matched_rule
            },
            if dns64_synth {
                Some("dns64".to_string())
            } else {
                matched_list
            },
            Some(upstream_source),
            &rcode_str,
            answers,
        );
        Ok(resp_bytes)
    }
}
