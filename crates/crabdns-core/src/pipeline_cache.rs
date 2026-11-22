use std::sync::Arc;
use std::sync::atomic::Ordering;

use chrono::Utc;
use hickory_proto::op::Message;
use hickory_proto::rr::{RData, RecordType};

use crate::cache::{CacheKey, DnsCache};
use crate::clients::{ClientRegistry, ResolvedClientPolicy};
use crate::config::BlockMode;
use crate::error::Result;
use crate::filter::FilterAction;
use crate::filter_rules::FilterQueryContext;
use crate::pipeline::{DnsPipeline, QueryEvent, QueryOutcome};
use crate::pipeline_types::LogMeta;
use crate::upstream::UpstreamPool;
use crate::wire::{build_blocked_response, compute_response_cache_ttl};

pub(crate) struct CnameBlock {
    pub bytes: Vec<u8>,
    pub rule: String,
    pub list: Option<String>,
    pub rcode: &'static str,
}

impl DnsPipeline {
    pub(crate) fn check_cname_cloaking_msg(
        &self,
        policy: Option<&ResolvedClientPolicy>,
        meta: &LogMeta,
        request: &Message,
        resp_msg: &Message,
        block_mode: BlockMode,
    ) -> Result<Option<CnameBlock>> {
        let qtype = request
            .queries
            .first()
            .map_or(RecordType::A, hickory_proto::op::Query::query_type);
        let empty_tags: &[String] = &[];
        for answer in &resp_msg.answers {
            if let RData::CNAME(cname) = &answer.data {
                let target = cname.to_utf8();
                let target_clean = target.trim_end_matches('.');
                let ctx = FilterQueryContext {
                    domain: target_clean,
                    qtype: Some(qtype),
                    client_ip: Some(meta.client_addr.ip()),
                    client_id: meta.client_id.as_deref(),
                    client_name: meta.client_name.as_deref(),
                    client_tags: policy.map_or(empty_tags, |p| p.tags.as_slice()),
                };
                let decision =
                    ClientRegistry::evaluate_domain_with_context(policy, &self.filter, &ctx);
                if decision.action == FilterAction::Block {
                    let (bytes, rcode) = build_blocked_response(request, qtype, block_mode)?;
                    let rule = decision
                        .matched_rule
                        .unwrap_or_else(|| format!("cname:{target_clean}"));
                    return Ok(Some(CnameBlock {
                        bytes,
                        rule,
                        list: decision.matched_list,
                        rcode,
                    }));
                }
            }
        }
        Ok(None)
    }

    pub(crate) fn spawn_background_refresh(
        &self,
        upstream: Arc<UpstreamPool>,
        query_wire: Vec<u8>,
        key: CacheKey,
        dnssec_on: bool,
        client_wants_do: bool,
    ) {
        let cache = self.cache.load_full();
        let Ok(permit) = Arc::clone(&self.refresh_limiter).try_acquire_owned() else {
            cache.clear_refresh_inflight(&key);
            return;
        };
        let validator = Arc::clone(&self.dnssec_validator);
        let budget = upstream.query_budget();
        tokio::spawn(async move {
            let _permit = permit;
            let mut guard = RefreshGuard {
                cache,
                key,
                inserted: false,
            };
            let Ok(Ok((mut resp_bytes, _))) =
                tokio::time::timeout(budget, upstream.exchange(&query_wire)).await
            else {
                return;
            };
            if dnssec_on {
                let Ok(Ok(processed)) = tokio::time::timeout(
                    budget,
                    validator.validate_and_process(&resp_bytes, &upstream, client_wants_do),
                )
                .await
                else {
                    return;
                };
                resp_bytes = processed;
            }
            guard.inserted = cache_upstream_response(&guard.cache, guard.key.clone(), &resp_bytes);
        });
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn emit_log(
        &self,
        meta: &LogMeta,
        outcome: QueryOutcome,
        matched_rule: Option<String>,
        matched_list: Option<String>,
        upstream: Option<String>,
        rcode: &str,
        answers: Vec<String>,
    ) {
        let Some(tx) = &self.log_tx else {
            return;
        };
        let elapsed_us = u64::try_from(meta.start.elapsed().as_micros()).unwrap_or(u64::MAX);
        let event = QueryEvent {
            timestamp: Utc::now(),
            client_ip: meta.client_addr.ip().to_string(),
            client_name: meta.client_name.clone(),
            client_id: meta.client_id.clone(),
            profile_id: meta.profile_id.clone(),
            protocol: meta.protocol,
            domain: meta.domain.clone(),
            qtype: meta.qtype.to_string(),
            outcome,
            matched_rule,
            matched_list,
            upstream,
            elapsed_us,
            rcode: rcode.to_string(),
            answers,
        };
        if tx.try_send(event).is_err() {
            self.log_dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

struct RefreshGuard {
    cache: Arc<DnsCache>,
    key: CacheKey,
    inserted: bool,
}

impl Drop for RefreshGuard {
    fn drop(&mut self) {
        if !self.inserted {
            self.cache.clear_refresh_inflight(&self.key);
        }
    }
}

pub(crate) fn cache_upstream_response(cache: &DnsCache, key: CacheKey, resp_bytes: &[u8]) -> bool {
    let Ok(msg) = Message::from_vec(resp_bytes) else {
        return false;
    };
    cache_upstream_response_msg(cache, key, resp_bytes, &msg)
}

pub(crate) fn cache_upstream_response_msg(
    cache: &DnsCache,
    key: CacheKey,
    resp_bytes: &[u8],
    msg: &Message,
) -> bool {
    if let Some(ttl) = compute_response_cache_ttl(msg) {
        cache.insert(key, resp_bytes.to_vec(), ttl);
        true
    } else {
        false
    }
}
