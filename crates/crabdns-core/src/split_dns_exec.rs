use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use hickory_proto::op::Message;
use hickory_proto::rr::RecordType;

use crate::clients::ResolvedClientPolicy;
use crate::config::CompiledUpstreamPolicy;
use crate::edns::{EcsConfig, resolve_ecs_subnet};
use crate::lan::is_private_ptr_domain;
use crate::pipeline::{DnsPipeline, QueryProtocol};
use crate::pipeline_exec::{ExchangeError, PolicyFlags};
use crate::pipeline_types::LogMeta;
use crate::split_dns::{CompiledResponseIpRule, RouteTarget, SplitQueryContext};
use crate::upstream::UpstreamPool;

pub(crate) struct FastResolvedRoute {
    pub pool: Arc<UpstreamPool>,
    pub cache_scope: Option<String>,
    pub is_local_route: bool,
    pub upstream_policy: Option<Arc<CompiledUpstreamPolicy>>,
}

pub(crate) struct ResolvedUpstreamRoute {
    pub pool: Arc<UpstreamPool>,
    pub cache_scope: Option<String>,
    pub is_local_route: bool,
    pub upstream_policy: Option<Arc<CompiledUpstreamPolicy>>,
    pub fallbacks: Vec<RouteTarget>,
    pub fallback_on_nxdomain: bool,
    pub response_ip: Option<Arc<CompiledResponseIpRule>>,
}

impl ResolvedUpstreamRoute {
    pub fn query_budget(&self) -> Duration {
        let mut max_budget = self.pool.query_budget();
        for fb in &self.fallbacks {
            max_budget = max_budget.max(fb.pool.query_budget());
        }
        if let Some(ref rip) = self.response_ip
            && let Some(ref fb) = rip.fallback_target
        {
            max_budget = max_budget.max(fb.pool.query_budget());
        }
        if !self.fallbacks.is_empty() || self.response_ip.is_some() {
            max_budget = max_budget
                .saturating_mul(2)
                .clamp(Duration::from_secs(3), Duration::from_secs(30));
        }
        max_budget
    }
}

impl DnsPipeline {
    pub(crate) fn resolve_fast_route_for_query(
        &self,
        client_ip: Option<IpAddr>,
        protocol: Option<QueryProtocol>,
        policy: Option<&ResolvedClientPolicy>,
        domain: &str,
        qtype: RecordType,
    ) -> FastResolvedRoute {
        let split_first = self
            .split_dns_before_client_upstreams
            .load(Ordering::Relaxed);

        if !split_first && let Some(client_route) = build_fast_client_route(policy) {
            return client_route;
        }

        if qtype == RecordType::PTR
            && is_private_ptr_domain(domain)
            && let Some(ref pool) = self.private_ptr_router.load().pool
        {
            return FastResolvedRoute {
                pool: Arc::clone(pool),
                cache_scope: None,
                is_local_route: true,
                upstream_policy: policy.map(|p| Arc::clone(&p.upstream_policy)),
            };
        }

        let fallback_default =
            build_fast_client_route(policy).unwrap_or_else(|| FastResolvedRoute {
                pool: self.upstream.load_full(),
                cache_scope: policy.and_then(|p| p.upstream_policy_scope.clone()),
                is_local_route: false,
                upstream_policy: policy.map(|p| Arc::clone(&p.upstream_policy)),
            });

        let split_router = self.split_router.load();
        if !split_router.is_empty() {
            let empty_tags: &[String] = &[];
            let split_ctx = SplitQueryContext {
                domain,
                qtype,
                client_ip,
                protocol,
                client_group_id: policy.and_then(|p| p.group_id.as_deref()),
                client_group_name: policy.and_then(|p| p.group_name.as_deref()),
                client_tags: policy.map_or(empty_tags, |p| p.tags.as_slice()),
            };
            if let Some(m) = split_router.resolve_fast(&split_ctx) {
                if !m.target.pool.has_healthy_endpoint()
                    && m.fallback_to_default
                    && fallback_default.pool.has_healthy_endpoint()
                {
                    return fallback_default;
                }
                let (merged_policy, cache_scope) = match policy {
                    Some(p) => {
                        let merged = Arc::new(m.target.policy.merge_over(&p.upstream_policy));
                        let scope = match p.upstream_policy_scope.as_deref() {
                            Some(cs) => format!("{}:{cs}", m.target.scope),
                            None => m.target.scope.clone(),
                        };
                        (merged, Some(scope))
                    }
                    None => (Arc::clone(&m.target.policy), Some(m.target.scope.clone())),
                };
                return FastResolvedRoute {
                    pool: Arc::clone(&m.target.pool),
                    cache_scope,
                    is_local_route: m.target.is_local_route,
                    upstream_policy: Some(merged_policy),
                };
            }
        }

        fallback_default
    }

    pub(crate) fn resolve_upstream_for_query(
        &self,
        client_ip: Option<IpAddr>,
        protocol: Option<QueryProtocol>,
        policy: Option<&ResolvedClientPolicy>,
        domain: &str,
        qtype: RecordType,
    ) -> ResolvedUpstreamRoute {
        let split_first = self
            .split_dns_before_client_upstreams
            .load(Ordering::Relaxed);

        if !split_first && let Some(client_route) = build_client_route(policy) {
            return client_route;
        }

        if let Some(ptr_route) = self.resolve_private_ptr_route(policy, domain, qtype) {
            return ptr_route;
        }

        let fallback_default =
            build_client_route(policy).unwrap_or_else(|| self.default_route(policy));
        if let Some(split_route) = self.resolve_split_route(
            client_ip,
            protocol,
            policy,
            domain,
            qtype,
            &fallback_default,
        ) {
            return split_route;
        }

        if split_first && let Some(client_route) = build_client_route(policy) {
            return client_route;
        }

        fallback_default
    }

    fn default_route(&self, policy: Option<&ResolvedClientPolicy>) -> ResolvedUpstreamRoute {
        ResolvedUpstreamRoute {
            pool: self.upstream.load_full(),
            cache_scope: policy.and_then(|p| p.upstream_policy_scope.clone()),
            is_local_route: false,
            upstream_policy: policy.map(|p| Arc::clone(&p.upstream_policy)),
            fallbacks: Vec::new(),
            fallback_on_nxdomain: false,
            response_ip: None,
        }
    }

    fn resolve_private_ptr_route(
        &self,
        policy: Option<&ResolvedClientPolicy>,
        domain: &str,
        qtype: RecordType,
    ) -> Option<ResolvedUpstreamRoute> {
        if qtype != RecordType::PTR || !is_private_ptr_domain(domain) {
            return None;
        }
        let ptr_router = self.private_ptr_router.load();
        let pool = ptr_router.pool.as_ref()?;
        Some(ResolvedUpstreamRoute {
            pool: Arc::clone(pool),
            cache_scope: None,
            is_local_route: true,
            upstream_policy: policy.map(|p| Arc::clone(&p.upstream_policy)),
            fallbacks: Vec::new(),
            fallback_on_nxdomain: false,
            response_ip: None,
        })
    }

    fn resolve_split_route(
        &self,
        client_ip: Option<IpAddr>,
        protocol: Option<QueryProtocol>,
        policy: Option<&ResolvedClientPolicy>,
        domain: &str,
        qtype: RecordType,
        default_route: &ResolvedUpstreamRoute,
    ) -> Option<ResolvedUpstreamRoute> {
        let empty_tags: &[String] = &[];
        let split_ctx = SplitQueryContext {
            domain,
            qtype,
            client_ip,
            protocol,
            client_group_id: policy.and_then(|p| p.group_id.as_deref()),
            client_group_name: policy.and_then(|p| p.group_name.as_deref()),
            client_tags: policy.map_or(empty_tags, |p| p.tags.as_slice()),
        };
        let plan = self.split_router.load().resolve_plan(&split_ctx)?;

        let mut fallbacks = plan.fallbacks;
        if plan.fallback_to_default {
            let default_policy = default_route
                .upstream_policy
                .clone()
                .unwrap_or_else(|| Arc::new(CompiledUpstreamPolicy::default()));
            fallbacks.push(RouteTarget {
                pool: Arc::clone(&default_route.pool),
                policy: default_policy,
                is_local_route: default_route.is_local_route,
                scope: default_route
                    .cache_scope
                    .clone()
                    .unwrap_or_else(|| "default".to_string()),
            });
        }

        let mut primary = plan.primary;
        let mut response_ip = plan.response_ip;
        let mut is_local_route = primary.is_local_route;
        if !primary.pool.has_healthy_endpoint()
            && let Some(pos) = fallbacks.iter().position(|f| f.pool.has_healthy_endpoint())
        {
            let promoted = fallbacks.remove(pos);
            let old_primary = std::mem::replace(&mut primary, promoted);
            fallbacks.push(old_primary);
            is_local_route = primary.is_local_route;
            response_ip = None;
        }

        let (merged_policy, cache_scope) = match policy {
            Some(p) => {
                let merged = Arc::new(primary.policy.merge_over(&p.upstream_policy));
                let scope = match p.upstream_policy_scope.as_deref() {
                    Some(cs) => format!("{}:{cs}", primary.scope),
                    None => primary.scope,
                };
                (merged, Some(scope))
            }
            None => (primary.policy, Some(primary.scope)),
        };

        Some(ResolvedUpstreamRoute {
            pool: primary.pool,
            cache_scope,
            is_local_route,
            upstream_policy: Some(merged_policy),
            fallbacks,
            fallback_on_nxdomain: plan.fallback_on_nxdomain,
            response_ip,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn execute_route_exchange(
        &self,
        route: &ResolvedUpstreamRoute,
        request: &Message,
        raw_query: &[u8],
        primary_query: &[u8],
        meta: &LogMeta,
        base_flags: PolicyFlags,
        primary_flags: PolicyFlags,
        global_ecs: &EcsConfig,
    ) -> std::result::Result<(Vec<u8>, String), ExchangeError> {
        if let Some(ref rip) = route.response_ip {
            return self
                .execute_response_ip_exchange(
                    route,
                    rip,
                    request,
                    raw_query,
                    primary_query,
                    meta,
                    base_flags,
                    primary_flags,
                    global_ecs,
                )
                .await;
        }

        if route.cache_scope.is_none()
            && let Some(recursor) = self.recursor.load_full()
        {
            return recursor
                .query_raw(primary_query)
                .await
                .map_err(|e| ExchangeError::UpstreamFailed(e.to_string()));
        }

        let primary_res = self
            .exchange_and_validate(&route.pool, primary_query, &meta.domain, primary_flags)
            .await;

        let mut fallback_err_resp: Option<(Vec<u8>, String)> = None;
        let mut last_err: Option<ExchangeError> = None;

        match primary_res {
            Ok((bytes, label)) => {
                if !response_triggers_fallback(&bytes, route.fallback_on_nxdomain) {
                    return Ok((bytes, label));
                }
                fallback_err_resp = Some((bytes, label));
            }
            Err(ExchangeError::DnssecBogus(label)) => {
                return Err(ExchangeError::DnssecBogus(label));
            }
            Err(err) => last_err = Some(err),
        }

        if route.fallbacks.is_empty() {
            return match (fallback_err_resp, last_err) {
                (Some(resp), _) => Ok(resp),
                (None, Some(err)) => Err(err),
                (None, None) => Err(ExchangeError::UpstreamFailed(
                    "upstream exchange failed".to_string(),
                )),
            };
        }

        let total_fb = route.fallbacks.len();
        for (idx, fb) in route.fallbacks.iter().enumerate() {
            let is_last = idx + 1 == total_fb;
            match self
                .exchange_for_target(fb, request, raw_query, meta, base_flags, global_ecs)
                .await
            {
                Ok((bytes, label)) => {
                    let check_nx = !is_last && route.fallback_on_nxdomain;
                    if !response_triggers_fallback(&bytes, check_nx) {
                        return Ok((bytes, label));
                    }
                    fallback_err_resp.get_or_insert((bytes, label));
                }
                Err(ExchangeError::DnssecBogus(label)) => {
                    return Err(ExchangeError::DnssecBogus(label));
                }
                Err(err) => last_err = Some(err),
            }
        }

        if let Some(resp) = fallback_err_resp {
            return Ok(resp);
        }
        Err(last_err.unwrap_or_else(|| {
            ExchangeError::UpstreamFailed("all fallback upstreams failed".to_string())
        }))
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_response_ip_exchange(
        &self,
        route: &ResolvedUpstreamRoute,
        rip: &CompiledResponseIpRule,
        request: &Message,
        raw_query: &[u8],
        primary_query: &[u8],
        meta: &LogMeta,
        base_flags: PolicyFlags,
        primary_flags: PolicyFlags,
        global_ecs: &EcsConfig,
    ) -> std::result::Result<(Vec<u8>, String), ExchangeError> {
        let Some(fb_target) = rip
            .fallback_target
            .as_ref()
            .or_else(|| route.fallbacks.first())
        else {
            return self
                .exchange_and_validate(&route.pool, primary_query, &meta.domain, primary_flags)
                .await;
        };

        if let Some(delay_ms) = rip.fallback_delay_ms {
            return self
                .execute_response_ip_hedged(
                    route,
                    rip,
                    fb_target,
                    delay_ms,
                    request,
                    raw_query,
                    primary_query,
                    meta,
                    base_flags,
                    primary_flags,
                    global_ecs,
                )
                .await;
        }

        if route.cache_scope.is_none()
            && let Some(recursor) = self.recursor.load_full()
        {
            return recursor
                .query_raw(primary_query)
                .await
                .map_err(|e| ExchangeError::UpstreamFailed(e.to_string()));
        }

        let primary_res = self
            .exchange_and_validate(&route.pool, primary_query, &meta.domain, primary_flags)
            .await;

        let primary_ok = match primary_res {
            Ok((bytes, label)) => {
                if !response_triggers_fallback(&bytes, route.fallback_on_nxdomain)
                    && response_accepted_by_rule(
                        rip,
                        &bytes,
                        meta.qtype,
                        route.fallback_on_nxdomain,
                    )
                {
                    return Ok((bytes, label));
                }
                Some((bytes, label))
            }
            Err(ExchangeError::DnssecBogus(label)) => {
                return Err(ExchangeError::DnssecBogus(label));
            }
            Err(_) => None,
        };

        match self
            .exchange_for_target(fb_target, request, raw_query, meta, base_flags, global_ecs)
            .await
        {
            Ok((bytes, label)) => Ok((bytes, label)),
            Err(ExchangeError::DnssecBogus(label)) => Err(ExchangeError::DnssecBogus(label)),
            Err(err) => {
                for extra_fb in &route.fallbacks {
                    if std::ptr::eq(extra_fb, fb_target) {
                        continue;
                    }
                    if let Ok((bytes, label)) = self
                        .exchange_for_target(
                            extra_fb, request, raw_query, meta, base_flags, global_ecs,
                        )
                        .await
                        && !response_triggers_fallback(&bytes, false)
                    {
                        return Ok((bytes, label));
                    }
                }
                primary_ok.ok_or(err)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_response_ip_hedged(
        &self,
        route: &ResolvedUpstreamRoute,
        rip: &CompiledResponseIpRule,
        fb_target: &RouteTarget,
        delay_ms: u64,
        request: &Message,
        raw_query: &[u8],
        primary_query: &[u8],
        meta: &LogMeta,
        base_flags: PolicyFlags,
        primary_flags: PolicyFlags,
        global_ecs: &EcsConfig,
    ) -> std::result::Result<(Vec<u8>, String), ExchangeError> {
        let mut primary_fut = Box::pin(self.exchange_and_validate(
            &route.pool,
            primary_query,
            &meta.domain,
            primary_flags,
        ));

        let primary_early = tokio::select! {
            res = &mut primary_fut => Some(res),
            () = tokio::time::sleep(Duration::from_millis(delay_ms)) => None,
        };

        if let Some(res) = primary_early {
            return match res {
                Ok((bytes, label)) => {
                    if !response_triggers_fallback(&bytes, route.fallback_on_nxdomain)
                        && response_accepted_by_rule(
                            rip,
                            &bytes,
                            meta.qtype,
                            route.fallback_on_nxdomain,
                        )
                    {
                        Ok((bytes, label))
                    } else {
                        match self
                            .exchange_for_target(
                                fb_target, request, raw_query, meta, base_flags, global_ecs,
                            )
                            .await
                        {
                            Ok(fb) => Ok(fb),
                            Err(ExchangeError::DnssecBogus(l)) => {
                                Err(ExchangeError::DnssecBogus(l))
                            }
                            Err(_) => Ok((bytes, label)),
                        }
                    }
                }
                Err(ExchangeError::DnssecBogus(l)) => Err(ExchangeError::DnssecBogus(l)),
                Err(_) => {
                    self.exchange_for_target(
                        fb_target, request, raw_query, meta, base_flags, global_ecs,
                    )
                    .await
                }
            };
        }

        let mut fb_fut = Box::pin(
            self.exchange_for_target(fb_target, request, raw_query, meta, base_flags, global_ecs),
        );

        tokio::select! {
            res = &mut primary_fut => match res {
                Ok((bytes, label)) => {
                    if !response_triggers_fallback(&bytes, route.fallback_on_nxdomain)
                        && response_accepted_by_rule(
                            rip,
                            &bytes,
                            meta.qtype,
                            route.fallback_on_nxdomain,
                        )
                    {
                        Ok((bytes, label))
                    } else {
                        match fb_fut.await {
                            Ok(fb) => Ok(fb),
                            Err(ExchangeError::DnssecBogus(l)) => Err(ExchangeError::DnssecBogus(l)),
                            Err(_) => Ok((bytes, label)),
                        }
                    }
                }
                Err(ExchangeError::DnssecBogus(l)) => Err(ExchangeError::DnssecBogus(l)),
                Err(_) => fb_fut.await,
            },
            fb_res = &mut fb_fut => match fb_res {
                Ok((bytes, label)) if !response_triggers_fallback(&bytes, false) => Ok((bytes, label)),
                Err(ExchangeError::DnssecBogus(l)) => Err(ExchangeError::DnssecBogus(l)),
                other_fb => match primary_fut.await {
                    Ok(p) => Ok(p),
                    Err(ExchangeError::DnssecBogus(l)) => Err(ExchangeError::DnssecBogus(l)),
                    Err(perr) => other_fb.or(Err(perr)),
                },
            }
        }
    }

    async fn exchange_for_target(
        &self,
        target: &RouteTarget,
        request: &Message,
        raw_query: &[u8],
        meta: &LogMeta,
        base_flags: PolicyFlags,
        global_ecs: &EcsConfig,
    ) -> std::result::Result<(Vec<u8>, String), ExchangeError> {
        let target_flags = self.apply_upstream_policy_flags(
            base_flags,
            Some(&target.policy),
            target.is_local_route,
        );
        let ecs_cfg = target.policy.resolve_ecs_config(global_ecs);
        let ecs_subnet = resolve_ecs_subnet(&ecs_cfg, meta.client_addr.ip());
        let query_wire =
            Self::build_upstream_query(request, raw_query, ecs_subnet, target_flags.dnssec_on);
        self.exchange_and_validate(&target.pool, &query_wire, &meta.domain, target_flags)
            .await
    }
}

fn build_fast_client_route(policy: Option<&ResolvedClientPolicy>) -> Option<FastResolvedRoute> {
    let p = policy?;
    let (scope, pool) = p.upstream_pool.as_ref()?;
    Some(FastResolvedRoute {
        pool: Arc::clone(pool),
        cache_scope: Some(scope.clone()),
        is_local_route: pool.has_private_endpoint(),
        upstream_policy: Some(Arc::clone(&p.upstream_policy)),
    })
}

fn build_client_route(policy: Option<&ResolvedClientPolicy>) -> Option<ResolvedUpstreamRoute> {
    let p = policy?;
    let (scope, pool) = p.upstream_pool.as_ref()?;
    Some(ResolvedUpstreamRoute {
        pool: Arc::clone(pool),
        cache_scope: Some(scope.clone()),
        is_local_route: pool.has_private_endpoint(),
        upstream_policy: Some(Arc::clone(&p.upstream_policy)),
        fallbacks: Vec::new(),
        fallback_on_nxdomain: false,
        response_ip: None,
    })
}

fn response_triggers_fallback(resp: &[u8], fallback_on_nxdomain: bool) -> bool {
    if resp.len() < 12 {
        return false;
    }
    let rcode = resp[3] & 0x0F;
    matches!(rcode, 1 | 2 | 4 | 5) || (fallback_on_nxdomain && rcode == 3)
}

fn response_accepted_by_rule(
    rip: &CompiledResponseIpRule,
    resp: &[u8],
    qtype: RecordType,
    fallback_on_nxdomain: bool,
) -> bool {
    let Ok(msg) = Message::from_vec(resp) else {
        return false;
    };
    rip.accepts(&msg, qtype, fallback_on_nxdomain)
}
