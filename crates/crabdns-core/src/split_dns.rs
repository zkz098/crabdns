use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::ops::ControlFlow;
use std::path::Path;
use std::sync::Arc;

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::RecordType;

use crate::acl::IpNet;
use crate::config::{
    CompiledUpstreamPolicy, ResponseIpRule, SplitDnsMatchMode, SplitDnsRule, UpstreamStrategy,
};
use crate::error::{CoreError, Result};
use crate::ip_set::{IpSet, build_response_ip_set, extract_response_cnames, extract_response_ips};
use crate::pipeline_types::QueryProtocol;
use crate::split_dns_config::{normalize_str_list, parse_qtypes};
use crate::split_dns_trie::{
    NonTrieMatcher, NonTrieMatcherBuilder, RouteBitset, ScoredCandidates, UnifiedSplitTrie,
    UnifiedSplitTrieBuilder, insert_domains_into_route, matches_suffix_ci, normalize_suffix,
};
use crate::upstream::UpstreamPool;
use crate::upstream_groups::{Fnv64, UpstreamGroupRegistry, hash_pool_and_policy};

#[derive(Debug, Clone)]
pub struct SplitQueryContext<'a> {
    pub domain: &'a str,
    pub qtype: RecordType,
    pub client_ip: Option<IpAddr>,
    pub protocol: Option<QueryProtocol>,
    pub client_group_id: Option<&'a str>,
    pub client_group_name: Option<&'a str>,
    pub client_tags: &'a [String],
}

impl<'a> SplitQueryContext<'a> {
    pub fn domain_only(domain: &'a str) -> Self {
        Self {
            domain,
            qtype: RecordType::A,
            client_ip: None,
            protocol: None,
            client_group_id: None,
            client_group_name: None,
            client_tags: &[],
        }
    }
}

#[derive(Clone)]
pub struct RouteTarget {
    pub pool: Arc<UpstreamPool>,
    pub policy: Arc<CompiledUpstreamPolicy>,
    pub is_local_route: bool,
    pub scope: String,
}

#[derive(Clone)]
pub struct CompiledResponseIpRule {
    pub ip_set: IpSet,
    pub invert: bool,
    pub cname_suffixes: Vec<String>,
    pub fallback_delay_ms: Option<u64>,
    pub fallback_on_empty: bool,
    pub fallback_target: Option<RouteTarget>,
}

impl CompiledResponseIpRule {
    pub fn accepts(&self, msg: &Message, qtype: RecordType, fallback_on_nxdomain: bool) -> bool {
        if msg.response_code == ResponseCode::NXDomain && fallback_on_nxdomain {
            return false;
        }
        if !self.cname_suffixes.is_empty() {
            let cnames = extract_response_cnames(msg);
            if cnames
                .iter()
                .any(|c| self.cname_suffixes.iter().any(|s| matches_suffix_ci(c, s)))
            {
                return !self.invert;
            }
        }

        let ips = extract_response_ips(msg);
        if ips.is_empty() {
            let is_ip_qtype = matches!(
                qtype,
                RecordType::A | RecordType::AAAA | RecordType::HTTPS | RecordType::SVCB
            );
            if !is_ip_qtype {
                return true;
            }
            return !self.fallback_on_empty;
        }

        if self.ip_set.is_empty() {
            return true;
        }
        let any_match = ips.iter().any(|ip| self.ip_set.contains(*ip));
        if self.invert { !any_match } else { any_match }
    }
}

#[derive(Clone)]
pub struct SplitRoutePlan {
    pub primary: RouteTarget,
    pub fallbacks: Vec<RouteTarget>,
    pub fallback_to_default: bool,
    pub fallback_on_nxdomain: bool,
    pub response_ip: Option<Arc<CompiledResponseIpRule>>,
    pub rule_name: Option<String>,
}

pub(crate) struct FastSplitMatch<'a> {
    pub target: &'a RouteTarget,
    pub fallback_to_default: bool,
}

struct SplitRoute {
    non_trie: NonTrieMatcher,
    qtypes: Vec<RecordType>,
    client_cidrs: Vec<IpNet>,
    client_groups: Vec<String>,
    client_tags: Vec<String>,
    protocols: Vec<QueryProtocol>,
    primary: RouteTarget,
    explicit_fallbacks: Vec<RouteTarget>,
    fallback_to_default: bool,
    fallback_on_nxdomain: bool,
    response_ip: Option<Arc<CompiledResponseIpRule>>,
    rule_name: Option<String>,
}

impl SplitRoute {
    fn matches_non_domain_context(&self, ctx: &SplitQueryContext<'_>) -> bool {
        if !self.qtypes.is_empty() && !self.qtypes.contains(&ctx.qtype) {
            return false;
        }
        if !self.protocols.is_empty() && !ctx.protocol.is_some_and(|p| self.protocols.contains(&p))
        {
            return false;
        }
        if !self.client_cidrs.is_empty()
            && !ctx
                .client_ip
                .is_some_and(|ip| self.client_cidrs.iter().any(|net| net.contains(ip)))
        {
            return false;
        }
        if !self.client_groups.is_empty() {
            let matched_gid = ctx.client_group_id.is_some_and(|id| {
                self.client_groups
                    .iter()
                    .any(|g| g.eq_ignore_ascii_case(id))
            });
            let matched_gname = ctx.client_group_name.is_some_and(|name| {
                self.client_groups
                    .iter()
                    .any(|g| g.eq_ignore_ascii_case(name))
            });
            if !(matched_gid || matched_gname) {
                return false;
            }
        }
        if !self.client_tags.is_empty()
            && !self
                .client_tags
                .iter()
                .any(|req| ctx.client_tags.iter().any(|t| t.eq_ignore_ascii_case(req)))
        {
            return false;
        }
        true
    }
}

#[derive(Default)]
pub struct SplitUpstreamRouter {
    match_mode: SplitDnsMatchMode,
    trie: UnifiedSplitTrie,
    routes: Box<[SplitRoute]>,
    non_trie_positive_routes: Box<[u32]>,
}

impl SplitUpstreamRouter {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn new(
        rules: &[SplitDnsRule],
        timeout_ms: u64,
        strategy: UpstreamStrategy,
    ) -> Result<Self> {
        Self::new_with_bootstrap(rules, timeout_ms, strategy, &[])
    }

    pub fn new_with_bootstrap(
        rules: &[SplitDnsRule],
        timeout_ms: u64,
        strategy: UpstreamStrategy,
        bootstrap_dns: &[String],
    ) -> Result<Self> {
        Self::new_with_resolver(rules, timeout_ms, strategy, bootstrap_dns, |_| None)
    }

    /// Builds a split-DNS router, resolving any `domains_url` entries via `resolve_url`.
    pub fn new_with_resolver<F>(
        rules: &[SplitDnsRule],
        timeout_ms: u64,
        strategy: UpstreamStrategy,
        bootstrap_dns: &[String],
        resolve_url: F,
    ) -> Result<Self>
    where
        F: Fn(&str) -> Option<String>,
    {
        Self::new_full(
            rules,
            &UpstreamGroupRegistry::empty(),
            SplitDnsMatchMode::SpecificityFirst,
            timeout_ms,
            strategy,
            bootstrap_dns,
            resolve_url,
        )
    }

    /// Builds a split-DNS router with named upstream groups, match mode, and remote list resolver.
    pub fn new_full<F>(
        rules: &[SplitDnsRule],
        groups: &UpstreamGroupRegistry,
        match_mode: SplitDnsMatchMode,
        timeout_ms: u64,
        strategy: UpstreamStrategy,
        bootstrap_dns: &[String],
        resolve_url: F,
    ) -> Result<Self>
    where
        F: Fn(&str) -> Option<String>,
    {
        let mut trie_builder = UnifiedSplitTrieBuilder::default();
        let mut routes = Vec::with_capacity(rules.len());
        let mut non_trie_positive_routes = Vec::new();

        for rule in rules {
            if !rule.enabled {
                continue;
            }
            let route_idx = u32::try_from(routes.len()).unwrap_or(u32::MAX);
            let (route, has_non_trie_pos) = build_split_route(
                rule,
                route_idx,
                &mut trie_builder,
                groups,
                timeout_ms,
                strategy,
                bootstrap_dns,
                &resolve_url,
            )?;
            if has_non_trie_pos {
                non_trie_positive_routes.push(route_idx);
            }
            routes.push(route);
        }

        Ok(Self {
            match_mode,
            trie: trie_builder.freeze(),
            routes: routes.into_boxed_slice(),
            non_trie_positive_routes: non_trie_positive_routes.into_boxed_slice(),
        })
    }

    pub fn resolve(&self, domain: &str) -> Option<Arc<UpstreamPool>> {
        let ctx = SplitQueryContext::domain_only(domain);
        self.resolve_fast(&ctx).map(|m| Arc::clone(&m.target.pool))
    }

    pub fn resolve_with_policy(
        &self,
        domain: &str,
    ) -> Option<(Arc<UpstreamPool>, Arc<CompiledUpstreamPolicy>, String)> {
        let ctx = SplitQueryContext::domain_only(domain);
        self.resolve_fast(&ctx).map(|m| {
            (
                Arc::clone(&m.target.pool),
                Arc::clone(&m.target.policy),
                m.target.scope.clone(),
            )
        })
    }

    pub(crate) fn resolve_fast<'a>(
        &'a self,
        ctx: &SplitQueryContext<'_>,
    ) -> Option<FastSplitMatch<'a>> {
        let clean = ctx.domain.trim().trim_end_matches('.');
        if clean.is_empty() || self.routes.is_empty() {
            return None;
        }

        let mut first_route: Option<&SplitRoute> = None;
        let mut healthy_target: Option<&RouteTarget> = None;

        self.match_routes(ctx, clean, |route| {
            if first_route.is_some() {
                if route.primary.pool.has_healthy_endpoint() {
                    healthy_target = Some(&route.primary);
                    return ControlFlow::Break(());
                }
                return if route.fallback_to_default {
                    ControlFlow::Continue(())
                } else {
                    ControlFlow::Break(())
                };
            }

            first_route = Some(route);
            if route.primary.pool.has_healthy_endpoint() {
                healthy_target = Some(&route.primary);
                return ControlFlow::Break(());
            }
            if let Some(fb) = route
                .explicit_fallbacks
                .iter()
                .find(|f| f.pool.has_healthy_endpoint())
            {
                healthy_target = Some(fb);
                return ControlFlow::Break(());
            }
            if route.fallback_to_default {
                ControlFlow::Continue(())
            } else {
                ControlFlow::Break(())
            }
        });

        let first = first_route?;
        Some(FastSplitMatch {
            target: healthy_target.unwrap_or(&first.primary),
            fallback_to_default: first.fallback_to_default,
        })
    }

    pub fn resolve_plan(&self, ctx: &SplitQueryContext<'_>) -> Option<SplitRoutePlan> {
        let clean = ctx.domain.trim().trim_end_matches('.');
        if clean.is_empty() || self.routes.is_empty() {
            return None;
        }

        let mut first_route: Option<&SplitRoute> = None;
        let mut fallbacks = Vec::new();

        self.match_routes(ctx, clean, |route| {
            if first_route.is_some() {
                fallbacks.push(route.primary.clone());
                return if route.fallback_to_default {
                    ControlFlow::Continue(())
                } else {
                    ControlFlow::Break(())
                };
            }
            first_route = Some(route);
            fallbacks.extend(route.explicit_fallbacks.iter().cloned());
            if route.fallback_to_default {
                ControlFlow::Continue(())
            } else {
                ControlFlow::Break(())
            }
        });

        let first = first_route?;
        let mut primary = first.primary.clone();
        let mut response_ip = first.response_ip.clone();
        if !primary.pool.has_healthy_endpoint()
            && let Some(healthy_pos) = fallbacks.iter().position(|f| f.pool.has_healthy_endpoint())
        {
            let promoted = fallbacks.remove(healthy_pos);
            fallbacks.push(primary);
            primary = promoted;
            if response_ip.is_some() {
                response_ip = None;
            }
        }

        Some(SplitRoutePlan {
            primary,
            fallbacks,
            fallback_to_default: first.fallback_to_default,
            fallback_on_nxdomain: first.fallback_on_nxdomain,
            response_ip,
            rule_name: first.rule_name.clone(),
        })
    }

    fn match_routes<'a, F>(&'a self, ctx: &SplitQueryContext<'_>, clean: &str, mut on_match: F)
    where
        F: FnMut(&'a SplitRoute) -> ControlFlow<()>,
    {
        let route_count = self.routes.len();
        match self.match_mode {
            SplitDnsMatchMode::ConfigOrder => {
                let mut pos = RouteBitset::new(route_count);
                let mut excl = RouteBitset::new(route_count);
                self.trie.collect_config_order(clean, &mut pos, &mut excl);
                for &ridx in &self.non_trie_positive_routes {
                    if !pos.contains(ridx)
                        && !excl.contains(ridx)
                        && self.routes[ridx as usize].non_trie.matches_positive(clean)
                    {
                        pos.set(ridx);
                    }
                }
                for ridx in pos.iter_excluding(&excl) {
                    let route = &self.routes[ridx as usize];
                    if route.matches_non_domain_context(ctx)
                        && !route.non_trie.matches_exclude(clean)
                        && on_match(route).is_break()
                    {
                        break;
                    }
                }
            }
            SplitDnsMatchMode::SpecificityFirst => {
                let mut candidates = ScoredCandidates::new();
                let mut excl = RouteBitset::new(route_count);
                self.trie
                    .collect_specificity_first(clean, &mut candidates, &mut excl);
                for &ridx in &self.non_trie_positive_routes {
                    if !excl.contains(ridx)
                        && self.routes[ridx as usize].non_trie.matches_positive(clean)
                    {
                        candidates.insert_max(ridx, 0);
                    }
                }
                for &(ridx, _score) in candidates.sort_excluding(&excl) {
                    let route = &self.routes[ridx as usize];
                    if route.matches_non_domain_context(ctx)
                        && !route.non_trie.matches_exclude(clean)
                        && on_match(route).is_break()
                    {
                        break;
                    }
                }
            }
        }
    }

    pub fn pools(&self) -> Vec<Arc<UpstreamPool>> {
        self.routes
            .iter()
            .map(|route| Arc::clone(&route.primary.pool))
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

#[allow(clippy::too_many_arguments)]
fn build_split_route<F>(
    rule: &SplitDnsRule,
    route_idx: u32,
    trie: &mut UnifiedSplitTrieBuilder,
    groups: &UpstreamGroupRegistry,
    timeout_ms: u64,
    strategy: UpstreamStrategy,
    bootstrap_dns: &[String],
    resolve_url: &F,
) -> Result<(SplitRoute, bool)>
where
    F: Fn(&str) -> Option<String>,
{
    let (non_trie, has_non_trie_pos, has_target) =
        compile_rule_matcher(rule, route_idx, trie, resolve_url)?;
    if !has_target {
        return Err(CoreError::Config(
            "split_dns rule must specify domain, domains_file, or domains_url".to_string(),
        ));
    }
    if rule.upstreams.is_empty() {
        let label = rule
            .name
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| {
                if rule.domain.trim().is_empty() {
                    "split_dns_list"
                } else {
                    rule.domain.trim()
                }
            });
        return Err(CoreError::Config(format!(
            "split_dns rule for '{label}' must specify at least one upstream"
        )));
    }

    let rule_policy = CompiledUpstreamPolicy::compile(&rule.policy)?;
    let resolved = groups.resolve_specs_pool(
        &rule.upstreams,
        &rule_policy,
        timeout_ms,
        strategy,
        bootstrap_dns,
    )?;
    let is_local_route = rule.is_local.unwrap_or(resolved.is_local);

    let qtypes = parse_qtypes(&rule.qtypes)?;
    let client_cidrs = crate::acl::parse_cidr_list(&rule.client_cidrs)?;
    let client_groups = normalize_str_list(&rule.client_groups);
    let client_tags = normalize_str_list(&rule.client_tags);
    let protocols = rule.protocols.clone();

    let explicit_fallbacks = build_fallback_targets(
        &rule.fallback_upstreams,
        &resolved.fallback_groups,
        groups,
        timeout_ms,
        strategy,
        bootstrap_dns,
    )?;

    let response_ip = build_response_ip_rule(
        rule.response_ip.as_ref(),
        groups,
        timeout_ms,
        strategy,
        bootstrap_dns,
        resolve_url,
    )?;

    let scope_fp = compute_route_scope_fp(
        resolved.fingerprint,
        is_local_route,
        rule,
        &explicit_fallbacks,
    );
    let primary = RouteTarget {
        pool: resolved.pool,
        policy: resolved.policy,
        is_local_route,
        scope: format!("split:{scope_fp:016x}"),
    };

    Ok((
        SplitRoute {
            non_trie,
            qtypes,
            client_cidrs,
            client_groups,
            client_tags,
            protocols,
            primary,
            explicit_fallbacks,
            fallback_to_default: rule.fallback_to_default,
            fallback_on_nxdomain: rule.fallback_on_nxdomain,
            response_ip: response_ip.map(Arc::new),
            rule_name: rule
                .name
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToString::to_string),
        },
        has_non_trie_pos,
    ))
}

fn compile_rule_matcher<F>(
    rule: &SplitDnsRule,
    route_idx: u32,
    trie: &mut UnifiedSplitTrieBuilder,
    resolve_url: &F,
) -> Result<(NonTrieMatcher, bool, bool)>
where
    F: Fn(&str) -> Option<String>,
{
    let mut non_trie = NonTrieMatcherBuilder::default();
    let mut has_target = false;

    let inline_raw = rule.domain.trim();
    if !inline_raw.is_empty() {
        has_target = true;
        for part in inline_raw
            .split([',', '\n'])
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            non_trie.insert_pattern(trie, route_idx, part, false, true)?;
        }
    }

    if let Some(path) = rule
        .domains_file
        .as_deref()
        .map(str::trim)
        .filter(|p| !p.is_empty())
    {
        has_target = true;
        let content = std::fs::read_to_string(Path::new(path)).map_err(|err| {
            CoreError::Config(format!(
                "failed to read split_dns domains_file '{path}': {err}"
            ))
        })?;
        insert_domains_into_route(&content, trie, route_idx, &mut non_trie);
    }

    if let Some(url) = rule
        .domains_url
        .as_deref()
        .map(str::trim)
        .filter(|u| !u.is_empty())
    {
        has_target = true;
        if let Some(content) = resolve_url(url) {
            insert_domains_into_route(&content, trie, route_idx, &mut non_trie);
        }
    }

    for excl in &rule.exclude_domains {
        non_trie.insert_pattern(trie, route_idx, excl, true, true)?;
    }

    let has_non_trie_pos = non_trie.has_positive_non_trie;
    Ok((non_trie.build()?, has_non_trie_pos, has_target))
}

fn build_fallback_targets(
    explicit_upstreams: &[String],
    group_fallbacks: &[String],
    groups: &UpstreamGroupRegistry,
    timeout_ms: u64,
    strategy: UpstreamStrategy,
    bootstrap_dns: &[String],
) -> Result<Vec<RouteTarget>> {
    let mut out = Vec::new();
    let empty_policy = CompiledUpstreamPolicy::default();

    if !explicit_upstreams.is_empty() {
        let all_group_refs = explicit_upstreams.iter().all(|s| s.trim().starts_with('@'));
        if all_group_refs && explicit_upstreams.len() > 1 {
            for spec in explicit_upstreams {
                let resolved = groups.resolve_specs_pool(
                    std::slice::from_ref(spec),
                    &empty_policy,
                    timeout_ms,
                    strategy,
                    bootstrap_dns,
                )?;
                out.push(RouteTarget {
                    pool: resolved.pool,
                    policy: resolved.policy,
                    is_local_route: resolved.is_local,
                    scope: format!("split-fb:{:016x}", resolved.fingerprint),
                });
            }
        } else {
            let resolved = groups.resolve_specs_pool(
                explicit_upstreams,
                &empty_policy,
                timeout_ms,
                strategy,
                bootstrap_dns,
            )?;
            out.push(RouteTarget {
                pool: resolved.pool,
                policy: resolved.policy,
                is_local_route: resolved.is_local,
                scope: format!("split-fb:{:016x}", resolved.fingerprint),
            });
        }
    }

    for g in groups.expand_fallback_chain(group_fallbacks) {
        let fp = hash_pool_and_policy(&g.pool, Some(&g.name), &g.policy);
        out.push(RouteTarget {
            pool: g.pool,
            policy: g.policy,
            is_local_route: g.is_local,
            scope: format!("split-fb:{fp:016x}"),
        });
    }
    Ok(out)
}

fn build_response_ip_rule<F>(
    spec: Option<&ResponseIpRule>,
    groups: &UpstreamGroupRegistry,
    timeout_ms: u64,
    strategy: UpstreamStrategy,
    bootstrap_dns: &[String],
    resolve_url: &F,
) -> Result<Option<CompiledResponseIpRule>>
where
    F: Fn(&str) -> Option<String>,
{
    let Some(rule) = spec.filter(|r| r.is_active()) else {
        return Ok(None);
    };

    let ip_set = build_response_ip_set(
        &rule.expected_cidrs,
        rule.expected_ip_file.as_deref(),
        rule.expected_ip_url.as_deref(),
        resolve_url,
    )?;

    let cname_suffixes = rule
        .match_cname_domains
        .iter()
        .map(|s| normalize_suffix(s))
        .filter(|s| !s.is_empty())
        .collect();

    let fallback_target = if rule.fallback_upstreams.is_empty() {
        None
    } else {
        let resolved = groups.resolve_specs_pool(
            &rule.fallback_upstreams,
            &CompiledUpstreamPolicy::default(),
            timeout_ms,
            strategy,
            bootstrap_dns,
        )?;
        Some(RouteTarget {
            pool: resolved.pool,
            policy: resolved.policy,
            is_local_route: resolved.is_local,
            scope: format!("split-rip:{:016x}", resolved.fingerprint),
        })
    };

    Ok(Some(CompiledResponseIpRule {
        ip_set,
        invert: rule.invert,
        cname_suffixes,
        fallback_delay_ms: rule.fallback_delay_ms.filter(|&ms| ms > 0),
        fallback_on_empty: rule.fallback_on_empty,
        fallback_target,
    }))
}

fn compute_route_scope_fp(
    pool_fp: u64,
    is_local: bool,
    rule: &SplitDnsRule,
    explicit_fallbacks: &[RouteTarget],
) -> u64 {
    let mut h = Fnv64::new();
    pool_fp.hash(&mut h);
    is_local.hash(&mut h);
    rule.fallback_to_default.hash(&mut h);
    rule.fallback_on_nxdomain.hash(&mut h);
    for fb in explicit_fallbacks {
        fb.scope.hash(&mut h);
    }
    if let Some(ref rip) = rule.response_ip
        && rip.is_active()
    {
        true.hash(&mut h);
        rip.invert.hash(&mut h);
        rip.expected_cidrs.hash(&mut h);
        rip.expected_ip_file.hash(&mut h);
        rip.expected_ip_url.hash(&mut h);
        rip.fallback_upstreams.hash(&mut h);
        rip.fallback_delay_ms.hash(&mut h);
        rip.match_cname_domains.hash(&mut h);
        rip.fallback_on_empty.hash(&mut h);
    }
    h.finish()
}
