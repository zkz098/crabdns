use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use foldhash::fast::RandomState;

use crate::config::{CompiledUpstreamPolicy, UpstreamGroup, UpstreamStrategy};
use crate::error::{CoreError, Result};
use crate::upstream::UpstreamPool;

const MAX_GROUP_NAME_LEN: usize = 64;

#[derive(Clone)]
pub struct CompiledUpstreamGroup {
    pub name: String,
    pub raw_upstreams: Vec<String>,
    pub proxy_url: Option<String>,
    pub pool: Arc<UpstreamPool>,
    pub policy: Arc<CompiledUpstreamPolicy>,
    pub fallback_groups: Vec<String>,
    pub is_local: bool,
    pub fingerprint: u64,
}

pub struct ResolvedSpecsPool {
    pub pool: Arc<UpstreamPool>,
    pub policy: Arc<CompiledUpstreamPolicy>,
    pub fallback_groups: Vec<String>,
    pub is_local: bool,
    pub fingerprint: u64,
}

#[derive(Default)]
pub struct UpstreamGroupRegistry {
    groups: HashMap<String, CompiledUpstreamGroup, RandomState>,
    order: Vec<String>,
}

impl UpstreamGroupRegistry {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn compile(
        groups: &[UpstreamGroup],
        default_timeout_ms: u64,
        default_strategy: UpstreamStrategy,
        bootstrap_dns: &[String],
    ) -> Result<Self> {
        let mut compiled = HashMap::with_capacity_and_hasher(groups.len(), RandomState::default());
        let mut order = Vec::with_capacity(groups.len());

        for raw_group in groups {
            let g = raw_group.clone().normalized();
            validate_group_name(&g.name)?;
            if compiled.contains_key(&g.name) {
                return Err(CoreError::Config(format!(
                    "duplicate upstream group name '{}'",
                    g.name
                )));
            }
            if g.upstreams.is_empty() {
                return Err(CoreError::Config(format!(
                    "upstream group '{}' must specify at least one upstream",
                    g.name
                )));
            }
            if g.upstreams.iter().any(|u| u.starts_with('@')) {
                return Err(CoreError::Config(format!(
                    "upstream group '{}' cannot reference another @group in upstreams; use fallback_groups instead",
                    g.name
                )));
            }

            let policy = Arc::new(CompiledUpstreamPolicy::compile(&g.policy)?);
            let effective_timeout = policy.upstream_timeout_ms.unwrap_or(default_timeout_ms);
            let effective_strategy = policy.upstream_strategy.unwrap_or(default_strategy);
            let pool = Arc::new(UpstreamPool::new_with_options(
                &g.upstreams,
                effective_timeout,
                effective_strategy,
                bootstrap_dns,
                g.proxy_url.as_deref(),
            )?);
            let is_local = pool.has_private_endpoint();
            let fingerprint = compute_group_fingerprint(&g, &pool);

            order.push(g.name.clone());
            compiled.insert(
                g.name.clone(),
                CompiledUpstreamGroup {
                    name: g.name,
                    raw_upstreams: g.upstreams,
                    proxy_url: g.proxy_url,
                    pool,
                    policy,
                    fallback_groups: g.fallback_groups,
                    is_local,
                    fingerprint,
                },
            );
        }

        for name in &order {
            let group = &compiled[name];
            for fb in &group.fallback_groups {
                if !compiled.contains_key(fb) {
                    return Err(CoreError::Config(format!(
                        "upstream group '{}' references unknown fallback group '{fb}'",
                        group.name
                    )));
                }
            }
        }
        detect_fallback_cycles(&compiled, &order)?;

        Ok(Self {
            groups: compiled,
            order,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    pub fn get(&self, name: &str) -> Option<&CompiledUpstreamGroup> {
        let norm = name.trim().trim_start_matches('@').to_ascii_lowercase();
        self.groups.get(&norm)
    }

    pub fn resolve_group_ref(&self, spec: &str) -> Option<&CompiledUpstreamGroup> {
        let trimmed = spec.trim();
        let name = trimmed.strip_prefix('@')?;
        self.get(name)
    }

    pub fn resolve_specs_pool(
        &self,
        specs: &[String],
        policy: &CompiledUpstreamPolicy,
        default_timeout_ms: u64,
        default_strategy: UpstreamStrategy,
        bootstrap_dns: &[String],
    ) -> Result<ResolvedSpecsPool> {
        if specs.is_empty() {
            return Err(CoreError::Config(
                "at least one upstream DNS server or @group is required".to_string(),
            ));
        }

        if specs.len() == 1
            && let Some(raw_name) = specs[0].trim().strip_prefix('@')
        {
            let group = self.get(raw_name).ok_or_else(|| {
                CoreError::Config(format!("unknown upstream group '@{}'", raw_name.trim()))
            })?;
            let merged_policy = policy.merge_over(&group.policy);
            let can_share_pool =
                policy.upstream_strategy.is_none() && policy.upstream_timeout_ms.is_none();
            let pool = if can_share_pool {
                Arc::clone(&group.pool)
            } else {
                let effective_timeout = merged_policy
                    .upstream_timeout_ms
                    .unwrap_or(default_timeout_ms);
                let effective_strategy =
                    merged_policy.upstream_strategy.unwrap_or(default_strategy);
                Arc::new(UpstreamPool::new_with_options(
                    &group.raw_upstreams,
                    effective_timeout,
                    effective_strategy,
                    bootstrap_dns,
                    group.proxy_url.as_deref(),
                )?)
            };
            let fp = hash_pool_and_policy(&pool, Some(&group.name), &merged_policy);
            return Ok(ResolvedSpecsPool {
                pool,
                policy: Arc::new(merged_policy),
                fallback_groups: group.fallback_groups.clone(),
                is_local: group.is_local,
                fingerprint: fp,
            });
        }

        let mut expanded = Vec::with_capacity(specs.len());
        let mut fallback_groups = Vec::new();
        let mut base_policy: Option<&CompiledUpstreamPolicy> = None;
        let mut proxy_url: Option<String> = None;

        for spec in specs {
            let trimmed = spec.trim();
            if let Some(raw_name) = trimmed.strip_prefix('@') {
                let group = self.get(raw_name).ok_or_else(|| {
                    CoreError::Config(format!("unknown upstream group '@{}'", raw_name.trim()))
                })?;
                expanded.extend(group.raw_upstreams.iter().cloned());
                for fb in &group.fallback_groups {
                    if !fallback_groups.contains(fb) {
                        fallback_groups.push(fb.clone());
                    }
                }
                if base_policy.is_none() {
                    base_policy = Some(&group.policy);
                }
                if let Some(ref g_proxy) = group.proxy_url {
                    if let Some(ref existing) = proxy_url
                        && existing != g_proxy
                    {
                        return Err(CoreError::Config(
                            "cannot combine upstream groups with different proxy_url values"
                                .to_string(),
                        ));
                    }
                    proxy_url = Some(g_proxy.clone());
                }
            } else if !trimmed.is_empty() {
                expanded.push(trimmed.to_string());
            }
        }

        let merged_policy = match base_policy {
            Some(base) => policy.merge_over(base),
            None => policy.clone(),
        };
        let effective_timeout = merged_policy
            .upstream_timeout_ms
            .unwrap_or(default_timeout_ms);
        let effective_strategy = merged_policy.upstream_strategy.unwrap_or(default_strategy);
        let pool = Arc::new(UpstreamPool::new_with_options(
            &expanded,
            effective_timeout,
            effective_strategy,
            bootstrap_dns,
            proxy_url.as_deref(),
        )?);
        let is_local = pool.has_private_endpoint();
        let fp = hash_pool_and_policy(&pool, None, &merged_policy);
        Ok(ResolvedSpecsPool {
            pool,
            policy: Arc::new(merged_policy),
            fallback_groups,
            is_local,
            fingerprint: fp,
        })
    }

    pub fn expand_fallback_chain(&self, start_groups: &[String]) -> Vec<CompiledUpstreamGroup> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        let mut queue: VecDeque<String> = start_groups.iter().cloned().collect();
        while let Some(name) = queue.pop_front() {
            let norm = name.trim().trim_start_matches('@').to_ascii_lowercase();
            if !seen.insert(norm.clone()) {
                continue;
            }
            let Some(group) = self.groups.get(&norm) else {
                continue;
            };
            out.push(group.clone());
            for next in &group.fallback_groups {
                if !seen.contains(next) {
                    queue.push_back(next.clone());
                }
            }
        }
        out
    }

    pub fn pools(&self) -> Vec<(String, Arc<UpstreamPool>)> {
        self.order
            .iter()
            .filter_map(|name| {
                self.groups
                    .get(name)
                    .map(|g| (format!("group:{name}"), Arc::clone(&g.pool)))
            })
            .collect()
    }
}

fn validate_group_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > MAX_GROUP_NAME_LEN {
        return Err(CoreError::Config(format!(
            "upstream group name '{name}' must be 1..={MAX_GROUP_NAME_LEN} characters"
        )));
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(CoreError::Config(format!(
            "upstream group name '{name}' may only contain ASCII letters, digits, '-' or '_'"
        )));
    }
    Ok(())
}

fn detect_fallback_cycles(
    groups: &HashMap<String, CompiledUpstreamGroup, RandomState>,
    order: &[String],
) -> Result<()> {
    let mut state: HashMap<&str, u8, RandomState> =
        HashMap::with_capacity_and_hasher(groups.len(), RandomState::default());
    for name in order {
        if state.get(name.as_str()).copied().unwrap_or(0) == 0 {
            dfs_cycle(name, groups, &mut state)?;
        }
    }
    Ok(())
}

fn dfs_cycle<'a>(
    node: &'a str,
    groups: &'a HashMap<String, CompiledUpstreamGroup, RandomState>,
    state: &mut HashMap<&'a str, u8, RandomState>,
) -> Result<()> {
    state.insert(node, 1);
    if let Some(group) = groups.get(node) {
        for next in &group.fallback_groups {
            match state.get(next.as_str()).copied().unwrap_or(0) {
                1 => {
                    return Err(CoreError::Config(format!(
                        "upstream group fallback cycle detected involving '{node}' -> '{next}'"
                    )));
                }
                0 => dfs_cycle(next, groups, state)?,
                _ => {}
            }
        }
    }
    state.insert(node, 2);
    Ok(())
}

fn compute_group_fingerprint(group: &UpstreamGroup, pool: &UpstreamPool) -> u64 {
    let mut h = Fnv64::new();
    group.name.hash(&mut h);
    group.proxy_url.hash(&mut h);
    group.fallback_groups.hash(&mut h);
    pool.endpoint_labels().hash(&mut h);
    h.finish()
}

pub(crate) fn hash_pool_and_policy(
    pool: &UpstreamPool,
    group_name: Option<&str>,
    policy: &CompiledUpstreamPolicy,
) -> u64 {
    let mut h = Fnv64::new();
    group_name.hash(&mut h);
    pool.endpoint_labels().hash(&mut h);
    (policy.upstream_strategy.map(|s| s as u8)).hash(&mut h);
    policy.upstream_timeout_ms.hash(&mut h);
    policy.dnssec_enabled.hash(&mut h);
    policy.ecs_enabled.hash(&mut h);
    policy.ecs_custom_subnet.hash(&mut h);
    policy.ecs_ipv4_prefix.hash(&mut h);
    policy.ecs_ipv6_prefix.hash(&mut h);
    policy.dns_rebinding_protection.hash(&mut h);
    policy.dns64_enabled.hash(&mut h);
    policy.svcb_strip_ech.hash(&mut h);
    policy.svcb_strip_hints.hash(&mut h);
    policy.cf_cdn_enabled.hash(&mut h);
    policy.disable_ipv6.hash(&mut h);
    h.finish()
}

/// Deterministic FNV-1a 64-bit hasher for stable cache scopes across restarts and rule reorders.
#[derive(Clone, Copy)]
pub(crate) struct Fnv64(u64);

impl Fnv64 {
    pub(crate) const fn new() -> Self {
        Self(0xcbf2_9ce4_8422_2325)
    }
}

impl Default for Fnv64 {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher for Fnv64 {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 ^= u64::from(b);
            self.0 = self.0.wrapping_mul(0x0100_0000_01b3);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_upstream_group_shared_pool_and_fallback_chain() {
        let groups = vec![
            UpstreamGroup {
                name: "cn_dns".to_string(),
                upstreams: vec!["udp://223.5.5.5:53".to_string()],
                fallback_groups: vec!["overseas".to_string()],
                proxy_url: None,
                policy: crate::config::UpstreamPolicy::default(),
            },
            UpstreamGroup {
                name: "overseas".to_string(),
                upstreams: vec!["udp://1.1.1.1:53".to_string()],
                fallback_groups: Vec::new(),
                proxy_url: None,
                policy: crate::config::UpstreamPolicy::default(),
            },
        ];

        let reg = UpstreamGroupRegistry::compile(&groups, 1000, UpstreamStrategy::Failover, &[])
            .expect("valid groups");

        let r1 = reg
            .resolve_specs_pool(
                &["@cn_dns".to_string()],
                &CompiledUpstreamPolicy::default(),
                1000,
                UpstreamStrategy::Failover,
                &[],
            )
            .unwrap();
        let r2 = reg
            .resolve_specs_pool(
                &["@CN_DNS".to_string()],
                &CompiledUpstreamPolicy::default(),
                1000,
                UpstreamStrategy::Failover,
                &[],
            )
            .unwrap();
        assert!(Arc::ptr_eq(&r1.pool, &r2.pool));
        assert!(!r1.is_local);
        assert_eq!(r1.fallback_groups, vec!["overseas".to_string()]);
        assert_eq!(reg.expand_fallback_chain(&r1.fallback_groups).len(), 1);
    }

    #[test]
    fn test_upstream_group_cycle_rejected() {
        let groups = vec![
            UpstreamGroup {
                name: "a".to_string(),
                upstreams: vec!["udp://1.1.1.1:53".to_string()],
                fallback_groups: vec!["b".to_string()],
                ..Default::default()
            },
            UpstreamGroup {
                name: "b".to_string(),
                upstreams: vec!["udp://8.8.8.8:53".to_string()],
                fallback_groups: vec!["a".to_string()],
                ..Default::default()
            },
        ];
        let err = UpstreamGroupRegistry::compile(&groups, 1000, UpstreamStrategy::Failover, &[])
            .err()
            .expect("cycle must fail");
        assert!(err.to_string().contains("cycle"));
    }
}
