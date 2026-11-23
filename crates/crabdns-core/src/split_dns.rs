use std::path::Path;
use std::sync::Arc;

use crate::config::{CompiledUpstreamPolicy, SplitDnsRule, UpstreamStrategy};
use crate::error::{CoreError, Result};
use crate::split_dns_trie::{SplitDomainTrie, SplitDomainTrieBuilder};
use crate::upstream::UpstreamPool;

struct SplitRoute {
    suffix: Option<String>,
    trie: SplitDomainTrie,
    pool: Arc<UpstreamPool>,
    policy: Arc<CompiledUpstreamPolicy>,
    scope: String,
    fallback_to_default: bool,
}

impl SplitRoute {
    fn matches(&self, domain: &str) -> bool {
        if let Some(suffix) = &self.suffix
            && matches_suffix(domain, suffix)
        {
            return true;
        }
        self.trie.matches(domain)
    }

    fn specificity(&self) -> usize {
        self.suffix.as_ref().map_or(0, String::len)
    }
}

#[derive(Default)]
pub struct SplitUpstreamRouter {
    routes: Vec<SplitRoute>,
}

impl SplitUpstreamRouter {
    pub fn empty() -> Self {
        Self { routes: Vec::new() }
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
        let mut routes = Vec::with_capacity(rules.len());
        for (idx, rule) in rules.iter().enumerate() {
            routes.push(build_split_route(
                idx,
                rule,
                timeout_ms,
                strategy,
                bootstrap_dns,
                &resolve_url,
            )?);
        }

        // Longest explicit suffix first; list-based routes follow in configured order.
        routes.sort_by_key(|a| std::cmp::Reverse(a.specificity()));

        Ok(Self { routes })
    }

    pub fn resolve(&self, domain: &str) -> Option<Arc<UpstreamPool>> {
        self.resolve_with_policy(domain).map(|(pool, _, _)| pool)
    }

    pub fn resolve_with_policy(
        &self,
        domain: &str,
    ) -> Option<(Arc<UpstreamPool>, Arc<CompiledUpstreamPolicy>, String)> {
        if self.routes.is_empty() {
            return None;
        }
        let normalized = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if normalized.is_empty() {
            return None;
        }

        for route in &self.routes {
            if route.matches(&normalized) {
                if route.fallback_to_default && !route.pool.has_healthy_endpoint() {
                    continue;
                }
                return Some((
                    Arc::clone(&route.pool),
                    Arc::clone(&route.policy),
                    route.scope.clone(),
                ));
            }
        }
        None
    }

    pub fn pools(&self) -> Vec<Arc<UpstreamPool>> {
        self.routes
            .iter()
            .map(|route| Arc::clone(&route.pool))
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

fn build_split_route<F>(
    idx: usize,
    rule: &SplitDnsRule,
    timeout_ms: u64,
    strategy: UpstreamStrategy,
    bootstrap_dns: &[String],
    resolve_url: &F,
) -> Result<SplitRoute>
where
    F: Fn(&str) -> Option<String>,
{
    let suffix_raw = normalize_suffix(&rule.domain);
    let suffix = (!suffix_raw.is_empty()).then_some(suffix_raw);

    let mut builder = SplitDomainTrieBuilder::default();
    let mut has_list_source = false;

    if let Some(path) = rule
        .domains_file
        .as_deref()
        .map(str::trim)
        .filter(|p| !p.is_empty())
    {
        has_list_source = true;
        let content = std::fs::read_to_string(Path::new(path)).map_err(|err| {
            CoreError::Config(format!(
                "failed to read split_dns domains_file '{path}': {err}"
            ))
        })?;
        insert_domains_into_trie(&content, &mut builder);
    }

    if let Some(url) = rule
        .domains_url
        .as_deref()
        .map(str::trim)
        .filter(|u| !u.is_empty())
    {
        has_list_source = true;
        if let Some(content) = resolve_url(url) {
            insert_domains_into_trie(&content, &mut builder);
        }
    }

    let trie = builder.freeze();
    if suffix.is_none() && !has_list_source {
        return Err(CoreError::Config(
            "split_dns rule must specify domain, domains_file, or domains_url".to_string(),
        ));
    }
    if rule.upstreams.is_empty() {
        let label = suffix.as_deref().unwrap_or("split_dns_list");
        return Err(CoreError::Config(format!(
            "split_dns rule for '{label}' must specify at least one upstream"
        )));
    }
    let compiled_policy = Arc::new(CompiledUpstreamPolicy::compile(&rule.policy)?);
    let effective_timeout = compiled_policy.upstream_timeout_ms.unwrap_or(timeout_ms);
    let effective_strategy = compiled_policy.upstream_strategy.unwrap_or(strategy);
    let pool = Arc::new(UpstreamPool::new_with_bootstrap(
        &rule.upstreams,
        effective_timeout,
        effective_strategy,
        bootstrap_dns,
    )?);
    Ok(SplitRoute {
        suffix,
        trie,
        pool,
        policy: compiled_policy,
        scope: format!("split:{idx}"),
        fallback_to_default: rule.fallback_to_default,
    })
}

/// Parses domain list lines (`example.com`, `*.example.com`, `domain:example.com`,
/// `full:example.com`, `||example.com^`, or dnsmasq `server=/example.com/...`)
/// and inserts them into `builder`.
pub(crate) fn insert_domains_into_trie(content: &str, builder: &mut SplitDomainTrieBuilder) {
    for raw_line in content.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("full:") {
            let domain = normalize_suffix(rest);
            if !domain.is_empty() {
                builder.insert(&domain, true);
            }
            continue;
        }
        if let Some(domain) = parse_suffix_line(line) {
            builder.insert(&domain, false);
        }
    }
}

fn parse_suffix_line(line: &str) -> Option<String> {
    let candidate = if let Some(rest) = line.strip_prefix("domain:") {
        rest
    } else if let Some(rest) = line.strip_prefix("server=/") {
        rest.split('/').next().unwrap_or("")
    } else if let Some(rest) = line.strip_prefix("||") {
        rest.trim_end_matches('^')
    } else {
        line
    };
    let norm = normalize_suffix(candidate);
    (!norm.is_empty()).then_some(norm)
}

fn normalize_suffix(raw: &str) -> String {
    raw.trim()
        .trim_start_matches("*.")
        .trim_start_matches('.')
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

fn matches_suffix(domain: &str, suffix: &str) -> bool {
    if domain == suffix {
        return true;
    }
    domain
        .strip_suffix(suffix)
        .is_some_and(|prefix| prefix.ends_with('.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_dns_longest_suffix_match() {
        let rules = vec![
            SplitDnsRule {
                domain: "local".to_string(),
                domains_file: None,
                domains_url: None,
                upstreams: vec!["udp://192.168.1.1:53".to_string()],
                fallback_to_default: true,
                policy: Default::default(),
            },
            SplitDnsRule {
                domain: "*.corp.local".to_string(),
                domains_file: None,
                domains_url: None,
                upstreams: vec!["udp://10.0.0.1:53".to_string()],
                fallback_to_default: true,
                policy: Default::default(),
            },
        ];

        let router =
            SplitUpstreamRouter::new(&rules, 1000, UpstreamStrategy::Failover).expect("valid");
        assert!(router.resolve("nas.local").is_some());
        assert!(router.resolve("api.corp.local").is_some());
        assert!(router.resolve("notlocal").is_none());
        assert!(router.resolve("example.com").is_none());

        let corp_pool = router.resolve("db.corp.local").expect("corp match");
        assert_eq!(corp_pool.health_snapshot()[0].endpoint, "udp://10.0.0.1:53");

        let local_pool = router.resolve("printer.local").expect("local match");
        assert_eq!(
            local_pool.health_snapshot()[0].endpoint,
            "udp://192.168.1.1:53"
        );
    }

    #[test]
    fn test_split_dns_domains_file_and_url_resolver() {
        let dir = tempfile::tempdir().expect("tempdir");
        let list_path = dir.path().join("cn-domains.txt");
        std::fs::write(
            &list_path,
            "# CN domains\ndomain:cn\n*.qq.com\n||bilibili.com^\nfull:exact.example.org\n",
        )
        .expect("write list");

        let rules = vec![
            SplitDnsRule {
                domain: String::new(),
                domains_file: Some(list_path.display().to_string()),
                domains_url: None,
                upstreams: vec!["udp://223.5.5.5:53".to_string()],
                fallback_to_default: true,
                policy: Default::default(),
            },
            SplitDnsRule {
                domain: String::new(),
                domains_file: None,
                domains_url: Some("https://example.invalid/cn.txt".to_string()),
                upstreams: vec!["udp://119.29.29.29:53".to_string()],
                fallback_to_default: true,
                policy: Default::default(),
            },
        ];
        let router = SplitUpstreamRouter::new_with_resolver(
            &rules,
            1000,
            UpstreamStrategy::Failover,
            &[],
            |url| {
                (url == "https://example.invalid/cn.txt")
                    .then(|| "server=/taobao.com/223.5.5.5\n".to_string())
            },
        )
        .expect("valid");
        assert!(router.resolve("gov.cn").is_some());
        assert!(router.resolve("news.qq.com").is_some());
        assert!(router.resolve("api.bilibili.com").is_some());
        assert!(router.resolve("www.taobao.com").is_some());
        assert!(router.resolve("exact.example.org").is_some());
        assert!(router.resolve("sub.exact.example.org").is_none());
        assert!(router.resolve("google.com").is_none());
    }
}
