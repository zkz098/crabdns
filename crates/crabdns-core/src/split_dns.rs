use std::sync::Arc;

use crate::config::{SplitDnsRule, UpstreamStrategy};
use crate::error::{CoreError, Result};
use crate::upstream::UpstreamPool;

#[derive(Clone)]
struct SplitRoute {
    suffix: String,
    pool: Arc<UpstreamPool>,
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
        let mut routes = Vec::with_capacity(rules.len());
        for rule in rules {
            let suffix = normalize_suffix(&rule.domain);
            if suffix.is_empty() {
                return Err(CoreError::Config(
                    "split_dns domain suffix cannot be empty".to_string(),
                ));
            }
            if rule.upstreams.is_empty() {
                return Err(CoreError::Config(format!(
                    "split_dns rule for '{suffix}' must specify at least one upstream"
                )));
            }
            let pool = Arc::new(UpstreamPool::new_with_bootstrap(
                &rule.upstreams,
                timeout_ms,
                strategy,
                bootstrap_dns,
            )?);
            routes.push(SplitRoute { suffix, pool });
        }

        // Longest suffix first so more specific rules take precedence.
        routes.sort_by_key(|a| std::cmp::Reverse(a.suffix.len()));

        Ok(Self { routes })
    }

    pub fn resolve(&self, domain: &str) -> Option<Arc<UpstreamPool>> {
        if self.routes.is_empty() {
            return None;
        }
        let normalized = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if normalized.is_empty() {
            return None;
        }

        for route in &self.routes {
            if matches_suffix(&normalized, &route.suffix) {
                return Some(Arc::clone(&route.pool));
            }
        }
        None
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
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
                upstreams: vec!["udp://192.168.1.1:53".to_string()],
            },
            SplitDnsRule {
                domain: "*.corp.local".to_string(),
                upstreams: vec!["udp://10.0.0.1:53".to_string()],
            },
        ];

        let router =
            SplitUpstreamRouter::new(&rules, 1000, UpstreamStrategy::Failover).expect("valid");
        assert!(router.resolve("nas.local").is_some());
        assert!(router.resolve("api.corp.local").is_some());
        assert!(router.resolve("notlocal").is_none());
        assert!(router.resolve("example.com").is_none());

        // Verify longest match wins (10.0.0.1 for *.corp.local).
        let corp_pool = router.resolve("db.corp.local").expect("corp match");
        let statuses = corp_pool.health_snapshot();
        assert_eq!(statuses[0].endpoint, "udp://10.0.0.1:53");

        let local_pool = router.resolve("printer.local").expect("local match");
        let local_statuses = local_pool.health_snapshot();
        assert_eq!(local_statuses[0].endpoint, "udp://192.168.1.1:53");
    }
}
