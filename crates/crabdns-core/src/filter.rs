use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FilterAction {
    Allow,
    Block,
    Rewrite(IpAddr),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilterDecision {
    pub action: FilterAction,
    pub matched_rule: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct FilterStats {
    pub total_rules: usize,
    pub block_rules: usize,
    pub allow_rules: usize,
    pub rewrite_rules: usize,
}

#[derive(Debug, Clone)]
struct RuleMeta {
    rule_text: String,
    exact_only: bool,
    rewrite_ip: Option<IpAddr>,
}

#[derive(Debug, Default)]
struct TrieNode {
    children: HashMap<String, TrieNode>,
    rule: Option<RuleMeta>,
}

impl TrieNode {
    fn insert(&mut self, domain: &str, meta: RuleMeta) {
        let mut current = self;
        for label in domain.rsplit('.').filter(|s| !s.is_empty()) {
            current = current
                .children
                .entry(label.to_ascii_lowercase())
                .or_default();
        }
        current.rule = Some(meta);
    }

    fn match_domain(&self, domain: &str) -> Option<&RuleMeta> {
        let labels: Vec<&str> = domain.rsplit('.').filter(|s| !s.is_empty()).collect();
        let mut current = self;
        let mut best: Option<&RuleMeta> = None;

        for (idx, label) in labels.iter().enumerate() {
            let lower = label.to_ascii_lowercase();
            let Some(next) = current.children.get(&lower) else {
                break;
            };
            current = next;
            if let Some(meta) = &current.rule {
                let is_exact = idx + 1 == labels.len();
                if !meta.exact_only || is_exact {
                    best = Some(meta);
                }
            }
        }
        best
    }
}

#[derive(Debug, Default)]
struct RuleSet {
    important_allows: TrieNode,
    important_blocks: TrieNode,
    allows: TrieNode,
    blocks: TrieNode,
    rewrites: TrieNode,
    stats: FilterStats,
}

impl RuleSet {
    fn from_lines<'a>(lines: impl Iterator<Item = &'a str>) -> Self {
        let mut set = Self::default();
        for raw_line in lines {
            set.parse_and_insert(raw_line);
        }
        set
    }

    fn parse_and_insert(&mut self, raw_line: &str) {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('!') || line.starts_with('#') {
            return;
        }

        if let Some(parsed) = parse_adguard_rule(line) {
            self.insert_parsed(&parsed, line);
            return;
        }

        self.parse_hosts_or_bare(line);
    }

    fn insert_parsed(&mut self, parsed: &ParsedRule, raw: &str) {
        self.stats.total_rules += 1;
        let meta = RuleMeta {
            rule_text: raw.to_string(),
            exact_only: parsed.exact_only,
            rewrite_ip: parsed.rewrite_ip,
        };

        if parsed.rewrite_ip.is_some() {
            self.stats.rewrite_rules += 1;
            self.rewrites.insert(&parsed.domain, meta);
            return;
        }

        match (parsed.is_allow, parsed.is_important) {
            (true, true) => {
                self.stats.allow_rules += 1;
                self.important_allows.insert(&parsed.domain, meta);
            }
            (true, false) => {
                self.stats.allow_rules += 1;
                self.allows.insert(&parsed.domain, meta);
            }
            (false, true) => {
                self.stats.block_rules += 1;
                self.important_blocks.insert(&parsed.domain, meta);
            }
            (false, false) => {
                self.stats.block_rules += 1;
                self.blocks.insert(&parsed.domain, meta);
            }
        }
    }

    fn parse_hosts_or_bare(&mut self, line: &str) {
        let no_comment = line.split('#').next().unwrap_or(line).trim();
        let parts: Vec<&str> = no_comment.split_whitespace().collect();
        if parts.is_empty() {
            return;
        }

        if parts.len() >= 2 && parts[0].parse::<IpAddr>().is_ok() {
            let ip_str = parts[0];
            let is_sinkhole = ip_str == "0.0.0.0" || ip_str == "::" || ip_str == "127.0.0.1";
            for &host in &parts[1..] {
                if !is_valid_domain_token(host) {
                    continue;
                }
                self.stats.total_rules += 1;
                self.stats.block_rules += 1;
                let meta = RuleMeta {
                    rule_text: line.to_string(),
                    exact_only: is_sinkhole,
                    rewrite_ip: None,
                };
                self.blocks.insert(host, meta);
            }
            return;
        }

        if parts.len() == 1 && is_valid_domain_token(parts[0]) {
            self.stats.total_rules += 1;
            self.stats.block_rules += 1;
            let meta = RuleMeta {
                rule_text: line.to_string(),
                exact_only: false,
                rewrite_ip: None,
            };
            self.blocks.insert(parts[0], meta);
        }
    }

    fn evaluate(&self, domain: &str) -> FilterDecision {
        let clean = domain.trim_end_matches('.');
        if clean.is_empty() {
            return FilterDecision {
                action: FilterAction::Allow,
                matched_rule: None,
            };
        }

        if let Some(meta) = self.important_allows.match_domain(clean) {
            return FilterDecision {
                action: FilterAction::Allow,
                matched_rule: Some(meta.rule_text.clone()),
            };
        }
        if let Some(meta) = self.important_blocks.match_domain(clean) {
            return FilterDecision {
                action: FilterAction::Block,
                matched_rule: Some(meta.rule_text.clone()),
            };
        }
        if let Some(meta) = self.allows.match_domain(clean) {
            return FilterDecision {
                action: FilterAction::Allow,
                matched_rule: Some(meta.rule_text.clone()),
            };
        }
        if let Some(meta) = self.rewrites.match_domain(clean)
            && let Some(ip) = meta.rewrite_ip
        {
            return FilterDecision {
                action: FilterAction::Rewrite(ip),
                matched_rule: Some(meta.rule_text.clone()),
            };
        }
        if let Some(meta) = self.blocks.match_domain(clean) {
            return FilterDecision {
                action: FilterAction::Block,
                matched_rule: Some(meta.rule_text.clone()),
            };
        }

        FilterDecision {
            action: FilterAction::Allow,
            matched_rule: None,
        }
    }
}

struct ParsedRule {
    domain: String,
    is_allow: bool,
    is_important: bool,
    exact_only: bool,
    rewrite_ip: Option<IpAddr>,
}

fn parse_adguard_rule(line: &str) -> Option<ParsedRule> {
    let (is_allow, rest) = if let Some(stripped) = line.strip_prefix("@@") {
        (true, stripped)
    } else {
        (false, line)
    };

    let (pattern, modifiers) = match rest.split_once('$') {
        Some((p, m)) => (p, Some(m)),
        None => (rest, None),
    };

    let (exact_only, domain_raw) = if let Some(d) = pattern.strip_prefix("||") {
        (false, d)
    } else if let Some(d) = pattern.strip_prefix('|') {
        (true, d)
    } else if modifiers.is_some() {
        (false, pattern)
    } else {
        return None;
    };

    let domain = domain_raw.trim_end_matches('^').trim_end_matches('.');
    if !is_valid_domain_token(domain) {
        return None;
    }

    let mut is_important = false;
    let mut rewrite_ip = None;
    if let Some(mods) = modifiers {
        for part in mods.split(',') {
            let trimmed = part.trim();
            if trimmed == "important" {
                is_important = true;
            } else if let Some(val) = trimmed.strip_prefix("dnsrewrite=")
                && let Ok(ip) = val.trim().parse::<IpAddr>()
            {
                rewrite_ip = Some(ip);
            }
        }
    }

    Some(ParsedRule {
        domain: domain.to_string(),
        is_allow,
        is_important,
        exact_only,
        rewrite_ip,
    })
}

fn is_valid_domain_token(token: &str) -> bool {
    !token.is_empty()
        && !token.contains('*')
        && !token.contains('/')
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
}

pub struct FilterEngine {
    ruleset: ArcSwap<RuleSet>,
    raw_rules: ArcSwap<String>,
}

impl FilterEngine {
    pub fn new(initial_rules: &[String]) -> Self {
        let joined = initial_rules.join("\n");
        let ruleset = RuleSet::from_lines(joined.lines());
        Self {
            ruleset: ArcSwap::from_pointee(ruleset),
            raw_rules: ArcSwap::from_pointee(joined),
        }
    }

    pub fn reload_from_text(&self, rules_text: &str) -> FilterStats {
        let next_set = RuleSet::from_lines(rules_text.lines());
        let stats = next_set.stats.clone();
        self.ruleset.store(Arc::new(next_set));
        self.raw_rules.store(Arc::new(rules_text.to_string()));
        stats
    }

    pub fn evaluate(&self, domain: &str) -> FilterDecision {
        self.ruleset.load().evaluate(domain)
    }

    pub fn stats(&self) -> FilterStats {
        self.ruleset.load().stats.clone()
    }

    pub fn raw_rules_text(&self) -> String {
        self.raw_rules.load().as_ref().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adguard_block_and_allow_precedence() {
        let rules = vec![
            "! comment line".to_string(),
            "||ads.example.com^".to_string(),
            "@@||safe.ads.example.com^".to_string(),
            "||malware.example.com^$important".to_string(),
            "@@||malware.example.com^".to_string(),
        ];
        let engine = FilterEngine::new(&rules);

        assert_eq!(
            engine.evaluate("ads.example.com").action,
            FilterAction::Block
        );
        assert_eq!(
            engine.evaluate("sub.ads.example.com").action,
            FilterAction::Block
        );
        assert_eq!(
            engine.evaluate("safe.ads.example.com").action,
            FilterAction::Allow
        );
        assert_eq!(
            engine.evaluate("malware.example.com").action,
            FilterAction::Block
        );
        assert_eq!(engine.evaluate("example.com").action, FilterAction::Allow);
    }

    #[test]
    fn test_hosts_and_rewrite_rules() {
        let rules = vec![
            "0.0.0.0 tracker.test".to_string(),
            "||nas.local^$dnsrewrite=192.168.1.50".to_string(),
        ];
        let engine = FilterEngine::new(&rules);

        assert_eq!(engine.evaluate("tracker.test").action, FilterAction::Block);
        assert_eq!(
            engine.evaluate("nas.local").action,
            FilterAction::Rewrite("192.168.1.50".parse().expect("valid ip"))
        );
    }

    #[test]
    fn test_hot_reload() {
        let engine = FilterEngine::new(&["||old.example.com^".to_string()]);
        assert_eq!(
            engine.evaluate("old.example.com").action,
            FilterAction::Block
        );

        let stats = engine.reload_from_text("||new.example.com^\n");
        assert_eq!(stats.block_rules, 1);
        assert_eq!(
            engine.evaluate("old.example.com").action,
            FilterAction::Allow
        );
        assert_eq!(
            engine.evaluate("new.example.com").action,
            FilterAction::Block
        );
    }
}
