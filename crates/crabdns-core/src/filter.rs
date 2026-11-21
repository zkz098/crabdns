use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RewriteAction {
    Ip(IpAddr),
    Cname(String),
    Txt(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FilterAction {
    Allow,
    Block,
    Rewrite(RewriteAction),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilterDecision {
    pub action: FilterAction,
    pub matched_rule: Option<String>,
    pub matched_list: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct FilterStats {
    pub total_rules: usize,
    pub block_rules: usize,
    pub allow_rules: usize,
    pub rewrite_rules: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MatchScope {
    Exact,
    DomainAndSubdomains,
    SubdomainsOnly,
}

#[derive(Debug, Clone)]
struct RuleMeta {
    rule_text: String,
    scope: MatchScope,
    rewrite: Option<RewriteAction>,
    source_id: u32,
}

type TrieMap<K, V> = HashMap<K, V, foldhash::fast::RandomState>;

fn lookup_child<'a>(children: &'a TrieMap<String, TrieNode>, label: &str) -> Option<&'a TrieNode> {
    if !label.bytes().any(|b| b.is_ascii_uppercase()) {
        return children.get(label);
    }
    if label.len() <= 128 {
        let mut buf = [0u8; 128];
        let slice = &mut buf[..label.len()];
        slice.copy_from_slice(label.as_bytes());
        slice.make_ascii_lowercase();
        if let Ok(lower) = std::str::from_utf8(slice) {
            return children.get(lower);
        }
    }
    children.get(&label.to_ascii_lowercase())
}

#[derive(Debug, Default)]
struct TrieNode {
    children: TrieMap<String, TrieNode>,
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
        let mut labels = domain.rsplit('.').filter(|s| !s.is_empty()).peekable();
        let mut current = self;
        let mut best: Option<&RuleMeta> = None;

        while let Some(label) = labels.next() {
            let Some(next) = lookup_child(&current.children, label) else {
                break;
            };
            current = next;
            if let Some(meta) = &current.rule {
                let is_exact = labels.peek().is_none();
                let matches = match meta.scope {
                    MatchScope::Exact => is_exact,
                    MatchScope::DomainAndSubdomains => true,
                    MatchScope::SubdomainsOnly => !is_exact,
                };
                if matches {
                    best = Some(meta);
                }
            }
        }
        best
    }
}

#[derive(Debug, Clone, Copy)]
enum RuleBucket {
    ImportantAllow,
    ImportantBlock,
    Allow,
    Block,
    Rewrite,
}

fn parse_rule_line(
    raw_line: &str,
    mut on_rule: impl FnMut(RuleBucket, &str, &str, MatchScope, Option<RewriteAction>),
) {
    let line = raw_line.trim();
    if line.is_empty() || line.starts_with('!') || line.starts_with('#') {
        return;
    }

    if let Some(parsed) = parse_adguard_rule(line) {
        let bucket = if parsed.rewrite.is_some() {
            RuleBucket::Rewrite
        } else {
            match (parsed.is_allow, parsed.is_important) {
                (true, true) => RuleBucket::ImportantAllow,
                (true, false) => RuleBucket::Allow,
                (false, true) => RuleBucket::ImportantBlock,
                (false, false) => RuleBucket::Block,
            }
        };
        on_rule(bucket, line, &parsed.domain, parsed.scope, parsed.rewrite);
        return;
    }

    parse_hosts_or_bare_line(line, &mut on_rule);
}

fn parse_hosts_or_bare_line(
    line: &str,
    on_rule: &mut impl FnMut(RuleBucket, &str, &str, MatchScope, Option<RewriteAction>),
) {
    let no_comment = line.split('#').next().unwrap_or(line).trim();
    let mut parts = no_comment.split_whitespace();
    let Some(first) = parts.next() else {
        return;
    };

    if let Some(second) = parts.next() {
        if first.parse::<IpAddr>().is_ok() {
            let is_sinkhole = first == "0.0.0.0" || first == "::" || first == "127.0.0.1";
            let scope = if is_sinkhole {
                MatchScope::Exact
            } else {
                MatchScope::DomainAndSubdomains
            };
            for host in std::iter::once(second).chain(parts) {
                if is_valid_domain_token(host) {
                    on_rule(RuleBucket::Block, line, host, scope, None);
                }
            }
        }
        return;
    }

    let (scope, token) = if let Some(rest) = first.strip_prefix("*.") {
        (MatchScope::SubdomainsOnly, rest)
    } else {
        (MatchScope::DomainAndSubdomains, first)
    };
    if is_valid_domain_token(token) {
        on_rule(RuleBucket::Block, line, token, scope, None);
    }
}

#[derive(Debug, Default)]
struct RuleSet {
    important_allows: TrieNode,
    important_blocks: TrieNode,
    allows: TrieNode,
    blocks: TrieNode,
    rewrites: TrieNode,
    list_names: Vec<String>,
    stats: FilterStats,
}

impl RuleSet {
    fn from_named_lines<'a>(source_name: &str, lines: impl Iterator<Item = &'a str>) -> Self {
        let mut set = Self::default();
        let sid = set.register_source(source_name);
        for raw_line in lines {
            set.parse_and_insert_with_source(raw_line, sid);
        }
        set
    }

    fn register_source(&mut self, name: &str) -> u32 {
        let id = u32::try_from(self.list_names.len()).unwrap_or(u32::MAX);
        self.list_names.push(name.to_string());
        id
    }

    fn source_name(&self, source_id: u32) -> Option<String> {
        self.list_names.get(source_id as usize).cloned()
    }

    fn parse_and_insert_with_source(&mut self, raw_line: &str, source_id: u32) {
        parse_rule_line(raw_line, |bucket, raw, domain, scope, rewrite| {
            self.stats.total_rules += 1;
            let meta = RuleMeta {
                rule_text: raw.to_string(),
                scope,
                rewrite,
                source_id,
            };
            match bucket {
                RuleBucket::ImportantAllow => {
                    self.stats.allow_rules += 1;
                    self.important_allows.insert(domain, meta);
                }
                RuleBucket::Allow => {
                    self.stats.allow_rules += 1;
                    self.allows.insert(domain, meta);
                }
                RuleBucket::ImportantBlock => {
                    self.stats.block_rules += 1;
                    self.important_blocks.insert(domain, meta);
                }
                RuleBucket::Block => {
                    self.stats.block_rules += 1;
                    self.blocks.insert(domain, meta);
                }
                RuleBucket::Rewrite => {
                    self.stats.rewrite_rules += 1;
                    self.rewrites.insert(domain, meta);
                }
            }
        });
    }

    fn evaluate(&self, domain: &str) -> FilterDecision {
        let clean = domain.trim_end_matches('.');
        if clean.is_empty() {
            return FilterDecision {
                action: FilterAction::Allow,
                matched_rule: None,
                matched_list: None,
            };
        }

        if let Some(meta) = self.important_allows.match_domain(clean) {
            return FilterDecision {
                action: FilterAction::Allow,
                matched_rule: Some(meta.rule_text.clone()),
                matched_list: self.source_name(meta.source_id),
            };
        }
        if let Some(meta) = self.important_blocks.match_domain(clean) {
            return FilterDecision {
                action: FilterAction::Block,
                matched_rule: Some(meta.rule_text.clone()),
                matched_list: self.source_name(meta.source_id),
            };
        }
        if let Some(meta) = self.allows.match_domain(clean) {
            return FilterDecision {
                action: FilterAction::Allow,
                matched_rule: Some(meta.rule_text.clone()),
                matched_list: self.source_name(meta.source_id),
            };
        }
        if let Some(meta) = self.rewrites.match_domain(clean)
            && let Some(rewrite) = &meta.rewrite
        {
            return FilterDecision {
                action: FilterAction::Rewrite(rewrite.clone()),
                matched_rule: Some(meta.rule_text.clone()),
                matched_list: self.source_name(meta.source_id),
            };
        }
        if let Some(meta) = self.blocks.match_domain(clean) {
            return FilterDecision {
                action: FilterAction::Block,
                matched_rule: Some(meta.rule_text.clone()),
                matched_list: self.source_name(meta.source_id),
            };
        }

        FilterDecision {
            action: FilterAction::Allow,
            matched_rule: None,
            matched_list: None,
        }
    }
}

struct ParsedRule {
    domain: String,
    is_allow: bool,
    is_important: bool,
    scope: MatchScope,
    rewrite: Option<RewriteAction>,
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

    let trimmed_domain = domain_raw.trim_end_matches('^').trim_end_matches('.');
    let (scope, domain) = if exact_only {
        (MatchScope::Exact, trimmed_domain)
    } else if let Some(d) = trimmed_domain.strip_prefix("*.") {
        (MatchScope::SubdomainsOnly, d)
    } else {
        (MatchScope::DomainAndSubdomains, trimmed_domain)
    };
    if !is_valid_domain_token(domain) {
        return None;
    }

    let mut is_important = false;
    let mut rewrite = None;
    if let Some(mods) = modifiers {
        for part in mods.split(',') {
            let trimmed = part.trim();
            if trimmed == "important" {
                is_important = true;
            } else if let Some(val) = trimmed.strip_prefix("dnsrewrite=") {
                rewrite = parse_dnsrewrite_value(val);
            }
        }
    }

    Some(ParsedRule {
        domain: domain.to_string(),
        is_allow,
        is_important,
        scope,
        rewrite,
    })
}

fn parse_dnsrewrite_value(raw: &str) -> Option<RewriteAction> {
    let val = raw.trim();
    if val.is_empty() {
        return None;
    }
    if let Ok(ip) = val.parse::<IpAddr>() {
        return Some(RewriteAction::Ip(ip));
    }
    if let Some((rr_type, target)) = val.split_once(';') {
        let kind = rr_type.trim().to_ascii_uppercase();
        let target = target.trim();
        if target.is_empty() {
            return None;
        }
        return match kind.as_str() {
            "A" | "AAAA" => target.parse::<IpAddr>().ok().map(RewriteAction::Ip),
            "CNAME" => {
                let clean = target.trim_end_matches('.');
                is_valid_domain_token(clean).then(|| RewriteAction::Cname(clean.to_string()))
            }
            "TXT" => Some(RewriteAction::Txt(target.to_string())),
            _ => None,
        };
    }
    let clean = val.trim_end_matches('.');
    is_valid_domain_token(clean).then(|| RewriteAction::Cname(clean.to_string()))
}

fn is_valid_domain_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= 253
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
        Self::from_named_text("custom", &joined)
    }

    pub fn from_named_text(source_name: &str, rules_text: &str) -> Self {
        let ruleset = RuleSet::from_named_lines(source_name, rules_text.lines());
        Self {
            ruleset: ArcSwap::from_pointee(ruleset),
            raw_rules: ArcSwap::from_pointee(rules_text.to_string()),
        }
    }

    pub fn reload_from_text(&self, rules_text: &str) -> FilterStats {
        let next_set = RuleSet::from_named_lines("custom", rules_text.lines());
        let stats = next_set.stats.clone();
        self.ruleset.store(Arc::new(next_set));
        self.raw_rules.store(Arc::new(rules_text.to_string()));
        stats
    }

    pub fn reload_from_sources(
        &self,
        custom_rules: &str,
        custom_enabled: bool,
        subscription_texts: &[String],
    ) -> FilterStats {
        let named: Vec<(String, String)> = subscription_texts
            .iter()
            .map(|text| ("subscription".to_string(), text.clone()))
            .collect();
        self.reload_from_named_sources(custom_rules, custom_enabled, &named)
    }

    pub fn reload_from_named_sources(
        &self,
        custom_rules: &str,
        custom_enabled: bool,
        subscriptions: &[(String, String)],
    ) -> FilterStats {
        let mut next_set = RuleSet::default();
        for (name, text) in subscriptions {
            let sid = next_set.register_source(name);
            for line in text.lines() {
                next_set.parse_and_insert_with_source(line, sid);
            }
        }
        if custom_enabled {
            let sid = next_set.register_source("custom");
            for line in custom_rules.lines() {
                next_set.parse_and_insert_with_source(line, sid);
            }
        }
        let stats = next_set.stats.clone();
        self.ruleset.store(Arc::new(next_set));
        self.raw_rules.store(Arc::new(custom_rules.to_string()));
        stats
    }

    pub fn count_rules_in_text(rules_text: &str) -> FilterStats {
        let mut stats = FilterStats::default();
        for line in rules_text.lines() {
            parse_rule_line(line, |bucket, _, _, _, _| {
                stats.total_rules += 1;
                match bucket {
                    RuleBucket::ImportantAllow | RuleBucket::Allow => stats.allow_rules += 1,
                    RuleBucket::ImportantBlock | RuleBucket::Block => stats.block_rules += 1,
                    RuleBucket::Rewrite => stats.rewrite_rules += 1,
                }
            });
        }
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
            "||alias.local^$dnsrewrite=CNAME;nas.local".to_string(),
            "||info.local^$dnsrewrite=TXT;crabdns-ok".to_string(),
            "*.wild.test".to_string(),
        ];
        let engine = FilterEngine::new(&rules);

        assert_eq!(engine.evaluate("tracker.test").action, FilterAction::Block);
        assert_eq!(
            engine.evaluate("nas.local").action,
            FilterAction::Rewrite(RewriteAction::Ip("192.168.1.50".parse().expect("valid ip")))
        );
        assert_eq!(
            engine.evaluate("alias.local").action,
            FilterAction::Rewrite(RewriteAction::Cname("nas.local".to_string()))
        );
        assert_eq!(
            engine.evaluate("info.local").action,
            FilterAction::Rewrite(RewriteAction::Txt("crabdns-ok".to_string()))
        );
        assert_eq!(engine.evaluate("wild.test").action, FilterAction::Allow);
        assert_eq!(engine.evaluate("sub.wild.test").action, FilterAction::Block);
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

    #[test]
    fn test_reload_from_sources_and_count() {
        let sub1 = "||ad1.example.com^\n! comment\n0.0.0.0 ad2.example.com\n".to_string();
        let sub2 = "||ad3.example.com^\n".to_string();
        assert_eq!(FilterEngine::count_rules_in_text(&sub1).total_rules, 2);

        let engine = FilterEngine::new(&[]);
        let stats = engine.reload_from_sources(
            "@@||ad1.example.com^\n||custom.example.com^",
            true,
            &[sub1.clone(), sub2.clone()],
        );
        assert_eq!(stats.total_rules, 5);
        assert_eq!(
            engine.evaluate("ad1.example.com").action,
            FilterAction::Allow
        );
        assert_eq!(
            engine.evaluate("ad2.example.com").action,
            FilterAction::Block
        );
        assert_eq!(
            engine.evaluate("custom.example.com").action,
            FilterAction::Block
        );

        let stats_disabled = engine.reload_from_sources(
            "@@||ad1.example.com^\n||custom.example.com^",
            false,
            &[sub1],
        );
        assert_eq!(stats_disabled.total_rules, 2);
        assert_eq!(
            engine.evaluate("ad1.example.com").action,
            FilterAction::Block
        );
        assert_eq!(
            engine.evaluate("custom.example.com").action,
            FilterAction::Allow
        );
    }

    #[test]
    fn test_filter_rejects_overlong_domain_and_counts_without_trie() {
        let overlong = format!("||{}example.com^", "a.".repeat(200));
        assert!(!is_valid_domain_token(&"a.".repeat(200)));

        let mixed = format!(
            "! comment\n\
             {overlong}\n\
             ||ad.example.com^\n\
             @@||ok.example.com^\n\
             ||imp.example.com^$important\n\
             ||rw.example.com^$dnsrewrite=1.2.3.4\n\
             0.0.0.0 host1.test host2.test\n\
             *.wild.example.com\n"
        );
        let counted = FilterEngine::count_rules_in_text(&mixed);
        let built = RuleSet::from_named_lines("check", mixed.lines()).stats;
        assert_eq!(counted.total_rules, built.total_rules);
        assert_eq!(counted.block_rules, built.block_rules);
        assert_eq!(counted.allow_rules, built.allow_rules);
        assert_eq!(counted.rewrite_rules, built.rewrite_rules);
        assert_eq!(counted.total_rules, 7);
    }
}
