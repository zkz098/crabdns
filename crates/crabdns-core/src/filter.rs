use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use regex::Regex;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::filter_rules::{
    FilterQueryContext, RewriteAction, RuleConditions, compile_safe_regex, is_valid_domain_token,
    parse_modifiers, parse_regex_rule,
};

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
    conditions: RuleConditions,
    source_id: u32,
}

#[derive(Debug, Clone)]
struct RegexRule {
    regex: Regex,
    rule_text: String,
    rewrite: Option<RewriteAction>,
    conditions: RuleConditions,
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
    rules: Vec<RuleMeta>,
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
        current.rules.push(meta);
    }

    fn match_domain<'a>(
        &'a self,
        clean_domain: &str,
        ctx: &FilterQueryContext<'_>,
        prefer_rewrite_qtype: bool,
    ) -> Option<&'a RuleMeta> {
        let mut labels = clean_domain
            .rsplit('.')
            .filter(|s| !s.is_empty())
            .peekable();
        let mut current = self;
        let mut best: Option<&RuleMeta> = None;
        let mut best_qtype_hit = false;

        while let Some(label) = labels.next() {
            let Some(next) = lookup_child(&current.children, label) else {
                break;
            };
            current = next;
            let is_exact = labels.peek().is_none();
            for meta in &current.rules {
                let scope_matches = match meta.scope {
                    MatchScope::Exact => is_exact,
                    MatchScope::DomainAndSubdomains => true,
                    MatchScope::SubdomainsOnly => !is_exact,
                };
                if !scope_matches || !meta.conditions.matches(ctx, clean_domain) {
                    continue;
                }
                let qtype_hit = prefer_rewrite_qtype
                    && ctx.qtype.is_some_and(|qt| {
                        meta.rewrite.as_ref().is_some_and(|r| r.matches_qtype(qt))
                    });
                if best.is_none() || qtype_hit || !best_qtype_hit {
                    best = Some(meta);
                    best_qtype_hit = qtype_hit;
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

fn classify_bucket(is_allow: bool, is_important: bool, has_rewrite: bool) -> RuleBucket {
    if has_rewrite && !is_allow {
        return RuleBucket::Rewrite;
    }
    match (is_allow, is_important) {
        (true, true) => RuleBucket::ImportantAllow,
        (true, false) => RuleBucket::Allow,
        (false, true) => RuleBucket::ImportantBlock,
        (false, false) => RuleBucket::Block,
    }
}

enum ParsedLine {
    Domain {
        bucket: RuleBucket,
        raw: String,
        domain: String,
        scope: MatchScope,
        rewrite: Option<RewriteAction>,
        conditions: RuleConditions,
    },
    Regex {
        bucket: RuleBucket,
        raw: String,
        pattern: String,
        rewrite: Option<RewriteAction>,
        conditions: RuleConditions,
    },
}

fn parse_line_items(raw_line: &str) -> Vec<ParsedLine> {
    let trimmed = raw_line.trim();
    if trimmed.is_empty()
        || trimmed.starts_with('!')
        || trimmed.starts_with('#')
        || trimmed.starts_with('[')
    {
        return Vec::new();
    }

    if let Some(rx) = parse_regex_rule(trimmed) {
        if compile_safe_regex(&rx.pattern).is_none() {
            return Vec::new();
        }
        let bucket = classify_bucket(rx.is_allow, rx.is_important, rx.rewrite.is_some());
        return vec![ParsedLine::Regex {
            bucket,
            raw: trimmed.to_string(),
            pattern: rx.pattern,
            rewrite: rx.rewrite,
            conditions: rx.conditions,
        }];
    }

    if let Some(parsed) = parse_adguard_rule(trimmed) {
        let bucket = classify_bucket(
            parsed.is_allow,
            parsed.is_important,
            parsed.rewrite.is_some(),
        );
        return vec![ParsedLine::Domain {
            bucket,
            raw: trimmed.to_string(),
            domain: parsed.domain,
            scope: parsed.scope,
            rewrite: parsed.rewrite,
            conditions: parsed.conditions,
        }];
    }

    parse_hosts_or_bare_line(trimmed)
}

fn parse_hosts_or_bare_line(line: &str) -> Vec<ParsedLine> {
    let no_comment = line.split('#').next().unwrap_or(line).trim();
    let mut parts = no_comment.split_whitespace();
    let Some(first) = parts.next() else {
        return Vec::new();
    };

    if let Some(second) = parts.next() {
        let mut out = Vec::new();
        if first.parse::<IpAddr>().is_ok() {
            let is_sinkhole = first == "0.0.0.0" || first == "::" || first == "127.0.0.1";
            let scope = if is_sinkhole {
                MatchScope::Exact
            } else {
                MatchScope::DomainAndSubdomains
            };
            for host in std::iter::once(second).chain(parts) {
                if is_valid_domain_token(host) {
                    out.push(ParsedLine::Domain {
                        bucket: RuleBucket::Block,
                        raw: line.to_string(),
                        domain: host.to_string(),
                        scope,
                        rewrite: None,
                        conditions: RuleConditions::default(),
                    });
                }
            }
        }
        return out;
    }

    let (scope, token) = if let Some(rest) = first.strip_prefix("*.") {
        (MatchScope::SubdomainsOnly, rest)
    } else {
        (MatchScope::DomainAndSubdomains, first)
    };
    if is_valid_domain_token(token) {
        return vec![ParsedLine::Domain {
            bucket: RuleBucket::Block,
            raw: line.to_string(),
            domain: token.to_string(),
            scope,
            rewrite: None,
            conditions: RuleConditions::default(),
        }];
    }
    Vec::new()
}

#[derive(Debug, Default)]
struct RuleSet {
    important_allows: TrieNode,
    important_blocks: TrieNode,
    allows: TrieNode,
    blocks: TrieNode,
    rewrites: TrieNode,
    regex_important_allows: Vec<RegexRule>,
    regex_important_blocks: Vec<RegexRule>,
    regex_allows: Vec<RegexRule>,
    regex_blocks: Vec<RegexRule>,
    regex_rewrites: Vec<RegexRule>,
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
        for item in parse_line_items(raw_line) {
            match item {
                ParsedLine::Domain {
                    bucket,
                    raw,
                    domain,
                    scope,
                    rewrite,
                    conditions,
                } => {
                    self.record_bucket_stat(bucket);
                    let meta = RuleMeta {
                        rule_text: raw,
                        scope,
                        rewrite,
                        conditions,
                        source_id,
                    };
                    match bucket {
                        RuleBucket::ImportantAllow => self.important_allows.insert(&domain, meta),
                        RuleBucket::Allow => self.allows.insert(&domain, meta),
                        RuleBucket::ImportantBlock => self.important_blocks.insert(&domain, meta),
                        RuleBucket::Block => self.blocks.insert(&domain, meta),
                        RuleBucket::Rewrite => self.rewrites.insert(&domain, meta),
                    }
                }
                ParsedLine::Regex {
                    bucket,
                    raw,
                    pattern,
                    rewrite,
                    conditions,
                } => {
                    let Some(regex) = compile_safe_regex(&pattern) else {
                        continue;
                    };
                    self.record_bucket_stat(bucket);
                    let rule = RegexRule {
                        regex,
                        rule_text: raw,
                        rewrite,
                        conditions,
                        source_id,
                    };
                    match bucket {
                        RuleBucket::ImportantAllow => self.regex_important_allows.push(rule),
                        RuleBucket::Allow => self.regex_allows.push(rule),
                        RuleBucket::ImportantBlock => self.regex_important_blocks.push(rule),
                        RuleBucket::Block => self.regex_blocks.push(rule),
                        RuleBucket::Rewrite => self.regex_rewrites.push(rule),
                    }
                }
            }
        }
    }

    fn record_bucket_stat(&mut self, bucket: RuleBucket) {
        self.stats.total_rules += 1;
        match bucket {
            RuleBucket::ImportantAllow | RuleBucket::Allow => self.stats.allow_rules += 1,
            RuleBucket::ImportantBlock | RuleBucket::Block => self.stats.block_rules += 1,
            RuleBucket::Rewrite => self.stats.rewrite_rules += 1,
        }
    }

    fn match_regex<'a>(
        rules: &'a [RegexRule],
        clean_domain: &str,
        ctx: &FilterQueryContext<'_>,
        prefer_rewrite_qtype: bool,
    ) -> Option<&'a RegexRule> {
        let mut fallback = None;
        for rule in rules {
            if rule.conditions.matches(ctx, clean_domain) && rule.regex.is_match(clean_domain) {
                if prefer_rewrite_qtype
                    && ctx.qtype.is_some_and(|qt| {
                        rule.rewrite.as_ref().is_some_and(|r| r.matches_qtype(qt))
                    })
                {
                    return Some(rule);
                }
                if fallback.is_none() {
                    fallback = Some(rule);
                }
            }
        }
        fallback
    }

    fn match_bucket(
        &self,
        trie: &TrieNode,
        regexes: &[RegexRule],
        clean: &str,
        ctx: &FilterQueryContext<'_>,
        action: FilterAction,
    ) -> Option<FilterDecision> {
        if let Some(meta) = trie.match_domain(clean, ctx, false) {
            return Some(FilterDecision {
                action,
                matched_rule: Some(meta.rule_text.clone()),
                matched_list: self.source_name(meta.source_id),
            });
        }
        if let Some(rx) = Self::match_regex(regexes, clean, ctx, false) {
            return Some(FilterDecision {
                action,
                matched_rule: Some(rx.rule_text.clone()),
                matched_list: self.source_name(rx.source_id),
            });
        }
        None
    }

    fn match_rewrite(&self, clean: &str, ctx: &FilterQueryContext<'_>) -> Option<FilterDecision> {
        let trie_hit = self.rewrites.match_domain(clean, ctx, true);
        let regex_hit = Self::match_regex(&self.regex_rewrites, clean, ctx, true);
        let trie_exact_qt = trie_hit.is_some_and(|m| {
            ctx.qtype
                .is_some_and(|qt| m.rewrite.as_ref().is_some_and(|r| r.matches_qtype(qt)))
        });
        if let Some(meta) = trie_hit
            && (trie_exact_qt || regex_hit.is_none())
            && let Some(rw) = &meta.rewrite
        {
            return Some(FilterDecision {
                action: FilterAction::Rewrite(rw.clone()),
                matched_rule: Some(meta.rule_text.clone()),
                matched_list: self.source_name(meta.source_id),
            });
        }
        if let Some(rx) = regex_hit
            && let Some(rw) = &rx.rewrite
        {
            return Some(FilterDecision {
                action: FilterAction::Rewrite(rw.clone()),
                matched_rule: Some(rx.rule_text.clone()),
                matched_list: self.source_name(rx.source_id),
            });
        }
        None
    }

    fn evaluate_with_context(&self, ctx: &FilterQueryContext<'_>) -> FilterDecision {
        let clean = ctx.domain.trim_end_matches('.');
        if clean.is_empty() {
            return FilterDecision {
                action: FilterAction::Allow,
                matched_rule: None,
                matched_list: None,
            };
        }

        if let Some(dec) = self.match_bucket(
            &self.important_allows,
            &self.regex_important_allows,
            clean,
            ctx,
            FilterAction::Allow,
        ) {
            return dec;
        }
        if let Some(dec) = self.match_bucket(
            &self.important_blocks,
            &self.regex_important_blocks,
            clean,
            ctx,
            FilterAction::Block,
        ) {
            return dec;
        }
        if let Some(dec) = self.match_bucket(
            &self.allows,
            &self.regex_allows,
            clean,
            ctx,
            FilterAction::Allow,
        ) {
            return dec;
        }
        if let Some(dec) = self.match_rewrite(clean, ctx) {
            return dec;
        }
        if let Some(dec) = self.match_bucket(
            &self.blocks,
            &self.regex_blocks,
            clean,
            ctx,
            FilterAction::Block,
        ) {
            return dec;
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
    conditions: RuleConditions,
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

    let parsed_mods = parse_modifiers(modifiers);
    Some(ParsedRule {
        domain: domain.to_string(),
        is_allow,
        is_important: parsed_mods.is_important,
        scope,
        rewrite: parsed_mods.rewrite,
        conditions: parsed_mods.conditions,
    })
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
            for item in parse_line_items(line) {
                let bucket = match item {
                    ParsedLine::Domain { bucket, .. } | ParsedLine::Regex { bucket, .. } => bucket,
                };
                stats.total_rules += 1;
                match bucket {
                    RuleBucket::ImportantAllow | RuleBucket::Allow => stats.allow_rules += 1,
                    RuleBucket::ImportantBlock | RuleBucket::Block => stats.block_rules += 1,
                    RuleBucket::Rewrite => stats.rewrite_rules += 1,
                }
            }
        }
        stats
    }

    pub fn evaluate(&self, domain: &str) -> FilterDecision {
        self.evaluate_with_context(&FilterQueryContext::from_domain(domain))
    }

    pub fn evaluate_with_context(&self, ctx: &FilterQueryContext<'_>) -> FilterDecision {
        self.ruleset.load().evaluate_with_context(ctx)
    }

    pub fn stats(&self) -> FilterStats {
        self.ruleset.load().stats.clone()
    }

    pub fn raw_rules_text(&self) -> String {
        self.raw_rules.load().as_ref().clone()
    }
}

#[cfg(test)]
#[path = "filter_tests.rs"]
mod tests;
