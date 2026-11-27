use std::collections::HashMap;

use foldhash::fast::RandomState;
use regex::{Regex, RegexSet, RegexSetBuilder};

use crate::error::{CoreError, Result};
use crate::filter_trie::LabelInterner;

const MAX_REGEX_SET_SIZE: usize = 2 * 1024 * 1024;

#[derive(Debug, Default)]
struct BuilderNode {
    children: HashMap<u32, u32, RandomState>,
    is_suffix: bool,
    is_exact: bool,
}

#[derive(Debug, Clone, Copy)]
struct FlatNode {
    children_start: u32,
    children_len: u32,
    is_suffix: bool,
    is_exact: bool,
}

/// Compact reversed-label Trie for fast, zero-allocation split-DNS domain matching.
#[derive(Debug, Default)]
pub struct SplitDomainTrie {
    interner: LabelInterner,
    nodes: Box<[FlatNode]>,
    children: Box<[(u32, u32)]>,
}

impl SplitDomainTrie {
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub fn matches(&self, domain: &str) -> bool {
        if self.nodes.is_empty() {
            return false;
        }
        let clean = domain.trim().trim_matches('.');
        if clean.is_empty() {
            return false;
        }
        let mut node_idx = 0_usize;
        for label in clean.rsplit('.').filter(|s| !s.is_empty()) {
            let node = self.nodes[node_idx];
            if node.is_suffix {
                return true;
            }
            let Some(label_id) = self.interner.lookup(label) else {
                return false;
            };
            let start = node.children_start as usize;
            let end = start + node.children_len as usize;
            let slice = &self.children[start..end];
            let Ok(pos) = slice.binary_search_by_key(&label_id, |&(id, _)| id) else {
                return false;
            };
            node_idx = slice[pos].1 as usize;
        }
        let terminal = self.nodes[node_idx];
        terminal.is_suffix || terminal.is_exact
    }
}

/// Builder for [`SplitDomainTrie`].
#[derive(Debug)]
pub struct SplitDomainTrieBuilder {
    interner: LabelInterner,
    nodes: Vec<BuilderNode>,
    has_entries: bool,
}

impl Default for SplitDomainTrieBuilder {
    fn default() -> Self {
        Self {
            interner: LabelInterner::default(),
            nodes: vec![BuilderNode::default()],
            has_entries: false,
        }
    }
}

impl SplitDomainTrieBuilder {
    pub fn insert(&mut self, domain: &str, exact_only: bool) {
        let mut current_idx = 0_usize;
        let mut any_label = false;
        for label in domain.rsplit('.').filter(|s| !s.is_empty()) {
            any_label = true;
            let label_id = self.interner.intern(label);
            if let Some(&next_idx) = self.nodes[current_idx].children.get(&label_id) {
                current_idx = next_idx as usize;
            } else {
                let next_idx = u32::try_from(self.nodes.len()).unwrap_or(u32::MAX);
                self.nodes.push(BuilderNode::default());
                self.nodes[current_idx].children.insert(label_id, next_idx);
                current_idx = next_idx as usize;
            }
        }
        if !any_label {
            return;
        }
        self.has_entries = true;
        if exact_only {
            self.nodes[current_idx].is_exact = true;
        } else {
            self.nodes[current_idx].is_suffix = true;
        }
    }

    pub fn freeze(self) -> SplitDomainTrie {
        if !self.has_entries {
            return SplitDomainTrie::default();
        }
        let mut flat_nodes = Vec::with_capacity(self.nodes.len());
        let total_children: usize = self.nodes.iter().map(|n| n.children.len()).sum();
        let mut children = Vec::with_capacity(total_children);

        for mut node in self.nodes {
            let children_start = u32::try_from(children.len()).unwrap_or(u32::MAX);
            let children_len = u32::try_from(node.children.len()).unwrap_or(u32::MAX);
            let mut pairs: Vec<(u32, u32)> = node.children.drain().collect();
            pairs.sort_unstable_by_key(|&(label_id, _)| label_id);
            children.extend(pairs);

            flat_nodes.push(FlatNode {
                children_start,
                children_len,
                is_suffix: node.is_suffix,
                is_exact: node.is_exact,
            });
        }

        SplitDomainTrie {
            interner: self.interner,
            nodes: flat_nodes.into_boxed_slice(),
            children: children.into_boxed_slice(),
        }
    }
}

pub(crate) struct DomainMatcher {
    single_suffix: Option<String>,
    trie: SplitDomainTrie,
    keywords: Vec<String>,
    regexes: Option<RegexSet>,
    exclude_trie: SplitDomainTrie,
    exclude_keywords: Vec<String>,
    exclude_regexes: Option<RegexSet>,
}

impl DomainMatcher {
    pub(crate) fn matches(&self, clean_domain: &str) -> bool {
        let pos = self
            .single_suffix
            .as_deref()
            .is_some_and(|s| matches_suffix_ci(clean_domain, s))
            || self.trie.matches(clean_domain)
            || matches_any_keyword_ci(clean_domain, &self.keywords)
            || self
                .regexes
                .as_ref()
                .is_some_and(|re| re.is_match(clean_domain));
        if !pos {
            return false;
        }
        let excluded = self.exclude_trie.matches(clean_domain)
            || matches_any_keyword_ci(clean_domain, &self.exclude_keywords)
            || self
                .exclude_regexes
                .as_ref()
                .is_some_and(|re| re.is_match(clean_domain));
        !excluded
    }
}

#[derive(Default)]
pub(crate) struct DomainMatcherBuilder {
    pub(crate) single_suffix: Option<String>,
    trie: SplitDomainTrieBuilder,
    keywords: Vec<String>,
    regex_patterns: Vec<String>,
    exclude_trie: SplitDomainTrieBuilder,
    exclude_keywords: Vec<String>,
    exclude_regex_patterns: Vec<String>,
    pub(crate) has_positive: bool,
}

impl DomainMatcherBuilder {
    pub(crate) fn insert_pattern(
        &mut self,
        raw: &str,
        force_exclude: bool,
        strict: bool,
    ) -> Result<()> {
        let line = strip_hash_comment(raw).trim();
        if line.is_empty() {
            return Ok(());
        }
        let (is_exclude, body) = if force_exclude {
            (true, strip_exclude_prefix(line))
        } else if let Some(rest) = line.strip_prefix("@@") {
            (true, rest.trim())
        } else if let Some(rest) = line.strip_prefix('!') {
            (true, rest.trim())
        } else if let Some(rest) = strip_prefix_ci(line, "exclude:") {
            (true, rest.trim())
        } else {
            (false, line)
        };
        if body.is_empty() {
            return Ok(());
        }

        if let Some(pat) = strip_prefix_ci(body, "regexp:") {
            return self.insert_regex_pattern(pat.trim(), is_exclude, strict);
        }

        if let Some(kw) = strip_prefix_ci(body, "keyword:")
            .or_else(|| strip_clash_rule_ci(body, "DOMAIN-KEYWORD,"))
        {
            let norm = kw.trim().to_ascii_lowercase();
            if !norm.is_empty() {
                if is_exclude {
                    self.exclude_keywords.push(norm);
                } else {
                    self.has_positive = true;
                    self.keywords.push(norm);
                }
            }
            return Ok(());
        }

        if let Some(exact) =
            strip_prefix_ci(body, "full:").or_else(|| strip_clash_rule_ci(body, "DOMAIN,"))
        {
            let norm = normalize_suffix(exact);
            if !norm.is_empty() {
                self.insert_trie(&norm, true, is_exclude);
            }
            return Ok(());
        }

        if let Some(clash_suffix) = strip_clash_rule_ci(body, "DOMAIN-SUFFIX,") {
            let norm = normalize_suffix(clash_suffix);
            if !norm.is_empty() {
                self.insert_trie(&norm, false, is_exclude);
            }
            return Ok(());
        }

        if !strict && is_non_domain_clash_line(body) {
            return Ok(());
        }

        if let Some(domain) = parse_suffix_line(body) {
            self.insert_trie(&domain, false, is_exclude);
        } else if strict {
            return Err(CoreError::Config(format!(
                "invalid split_dns domain pattern '{raw}'"
            )));
        }
        Ok(())
    }

    fn insert_regex_pattern(
        &mut self,
        trimmed: &str,
        is_exclude: bool,
        strict: bool,
    ) -> Result<()> {
        if trimmed.is_empty() {
            if strict {
                return Err(CoreError::Config(
                    "empty regexp: split-DNS rule".to_string(),
                ));
            }
            return Ok(());
        }
        if !strict && let Err(err) = Regex::new(trimmed) {
            tracing::warn!(pattern = %trimmed, error = %err, "skipping invalid split-DNS regexp pattern in external list");
            return Ok(());
        }
        if is_exclude {
            self.exclude_regex_patterns.push(trimmed.to_string());
        } else {
            self.has_positive = true;
            self.regex_patterns.push(trimmed.to_string());
        }
        Ok(())
    }

    fn insert_trie(&mut self, domain: &str, exact_only: bool, is_exclude: bool) {
        if is_exclude {
            self.exclude_trie.insert(domain, exact_only);
        } else {
            self.has_positive = true;
            self.trie.insert(domain, exact_only);
        }
    }

    pub(crate) fn build(self) -> Result<DomainMatcher> {
        let regexes = compile_regex_set(&self.regex_patterns)?;
        let exclude_regexes = compile_regex_set(&self.exclude_regex_patterns)?;
        Ok(DomainMatcher {
            single_suffix: self.single_suffix,
            trie: self.trie.freeze(),
            keywords: self.keywords,
            regexes,
            exclude_trie: self.exclude_trie.freeze(),
            exclude_keywords: self.exclude_keywords,
            exclude_regexes,
        })
    }
}

fn compile_regex_set(patterns: &[String]) -> Result<Option<RegexSet>> {
    if patterns.is_empty() {
        return Ok(None);
    }
    let set = RegexSetBuilder::new(patterns)
        .case_insensitive(true)
        .size_limit(MAX_REGEX_SET_SIZE)
        .build()
        .map_err(|e| CoreError::Config(format!("invalid split_dns regexp pattern: {e}")))?;
    Ok(Some(set))
}

pub(crate) fn insert_domains_into_matcher(content: &str, builder: &mut DomainMatcherBuilder) {
    for raw_line in content.lines() {
        let _ = builder.insert_pattern(raw_line, false, false);
    }
}

pub(crate) fn is_plain_suffix_spec(raw: &str) -> bool {
    let t = raw.trim();
    strip_prefix_ci(t, "full:").is_none()
        && strip_prefix_ci(t, "keyword:").is_none()
        && strip_prefix_ci(t, "regexp:").is_none()
        && strip_prefix_ci(t, "exclude:").is_none()
        && !t.starts_with("@@")
        && !t.starts_with('!')
        && !t.contains(',')
}

pub(crate) fn strip_hash_comment(raw: &str) -> &str {
    let mut end = raw.len();
    if let Some(idx) = raw.find('#') {
        end = end.min(idx);
    }
    if let Some(idx) = raw.find("//") {
        end = end.min(idx);
    }
    &raw[..end]
}

fn strip_exclude_prefix(line: &str) -> &str {
    if let Some(r) = line.strip_prefix("@@") {
        r.trim()
    } else if let Some(r) = line.strip_prefix('!') {
        r.trim()
    } else if let Some(r) = strip_prefix_ci(line, "exclude:") {
        r.trim()
    } else {
        line
    }
}

pub(crate) fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    s.get(..prefix.len())
        .filter(|head| head.eq_ignore_ascii_case(prefix))
        .map(|_| &s[prefix.len()..])
}

fn strip_clash_rule_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let rest = strip_prefix_ci(s, prefix)?;
    let value = rest.split(',').next()?.trim();
    (!value.is_empty()).then_some(value)
}

fn is_non_domain_clash_line(body: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "IP-CIDR,",
        "IP-CIDR6,",
        "GEOIP,",
        "MATCH,",
        "FINAL,",
        "USER-AGENT,",
        "PROCESS-NAME,",
        "SRC-IP-CIDR,",
        "DST-PORT,",
        "SRC-PORT,",
    ];
    PREFIXES.iter().any(|p| strip_prefix_ci(body, p).is_some())
}

pub(crate) fn parse_suffix_line(line: &str) -> Option<String> {
    let candidate = if let Some(rest) = strip_prefix_ci(line, "domain:") {
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

pub(crate) fn normalize_suffix(raw: &str) -> String {
    raw.trim()
        .trim_start_matches("*.")
        .trim_start_matches('.')
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

pub(crate) fn matches_suffix_ci(domain: &str, suffix_lower: &str) -> bool {
    if domain.len() < suffix_lower.len() {
        return false;
    }
    let split = domain.len() - suffix_lower.len();
    if !domain[split..].eq_ignore_ascii_case(suffix_lower) {
        return false;
    }
    split == 0 || domain.as_bytes()[split - 1] == b'.'
}

fn matches_any_keyword_ci(domain: &str, keywords_lower: &[String]) -> bool {
    keywords_lower
        .iter()
        .any(|kw| contains_ascii_ci(domain.as_bytes(), kw.as_bytes()))
}

fn contains_ascii_ci(haystack: &[u8], needle_lower: &[u8]) -> bool {
    if needle_lower.is_empty() {
        return false;
    }
    haystack
        .windows(needle_lower.len())
        .any(|w| w.eq_ignore_ascii_case(needle_lower))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_domain_trie_suffix_and_exact() {
        let mut builder = SplitDomainTrieBuilder::default();
        builder.insert("cn", false);
        builder.insert("bilibili.com", false);
        builder.insert("exact.example.org", true);

        let trie = builder.freeze();
        assert!(trie.matches("cn"));
        assert!(trie.matches("gov.cn"));
        assert!(trie.matches("a.b.gov.cn"));
        assert!(trie.matches("api.bilibili.com"));
        assert!(trie.matches("exact.example.org"));
        assert!(!trie.matches("sub.exact.example.org"));
        assert!(!trie.matches("google.com"));
        assert!(!trie.matches("notcn"));
    }
}
