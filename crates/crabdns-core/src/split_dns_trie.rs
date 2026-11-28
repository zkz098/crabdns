use std::cmp::Reverse;
use std::collections::HashMap;

use foldhash::fast::RandomState;
use regex::{Regex, RegexSet, RegexSetBuilder};

use crate::error::{CoreError, Result};
use crate::filter_trie::LabelInterner;

const MAX_REGEX_SET_SIZE: usize = 2 * 1024 * 1024;
const STACK_BITSET_WORDS: usize = 4;
const STACK_CANDIDATE_CAP: usize = 16;

pub(crate) const HIT_FLAG_EXACT: u8 = 0b01;
pub(crate) const HIT_FLAG_EXCLUDE: u8 = 0b10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TrieRouteHit {
    pub route_idx: u32,
    pub flags: u8,
    pub pattern_len: u16,
}

impl TrieRouteHit {
    #[inline]
    pub(crate) const fn is_exact(self) -> bool {
        (self.flags & HIT_FLAG_EXACT) != 0
    }

    #[inline]
    pub(crate) const fn is_exclude(self) -> bool {
        (self.flags & HIT_FLAG_EXCLUDE) != 0
    }

    #[inline]
    pub(crate) fn specificity_score(self) -> u32 {
        u32::from(self.pattern_len) * 2 + u32::from(self.is_exact())
    }
}

#[derive(Debug, Default)]
struct UnifiedBuilderNode {
    children: HashMap<u32, u32, RandomState>,
    hits: Vec<TrieRouteHit>,
}

#[derive(Debug, Clone, Copy)]
struct UnifiedFlatNode {
    children_start: u32,
    children_len: u32,
    hits_start: u32,
    hits_len: u32,
}

/// Stack-backed route bitset supporting up to 256 routes with zero heap allocation.
pub(crate) enum RouteBitset {
    Inline([u64; STACK_BITSET_WORDS]),
    Heap(Vec<u64>),
}

impl RouteBitset {
    pub(crate) fn new(route_count: usize) -> Self {
        let words = route_count.div_ceil(64).max(1);
        if words <= STACK_BITSET_WORDS {
            Self::Inline([0_u64; STACK_BITSET_WORDS])
        } else {
            Self::Heap(vec![0_u64; words])
        }
    }

    #[inline]
    fn words(&self) -> &[u64] {
        match self {
            Self::Inline(arr) => arr,
            Self::Heap(vec) => vec,
        }
    }

    #[inline]
    fn words_mut(&mut self) -> &mut [u64] {
        match self {
            Self::Inline(arr) => arr,
            Self::Heap(vec) => vec,
        }
    }

    #[inline]
    pub(crate) fn set(&mut self, route_idx: u32) {
        let word_idx = (route_idx as usize) >> 6;
        let bit = 1_u64 << (route_idx & 63);
        if let Some(w) = self.words_mut().get_mut(word_idx) {
            *w |= bit;
        }
    }

    #[inline]
    pub(crate) fn contains(&self, route_idx: u32) -> bool {
        let word_idx = (route_idx as usize) >> 6;
        let bit = 1_u64 << (route_idx & 63);
        self.words().get(word_idx).is_some_and(|w| (*w & bit) != 0)
    }

    pub(crate) fn iter_excluding<'a>(&'a self, excluded: &'a Self) -> RouteBitsetIter<'a> {
        RouteBitsetIter {
            pos_words: self.words(),
            excl_words: excluded.words(),
            word_idx: 0,
            current_word: 0,
            initialized: false,
        }
    }
}

pub(crate) struct RouteBitsetIter<'a> {
    pos_words: &'a [u64],
    excl_words: &'a [u64],
    word_idx: usize,
    current_word: u64,
    initialized: bool,
}

impl Iterator for RouteBitsetIter<'_> {
    type Item = u32;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.initialized {
            self.initialized = true;
            if let Some(&pw) = self.pos_words.first() {
                let ew = self.excl_words.first().copied().unwrap_or(0);
                self.current_word = pw & !ew;
            }
        }
        loop {
            if self.current_word != 0 {
                let tz = self.current_word.trailing_zeros();
                self.current_word &= self.current_word - 1;
                return Some(u32::try_from(self.word_idx * 64).unwrap_or(u32::MAX) + tz);
            }
            self.word_idx += 1;
            if self.word_idx >= self.pos_words.len() {
                return None;
            }
            let pw = self.pos_words[self.word_idx];
            let ew = self.excl_words.get(self.word_idx).copied().unwrap_or(0);
            self.current_word = pw & !ew;
        }
    }
}

/// Stack-backed scored route candidate list (zero heap allocation up to 16 hits).
pub(crate) struct ScoredCandidates {
    inline: [(u32, u32); STACK_CANDIDATE_CAP],
    inline_len: usize,
    heap: Option<Vec<(u32, u32)>>,
}

impl Default for ScoredCandidates {
    fn default() -> Self {
        Self::new()
    }
}

impl ScoredCandidates {
    pub(crate) fn new() -> Self {
        Self {
            inline: [(0, 0); STACK_CANDIDATE_CAP],
            inline_len: 0,
            heap: None,
        }
    }

    pub(crate) fn insert_max(&mut self, route_idx: u32, score: u32) {
        if let Some(ref mut vec) = self.heap {
            if let Some(existing) = vec.iter_mut().find(|(id, _)| *id == route_idx) {
                existing.1 = existing.1.max(score);
            } else {
                vec.push((route_idx, score));
            }
            return;
        }

        for entry in &mut self.inline[..self.inline_len] {
            if entry.0 == route_idx {
                entry.1 = entry.1.max(score);
                return;
            }
        }

        if self.inline_len < STACK_CANDIDATE_CAP {
            self.inline[self.inline_len] = (route_idx, score);
            self.inline_len += 1;
        } else {
            let mut vec = Vec::with_capacity(STACK_CANDIDATE_CAP + 4);
            vec.extend_from_slice(&self.inline[..self.inline_len]);
            vec.push((route_idx, score));
            self.heap = Some(vec);
        }
    }

    pub(crate) fn sort_excluding(&mut self, excluded: &RouteBitset) -> &[(u32, u32)] {
        if let Some(ref mut vec) = self.heap {
            vec.retain(|(id, _)| !excluded.contains(*id));
            vec.sort_unstable_by_key(|&(id, score)| (Reverse(score), id));
            return vec.as_slice();
        }

        let mut kept = 0_usize;
        for idx in 0..self.inline_len {
            let item = self.inline[idx];
            if !excluded.contains(item.0) {
                self.inline[kept] = item;
                kept += 1;
            }
        }
        self.inline_len = kept;
        let slice = &mut self.inline[..self.inline_len];
        slice.sort_unstable_by_key(|&(id, score)| (Reverse(score), id));
        slice
    }
}

/// Compact unified reversed-label Trie across all split-DNS routes.
#[derive(Debug, Default)]
pub struct UnifiedSplitTrie {
    interner: LabelInterner,
    nodes: Box<[UnifiedFlatNode]>,
    children: Box<[(u32, u32)]>,
    hits: Box<[TrieRouteHit]>,
}

impl UnifiedSplitTrie {
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub(crate) fn collect_config_order(
        &self,
        clean_domain: &str,
        pos: &mut RouteBitset,
        excl: &mut RouteBitset,
    ) {
        self.walk_hits(clean_domain, |hit| {
            if hit.is_exclude() {
                excl.set(hit.route_idx);
            } else {
                pos.set(hit.route_idx);
            }
        });
    }

    pub(crate) fn collect_specificity_first(
        &self,
        clean_domain: &str,
        candidates: &mut ScoredCandidates,
        excl: &mut RouteBitset,
    ) {
        self.walk_hits(clean_domain, |hit| {
            if hit.is_exclude() {
                excl.set(hit.route_idx);
            } else {
                candidates.insert_max(hit.route_idx, hit.specificity_score());
            }
        });
    }

    #[inline]
    fn walk_hits<F>(&self, clean_domain: &str, mut on_hit: F)
    where
        F: FnMut(TrieRouteHit),
    {
        if self.nodes.is_empty() {
            return;
        }
        let mut node_idx = 0_usize;
        let mut labels = clean_domain
            .rsplit('.')
            .filter(|s| !s.is_empty())
            .peekable();
        while let Some(label) = labels.next() {
            let Some(label_id) = self.interner.lookup(label) else {
                break;
            };
            let node = self.nodes[node_idx];
            let c_start = node.children_start as usize;
            let c_end = c_start + node.children_len as usize;
            let slice = &self.children[c_start..c_end];
            let Ok(pos) = slice.binary_search_by_key(&label_id, |&(id, _)| id) else {
                break;
            };
            node_idx = slice[pos].1 as usize;
            let hit_node = self.nodes[node_idx];
            if hit_node.hits_len > 0 {
                let is_terminal = labels.peek().is_none();
                let h_start = hit_node.hits_start as usize;
                let h_end = h_start + hit_node.hits_len as usize;
                for &hit in &self.hits[h_start..h_end] {
                    if !hit.is_exact() || is_terminal {
                        on_hit(hit);
                    }
                }
            }
        }
    }
}

/// Builder for [`UnifiedSplitTrie`].
#[derive(Debug)]
pub struct UnifiedSplitTrieBuilder {
    interner: LabelInterner,
    nodes: Vec<UnifiedBuilderNode>,
    has_entries: bool,
}

impl Default for UnifiedSplitTrieBuilder {
    fn default() -> Self {
        Self {
            interner: LabelInterner::default(),
            nodes: vec![UnifiedBuilderNode::default()],
            has_entries: false,
        }
    }
}

impl UnifiedSplitTrieBuilder {
    pub fn insert(&mut self, domain: &str, route_idx: u32, exact_only: bool, is_exclude: bool) {
        let mut current_idx = 0_usize;
        let mut any_label = false;
        for label in domain.rsplit('.').filter(|s| !s.is_empty()) {
            any_label = true;
            let label_id = self.interner.intern(label);
            if let Some(&next_idx) = self.nodes[current_idx].children.get(&label_id) {
                current_idx = next_idx as usize;
            } else {
                let next_idx = u32::try_from(self.nodes.len()).unwrap_or(u32::MAX);
                self.nodes.push(UnifiedBuilderNode::default());
                self.nodes[current_idx].children.insert(label_id, next_idx);
                current_idx = next_idx as usize;
            }
        }
        if !any_label {
            return;
        }
        self.has_entries = true;
        let flags = if exact_only { HIT_FLAG_EXACT } else { 0 }
            | if is_exclude { HIT_FLAG_EXCLUDE } else { 0 };
        let pattern_len = u16::try_from(domain.len()).unwrap_or(u16::MAX);
        let hits = &mut self.nodes[current_idx].hits;
        if let Some(existing) = hits
            .iter_mut()
            .find(|h| h.route_idx == route_idx && h.flags == flags)
        {
            existing.pattern_len = existing.pattern_len.max(pattern_len);
        } else {
            hits.push(TrieRouteHit {
                route_idx,
                flags,
                pattern_len,
            });
        }
    }

    pub fn freeze(self) -> UnifiedSplitTrie {
        if !self.has_entries {
            return UnifiedSplitTrie::default();
        }
        let total_children: usize = self.nodes.iter().map(|n| n.children.len()).sum();
        let total_hits: usize = self.nodes.iter().map(|n| n.hits.len()).sum();
        let mut flat_nodes = Vec::with_capacity(self.nodes.len());
        let mut children = Vec::with_capacity(total_children);
        let mut hits = Vec::with_capacity(total_hits);

        for mut node in self.nodes {
            let children_start = u32::try_from(children.len()).unwrap_or(u32::MAX);
            let children_len = u32::try_from(node.children.len()).unwrap_or(u32::MAX);
            let mut pairs: Vec<(u32, u32)> = node.children.drain().collect();
            pairs.sort_unstable_by_key(|&(label_id, _)| label_id);
            children.extend(pairs);

            let hits_start = u32::try_from(hits.len()).unwrap_or(u32::MAX);
            let hits_len = u32::try_from(node.hits.len()).unwrap_or(u32::MAX);
            hits.extend(node.hits);

            flat_nodes.push(UnifiedFlatNode {
                children_start,
                children_len,
                hits_start,
                hits_len,
            });
        }

        UnifiedSplitTrie {
            interner: self.interner,
            nodes: flat_nodes.into_boxed_slice(),
            children: children.into_boxed_slice(),
            hits: hits.into_boxed_slice(),
        }
    }
}

pub(crate) struct NonTrieMatcher {
    keywords: Box<[Box<str>]>,
    regexes: Option<RegexSet>,
    exclude_keywords: Box<[Box<str>]>,
    exclude_regexes: Option<RegexSet>,
}

impl NonTrieMatcher {
    #[inline]
    pub(crate) fn matches_positive(&self, clean_domain: &str) -> bool {
        matches_any_keyword_ci(clean_domain, &self.keywords)
            || self
                .regexes
                .as_ref()
                .is_some_and(|re| re.is_match(clean_domain))
    }

    #[inline]
    pub(crate) fn matches_exclude(&self, clean_domain: &str) -> bool {
        matches_any_keyword_ci(clean_domain, &self.exclude_keywords)
            || self
                .exclude_regexes
                .as_ref()
                .is_some_and(|re| re.is_match(clean_domain))
    }
}

#[derive(Default)]
pub(crate) struct NonTrieMatcherBuilder {
    keywords: Vec<String>,
    regex_patterns: Vec<String>,
    exclude_keywords: Vec<String>,
    exclude_regex_patterns: Vec<String>,
    pub(crate) has_positive_non_trie: bool,
}

impl NonTrieMatcherBuilder {
    pub(crate) fn insert_pattern(
        &mut self,
        trie: &mut UnifiedSplitTrieBuilder,
        route_idx: u32,
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
                    self.has_positive_non_trie = true;
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
                trie.insert(&norm, route_idx, true, is_exclude);
            }
            return Ok(());
        }

        if let Some(clash_suffix) = strip_clash_rule_ci(body, "DOMAIN-SUFFIX,") {
            let norm = normalize_suffix(clash_suffix);
            if !norm.is_empty() {
                trie.insert(&norm, route_idx, false, is_exclude);
            }
            return Ok(());
        }

        if !strict && is_non_domain_clash_line(body) {
            return Ok(());
        }

        if let Some(domain) = parse_suffix_line(body) {
            trie.insert(&domain, route_idx, false, is_exclude);
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
            self.has_positive_non_trie = true;
            self.regex_patterns.push(trimmed.to_string());
        }
        Ok(())
    }

    pub(crate) fn build(self) -> Result<NonTrieMatcher> {
        let regexes = compile_regex_set(&self.regex_patterns)?;
        let exclude_regexes = compile_regex_set(&self.exclude_regex_patterns)?;
        Ok(NonTrieMatcher {
            keywords: self
                .keywords
                .into_iter()
                .map(String::into_boxed_str)
                .collect(),
            regexes,
            exclude_keywords: self
                .exclude_keywords
                .into_iter()
                .map(String::into_boxed_str)
                .collect(),
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

pub(crate) fn insert_domains_into_route(
    content: &str,
    trie: &mut UnifiedSplitTrieBuilder,
    route_idx: u32,
    non_trie: &mut NonTrieMatcherBuilder,
) {
    for raw_line in content.lines() {
        let _ = non_trie.insert_pattern(trie, route_idx, raw_line, false, false);
    }
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

fn matches_any_keyword_ci(domain: &str, keywords_lower: &[Box<str>]) -> bool {
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
    fn test_unified_trie_specificity_exclude_and_case_insensitive() {
        let mut builder = UnifiedSplitTrieBuilder::default();
        builder.insert("cn", 0, false, false);
        builder.insert("bilibili.com", 1, false, false);
        builder.insert("api.bilibili.com", 2, false, false);
        builder.insert("exact.example.org", 3, true, false);
        builder.insert("example.org", 4, false, false);
        builder.insert("internal.cn", 0, false, true);
        builder.insert("exact.bilibili.com", 1, true, true);

        let trie = builder.freeze();

        let mut cand = ScoredCandidates::new();
        let mut excl = RouteBitset::new(5);
        trie.collect_specificity_first("API.BiliBili.COM", &mut cand, &mut excl);
        let sorted = cand.sort_excluding(&excl);
        assert_eq!(sorted[0].0, 2);
        assert_eq!(sorted[1].0, 1);

        let mut cand2 = ScoredCandidates::new();
        let mut excl2 = RouteBitset::new(5);
        trie.collect_specificity_first("exact.example.org", &mut cand2, &mut excl2);
        let sorted2 = cand2.sort_excluding(&excl2);
        assert_eq!(sorted2[0].0, 3);
        assert_eq!(sorted2[1].0, 4);

        let mut cand3 = ScoredCandidates::new();
        let mut excl3 = RouteBitset::new(5);
        trie.collect_specificity_first("sub.exact.example.org", &mut cand3, &mut excl3);
        let sorted3 = cand3.sort_excluding(&excl3);
        assert_eq!(sorted3.len(), 1);
        assert_eq!(sorted3[0].0, 4);

        let mut pos = RouteBitset::new(5);
        let mut excl4 = RouteBitset::new(5);
        trie.collect_config_order("app.internal.cn", &mut pos, &mut excl4);
        let remaining: Vec<u32> = pos.iter_excluding(&excl4).collect();
        assert_eq!(remaining, [] as [u32; 0]);

        let mut pos2 = RouteBitset::new(5);
        let mut excl5 = RouteBitset::new(5);
        trie.collect_config_order("sub.exact.bilibili.com", &mut pos2, &mut excl5);
        let remaining2: Vec<u32> = pos2.iter_excluding(&excl5).collect();
        assert_eq!(remaining2, vec![1]);
    }

    #[test]
    fn test_bitset_and_candidates_heap_spill() {
        let mut bs = RouteBitset::new(320);
        let mut excl = RouteBitset::new(320);
        bs.set(5);
        bs.set(270);
        bs.set(319);
        excl.set(270);
        assert_eq!(bs.iter_excluding(&excl).collect::<Vec<_>>(), vec![5, 319]);

        let mut cand = ScoredCandidates::new();
        let excl_empty = RouteBitset::new(24);
        for i in 0..20_u32 {
            cand.insert_max(i, i * 2);
        }
        cand.insert_max(3, 999);
        let sorted = cand.sort_excluding(&excl_empty);
        assert_eq!(sorted.len(), 20);
        assert_eq!(sorted[0], (3, 999));
    }
}
