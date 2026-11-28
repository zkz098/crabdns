use std::collections::HashMap;
use std::hash::BuildHasher;

use foldhash::fast::RandomState;

use crate::filter_rules::{FilterQueryContext, RewriteAction, RuleConditions};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MatchScope {
    Exact,
    DomainAndSubdomains,
    SubdomainsOnly,
}

#[derive(Debug, Clone)]
pub(crate) struct RuleMeta {
    pub rule_text: String,
    pub scope: MatchScope,
    pub rewrite: Option<RewriteAction>,
    pub conditions: RuleConditions,
    pub source_id: u32,
}

#[derive(Debug)]
enum BucketEntry {
    Single(u32),
    Multi(Vec<u32>),
}

#[derive(Debug)]
pub(crate) struct LabelInterner {
    buf: String,
    spans: Vec<(u32, u32)>,
    buckets: HashMap<u64, BucketEntry, RandomState>,
    hasher: RandomState,
}

impl Default for LabelInterner {
    fn default() -> Self {
        let hasher = RandomState::default();
        Self {
            buf: String::new(),
            spans: Vec::new(),
            buckets: HashMap::with_hasher(hasher.clone()),
            hasher,
        }
    }
}

impl LabelInterner {
    #[inline]
    fn slice(&self, id: u32) -> &str {
        let (start, len) = self.spans[id as usize];
        let s = start as usize;
        let l = len as usize;
        &self.buf[s..s + l]
    }

    fn lookup_lower_bytes(&self, lower: &str) -> Option<u32> {
        let hash = self.hasher.hash_one(lower.as_bytes());
        match self.buckets.get(&hash)? {
            BucketEntry::Single(id) => (self.slice(*id) == lower).then_some(*id),
            BucketEntry::Multi(ids) => ids.iter().copied().find(|&id| self.slice(id) == lower),
        }
    }

    pub(crate) fn lookup(&self, label: &str) -> Option<u32> {
        if !label.bytes().any(|b| b.is_ascii_uppercase()) {
            return self.lookup_lower_bytes(label);
        }
        if label.len() <= 128 {
            let mut buf = [0_u8; 128];
            let slice = &mut buf[..label.len()];
            slice.copy_from_slice(label.as_bytes());
            slice.make_ascii_lowercase();
            if let Ok(lower) = std::str::from_utf8(slice) {
                return self.lookup_lower_bytes(lower);
            }
        }
        let lower = label.to_ascii_lowercase();
        self.lookup_lower_bytes(&lower)
    }

    pub(crate) fn intern(&mut self, label: &str) -> u32 {
        let lower_owned;
        let lower: &str = if label.bytes().any(|b| b.is_ascii_uppercase()) {
            lower_owned = label.to_ascii_lowercase();
            &lower_owned
        } else {
            label
        };

        let hash = self.hasher.hash_one(lower.as_bytes());
        if let Some(entry) = self.buckets.get(&hash) {
            match entry {
                BucketEntry::Single(id) if self.slice(*id) == lower => return *id,
                BucketEntry::Multi(ids) => {
                    if let Some(&id) = ids.iter().find(|&&id| self.slice(id) == lower) {
                        return id;
                    }
                }
                BucketEntry::Single(_) => {}
            }
        }

        let id = u32::try_from(self.spans.len()).unwrap_or(u32::MAX - 1);
        let start = u32::try_from(self.buf.len()).unwrap_or(u32::MAX);
        let len = u32::try_from(lower.len()).unwrap_or(u32::MAX);
        self.buf.push_str(lower);
        self.spans.push((start, len));

        match self.buckets.get_mut(&hash) {
            Some(BucketEntry::Single(prev)) => {
                let first = *prev;
                self.buckets
                    .insert(hash, BucketEntry::Multi(vec![first, id]));
            }
            Some(BucketEntry::Multi(vec)) => {
                vec.push(id);
            }
            None => {
                self.buckets.insert(hash, BucketEntry::Single(id));
            }
        }
        id
    }
}

#[derive(Debug, Default)]
struct BuilderNode {
    children: HashMap<u32, u32, RandomState>,
    rules: Vec<RuleMeta>,
}

#[derive(Debug)]
pub(crate) struct TrieBuilder {
    nodes: Vec<BuilderNode>,
}

impl Default for TrieBuilder {
    fn default() -> Self {
        Self {
            nodes: vec![BuilderNode::default()],
        }
    }
}

impl TrieBuilder {
    pub(crate) fn insert(
        &mut self,
        interner: &mut LabelInterner,
        domain: &str,
        meta: RuleMeta,
    ) -> bool {
        let mut current_idx = 0_usize;
        for label in domain.rsplit('.').filter(|s| !s.is_empty()) {
            let label_id = interner.intern(label);
            if let Some(&next_idx) = self.nodes[current_idx].children.get(&label_id) {
                current_idx = next_idx as usize;
            } else {
                let next_idx = u32::try_from(self.nodes.len()).unwrap_or(u32::MAX);
                self.nodes.push(BuilderNode::default());
                self.nodes[current_idx].children.insert(label_id, next_idx);
                current_idx = next_idx as usize;
            }
        }
        let rules = &mut self.nodes[current_idx].rules;
        if let Some(pos) = rules.iter().position(|r| {
            r.scope == meta.scope && r.rewrite == meta.rewrite && r.conditions == meta.conditions
        }) {
            rules.remove(pos);
            rules.push(meta);
            return false;
        }
        rules.push(meta);
        true
    }

    pub(crate) fn freeze(self) -> FlatTrie {
        if self.nodes.len() <= 1 && self.nodes.first().is_none_or(|n| n.rules.is_empty()) {
            return FlatTrie::default();
        }
        let mut flat_nodes = Vec::with_capacity(self.nodes.len());
        let total_children: usize = self.nodes.iter().map(|n| n.children.len()).sum();
        let total_rules: usize = self.nodes.iter().map(|n| n.rules.len()).sum();
        let mut children = Vec::with_capacity(total_children);
        let mut rules = Vec::with_capacity(total_rules);

        for mut node in self.nodes {
            let children_start = u32::try_from(children.len()).unwrap_or(u32::MAX);
            let children_len = u32::try_from(node.children.len()).unwrap_or(u32::MAX);
            let mut pairs: Vec<(u32, u32)> = node.children.drain().collect();
            pairs.sort_unstable_by_key(|&(label_id, _)| label_id);
            children.extend(pairs);

            let rules_start = u32::try_from(rules.len()).unwrap_or(u32::MAX);
            let rules_len = u32::try_from(node.rules.len()).unwrap_or(u32::MAX);
            rules.extend(node.rules);

            flat_nodes.push(FlatNode {
                children_start,
                children_len,
                rules_start,
                rules_len,
            });
        }

        FlatTrie {
            nodes: flat_nodes.into_boxed_slice(),
            children: children.into_boxed_slice(),
            rules: rules.into_boxed_slice(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct FlatNode {
    children_start: u32,
    children_len: u32,
    rules_start: u32,
    rules_len: u32,
}

#[derive(Debug, Default)]
pub(crate) struct FlatTrie {
    nodes: Box<[FlatNode]>,
    children: Box<[(u32, u32)]>,
    rules: Box<[RuleMeta]>,
}

impl FlatTrie {
    #[inline]
    fn find_child(&self, node: &FlatNode, label_id: u32) -> Option<usize> {
        let start = node.children_start as usize;
        let len = node.children_len as usize;
        if len == 0 {
            return None;
        }
        let slice = &self.children[start..start + len];
        if len <= 8 {
            for &(id, child_idx) in slice {
                if id == label_id {
                    return Some(child_idx as usize);
                }
                if id > label_id {
                    return None;
                }
            }
            None
        } else {
            slice
                .binary_search_by_key(&label_id, |&(id, _)| id)
                .ok()
                .map(|pos| slice[pos].1 as usize)
        }
    }

    pub(crate) fn match_label_ids<'a>(
        &'a self,
        label_ids: &[Option<u32>],
        clean_domain: &str,
        ctx: &FilterQueryContext<'_>,
        prefer_rewrite_qtype: bool,
    ) -> Option<&'a RuleMeta> {
        if self.nodes.is_empty() || label_ids.is_empty() {
            return None;
        }
        let mut current_idx = 0_usize;
        let mut best: Option<&RuleMeta> = None;
        let mut best_qtype_hit = false;
        let last_pos = label_ids.len() - 1;

        for (idx, maybe_id) in label_ids.iter().enumerate() {
            let Some(label_id) = *maybe_id else {
                break;
            };
            let Some(next_idx) = self.find_child(&self.nodes[current_idx], label_id) else {
                break;
            };
            current_idx = next_idx;
            let node = &self.nodes[current_idx];
            if node.rules_len == 0 {
                continue;
            }
            let is_exact = idx == last_pos;
            let r_start = node.rules_start as usize;
            let r_end = r_start + node.rules_len as usize;
            for meta in &self.rules[r_start..r_end] {
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
