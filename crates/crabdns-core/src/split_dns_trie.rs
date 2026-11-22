use std::collections::HashMap;

use foldhash::fast::RandomState;

use crate::filter_trie::LabelInterner;

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
    pub fn matches(&self, domain: &str) -> bool {
        if self.nodes.is_empty() {
            return false;
        }
        let mut node_idx = 0_usize;
        for label in domain.rsplit('.').filter(|s| !s.is_empty()) {
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
