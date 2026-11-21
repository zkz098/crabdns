use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crabdns_core::{
    ClientGroup, ClientProfile, Config, PersistedCacheEntry, QueryEvent, QueryOutcome,
    QueryProtocol,
};
use dashmap::DashMap;
use fjall::{Database, Keyspace, KeyspaceCreateOptions};
use foldhash::fast::RandomState;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{broadcast, mpsc};
use ts_rs::TS;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("fjall error: {0}")]
    Fjall(#[from] fjall::Error),

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, StorageError>;

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct TopItem {
    pub name: String,
    #[ts(type = "number")]
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct StatsSnapshot {
    #[ts(type = "number")]
    pub total_queries: u64,
    #[ts(type = "number")]
    pub blocked_queries: u64,
    #[ts(type = "number")]
    pub cached_queries: u64,
    #[ts(type = "number")]
    pub rewritten_queries: u64,
    #[ts(type = "number")]
    pub error_queries: u64,
    pub top_domains: Vec<TopItem>,
    pub top_blocked: Vec<TopItem>,
    pub top_clients: Vec<TopItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct FilterSubscription {
    pub id: String,
    pub name: String,
    pub url: String,
    pub enabled: bool,
    pub rule_count: usize,
    pub last_updated: Option<chrono::DateTime<chrono::Utc>>,
    pub last_error: Option<String>,
}

const KEY_CUSTOM_RULES: &[u8] = b"custom_rules";
const KEY_CUSTOM_RULES_ENABLED: &[u8] = b"custom_rules_enabled";
const KEY_SUBSCRIPTIONS: &[u8] = b"subscriptions";
const KEY_COUNTERS: &[u8] = b"counters";
const KEY_RUNTIME_CONFIG: &[u8] = b"runtime_config";
const KEY_CLIENTS: &[u8] = b"clients";
const KEY_CLIENT_GROUPS: &[u8] = b"client_groups";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PersistedCounters {
    total: u64,
    blocked: u64,
    cached: u64,
    rewritten: u64,
    error: u64,
}

pub struct StorageEngine {
    db: Database,
    logs: Keyspace,
    meta: Keyspace,
    sub_contents: Keyspace,
    dns_cache: Keyspace,
    seq: AtomicU64,
    total_queries: AtomicU64,
    blocked_queries: AtomicU64,
    cached_queries: AtomicU64,
    rewritten_queries: AtomicU64,
    error_queries: AtomicU64,
    domain_counts: DashMap<String, u64, RandomState>,
    blocked_counts: DashMap<String, u64, RandomState>,
    client_counts: DashMap<String, u64, RandomState>,
}

impl StorageEngine {
    pub fn open(data_dir: &Path) -> Result<Self> {
        let db = Database::builder(data_dir.join("fjall")).open()?;
        let logs = db.keyspace("logs", KeyspaceCreateOptions::default)?;
        let meta = db.keyspace("meta", KeyspaceCreateOptions::default)?;
        let sub_contents = db.keyspace("sub_contents", KeyspaceCreateOptions::default)?;
        let dns_cache = db.keyspace("dns_cache", KeyspaceCreateOptions::default)?;

        let persisted = match meta.get(KEY_COUNTERS)? {
            Some(bytes) => serde_json::from_slice::<PersistedCounters>(&bytes).unwrap_or_default(),
            None => PersistedCounters::default(),
        };

        Ok(Self {
            db,
            logs,
            meta,
            sub_contents,
            dns_cache,
            seq: AtomicU64::new(0),
            total_queries: AtomicU64::new(persisted.total),
            blocked_queries: AtomicU64::new(persisted.blocked),
            cached_queries: AtomicU64::new(persisted.cached),
            rewritten_queries: AtomicU64::new(persisted.rewritten),
            error_queries: AtomicU64::new(persisted.error),
            domain_counts: DashMap::with_hasher(RandomState::default()),
            blocked_counts: DashMap::with_hasher(RandomState::default()),
            client_counts: DashMap::with_hasher(RandomState::default()),
        })
    }

    pub fn record_batch(&self, events: &[QueryEvent]) -> Result<()> {
        if events.is_empty() {
            return Ok(());
        }

        let mut batch = self.db.batch();
        for event in events {
            self.update_counters(event);
            let ts_ms = event.timestamp.timestamp_millis().max(0).cast_unsigned();
            let seq = self.seq.fetch_add(1, Ordering::Relaxed);
            let key = encode_log_key(ts_ms, seq);
            let value = serde_json::to_vec(event)?;
            batch.insert(&self.logs, key, value);
        }

        let counters = PersistedCounters {
            total: self.total_queries.load(Ordering::Relaxed),
            blocked: self.blocked_queries.load(Ordering::Relaxed),
            cached: self.cached_queries.load(Ordering::Relaxed),
            rewritten: self.rewritten_queries.load(Ordering::Relaxed),
            error: self.error_queries.load(Ordering::Relaxed),
        };
        batch.insert(&self.meta, KEY_COUNTERS, serde_json::to_vec(&counters)?);
        batch.commit()?;
        Ok(())
    }

    fn update_counters(&self, event: &QueryEvent) {
        self.total_queries.fetch_add(1, Ordering::Relaxed);
        match event.outcome {
            QueryOutcome::Blocked => {
                self.blocked_queries.fetch_add(1, Ordering::Relaxed);
                increment_map(&self.blocked_counts, &event.domain);
            }
            QueryOutcome::Cached => {
                self.cached_queries.fetch_add(1, Ordering::Relaxed);
            }
            QueryOutcome::Rewritten => {
                self.rewritten_queries.fetch_add(1, Ordering::Relaxed);
            }
            QueryOutcome::Error => {
                self.error_queries.fetch_add(1, Ordering::Relaxed);
            }
            QueryOutcome::Forwarded => {}
        }
        increment_map(&self.domain_counts, &event.domain);
        increment_map(&self.client_counts, &event.client_ip);
    }

    pub fn query_logs(
        &self,
        limit: usize,
        search: Option<&str>,
        outcome_filter: Option<&str>,
    ) -> Result<Vec<QueryEvent>> {
        let mut results = Vec::with_capacity(limit.min(500));
        let needle = search.map(str::to_ascii_lowercase);

        for guard in self.logs.iter().rev() {
            let val = guard.value()?;
            let Ok(event) = serde_json::from_slice::<QueryEvent>(&val) else {
                continue;
            };
            if let Some(ref q) = needle
                && !event_matches_search(&event, q)
            {
                continue;
            }
            if let Some(expected) = outcome_filter
                && !expected.is_empty()
                && outcome_label(&event.outcome) != expected
            {
                continue;
            }
            results.push(event);
            if results.len() >= limit {
                break;
            }
        }
        Ok(results)
    }

    pub fn stats_snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            total_queries: self.total_queries.load(Ordering::Relaxed),
            blocked_queries: self.blocked_queries.load(Ordering::Relaxed),
            cached_queries: self.cached_queries.load(Ordering::Relaxed),
            rewritten_queries: self.rewritten_queries.load(Ordering::Relaxed),
            error_queries: self.error_queries.load(Ordering::Relaxed),
            top_domains: top_n(&self.domain_counts, 10),
            top_blocked: top_n(&self.blocked_counts, 10),
            top_clients: top_n(&self.client_counts, 10),
        }
    }

    pub fn save_custom_rules(&self, rules_text: &str) -> Result<()> {
        self.meta.insert(KEY_CUSTOM_RULES, rules_text.as_bytes())?;
        Ok(())
    }

    pub fn load_custom_rules(&self) -> Result<Option<String>> {
        match self.meta.get(KEY_CUSTOM_RULES)? {
            Some(bytes) => Ok(Some(String::from_utf8_lossy(&bytes).into_owned())),
            None => Ok(None),
        }
    }

    pub fn save_custom_rules_enabled(&self, enabled: bool) -> Result<()> {
        let byte = [u8::from(enabled)];
        self.meta.insert(KEY_CUSTOM_RULES_ENABLED, byte)?;
        Ok(())
    }

    pub fn load_custom_rules_enabled(&self) -> Result<bool> {
        match self.meta.get(KEY_CUSTOM_RULES_ENABLED)? {
            Some(bytes) => Ok(bytes.first().copied().unwrap_or(1) != 0),
            None => Ok(true),
        }
    }

    pub fn list_subscriptions(&self) -> Result<Vec<FilterSubscription>> {
        match self.meta.get(KEY_SUBSCRIPTIONS)? {
            Some(bytes) => Ok(serde_json::from_slice(&bytes)?),
            None => Ok(Vec::new()),
        }
    }

    pub fn save_subscriptions(&self, subs: &[FilterSubscription]) -> Result<()> {
        let bytes = serde_json::to_vec(subs)?;
        self.meta.insert(KEY_SUBSCRIPTIONS, bytes)?;
        Ok(())
    }

    pub fn save_subscription_content(&self, id: &str, content: &str) -> Result<()> {
        self.sub_contents
            .insert(id.as_bytes(), content.as_bytes())?;
        Ok(())
    }

    pub fn load_subscription_content(&self, id: &str) -> Result<Option<String>> {
        match self.sub_contents.get(id.as_bytes())? {
            Some(bytes) => Ok(Some(String::from_utf8_lossy(&bytes).into_owned())),
            None => Ok(None),
        }
    }

    pub fn delete_subscription_content(&self, id: &str) -> Result<()> {
        self.sub_contents.remove(id.as_bytes())?;
        Ok(())
    }

    pub fn load_enabled_subscription_contents(&self) -> Result<Vec<String>> {
        let named = self.load_enabled_named_subscription_contents()?;
        Ok(named.into_iter().map(|(_, text)| text).collect())
    }

    pub fn load_enabled_named_subscription_contents(&self) -> Result<Vec<(String, String)>> {
        let subs = self.list_subscriptions()?;
        let mut contents = Vec::new();
        for sub in subs {
            if sub.enabled
                && let Some(text) = self.load_subscription_content(&sub.id)?
            {
                contents.push((sub.name, text));
            }
        }
        Ok(contents)
    }

    pub fn list_clients(&self) -> Result<Vec<ClientProfile>> {
        match self.meta.get(KEY_CLIENTS)? {
            Some(bytes) => Ok(serde_json::from_slice(&bytes)?),
            None => Ok(Vec::new()),
        }
    }

    pub fn save_clients(&self, clients: &[ClientProfile]) -> Result<()> {
        let bytes = serde_json::to_vec(clients)?;
        self.meta.insert(KEY_CLIENTS, bytes)?;
        Ok(())
    }

    pub fn list_client_groups(&self) -> Result<Vec<ClientGroup>> {
        match self.meta.get(KEY_CLIENT_GROUPS)? {
            Some(bytes) => Ok(serde_json::from_slice(&bytes)?),
            None => Ok(Vec::new()),
        }
    }

    pub fn save_client_groups(&self, groups: &[ClientGroup]) -> Result<()> {
        let bytes = serde_json::to_vec(groups)?;
        self.meta.insert(KEY_CLIENT_GROUPS, bytes)?;
        Ok(())
    }

    pub fn client_query_counts(&self) -> Vec<(String, u64)> {
        let mut out: Vec<(String, u64)> = self
            .client_counts
            .iter()
            .map(|e| (e.key().clone(), *e.value()))
            .collect();
        out.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
        out
    }

    pub fn save_config(&self, config: &Config) -> Result<()> {
        let bytes = serde_json::to_vec(config)?;
        self.meta.insert(KEY_RUNTIME_CONFIG, bytes)?;
        Ok(())
    }

    pub fn load_config(&self) -> Result<Option<Config>> {
        match self.meta.get(KEY_RUNTIME_CONFIG)? {
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            None => Ok(None),
        }
    }

    pub fn prune_older_than(&self, cutoff_ms: u64) -> Result<usize> {
        const CHUNK_SIZE: usize = 4096;
        let end_key = encode_log_key(cutoff_ms, 0);
        let mut removed = 0_usize;
        loop {
            let mut keys = Vec::new();
            for guard in self.logs.range(..end_key) {
                keys.push(guard.key()?);
                if keys.len() >= CHUNK_SIZE {
                    break;
                }
            }
            let chunk_len = keys.len();
            if chunk_len == 0 {
                break;
            }
            let mut batch = self.db.batch();
            for k in keys {
                batch.remove(&self.logs, k);
            }
            batch.commit()?;
            removed += chunk_len;
            if chunk_len < CHUNK_SIZE {
                break;
            }
        }
        Ok(removed)
    }

    pub fn clear_dns_cache(&self) -> Result<()> {
        let mut batch = self.db.batch();
        for guard in self.dns_cache.iter() {
            let key = guard.key()?;
            batch.remove(&self.dns_cache, key);
        }
        batch.commit()?;
        Ok(())
    }

    pub fn save_dns_cache(&self, entries: &[PersistedCacheEntry]) -> Result<usize> {
        let mut batch = self.db.batch();
        for guard in self.dns_cache.iter() {
            let key = guard.key()?;
            batch.remove(&self.dns_cache, key);
        }
        let mut saved = 0;
        for (idx, entry) in entries.iter().enumerate() {
            let key = idx.to_be_bytes();
            let val = serde_json::to_vec(entry)?;
            batch.insert(&self.dns_cache, key, val);
            saved += 1;
        }
        batch.commit()?;
        Ok(saved)
    }

    pub fn load_dns_cache(
        &self,
        now_unix_secs: i64,
        stale_grace_secs: i64,
    ) -> Result<Vec<PersistedCacheEntry>> {
        let mut entries = Vec::new();
        for guard in self.dns_cache.iter() {
            let val = guard.value()?;
            if let Ok(entry) = serde_json::from_slice::<PersistedCacheEntry>(&val)
                && entry.expires_at_unix_secs + stale_grace_secs > now_unix_secs
            {
                entries.push(entry);
            }
        }
        Ok(entries)
    }
}

fn encode_log_key(ts_ms: u64, seq: u64) -> [u8; 16] {
    let mut key = [0_u8; 16];
    key[0..8].copy_from_slice(&ts_ms.to_be_bytes());
    key[8..16].copy_from_slice(&seq.to_be_bytes());
    key
}

fn increment_map(map: &DashMap<String, u64, RandomState>, key: &str) {
    if let Some(mut entry) = map.get_mut(key) {
        *entry += 1;
    } else if map.len() < 10_000 {
        map.insert(key.to_string(), 1);
    }
}

fn top_n(map: &DashMap<String, u64, RandomState>, limit: usize) -> Vec<TopItem> {
    let mut items: Vec<TopItem> = map
        .iter()
        .map(|entry| TopItem {
            name: entry.key().clone(),
            count: *entry.value(),
        })
        .collect();
    items.sort_by_key(|a| std::cmp::Reverse(a.count));
    items.truncate(limit);
    items
}

fn protocol_label(protocol: QueryProtocol) -> &'static str {
    match protocol {
        QueryProtocol::Udp => "udp",
        QueryProtocol::Tcp => "tcp",
        QueryProtocol::Dot => "dot",
        QueryProtocol::Doh => "doh",
    }
}

fn event_matches_search(event: &QueryEvent, needle: &str) -> bool {
    event.domain.to_ascii_lowercase().contains(needle)
        || event.client_ip.contains(needle)
        || event
            .client_name
            .as_deref()
            .is_some_and(|n| n.to_ascii_lowercase().contains(needle))
        || event
            .matched_list
            .as_deref()
            .is_some_and(|l| l.to_ascii_lowercase().contains(needle))
        || event
            .answers
            .iter()
            .any(|a| a.to_ascii_lowercase().contains(needle))
        || protocol_label(event.protocol).contains(needle)
}

fn outcome_label(outcome: &QueryOutcome) -> &'static str {
    match outcome {
        QueryOutcome::Forwarded => "forwarded",
        QueryOutcome::Cached => "cached",
        QueryOutcome::Blocked => "blocked",
        QueryOutcome::Rewritten => "rewritten",
        QueryOutcome::Error => "error",
    }
}

pub fn spawn_log_sink(
    storage: Arc<StorageEngine>,
    mut rx: mpsc::Receiver<QueryEvent>,
    live_tx: broadcast::Sender<QueryEvent>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut buffer = Vec::with_capacity(256);
        let mut interval = tokio::time::interval(Duration::from_millis(250));

        loop {
            tokio::select! {
                maybe_event = rx.recv() => {
                    if let Some(event) = maybe_event {
                        let _ = live_tx.send(event.clone());
                        buffer.push(event);
                        if buffer.len() >= 256 {
                            flush_buffer(&storage, &mut buffer);
                        }
                    } else {
                        flush_buffer(&storage, &mut buffer);
                        break;
                    }
                }
                _ = interval.tick() => {
                    flush_buffer(&storage, &mut buffer);
                }
            }
        }
    })
}

fn flush_buffer(storage: &StorageEngine, buffer: &mut Vec<QueryEvent>) {
    if buffer.is_empty() {
        return;
    }
    if let Err(err) = storage.record_batch(buffer) {
        tracing::error!(error = %err, "failed to flush query logs to fjall");
    }
    buffer.clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_fjall_storage_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = StorageEngine::open(dir.path()).expect("open fjall");

        let events = vec![
            QueryEvent {
                timestamp: Utc::now(),
                client_ip: "127.0.0.1".to_string(),
                client_name: None,
                protocol: QueryProtocol::Udp,
                domain: "ads.example.com".to_string(),
                qtype: "A".to_string(),
                outcome: QueryOutcome::Blocked,
                matched_rule: Some("||ads.example.com^".to_string()),
                matched_list: Some("custom".to_string()),
                upstream: None,
                elapsed_us: 42,
                rcode: "NOERROR".to_string(),
                answers: vec!["0.0.0.0".to_string()],
            },
            QueryEvent {
                timestamp: Utc::now(),
                client_ip: "127.0.0.1".to_string(),
                client_name: Some("nas-box".to_string()),
                protocol: QueryProtocol::Doh,
                domain: "rust-lang.org".to_string(),
                qtype: "AAAA".to_string(),
                outcome: QueryOutcome::Forwarded,
                matched_rule: None,
                matched_list: None,
                upstream: Some("udp://1.1.1.1:53".to_string()),
                elapsed_us: 1200,
                rcode: "NOERROR".to_string(),
                answers: vec!["2606:4700::1".to_string()],
            },
        ];

        storage.record_batch(&events).expect("record batch");
        let logs = storage.query_logs(10, None, None).expect("query logs");
        assert_eq!(logs.len(), 2);

        let blocked = storage
            .query_logs(10, None, Some("blocked"))
            .expect("filter blocked");
        assert_eq!(blocked.len(), 1);
        assert_eq!(blocked[0].domain, "ads.example.com");

        let stats = storage.stats_snapshot();
        assert_eq!(stats.total_queries, 2);
        assert_eq!(stats.blocked_queries, 1);

        storage
            .save_custom_rules("||test.com^\n")
            .expect("save rules");
        assert_eq!(
            storage.load_custom_rules().expect("load rules").as_deref(),
            Some("||test.com^\n")
        );

        let future_cutoff = Utc::now().timestamp_millis().cast_unsigned() + 60_000;
        let pruned = storage.prune_older_than(future_cutoff).expect("prune");
        assert_eq!(pruned, 2);
        assert!(
            storage
                .query_logs(10, None, None)
                .expect("empty")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn test_spawn_log_sink_batches_and_broadcasts() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Arc::new(StorageEngine::open(dir.path()).expect("open fjall"));
        let (tx, rx) = mpsc::channel(16);
        let (live_tx, mut live_rx) = broadcast::channel(16);
        let handle = spawn_log_sink(Arc::clone(&storage), rx, live_tx);

        tx.send(QueryEvent {
            timestamp: Utc::now(),
            client_ip: "10.0.0.5".to_string(),
            client_name: None,
            protocol: QueryProtocol::Udp,
            domain: "sink.example.com".to_string(),
            qtype: "A".to_string(),
            outcome: QueryOutcome::Cached,
            matched_rule: None,
            matched_list: None,
            upstream: Some("cache".to_string()),
            elapsed_us: 10,
            rcode: "NOERROR".to_string(),
            answers: vec!["1.2.3.4".to_string()],
        })
        .await
        .expect("send");

        let live_ev = live_rx.recv().await.expect("live broadcast");
        assert_eq!(live_ev.domain, "sink.example.com");

        drop(tx);
        handle.await.expect("sink join");
        let logs = storage.query_logs(10, Some("sink"), None).expect("logs");
        assert_eq!(logs.len(), 1);
    }

    #[test]
    fn test_clients_groups_persistence_and_selective_pruning() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = StorageEngine::open(dir.path()).expect("open fjall");

        let groups = vec![ClientGroup {
            id: "grp-1".to_string(),
            name: "Family".to_string(),
            description: "Home devices".to_string(),
            blocking_enabled: true,
            use_global_rules: true,
            custom_rules: "||ads.test^".to_string(),
            upstreams: vec![],
            block_mode: None,
            cname_cloaking_blocking: None,
        }];
        let clients = vec![ClientProfile {
            id: "cli-1".to_string(),
            name: "Living Room TV".to_string(),
            identifiers: vec!["192.168.1.55".to_string()],
            group_id: Some("grp-1".to_string()),
            blocking_enabled: None,
            use_global_rules: None,
            custom_rules: String::new(),
            upstreams: vec![],
            block_mode: None,
            tags: vec!["tv".to_string()],
        }];
        storage.save_client_groups(&groups).expect("save groups");
        storage.save_clients(&clients).expect("save clients");
        assert_eq!(storage.list_client_groups().unwrap(), groups);
        assert_eq!(storage.list_clients().unwrap(), clients);

        let now = Utc::now();
        let old_event = QueryEvent {
            timestamp: now - chrono::TimeDelta::hours(48),
            client_ip: "192.168.1.55".to_string(),
            client_name: Some("Living Room TV".to_string()),
            protocol: QueryProtocol::Udp,
            domain: "old.example.com".to_string(),
            qtype: "A".to_string(),
            outcome: QueryOutcome::Forwarded,
            matched_rule: None,
            matched_list: None,
            upstream: None,
            elapsed_us: 100,
            rcode: "NOERROR".to_string(),
            answers: vec!["93.184.216.34".to_string()],
        };
        let fresh_event = QueryEvent {
            timestamp: now - chrono::TimeDelta::hours(1),
            domain: "fresh.example.com".to_string(),
            ..old_event.clone()
        };
        storage
            .record_batch(&[old_event, fresh_event])
            .expect("record");

        let cutoff_ms = (now - chrono::TimeDelta::hours(24))
            .timestamp_millis()
            .max(0)
            .cast_unsigned();
        let pruned = storage.prune_older_than(cutoff_ms).expect("prune");
        assert_eq!(pruned, 1);

        let remaining = storage.query_logs(10, None, None).expect("logs");
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].domain, "fresh.example.com");
    }
}
