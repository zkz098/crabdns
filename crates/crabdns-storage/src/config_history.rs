use std::time::{SystemTime, UNIX_EPOCH};

use crabdns_core::{Config, RuntimeConfig};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::StorageEngine;
use crate::models::Result;

const CONFIG_HISTORY_PREFIX: &[u8] = b"cfg_hist:";
const SPLIT_LIST_PREFIX: &[u8] = b"split_list:";
const SPLIT_LIST_META_PREFIX: &[u8] = b"split_list_meta:";
const MAX_CONFIG_HISTORY: usize = 20;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
pub struct SplitDnsListMeta {
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(type = "number | null")]
    pub last_synced_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(type = "number | null")]
    pub last_attempt_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(default)]
    pub entry_count: usize,
    #[serde(default)]
    #[ts(type = "number")]
    pub bytes: u64,
    #[serde(default)]
    pub not_modified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ConfigSnapshotMeta {
    pub id: String,
    pub created_at: i64,
    pub reason: String,
    pub listen_dns: String,
    pub upstreams_count: usize,
    pub split_dns_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConfigSnapshotRecord {
    meta: ConfigSnapshotMeta,
    config: RuntimeConfig,
}

fn encode_history_key(id: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(CONFIG_HISTORY_PREFIX.len() + 8);
    key.extend_from_slice(CONFIG_HISTORY_PREFIX);
    key.extend_from_slice(&id.to_be_bytes());
    key
}

fn decode_history_id(key: &[u8]) -> Option<u64> {
    let suffix = key.strip_prefix(CONFIG_HISTORY_PREFIX)?;
    let bytes: [u8; 8] = suffix.try_into().ok()?;
    Some(u64::from_be_bytes(bytes))
}

fn unix_now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}

impl StorageEngine {
    /// Records a configuration snapshot and prunes entries beyond `MAX_CONFIG_HISTORY`.
    pub fn record_config_snapshot(
        &self,
        config: &Config,
        reason: &str,
    ) -> Result<ConfigSnapshotMeta> {
        let mut keys = Vec::new();
        let mut last_id = 0_u64;
        for guard in self.meta.prefix(CONFIG_HISTORY_PREFIX) {
            let key = guard.key()?;
            if let Some(id) = decode_history_id(&key) {
                last_id = last_id.max(id);
                keys.push(key);
            }
        }

        let now_ms = unix_now_ms();
        let next_id = now_ms.max(last_id.saturating_add(1));
        let created_at = i64::try_from(now_ms / 1000).unwrap_or(i64::MAX);
        let meta = ConfigSnapshotMeta {
            id: next_id.to_string(),
            created_at,
            reason: reason.to_string(),
            listen_dns: config.bootstrap.listen_dns.to_string(),
            upstreams_count: config.upstreams.len(),
            split_dns_count: config.split_dns.len(),
        };
        let record = ConfigSnapshotRecord {
            meta: meta.clone(),
            config: config.runtime.clone(),
        };
        let bytes = serde_json::to_vec(&record)?;
        self.meta.insert(encode_history_key(next_id), bytes)?;

        let total = keys.len().saturating_add(1);
        if total > MAX_CONFIG_HISTORY {
            let to_remove = total - MAX_CONFIG_HISTORY;
            for old_key in keys.into_iter().take(to_remove) {
                self.meta.remove(old_key)?;
            }
        }

        Ok(meta)
    }

    /// Lists saved configuration snapshots, newest first.
    pub fn list_config_history(&self) -> Result<Vec<ConfigSnapshotMeta>> {
        let mut out = Vec::new();
        for guard in self.meta.prefix(CONFIG_HISTORY_PREFIX) {
            let val = guard.value()?;
            if let Ok(record) = serde_json::from_slice::<ConfigSnapshotRecord>(&val) {
                out.push(record.meta);
            }
        }
        out.reverse();
        Ok(out)
    }

    /// Loads a specific configuration snapshot by ID.
    pub fn get_config_snapshot(&self, id: &str) -> Result<Option<RuntimeConfig>> {
        let Ok(parsed_id) = id.trim().parse::<u64>() else {
            return Ok(None);
        };
        match self.meta.get(encode_history_key(parsed_id))? {
            Some(bytes) => {
                let record = serde_json::from_slice::<ConfigSnapshotRecord>(&bytes)?;
                Ok(Some(record.config))
            }
            None => Ok(None),
        }
    }

    /// Caches a downloaded remote split-DNS domain list by its URL.
    pub fn save_split_dns_list(&self, url: &str, content: &str) -> Result<()> {
        let mut key = Vec::with_capacity(SPLIT_LIST_PREFIX.len() + url.len());
        key.extend_from_slice(SPLIT_LIST_PREFIX);
        key.extend_from_slice(url.trim().as_bytes());
        self.meta.insert(key, content.as_bytes())?;
        Ok(())
    }

    /// Loads a cached remote split-DNS domain list by its URL.
    pub fn load_split_dns_list(&self, url: &str) -> Result<Option<String>> {
        let mut key = Vec::with_capacity(SPLIT_LIST_PREFIX.len() + url.len());
        key.extend_from_slice(SPLIT_LIST_PREFIX);
        key.extend_from_slice(url.trim().as_bytes());
        match self.meta.get(key)? {
            Some(bytes) => Ok(Some(String::from_utf8_lossy(&bytes).into_owned())),
            None => Ok(None),
        }
    }

    /// Saves synchronization metadata (`ETag`, Last-Modified, timestamps, error) for a remote split-DNS list URL.
    pub fn save_split_dns_list_meta(&self, meta: &SplitDnsListMeta) -> Result<()> {
        let mut key = Vec::with_capacity(SPLIT_LIST_META_PREFIX.len() + meta.url.len());
        key.extend_from_slice(SPLIT_LIST_META_PREFIX);
        key.extend_from_slice(meta.url.trim().as_bytes());
        let bytes = serde_json::to_vec(meta)?;
        self.meta.insert(key, bytes)?;
        Ok(())
    }

    /// Loads synchronization metadata for a remote split-DNS list URL.
    pub fn load_split_dns_list_meta(&self, url: &str) -> Result<Option<SplitDnsListMeta>> {
        let mut key = Vec::with_capacity(SPLIT_LIST_META_PREFIX.len() + url.len());
        key.extend_from_slice(SPLIT_LIST_META_PREFIX);
        key.extend_from_slice(url.trim().as_bytes());
        match self.meta.get(key)? {
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Lists all persisted split-DNS list synchronization metadata records.
    pub fn list_split_dns_list_metas(&self) -> Result<Vec<SplitDnsListMeta>> {
        let mut out = Vec::new();
        for guard in self.meta.prefix(SPLIT_LIST_META_PREFIX) {
            let val = guard.value()?;
            if let Ok(meta) = serde_json::from_slice::<SplitDnsListMeta>(&val) {
                out.push(meta);
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_history_record_list_prune_and_get() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = StorageEngine::open(dir.path()).expect("open storage");

        let mut last_id = String::new();
        for i in 0..25_u32 {
            let cfg = Config {
                runtime: RuntimeConfig {
                    cache_size: u64::from(1000 + i),
                    ..RuntimeConfig::default()
                },
                ..Config::default()
            };
            let meta = storage
                .record_config_snapshot(&cfg, &format!("update_{i}"))
                .expect("record");
            last_id = meta.id;
        }

        let list = storage.list_config_history().expect("list");
        assert_eq!(list.len(), MAX_CONFIG_HISTORY);
        assert_eq!(list[0].id, last_id);
        assert_eq!(list[0].reason, "update_24");
        assert_eq!(list[MAX_CONFIG_HISTORY - 1].reason, "update_5");

        let loaded = storage
            .get_config_snapshot(&last_id)
            .expect("get")
            .expect("present");
        assert_eq!(loaded.cache_size, 1024);
        assert!(
            storage
                .get_config_snapshot("invalid")
                .expect("get")
                .is_none()
        );
    }

    #[test]
    fn test_split_dns_list_meta_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = StorageEngine::open(dir.path()).expect("open storage");

        let meta = SplitDnsListMeta {
            url: "https://example.invalid/cn.txt".to_string(),
            etag: Some("\"abc123\"".to_string()),
            last_modified: Some("Wed, 21 Oct 2015 07:28:00 GMT".to_string()),
            last_synced_at: Some(1_700_000_000),
            last_attempt_at: Some(1_700_000_100),
            last_error: Some("timeout".to_string()),
            entry_count: 42,
            bytes: 1024,
            not_modified: true,
        };
        storage.save_split_dns_list_meta(&meta).expect("save meta");

        let loaded = storage
            .load_split_dns_list_meta("  https://example.invalid/cn.txt ")
            .expect("load")
            .expect("present");
        assert_eq!(loaded, meta);

        let all = storage.list_split_dns_list_metas().expect("list");
        assert_eq!(all, vec![meta]);
    }

    #[test]
    fn test_runtime_config_loads_from_legacy_full_config_json() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = StorageEngine::open(dir.path()).expect("open storage");

        let mut legacy = Config::default();
        legacy.bootstrap.listen_dns = "127.0.0.1:25353".parse().unwrap();
        legacy.cf_cdn.enabled = true;
        legacy.cache_size = 4096;

        let legacy_bytes = serde_json::to_vec(&legacy).expect("serialize legacy full config");
        storage
            .meta
            .insert(crate::models::KEY_RUNTIME_CONFIG, legacy_bytes)
            .expect("insert legacy bytes");

        let loaded = storage.load_config().expect("load").expect("present");
        assert!(loaded.cf_cdn.enabled);
        assert_eq!(loaded.cache_size, 4096);
    }
}
