use std::sync::Arc;

use super::*;
use crate::models::MAX_STAT_KEYS;
use chrono::Utc;
use crabdns_core::QueryProtocol;
use tokio::sync::{broadcast, mpsc};

#[test]
fn test_fjall_storage_roundtrip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = StorageEngine::open(dir.path()).expect("open fjall");

    let events = vec![
        QueryEvent {
            timestamp: Utc::now(),
            client_ip: "127.0.0.1".to_string(),
            client_name: None,
            client_id: None,
            profile_id: None,
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
            client_id: None,
            profile_id: None,
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
        client_id: None,
        profile_id: None,
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
        safesearch_enabled: None,
        upstream_policy: crabdns_core::UpstreamPolicy::default(),
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
        safesearch_enabled: None,
        upstream_policy: crabdns_core::UpstreamPolicy::default(),
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
        client_id: None,
        profile_id: Some("cli-1".to_string()),
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

#[test]
fn test_bounded_count_map_decays_and_admits_new_hot_keys() {
    let map = BoundedCountMap::new();
    for _ in 0..50 {
        map.increment("hot-old.test");
    }
    for i in 0..MAX_STAT_KEYS {
        map.increment(&format!("cold-{i}.test"));
    }
    assert!(map.len() <= MAX_STAT_KEYS);
    for _ in 0..30 {
        map.increment("hot-new.test");
    }
    assert!(map.len() <= MAX_STAT_KEYS);
    let top = map.top_n(5);
    assert!(top.iter().any(|item| item.name == "hot-old.test"));
    assert!(top.iter().any(|item| item.name == "hot-new.test"));
}

#[test]
fn test_compiled_logs_filter_matches_all_dimensions() {
    let event = QueryEvent {
        timestamp: Utc::now(),
        client_ip: "192.168.10.25".to_string(),
        client_name: Some("MacBook-Pro".to_string()),
        client_id: Some("laptop-1".to_string()),
        profile_id: None,
        protocol: QueryProtocol::Doh,
        domain: "Ads.Tracker.Example".to_string(),
        qtype: "AAAA".to_string(),
        outcome: QueryOutcome::Blocked,
        matched_rule: Some("||tracker.example^".to_string()),
        matched_list: Some("EasyList".to_string()),
        upstream: None,
        elapsed_us: 15,
        rcode: "NOERROR".to_string(),
        answers: vec!["0.0.0.0".to_string()],
    };

    assert!(LogsFilter::default().compile().matches(&event));

    let full_match = LogsFilter {
        search: Some("  tracker "),
        outcome: Some("BLOCKED"),
        protocol: Some("DoH"),
        qtype: Some("aaaa"),
        client: Some("laptop-1"),
    }
    .compile();
    assert!(full_match.matches(&event));

    let wrong_search = LogsFilter {
        search: Some("missing.test"),
        ..LogsFilter::default()
    }
    .compile();
    assert!(!wrong_search.matches(&event));

    let wrong_outcome = LogsFilter {
        outcome: Some("forwarded"),
        ..LogsFilter::default()
    }
    .compile();
    assert!(!wrong_outcome.matches(&event));

    let wrong_protocol = LogsFilter {
        protocol: Some("udp"),
        ..LogsFilter::default()
    }
    .compile();
    assert!(!wrong_protocol.matches(&event));

    let wrong_qtype = LogsFilter {
        qtype: Some("A"),
        ..LogsFilter::default()
    }
    .compile();
    assert!(!wrong_qtype.matches(&event));

    let wrong_client = LogsFilter {
        client: Some("10.0.0.1"),
        ..LogsFilter::default()
    }
    .compile();
    assert!(!wrong_client.matches(&event));
}

#[test]
fn test_fjall_presets_and_disk_quota() {
    use crate::models::{FjallPreset, resolve_auto_profile};
    use crabdns_core::StorageProfile;

    assert_eq!(
        resolve_auto_profile(true, Some(16_384)),
        StorageProfile::Performance
    );
    assert_eq!(
        resolve_auto_profile(false, Some(2_048)),
        StorageProfile::Balanced
    );
    assert_eq!(
        resolve_auto_profile(true, Some(512)),
        StorageProfile::Embedded
    );

    let perf = FjallPreset::from_profile(StorageProfile::Performance);
    let emb = FjallPreset::from_profile(StorageProfile::Embedded);
    assert!(perf.cache_bytes > emb.cache_bytes);
    assert!(perf.max_journal_bytes > emb.max_journal_bytes);
    assert!(perf.worker_threads >= emb.worker_threads);

    let dir = tempfile::tempdir().expect("tempdir");
    let storage = StorageEngine::open_with_profile(dir.path(), StorageProfile::Balanced)
        .expect("open balanced storage");
    assert_eq!(
        storage.effective_storage_profile(),
        StorageProfile::Balanced
    );
    assert!(storage.available_disk_bytes().is_some());
    assert_eq!(
        storage
            .prune_with_disk_quota(64 * 1024 * 1024, 1)
            .expect("prune quota"),
        0
    );
    assert!(!storage.is_disk_pressure_active());
}
