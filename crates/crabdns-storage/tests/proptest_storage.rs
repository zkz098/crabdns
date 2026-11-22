use chrono::Utc;
use crabdns_core::{QueryEvent, QueryOutcome, QueryProtocol};
use crabdns_storage::StorageEngine;
use proptest::prelude::*;

fn arb_outcome() -> impl Strategy<Value = QueryOutcome> {
    prop_oneof![
        Just(QueryOutcome::Forwarded),
        Just(QueryOutcome::Cached),
        Just(QueryOutcome::Blocked),
        Just(QueryOutcome::Rewritten),
        Just(QueryOutcome::Error),
    ]
}

fn arb_domain() -> impl Strategy<Value = String> {
    "[a-z0-9]{1,8}\\.[a-z]{2,5}"
}

fn arb_client_ip() -> impl Strategy<Value = String> {
    (1_u8..=254, 1_u8..=254).prop_map(|(a, b)| format!("10.0.{a}.{b}"))
}

fn arb_event() -> impl Strategy<Value = QueryEvent> {
    (
        arb_client_ip(),
        arb_domain(),
        prop_oneof![Just("A".to_string()), Just("AAAA".to_string())],
        arb_outcome(),
        any::<u64>(),
    )
        .prop_map(
            |(client_ip, domain, qtype, outcome, elapsed_us)| QueryEvent {
                timestamp: Utc::now(),
                client_ip,
                client_name: None,
                client_id: None,
                profile_id: None,
                protocol: QueryProtocol::Udp,
                domain,
                qtype,
                outcome,
                matched_rule: None,
                matched_list: None,
                upstream: None,
                elapsed_us,
                rcode: "NOERROR".to_string(),
                answers: Vec::new(),
            },
        )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    #[test]
    fn prop_storage_batch_counters_and_log_filters_consistent(
        events in prop::collection::vec(arb_event(), 1..40),
    ) {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = StorageEngine::open(dir.path()).expect("open storage");

        storage.record_batch(&events).expect("record batch");

        let expected_total = events.len() as u64;
        let expected_blocked = events.iter().filter(|e| e.outcome == QueryOutcome::Blocked).count() as u64;
        let expected_cached = events.iter().filter(|e| e.outcome == QueryOutcome::Cached).count() as u64;
        let expected_rewritten = events.iter().filter(|e| e.outcome == QueryOutcome::Rewritten).count() as u64;
        let expected_error = events.iter().filter(|e| e.outcome == QueryOutcome::Error).count() as u64;

        let stats = storage.stats_snapshot();
        prop_assert_eq!(stats.total_queries, expected_total);
        prop_assert_eq!(stats.blocked_queries, expected_blocked);
        prop_assert_eq!(stats.cached_queries, expected_cached);
        prop_assert_eq!(stats.rewritten_queries, expected_rewritten);
        prop_assert_eq!(stats.error_queries, expected_error);

        let all_logs = storage.query_logs(events.len() + 10, None, None).expect("query all");
        prop_assert_eq!(all_logs.len(), events.len());

        let blocked_logs = storage
            .query_logs(events.len() + 10, None, Some("blocked"))
            .expect("query blocked");
        prop_assert_eq!(blocked_logs.len() as u64, expected_blocked);

        let cached_logs = storage
            .query_logs(events.len() + 10, None, Some("cached"))
            .expect("query cached");
        prop_assert_eq!(cached_logs.len() as u64, expected_cached);
    }

    #[test]
    fn prop_storage_custom_rules_roundtrip(rules_text in ".*") {
        let dir = tempfile::tempdir().expect("tempdir");
        {
            let storage = StorageEngine::open(dir.path()).expect("open storage");
            storage.save_custom_rules(&rules_text).expect("save rules");
            prop_assert_eq!(
                storage.load_custom_rules().expect("load rules"),
                Some(rules_text.clone())
            );
        }
        // Reopen to verify persistence across restarts
        let reopened = StorageEngine::open(dir.path()).expect("reopen storage");
        prop_assert_eq!(
            reopened.load_custom_rules().expect("load persisted"),
            Some(rules_text)
        );
    }
}
