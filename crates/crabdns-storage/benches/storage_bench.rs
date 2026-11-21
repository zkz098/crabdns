use std::hint::black_box;

use chrono::Utc;
use crabdns_core::{QueryEvent, QueryOutcome, QueryProtocol};
use crabdns_storage::StorageEngine;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use tempfile::TempDir;

fn sample_events(count: usize) -> Vec<QueryEvent> {
    let now = Utc::now();
    (0..count)
        .map(|i| QueryEvent {
            timestamp: now,
            client_ip: format!("192.168.1.{}", (i % 250) + 1),
            client_name: None,
            protocol: QueryProtocol::Udp,
            domain: format!("host-{}.example.com", i % 500),
            qtype: "A".to_string(),
            outcome: match i % 4 {
                0 => QueryOutcome::Cached,
                1 => QueryOutcome::Blocked,
                2 => QueryOutcome::Rewritten,
                _ => QueryOutcome::Forwarded,
            },
            matched_rule: if i % 4 == 1 {
                Some("||example.com^".to_string())
            } else {
                None
            },
            matched_list: None,
            upstream: if i % 4 == 3 {
                Some("127.0.0.1:5353".to_string())
            } else {
                None
            },
            elapsed_us: 120 + (i as u64 % 500),
            rcode: "NoError".to_string(),
            answers: Vec::new(),
        })
        .collect()
}

fn bench_record_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("storage_record_batch");
    for batch_size in [64_usize, 512] {
        let events = sample_events(batch_size);
        let dir = TempDir::new().expect("temp dir");
        let engine = StorageEngine::open(dir.path()).expect("open storage");

        group.throughput(Throughput::Elements(batch_size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(batch_size), &events, |b, ev| {
            b.iter(|| engine.record_batch(black_box(ev)).expect("record batch"));
        });
    }
    group.finish();
}

fn bench_storage_reads(c: &mut Criterion) {
    let dir = TempDir::new().expect("temp dir");
    let engine = StorageEngine::open(dir.path()).expect("open storage");
    let events = sample_events(5_000);
    for chunk in events.chunks(250) {
        engine.record_batch(chunk).expect("seed batch");
    }

    let mut group = c.benchmark_group("storage_reads_5k");
    group.bench_function("query_logs_100_unfiltered", |b| {
        b.iter(|| black_box(engine.query_logs(100, None, None).expect("query logs")));
    });
    group.bench_function("query_logs_100_filtered", |b| {
        b.iter(|| {
            black_box(
                engine
                    .query_logs(100, Some("host-42"), Some("blocked"))
                    .expect("query filtered logs"),
            )
        });
    });
    group.bench_function("stats_snapshot", |b| {
        b.iter(|| black_box(engine.stats_snapshot()));
    });
    group.finish();
}

criterion_group!(benches, bench_record_batch, bench_storage_reads);
criterion_main!(benches);
