use std::fmt::Write as _;
use std::hint::black_box;

use crabdns_core::FilterEngine;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

fn generate_rules(count: usize) -> String {
    let mut out = String::with_capacity(count * 36);
    for i in 0..count {
        match i % 10 {
            0 => {
                let _ = writeln!(out, "@@||allow-{i}.ads-domain-{i}.example.com^");
            }
            1 => {
                let _ = writeln!(out, "0.0.0.0 host-ad-{i}.example.net");
            }
            2 => {
                let _ = writeln!(out, "||important-{i}.malware.org^$important");
            }
            3 => {
                let _ = writeln!(out, "*.tracker-{i}.telemetry.io");
            }
            4 => {
                let _ = writeln!(out, "||rewrite-{i}.internal.lan^$dnsrewrite=10.0.0.1");
            }
            _ => {
                let _ = writeln!(out, "||ads-domain-{i}.example.com^");
            }
        }
    }
    out
}

fn bench_filter_compile(c: &mut Criterion) {
    let mut group = c.benchmark_group("filter_compile");
    for size in [1_000_usize, 10_000, 50_000] {
        let rules_text = generate_rules(size);
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &rules_text, |b, text| {
            let engine = FilterEngine::new(&[]);
            b.iter(|| black_box(engine.reload_from_sources(black_box(text), true, &[])));
        });
    }
    group.finish();
}

fn bench_filter_evaluate(c: &mut Criterion) {
    let rules_text = generate_rules(50_000);
    let engine = FilterEngine::new(&[]);
    engine.reload_from_sources(&rules_text, true, &[]);

    let mut group = c.benchmark_group("filter_evaluate_50k");
    let cases = [
        ("exact_block", "ads-domain-25005.example.com"),
        ("subdomain_block", "a.b.c.d.ads-domain-25005.example.com"),
        (
            "allowlist_override",
            "allow-25000.ads-domain-25000.example.com",
        ),
        ("wildcard_hit", "pixel.tracker-25003.telemetry.io"),
        ("rewrite_hit", "rewrite-25004.internal.lan"),
        ("clean_miss", "api.v2.production.github.com"),
    ];

    for (name, domain) in cases {
        group.bench_function(name, |b| {
            b.iter(|| black_box(engine.evaluate(black_box(domain))));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_filter_compile, bench_filter_evaluate);
criterion_main!(benches);
