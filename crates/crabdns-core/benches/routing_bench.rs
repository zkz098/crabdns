use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crabdns_core::{AccessController, SplitDnsRule, SplitUpstreamRouter, UpstreamStrategy};
use criterion::{Criterion, criterion_group, criterion_main};

fn bench_acl(c: &mut Criterion) {
    let allow: Vec<String> = (0_u16..32).map(|i| format!("10.{i}.0.0/16")).collect();
    let deny: Vec<String> = (0_u16..32)
        .map(|i| format!("192.168.{i}.0/24"))
        .chain((0_u16..8).map(|i| format!("2001:db8:{i}::/48")))
        .collect();

    let acl_no_rl = AccessController::new(&allow, &deny, 0).expect("valid acl");
    let acl_with_rl = AccessController::new(&allow, &deny, 1_000_000).expect("valid acl");

    let allowed_v4 = IpAddr::V4(Ipv4Addr::new(10, 15, 1, 42));
    let denied_v4 = IpAddr::V4(Ipv4Addr::new(192, 168, 31, 9));
    let denied_v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 7, 0, 0, 0, 0, 1));

    let mut group = c.benchmark_group("acl_check");
    group.bench_function("allow_v4_no_ratelimit", |b| {
        b.iter(|| black_box(acl_no_rl.check(black_box(allowed_v4))));
    });
    group.bench_function("deny_v4_no_ratelimit", |b| {
        b.iter(|| black_box(acl_no_rl.check(black_box(denied_v4))));
    });
    group.bench_function("deny_v6_no_ratelimit", |b| {
        b.iter(|| black_box(acl_no_rl.check(black_box(denied_v6))));
    });
    group.bench_function("allow_v4_with_ratelimit", |b| {
        b.iter(|| black_box(acl_with_rl.check(black_box(allowed_v4))));
    });
    group.finish();
}

fn bench_split_dns(c: &mut Criterion) {
    let rules: Vec<SplitDnsRule> = (0..100)
        .map(|i| SplitDnsRule {
            domain: format!("corp-{i}.internal"),
            domains_file: None,
            domains_url: None,
            upstreams: vec!["127.0.0.1:5353".to_string()],
            fallback_to_default: true,
        })
        .collect();

    let router = SplitUpstreamRouter::new(&rules, 1_000, UpstreamStrategy::Failover)
        .expect("valid split dns rules");

    let mut group = c.benchmark_group("split_dns_resolve");
    group.bench_function("exact_hit", |b| {
        b.iter(|| black_box(router.resolve(black_box("corp-50.internal"))));
    });
    group.bench_function("subdomain_hit", |b| {
        b.iter(|| black_box(router.resolve(black_box("db.prod.corp-99.internal"))));
    });
    group.bench_function("miss", |b| {
        b.iter(|| black_box(router.resolve(black_box("www.example.com"))));
    });
    group.finish();
}

criterion_group!(benches, bench_acl, bench_split_dns);
criterion_main!(benches);
