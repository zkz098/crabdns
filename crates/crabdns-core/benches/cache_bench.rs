use std::hint::black_box;

use crabdns_core::DnsCache;
use crabdns_core::cache::CacheKey;
use criterion::{Criterion, criterion_group, criterion_main};

fn sample_wire_response() -> Vec<u8> {
    vec![
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, b'w', b'w',
        b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00,
        0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04,
        0x5d, 0xb8, 0xd8, 0x22,
    ]
}

fn bench_cache_operations(c: &mut Criterion) {
    let cache = DnsCache::new(10_000, true);
    let wire = sample_wire_response();

    for i in 0_u32..5_000 {
        cache.insert(
            CacheKey {
                qname: format!("host-{i}.example.com."),
                qtype: 1,
                qclass: 1,
                ecs_subnet: None,
                dnssec_do: false,
            },
            wire.clone(),
            300,
        );
    }

    let hit_key = CacheKey {
        qname: "host-2500.example.com.".to_string(),
        qtype: 1,
        qclass: 1,
        ecs_subnet: None,
        dnssec_do: false,
    };
    let miss_key = CacheKey {
        qname: "uncached.example.org.".to_string(),
        qtype: 1,
        qclass: 1,
        ecs_subnet: None,
        dnssec_do: false,
    };

    let mut group = c.benchmark_group("dns_cache");
    group.bench_function("get_hit", |b| {
        b.iter(|| black_box(cache.get(black_box(&hit_key), 0xabcd)));
    });
    group.bench_function("get_miss", |b| {
        b.iter(|| black_box(cache.get(black_box(&miss_key), 0xabcd)));
    });
    group.bench_function("insert_overwrite", |b| {
        b.iter(|| {
            cache.insert(hit_key.clone(), wire.clone(), 300);
        });
    });
    group.finish();
}

criterion_group!(benches, bench_cache_operations);
criterion_main!(benches);
