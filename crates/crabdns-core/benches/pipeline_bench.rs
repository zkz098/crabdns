use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use crabdns_core::cache::CacheKey;
use crabdns_core::{DnsCache, DnsPipeline, FilterEngine, UpstreamPool};
use criterion::{Criterion, criterion_group, criterion_main};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};

fn build_query(domain: &str, qtype: RecordType) -> Vec<u8> {
    let mut msg = Message::new(0x1234, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    let name = Name::from_ascii(domain).expect("valid domain");
    msg.add_query(Query::query(name, qtype));
    msg.to_vec().expect("encode query")
}

fn build_cached_response(domain: &str) -> Vec<u8> {
    let mut msg = Message::new(0x1234, MessageType::Response, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.metadata.recursion_available = true;
    msg.metadata.response_code = ResponseCode::NoError;
    let name = Name::from_ascii(domain).expect("valid domain");
    msg.add_query(Query::query(name.clone(), RecordType::A));
    msg.add_answer(Record::from_rdata(
        name,
        300,
        RData::A(A(Ipv4Addr::new(93, 184, 216, 34))),
    ));
    msg.to_vec().expect("encode response")
}

fn bench_pipeline_handle_packet(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    let rules = vec![
        "||ads.blocked.example.com^".to_string(),
        "||rewrite.example.com^$dnsrewrite=10.10.10.10".to_string(),
    ];
    let filter = Arc::new(FilterEngine::new(&rules));
    let cache = Arc::new(DnsCache::new(10_000, true));
    cache.insert(
        CacheKey {
            qname: "cached.example.com.".to_string(),
            qtype: u16::from(RecordType::A),
            qclass: 1,
        },
        build_cached_response("cached.example.com."),
        300,
    );

    let upstream =
        Arc::new(UpstreamPool::new(&["127.0.0.1:59999".to_string()], 500).expect("upstream"));
    let pipeline = Arc::new(DnsPipeline::new(filter, cache, upstream, None));
    let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53000);

    let blocked_pkt = build_query("sub.ads.blocked.example.com.", RecordType::A);
    let cached_pkt = build_query("cached.example.com.", RecordType::A);
    let rewrite_pkt = build_query("rewrite.example.com.", RecordType::A);

    let mut group = c.benchmark_group("pipeline_handle_packet");
    group.bench_function("blocked_zero_ip", |b| {
        b.to_async(&rt).iter(|| async {
            black_box(
                pipeline
                    .handle_packet(black_box(&blocked_pkt), client)
                    .await
                    .expect("blocked packet"),
            )
        });
    });
    group.bench_function("cache_hit_a", |b| {
        b.to_async(&rt).iter(|| async {
            black_box(
                pipeline
                    .handle_packet(black_box(&cached_pkt), client)
                    .await
                    .expect("cached packet"),
            )
        });
    });
    group.bench_function("rewrite_a", |b| {
        b.to_async(&rt).iter(|| async {
            black_box(
                pipeline
                    .handle_packet(black_box(&rewrite_pkt), client)
                    .await
                    .expect("rewrite packet"),
            )
        });
    });
    group.finish();
}

criterion_group!(benches, bench_pipeline_handle_packet);
criterion_main!(benches);
