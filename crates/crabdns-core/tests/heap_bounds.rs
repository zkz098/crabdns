use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use crabdns_core::cache::CacheKey;
use crabdns_core::singleflight::{FlightRole, Singleflight, wait_follower};
use crabdns_core::{AccessController, DnsCache, DnsPipeline, FilterEngine, UpstreamPool};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use tokio::net::UdpSocket;

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

fn build_query(id: u16, domain: &str) -> Vec<u8> {
    let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(
        Name::from_ascii(domain).expect("valid domain"),
        RecordType::A,
    ));
    msg.to_vec().expect("encode query")
}

fn verify_acl_heap_bounds() {
    const CAP: usize = 16_384;
    let acl = AccessController::new(&[], &[], 10).expect("acl");
    for i in 0..CAP {
        let b = ((i >> 16) & 0xff) as u8;
        let c = ((i >> 8) & 0xff) as u8;
        let d = (i & 0xff) as u8;
        let _ = acl.check(IpAddr::V4(Ipv4Addr::new(10, b, c, d)));
    }
    assert_eq!(acl.tracked_clients(), CAP);

    let before = dhat::HeapStats::get();
    for i in CAP..(CAP * 11) {
        let b = ((i >> 16) & 0xff) as u8;
        let c = ((i >> 8) & 0xff) as u8;
        let d = (i & 0xff) as u8;
        let _ = acl.check(IpAddr::V4(Ipv4Addr::new(172, b, c, d)));
    }
    let after = dhat::HeapStats::get();
    assert!(acl.tracked_clients() <= CAP);
    dhat::assert!(
        after.curr_bytes.saturating_sub(before.curr_bytes) == 0,
        "ACL bucket heap grew after reaching cap: before={}, after={}",
        before.curr_bytes,
        after.curr_bytes
    );
    dhat::assert!(
        after.curr_blocks.saturating_sub(before.curr_blocks) == 0,
        "ACL bucket blocks grew after reaching cap: before={}, after={}",
        before.curr_blocks,
        after.curr_blocks
    );
}

fn verify_filter_reload_heap_bounds() {
    use std::fmt::Write as _;
    let mut rules_a = String::with_capacity(120_000);
    let mut rules_b = String::with_capacity(120_000);
    for i in 0..4_000 {
        let _ = writeln!(&mut rules_a, "||ad-a-{i}.example.test^");
        let _ = writeln!(&mut rules_b, "||ad-b-{i}.example.test^");
    }

    let engine = FilterEngine::new(&[]);
    for i in 0..4 {
        let text = if i % 2 == 0 { &rules_a } else { &rules_b };
        let _ = engine.reload_from_named_sources("", false, &[("sub".to_string(), text.clone())]);
    }

    let before = dhat::HeapStats::get();
    for i in 0..40 {
        let text = if i % 2 == 0 { &rules_a } else { &rules_b };
        let _ = engine.reload_from_named_sources("", false, &[("sub".to_string(), text.clone())]);
    }
    let after = dhat::HeapStats::get();

    let delta_bytes = after.curr_bytes.saturating_sub(before.curr_bytes);
    let delta_blocks = after.curr_blocks.saturating_sub(before.curr_blocks);
    dhat::assert!(
        delta_bytes <= 8192,
        "FilterEngine reload leaked heap across 40 reloads: delta_bytes={delta_bytes}"
    );
    dhat::assert!(
        delta_blocks <= 32,
        "FilterEngine reload leaked blocks across 40 reloads: delta_blocks={delta_blocks}"
    );
}

fn verify_cache_heap_bounds() {
    const CAP: u64 = 256;
    let cache = DnsCache::new(CAP, true);
    let sample_wire = vec![0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00];

    for i in 0..1_000_usize {
        let key = CacheKey {
            qname: format!("warm-{i:06}.example.test."),
            qtype: 1,
            qclass: 1,
            ecs_subnet: None,
            dnssec_do: false,
            upstream_scope: None,
        };
        cache.insert(key, sample_wire.clone(), 60);
    }
    cache.run_pending_tasks();

    let before = dhat::HeapStats::get();
    for i in 0..10_000_usize {
        let key = CacheKey {
            qname: format!("load-{i:06}.example.test."),
            qtype: 1,
            qclass: 1,
            ecs_subnet: None,
            dnssec_do: false,
            upstream_scope: None,
        };
        cache.insert(key, sample_wire.clone(), 60);
    }
    cache.run_pending_tasks();
    let after = dhat::HeapStats::get();

    assert!(cache.entry_count() <= CAP);
    let delta_bytes = after.curr_bytes.saturating_sub(before.curr_bytes);
    dhat::assert!(
        delta_bytes <= 64 * 1024,
        "DnsCache heap grew excessively across 10k evictions: delta_bytes={delta_bytes}"
    );
}

async fn run_sf_batch(sf: &Singleflight<String, Vec<u8>>, prefix: &str, count: usize) {
    for i in 0..count {
        let key = format!("{prefix}-{i}.test");
        if let FlightRole::Leader(guard) = sf.acquire(key.clone())
            && let FlightRole::Follower(rx) = sf.acquire(key)
        {
            if i % 2 == 0 {
                guard.complete(Ok(vec![1, 2, 3, 4]));
            } else {
                drop(guard);
            }
            let _ = wait_follower(rx).await;
        }
    }
}

async fn verify_singleflight_heap_bounds() {
    let sf: Arc<Singleflight<String, Vec<u8>>> = Arc::new(Singleflight::new());
    run_sf_batch(&sf, "sf-warm", 200).await;

    let sf_before = dhat::HeapStats::get();
    run_sf_batch(&sf, "sf-load", 2_000).await;
    let sf_after = dhat::HeapStats::get();

    assert_eq!(sf.inflight_count(), 0);
    dhat::assert!(
        sf_after.curr_bytes.saturating_sub(sf_before.curr_bytes) <= 4096,
        "Singleflight retained memory after 2000 cycles: delta={}",
        sf_after.curr_bytes.saturating_sub(sf_before.curr_bytes)
    );
}

async fn verify_pipeline_heap_bounds() {
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind mock");
    let addr = sock.local_addr().expect("addr");
    let upstream_hits = Arc::new(AtomicUsize::new(0));
    let hits_bg = Arc::clone(&upstream_hits);
    let mock_task = tokio::spawn(async move {
        let mut buf = [0_u8; 2048];
        while let Ok((len, peer)) = sock.recv_from(&mut buf).await {
            hits_bg.fetch_add(1, Ordering::Relaxed);
            if let Ok(req) = Message::from_vec(&buf[..len]) {
                let mut resp = Message::new(req.id, MessageType::Response, OpCode::Query);
                resp.metadata.recursion_available = true;
                resp.metadata.response_code = ResponseCode::NoError;
                resp.queries.clone_from(&req.queries);
                if let Some(q) = req.queries.first() {
                    resp.add_answer(Record::from_rdata(
                        q.name().clone(),
                        60,
                        RData::A(A(Ipv4Addr::new(93, 184, 216, 34))),
                    ));
                }
                if let Ok(wire) = resp.to_vec() {
                    let _ = sock.send_to(&wire, peer).await;
                }
            }
        }
    });

    let filter = Arc::new(FilterEngine::new(&[
        "||blocked.example.test^".to_string(),
        "||rw.example.test^$dnsrewrite=10.0.0.10".to_string(),
    ]));
    let cache = Arc::new(DnsCache::new(128, true));
    let upstream =
        Arc::new(UpstreamPool::new(&[format!("udp://{addr}")], 1000).expect("upstream pool"));
    let pipeline = DnsPipeline::new(filter, Arc::clone(&cache), upstream, None);
    pipeline.set_rdns_enabled(false);

    let blocked_pkt = build_query(1, "sub.blocked.example.test.");
    let rw_pkt = build_query(2, "rw.example.test.");
    let client: SocketAddr = "127.0.0.1:50000".parse().expect("addr");

    for i in 0..300_usize {
        let _ = pipeline.handle_packet(&blocked_pkt, client).await;
        let _ = pipeline.handle_packet(&rw_pkt, client).await;
        let fwd_pkt = build_query((i & 0xffff) as u16, &format!("warm-{i:05}.fwd.test."));
        let _ = pipeline.handle_packet(&fwd_pkt, client).await;
    }
    cache.run_pending_tasks();

    let pipe_before = dhat::HeapStats::get();
    for i in 0..3_000_usize {
        match i % 3 {
            0 => {
                let _ = pipeline.handle_packet(&blocked_pkt, client).await;
            }
            1 => {
                let _ = pipeline.handle_packet(&rw_pkt, client).await;
            }
            _ => {
                let fwd_pkt = build_query((i & 0xffff) as u16, &format!("load-{i:05}.fwd.test."));
                let _ = pipeline.handle_packet(&fwd_pkt, client).await;
            }
        }
    }
    cache.run_pending_tasks();
    let pipe_after = dhat::HeapStats::get();

    mock_task.abort();
    tokio::time::sleep(Duration::from_millis(1)).await;

    let metrics = pipeline.runtime_metrics();
    assert_eq!(metrics.singleflight_inflight, 0);
    assert_eq!(metrics.rdns_inflight, 0);
    assert_eq!(metrics.bg_refresh_inflight, 0);
    assert!(upstream_hits.load(Ordering::Relaxed) > 0);
    let delta_bytes = pipe_after.curr_bytes.saturating_sub(pipe_before.curr_bytes);
    dhat::assert!(
        delta_bytes <= 64 * 1024,
        "DnsPipeline retained excessive heap across 3000 queries: delta_bytes={delta_bytes}"
    );
}

#[test]
fn test_core_heap_boundedness() {
    let _profiler = dhat::Profiler::builder().testing().build();

    verify_acl_heap_bounds();
    verify_filter_reload_heap_bounds();
    verify_cache_heap_bounds();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current_thread runtime");
    rt.block_on(async {
        verify_singleflight_heap_bounds().await;
        verify_pipeline_heap_bounds().await;
    });
}
