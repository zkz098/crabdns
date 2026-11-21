use std::net::IpAddr;

use crabdns_web::auth::{LoginRateLimiter, SessionStore};

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

fn verify_session_store_heap_bounds() {
    const CAP: usize = 256;
    let store = SessionStore::default();
    // Warm up > 16x CAP so all DashMap shards reach steady-state bucket allocations.
    for _ in 0..(CAP * 16) {
        let _ = store.create_session("admin").expect("session");
    }
    assert_eq!(store.active_sessions(), CAP);

    for _ in 0..(CAP * 10) {
        let _ = store.create_session("admin").expect("session");
    }
    let mid = dhat::HeapStats::get();
    for _ in 0..(CAP * 10) {
        let _ = store.create_session("admin").expect("session");
    }
    let after = dhat::HeapStats::get();

    assert_eq!(store.active_sessions(), CAP);
    let delta_bytes = after.curr_bytes.saturating_sub(mid.curr_bytes);
    let delta_blocks = after.curr_blocks.saturating_sub(mid.curr_blocks);
    dhat::assert!(
        after.curr_bytes <= 128 * 1024,
        "SessionStore steady-state heap too large: curr_bytes={}",
        after.curr_bytes
    );
    dhat::assert!(
        delta_bytes <= 16 * 1024,
        "SessionStore heap grew excessively after reaching cap: delta_bytes={delta_bytes}"
    );
    dhat::assert!(
        delta_blocks <= 8,
        "SessionStore blocks grew excessively after reaching cap: delta_blocks={delta_blocks}"
    );
}

fn verify_login_limiter_heap_bounds() {
    const CAP: usize = 4_096;
    let limiter = LoginRateLimiter::default();
    // Warm up > 4x CAP so all DashMap shards reach steady-state bucket capacity.
    for i in 0..(CAP * 4) {
        let b = ((i >> 16) & 0xff) as u8;
        let c = ((i >> 8) & 0xff) as u8;
        let d = (i & 0xff) as u8;
        let ip: IpAddr = format!("192.{b}.{c}.{d}").parse().expect("ip");
        limiter.record_failure(ip);
    }
    assert!(limiter.tracked_entries() <= CAP);

    for i in (CAP * 4)..(CAP * 14) {
        let b = ((i >> 16) & 0xff) as u8;
        let c = ((i >> 8) & 0xff) as u8;
        let d = (i & 0xff) as u8;
        let ip: IpAddr = format!("10.{b}.{c}.{d}").parse().expect("ip");
        limiter.record_failure(ip);
    }
    let mid = dhat::HeapStats::get();
    for i in (CAP * 14)..(CAP * 24) {
        let b = ((i >> 16) & 0xff) as u8;
        let c = ((i >> 8) & 0xff) as u8;
        let d = (i & 0xff) as u8;
        let ip: IpAddr = format!("10.{b}.{c}.{d}").parse().expect("ip");
        limiter.record_failure(ip);
    }
    let after = dhat::HeapStats::get();

    assert!(limiter.tracked_entries() <= CAP);
    let delta_bytes = after.curr_bytes.saturating_sub(mid.curr_bytes);
    let delta_blocks = after.curr_blocks.saturating_sub(mid.curr_blocks);
    dhat::assert!(
        after.curr_bytes <= 1536 * 1024,
        "LoginRateLimiter steady-state heap too large: curr_bytes={}",
        after.curr_bytes
    );
    dhat::assert!(
        after.curr_blocks <= 32,
        "LoginRateLimiter retained too many blocks: curr_blocks={}",
        after.curr_blocks
    );
    dhat::assert!(
        delta_bytes <= 128 * 1024,
        "LoginRateLimiter heap grew excessively after reaching cap: delta_bytes={delta_bytes} (mid={}, after={})",
        mid.curr_bytes,
        after.curr_bytes
    );
    dhat::assert!(
        delta_blocks <= 4,
        "LoginRateLimiter blocks grew excessively after reaching cap: delta_blocks={delta_blocks} (mid={}, after={})",
        mid.curr_blocks,
        after.curr_blocks
    );
}

#[test]
fn test_web_heap_boundedness() {
    let _profiler = dhat::Profiler::builder().testing().build();

    verify_session_store_heap_bounds();
    verify_login_limiter_heap_bounds();
}
