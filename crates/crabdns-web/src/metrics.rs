use std::fmt::Write as _;

use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use crabdns_core::{
    CacheStats, FilterStats, LatencyHistogramSnapshot, PipelineRuntimeMetrics, UpstreamStatus,
};
use crabdns_storage::{StatsSnapshot, StorageRuntimeMetrics};

use crate::RouterState;

const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

#[derive(Debug, Default)]
struct ProcessMetrics {
    rss_bytes: Option<u64>,
    rss_anon_bytes: Option<u64>,
    open_fds: Option<usize>,
    threads: Option<u64>,
}

#[cfg(all(feature = "prof-jemalloc", unix))]
#[derive(Debug, Default)]
struct JemallocStats {
    allocated: u64,
    active: u64,
    resident: u64,
}

pub async fn prometheus_metrics(State(state): State<RouterState>) -> Response {
    let query_stats = state.app.storage.stats_snapshot();
    let storage_entries = state.app.storage.tracked_stat_entries();
    let storage_runtime = state.app.storage.runtime_metrics();
    let cache_stats = state.app.pipeline.cache().stats();
    let filter_stats = state.app.pipeline.filter().stats();
    let upstreams = state.app.pipeline.upstream().health_snapshot();
    let (paused, _) = state.app.pipeline.blocking_status();
    let runtime = state.app.pipeline.runtime_metrics();
    let latency = state.app.pipeline.latency_snapshot();
    let auth_sessions = state.sessions.active_sessions();
    let auth_attempts = state.login_limiter.tracked_entries();
    let proc_metrics = tokio::task::spawn_blocking(read_process_metrics)
        .await
        .unwrap_or_default();

    let mut out = String::with_capacity(4096);
    write_query_metrics(&mut out, &query_stats);
    write_query_latency_histogram(&mut out, &latency);
    write_cache_and_filter_metrics(&mut out, &cache_stats, &filter_stats, paused);
    write_upstream_metrics(&mut out, &upstreams);
    write_process_metrics(&mut out, &proc_metrics);
    #[cfg(all(feature = "prof-jemalloc", unix))]
    if let Some(jstats) = read_jemalloc_stats() {
        write_jemalloc_metrics(&mut out, &jstats);
    }
    write_runtime_metrics(
        &mut out,
        &runtime,
        &storage_runtime,
        auth_sessions,
        auth_attempts,
        storage_entries,
    );

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, PROMETHEUS_CONTENT_TYPE)],
        out,
    )
        .into_response()
}

fn write_query_metrics(out: &mut String, query_stats: &StatsSnapshot) {
    let forwarded = query_stats
        .total_queries
        .saturating_sub(query_stats.blocked_queries)
        .saturating_sub(query_stats.cached_queries)
        .saturating_sub(query_stats.rewritten_queries)
        .saturating_sub(query_stats.error_queries);
    let _ = writeln!(
        out,
        "# HELP crabdns_queries_total Total DNS queries processed by outcome.\n\
         # TYPE crabdns_queries_total counter\n\
         crabdns_queries_total{{outcome=\"forwarded\"}} {forwarded}\n\
         crabdns_queries_total{{outcome=\"cached\"}} {}\n\
         crabdns_queries_total{{outcome=\"blocked\"}} {}\n\
         crabdns_queries_total{{outcome=\"rewritten\"}} {}\n\
         crabdns_queries_total{{outcome=\"error\"}} {}",
        query_stats.cached_queries,
        query_stats.blocked_queries,
        query_stats.rewritten_queries,
        query_stats.error_queries
    );
}

fn write_cache_and_filter_metrics(
    out: &mut String,
    cache_stats: &CacheStats,
    filter_stats: &FilterStats,
    paused: bool,
) {
    let _ = writeln!(
        out,
        "# HELP crabdns_cache_entries Current cached DNS entries.\n\
         # TYPE crabdns_cache_entries gauge\n\
         crabdns_cache_entries {}\n\
         # HELP crabdns_cache_hits_total Total DNS cache hits.\n\
         # TYPE crabdns_cache_hits_total counter\n\
         crabdns_cache_hits_total {}\n\
         # HELP crabdns_cache_optimistic_hits_total Total DNS optimistic cache hits.\n\
         # TYPE crabdns_cache_optimistic_hits_total counter\n\
         crabdns_cache_optimistic_hits_total {}\n\
         # HELP crabdns_cache_misses_total Total DNS cache misses.\n\
         # TYPE crabdns_cache_misses_total counter\n\
         crabdns_cache_misses_total {}\n\
         # HELP crabdns_filter_rules Active filter rules by kind.\n\
         # TYPE crabdns_filter_rules gauge\n\
         crabdns_filter_rules{{kind=\"total\"}} {}\n\
         crabdns_filter_rules{{kind=\"block\"}} {}\n\
         crabdns_filter_rules{{kind=\"allow\"}} {}\n\
         crabdns_filter_rules{{kind=\"rewrite\"}} {}\n\
         # HELP crabdns_blocking_paused Whether DNS ad-blocking is paused (1=paused, 0=active).\n\
         # TYPE crabdns_blocking_paused gauge\n\
         crabdns_blocking_paused {}",
        cache_stats.entries,
        cache_stats.hits,
        cache_stats.optimistic_hits,
        cache_stats.misses,
        filter_stats.total_rules,
        filter_stats.block_rules,
        filter_stats.allow_rules,
        filter_stats.rewrite_rules,
        u8::from(paused)
    );
}

fn write_upstream_metrics(out: &mut String, upstreams: &[UpstreamStatus]) {
    let _ = writeln!(
        out,
        "# HELP crabdns_upstream_healthy Upstream health status (1=healthy, 0=unhealthy).\n\
         # TYPE crabdns_upstream_healthy gauge\n\
         # HELP crabdns_upstream_ewma_latency_ms Upstream EWMA latency in milliseconds.\n\
         # TYPE crabdns_upstream_ewma_latency_ms gauge\n\
         # HELP crabdns_upstream_requests_total Total requests sent to upstream.\n\
         # TYPE crabdns_upstream_requests_total counter\n\
         # HELP crabdns_upstream_failures_total Total failed requests to upstream.\n\
         # TYPE crabdns_upstream_failures_total counter"
    );
    for u in upstreams {
        let ep = escape_label(&u.endpoint);
        let _ = writeln!(
            out,
            "crabdns_upstream_healthy{{endpoint=\"{ep}\"}} {}\n\
             crabdns_upstream_ewma_latency_ms{{endpoint=\"{ep}\"}} {}\n\
             crabdns_upstream_requests_total{{endpoint=\"{ep}\"}} {}\n\
             crabdns_upstream_failures_total{{endpoint=\"{ep}\"}} {}",
            u8::from(u.healthy),
            u.ewma_latency_ms,
            u.total_requests,
            u.total_failures
        );
    }
}

fn escape_label(val: &str) -> String {
    val.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn write_process_metrics(out: &mut String, proc: &ProcessMetrics) {
    if let Some(rss) = proc.rss_bytes {
        let _ = writeln!(
            out,
            "# HELP crabdns_process_resident_memory_bytes Resident memory size in bytes.\n\
             # TYPE crabdns_process_resident_memory_bytes gauge\n\
             crabdns_process_resident_memory_bytes {rss}"
        );
    }
    if let Some(rss_anon) = proc.rss_anon_bytes {
        let _ = writeln!(
            out,
            "# HELP crabdns_process_rss_anon_bytes Anonymous resident memory size in bytes.\n\
             # TYPE crabdns_process_rss_anon_bytes gauge\n\
             crabdns_process_rss_anon_bytes {rss_anon}"
        );
    }
    if let Some(fds) = proc.open_fds {
        let _ = writeln!(
            out,
            "# HELP crabdns_process_open_fds Number of open file descriptors.\n\
             # TYPE crabdns_process_open_fds gauge\n\
             crabdns_process_open_fds {fds}"
        );
    }
    if let Some(threads) = proc.threads {
        let _ = writeln!(
            out,
            "# HELP crabdns_process_threads Number of OS threads in the process.\n\
             # TYPE crabdns_process_threads gauge\n\
             crabdns_process_threads {threads}"
        );
    }
}

fn write_query_latency_histogram(out: &mut String, latency: &LatencyHistogramSnapshot) {
    let _ = writeln!(
        out,
        "# HELP crabdns_query_duration_seconds End-to-end DNS query handling latency in seconds.\n\
         # TYPE crabdns_query_duration_seconds histogram"
    );
    for (bound_secs, count) in &latency.buckets {
        let _ = writeln!(
            out,
            "crabdns_query_duration_seconds_bucket{{le=\"{bound_secs}\"}} {count}"
        );
    }
    let _ = writeln!(
        out,
        "crabdns_query_duration_seconds_bucket{{le=\"+Inf\"}} {}\n\
         crabdns_query_duration_seconds_sum {:.6}\n\
         crabdns_query_duration_seconds_count {}",
        latency.inf_count, latency.sum_secs, latency.count
    );
}

#[allow(clippy::too_many_lines)]
fn write_runtime_metrics(
    out: &mut String,
    pipeline: &PipelineRuntimeMetrics,
    storage: &StorageRuntimeMetrics,
    auth_sessions: usize,
    auth_attempts: usize,
    storage_entries: (usize, usize, usize),
) {
    let (domains, blocked, clients) = storage_entries;
    #[allow(clippy::cast_precision_loss)]
    let flush_secs = storage.log_flush_total_us as f64 / 1_000_000.0;
    let _ = writeln!(
        out,
        "# HELP crabdns_log_channel_dropped_total Total query log events dropped due to full log channel.\n\
         # TYPE crabdns_log_channel_dropped_total counter\n\
         crabdns_log_channel_dropped_total {}\n\
         # HELP crabdns_singleflight_inflight Active deduplicated upstream singleflight lookups.\n\
         # TYPE crabdns_singleflight_inflight gauge\n\
         crabdns_singleflight_inflight {}\n\
         # HELP crabdns_rdns_inflight Active background reverse DNS lookups.\n\
         # TYPE crabdns_rdns_inflight gauge\n\
         crabdns_rdns_inflight {}\n\
         # HELP crabdns_bg_refresh_inflight Active optimistic cache background refreshes.\n\
         # TYPE crabdns_bg_refresh_inflight gauge\n\
         crabdns_bg_refresh_inflight {}\n\
         # HELP crabdns_acl_tracked_clients Tracked client IPs in ACL rate limiter.\n\
         # TYPE crabdns_acl_tracked_clients gauge\n\
         crabdns_acl_tracked_clients {}\n\
         # HELP crabdns_udp_dropped_inflight_total UDP DNS queries dropped due to inflight limit.\n\
         # TYPE crabdns_udp_dropped_inflight_total counter\n\
         crabdns_udp_dropped_inflight_total {}\n\
         # HELP crabdns_active_connections Active client connections by protocol.\n\
         # TYPE crabdns_active_connections gauge\n\
         crabdns_active_connections{{protocol=\"tcp\"}} {}\n\
         crabdns_active_connections{{protocol=\"dot\"}} {}\n\
         crabdns_active_connections{{protocol=\"doq\"}} {}\n\
         crabdns_active_connections{{protocol=\"web\"}} {}\n\
         # HELP crabdns_rejected_connections_total Rejected client connections by protocol.\n\
         # TYPE crabdns_rejected_connections_total counter\n\
         crabdns_rejected_connections_total{{protocol=\"tcp\"}} {}\n\
         crabdns_rejected_connections_total{{protocol=\"dot\"}} {}\n\
         crabdns_rejected_connections_total{{protocol=\"doq\"}} {}\n\
         crabdns_rejected_connections_total{{protocol=\"web\"}} {}\n\
         # HELP crabdns_doh_rejected_inflight_total DoH requests rejected due to inflight limit.\n\
         # TYPE crabdns_doh_rejected_inflight_total counter\n\
         crabdns_doh_rejected_inflight_total {}\n\
         # HELP crabdns_doh_timed_out_total DoH requests that exceeded the query timeout.\n\
         # TYPE crabdns_doh_timed_out_total counter\n\
         crabdns_doh_timed_out_total {}\n\
         # HELP crabdns_filter_reloads_total Total filter engine reloads.\n\
         # TYPE crabdns_filter_reloads_total counter\n\
         crabdns_filter_reloads_total {}\n\
         # HELP crabdns_filter_last_reload_ms Duration of the latest filter engine reload in milliseconds.\n\
         # TYPE crabdns_filter_last_reload_ms gauge\n\
         crabdns_filter_last_reload_ms {}\n\
         # HELP crabdns_storage_log_batches_total Total query log batches committed to storage.\n\
         # TYPE crabdns_storage_log_batches_total counter\n\
         crabdns_storage_log_batches_total {}\n\
         # HELP crabdns_storage_log_batch_failures_total Total failed query log batch flushes.\n\
         # TYPE crabdns_storage_log_batch_failures_total counter\n\
         crabdns_storage_log_batch_failures_total {}\n\
         # HELP crabdns_storage_log_batches_retried_total Total query log batch flush retries.\n\
         # TYPE crabdns_storage_log_batches_retried_total counter\n\
         crabdns_storage_log_batches_retried_total {}\n\
         # HELP crabdns_storage_log_batches_degraded_dropped_total Total log batches kept in memory only during disk backoff.\n\
         # TYPE crabdns_storage_log_batches_degraded_dropped_total counter\n\
         crabdns_storage_log_batches_degraded_dropped_total {}\n\
         # HELP crabdns_storage_log_disk_degraded Whether query log disk flushing is degraded (1=degraded, 0=healthy).\n\
         # TYPE crabdns_storage_log_disk_degraded gauge\n\
         crabdns_storage_log_disk_degraded {}\n\
         # HELP crabdns_storage_log_flush_duration_seconds_total Cumulative time spent flushing log batches.\n\
         # TYPE crabdns_storage_log_flush_duration_seconds_total counter\n\
         crabdns_storage_log_flush_duration_seconds_total {flush_secs:.6}\n\
         # HELP crabdns_storage_logs_pruned_total Total query log entries pruned.\n\
         # TYPE crabdns_storage_logs_pruned_total counter\n\
         crabdns_storage_logs_pruned_total {}\n\
         # HELP crabdns_auth_sessions Active web authentication sessions.\n\
         # TYPE crabdns_auth_sessions gauge\n\
         crabdns_auth_sessions {auth_sessions}\n\
         # HELP crabdns_auth_login_attempts Tracked client IPs in web login rate limiter.\n\
         # TYPE crabdns_auth_login_attempts gauge\n\
         crabdns_auth_login_attempts {auth_attempts}\n\
         # HELP crabdns_storage_tracked_entries Number of in-memory tracked statistics keys.\n\
         # TYPE crabdns_storage_tracked_entries gauge\n\
         crabdns_storage_tracked_entries{{kind=\"domains\"}} {domains}\n\
         crabdns_storage_tracked_entries{{kind=\"blocked\"}} {blocked}\n\
         crabdns_storage_tracked_entries{{kind=\"clients\"}} {clients}",
        pipeline.log_dropped,
        pipeline.singleflight_inflight,
        pipeline.rdns_inflight,
        pipeline.bg_refresh_inflight,
        pipeline.acl_tracked_clients,
        pipeline.udp_dropped_inflight,
        pipeline.tcp_active_connections,
        pipeline.dot_active_connections,
        pipeline.doq_active_connections,
        pipeline.web_active_connections,
        pipeline.tcp_rejected_connections,
        pipeline.dot_rejected_connections,
        pipeline.doq_rejected_connections,
        pipeline.web_rejected_connections,
        pipeline.doh_rejected_inflight,
        pipeline.doh_timed_out,
        pipeline.filter_reloads,
        pipeline.filter_last_reload_ms,
        storage.log_batches_written,
        storage.log_batch_failures,
        storage.log_batches_retried,
        storage.log_batches_degraded_dropped,
        u8::from(storage.log_disk_degraded),
        storage.log_pruned_total,
    );
}

#[cfg(target_os = "linux")]
fn read_process_metrics() -> ProcessMetrics {
    let mut metrics = ProcessMetrics {
        open_fds: std::fs::read_dir("/proc/self/fd")
            .ok()
            .map(|dir| dir.filter_map(std::result::Result::ok).count()),
        ..ProcessMetrics::default()
    };

    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if let Some(kb) = parse_status_u64(line, "VmRSS:") {
                metrics.rss_bytes = Some(kb.saturating_mul(1024));
            } else if let Some(kb) = parse_status_u64(line, "RssAnon:") {
                metrics.rss_anon_bytes = Some(kb.saturating_mul(1024));
            } else if let Some(threads) = parse_status_u64(line, "Threads:") {
                metrics.threads = Some(threads);
            }
        }
    }
    metrics
}

#[cfg(target_os = "linux")]
fn parse_status_u64(line: &str, prefix: &str) -> Option<u64> {
    let rest = line.strip_prefix(prefix)?.trim();
    rest.split_whitespace().next()?.parse::<u64>().ok()
}

#[cfg(not(target_os = "linux"))]
fn read_process_metrics() -> ProcessMetrics {
    ProcessMetrics::default()
}

#[cfg(all(feature = "prof-jemalloc", unix))]
fn read_jemalloc_stats() -> Option<JemallocStats> {
    use tikv_jemalloc_ctl::{epoch, stats};

    epoch::advance().ok()?;
    let allocated = stats::allocated::read().ok()? as u64;
    let active = stats::active::read().ok()? as u64;
    let resident = stats::resident::read().ok()? as u64;
    Some(JemallocStats {
        allocated,
        active,
        resident,
    })
}

#[cfg(all(feature = "prof-jemalloc", unix))]
fn write_jemalloc_metrics(out: &mut String, jstats: &JemallocStats) {
    let _ = writeln!(
        out,
        "# HELP crabdns_jemalloc_allocated_bytes Total bytes allocated by the application via jemalloc.\n\
         # TYPE crabdns_jemalloc_allocated_bytes gauge\n\
         crabdns_jemalloc_allocated_bytes {}\n\
         # HELP crabdns_jemalloc_active_bytes Total bytes in active pages allocated by the application via jemalloc.\n\
         # TYPE crabdns_jemalloc_active_bytes gauge\n\
         crabdns_jemalloc_active_bytes {}\n\
         # HELP crabdns_jemalloc_resident_bytes Maximum bytes in physically resident data pages mapped by jemalloc.\n\
         # TYPE crabdns_jemalloc_resident_bytes gauge\n\
         crabdns_jemalloc_resident_bytes {}",
        jstats.allocated, jstats.active, jstats.resident,
    );
}

#[cfg(all(feature = "prof-jemalloc", unix))]
pub async fn pprof_heap() -> Response {
    let Some(ctl) = jemalloc_pprof::PROF_CTL.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "jemalloc heap profiling is not active (set _RJEM_MALLOC_CONF=prof:true)",
        )
            .into_response();
    };

    let mut guard = ctl.lock().await;
    if !guard.activated()
        && let Err(err) = guard.activate()
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to activate jemalloc profiling: {err}"),
        )
            .into_response();
    }

    match guard.dump_pprof() {
        Ok(bytes) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/octet-stream")],
            bytes,
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to dump pprof heap profile: {err}"),
        )
            .into_response(),
    }
}
