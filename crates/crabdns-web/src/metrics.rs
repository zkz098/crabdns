use std::fmt::Write as _;

use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use crabdns_core::{CacheStats, FilterStats, UpstreamStatus};
use crabdns_storage::StatsSnapshot;

use crate::RouterState;

const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

pub async fn prometheus_metrics(State(state): State<RouterState>) -> Response {
    let query_stats = state.app.storage.stats_snapshot();
    let cache_stats = state.app.pipeline.cache().stats();
    let filter_stats = state.app.pipeline.filter().stats();
    let upstreams = state.app.pipeline.upstream().health_snapshot();
    let (paused, _) = state.app.pipeline.blocking_status();

    let mut out = String::with_capacity(1024);
    write_query_metrics(&mut out, &query_stats);
    write_cache_and_filter_metrics(&mut out, &cache_stats, &filter_stats, paused);
    write_upstream_metrics(&mut out, &upstreams);

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
