mod checks_core;
mod checks_extended;
mod trace;
mod types;

#[cfg(test)]
mod tests;

use std::time::{SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::extract::State;

use crate::RouterState;

pub use trace::trace_domain_resolution;
pub use types::{
    DiagnosticCategory, DiagnosticItem, DiagnosticStatus, DomainTraceRequest, DomainTraceResponse,
    DomainTraceStep, SystemDiagnosticsResponse, SystemHealthMetrics,
};

pub async fn run_system_diagnostics(
    State(state): State<RouterState>,
) -> Json<SystemDiagnosticsResponse> {
    let cfg = state.app.config.load();
    let listen_dns = cfg.bootstrap.listen_dns;

    let mdns_item = checks_core::check_mdns_port_conflict(listen_dns);
    let loopback_item = checks_core::check_loopback_probe(listen_dns).await;
    let system_dns_item = checks_extended::check_system_dns_takeover(listen_dns);
    let drops_item = checks_core::check_udp_inflight_drops(&state);
    let upstream_item = checks_core::check_upstream_health(&state);
    let bootstrap_item = checks_core::check_bootstrap_dns(&cfg.upstreams, &cfg.bootstrap_dns).await;
    let loop_item = checks_core::check_forwarding_loop(
        listen_dns,
        &cfg.upstreams,
        &cfg.upstream_groups,
        &cfg.split_dns,
    );
    let auth_item = checks_core::check_webui_auth(cfg.web_auth_enabled, &cfg.web_password_hash);
    let tls_item = checks_extended::check_tls_cert_health(&cfg, state.app.tls_reloader.as_deref());
    let open_resolver_item = checks_extended::check_open_resolver_risk(&cfg);
    let dnssec_clock_item = checks_extended::check_dnssec_and_clock(&cfg);
    let local_sources_item = checks_extended::check_local_data_sources(&cfg);
    let storage_item = checks_extended::check_data_dir_storage(&cfg);
    let cache_item = checks_extended::check_cache_config(&cfg, &state);

    let items = vec![
        mdns_item,
        loopback_item,
        system_dns_item,
        drops_item,
        upstream_item,
        bootstrap_item,
        loop_item,
        auth_item,
        tls_item,
        open_resolver_item,
        dnssec_clock_item,
        local_sources_item,
        storage_item,
        cache_item,
    ];
    let overall = compute_overall_status(&items);
    let metrics = collect_health_metrics(&state);
    let checked_at_ms = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(u64::MAX);

    Json(SystemDiagnosticsResponse {
        overall,
        checked_at_ms,
        listen_dns: listen_dns.to_string(),
        metrics,
        items,
    })
}

fn collect_health_metrics(state: &RouterState) -> SystemHealthMetrics {
    let latency = state.app.pipeline.latency_snapshot();
    let upstreams = state.app.pipeline.upstream().health_snapshot();
    let cache_stats = state.app.pipeline.cache().stats();
    let query_stats = state.app.storage.stats_snapshot();

    compute_health_metrics(
        latency.sum_secs,
        latency.count,
        &upstreams,
        &cache_stats,
        query_stats.total_queries,
        query_stats.error_queries,
    )
}

pub(crate) fn compute_health_metrics(
    latency_sum_secs: f64,
    latency_count: u64,
    upstreams: &[crabdns_core::UpstreamStatus],
    cache_stats: &crabdns_core::CacheStats,
    total_queries: u64,
    error_queries: u64,
) -> SystemHealthMetrics {
    #[allow(clippy::cast_precision_loss)]
    let avg_response_ms = if latency_count > 0 {
        Some((latency_sum_secs / latency_count as f64) * 1000.0)
    } else {
        None
    };

    let measured_upstreams: Vec<u64> = upstreams
        .iter()
        .filter(|u| u.healthy && u.total_requests > 0)
        .map(|u| u.ewma_latency_ms)
        .collect();
    let upstream_avg_latency_ms = if measured_upstreams.is_empty() {
        None
    } else {
        let sum: u64 = measured_upstreams.iter().sum();
        Some(sum / u64::try_from(measured_upstreams.len()).unwrap_or(1))
    };

    let cache_lookups = cache_stats
        .hits
        .saturating_add(cache_stats.optimistic_hits)
        .saturating_add(cache_stats.misses);
    #[allow(clippy::cast_precision_loss)]
    let cache_hit_rate_pct = if cache_lookups > 0 {
        let hits = cache_stats.hits.saturating_add(cache_stats.optimistic_hits);
        Some((hits as f64 / cache_lookups as f64) * 100.0)
    } else {
        None
    };

    #[allow(clippy::cast_precision_loss)]
    let error_rate_pct = if total_queries > 0 {
        Some((error_queries as f64 / total_queries as f64) * 100.0)
    } else {
        None
    };

    SystemHealthMetrics {
        avg_response_ms,
        upstream_avg_latency_ms,
        cache_hit_rate_pct,
        error_rate_pct,
        total_queries,
        cache_entries: cache_stats.entries,
    }
}

fn compute_overall_status(items: &[DiagnosticItem]) -> DiagnosticStatus {
    if items.iter().any(|i| i.status == DiagnosticStatus::Error) {
        DiagnosticStatus::Error
    } else if items.iter().any(|i| i.status == DiagnosticStatus::Warn) {
        DiagnosticStatus::Warn
    } else {
        DiagnosticStatus::Ok
    }
}
