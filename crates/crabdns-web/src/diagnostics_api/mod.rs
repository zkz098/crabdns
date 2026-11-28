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
    DomainTraceStep, SystemDiagnosticsResponse,
};

pub async fn run_system_diagnostics(
    State(state): State<RouterState>,
) -> Json<SystemDiagnosticsResponse> {
    let cfg = state.app.config.load();
    let listen_dns = cfg.listen_dns;

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
        items,
    })
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
