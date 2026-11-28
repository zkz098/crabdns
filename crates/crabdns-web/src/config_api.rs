use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use crabdns_core::acl::parse_cidr_list;
use crabdns_core::{
    AccessController, AcmeChallengeType, BlockMode, BlockedServicesConfig, CfCdnConfig,
    ClientRegistry, DdrConfig, DhcpLeaseTable, Dns64Config, DnssecNta, EcsConfig, HostsTable,
    PrivatePtrRouter, RecursiveConfig, SafeSearchConfig, SplitDnsMatchMode, SplitDnsRule,
    SplitUpstreamRouter, StorageProfile, UpstreamGroup, UpstreamGroupRegistry, UpstreamPool,
    UpstreamStrategy,
    dnssec_anchors::{normalize_nta_entries, parse_trust_anchors},
};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::RouterState;
use crate::acme_api::{AcmeConfigUpdates, apply_acme_updates};

#[derive(Debug, Serialize, Deserialize, TS)]
#[ts(export)]
#[allow(clippy::struct_excessive_bools)]
pub struct ConfigResponse {
    pub listen_dns: String,
    pub listen_web: String,
    pub listen_web_tls: Option<String>,
    pub listen_dot: Option<String>,
    pub listen_doq: Option<String>,
    pub listen_doh3: Option<String>,
    pub sni_client_id_hostnames: Vec<String>,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
    pub data_dir: String,
    pub upstreams: Vec<String>,
    pub bootstrap_dns: Vec<String>,
    pub upstream_strategy: UpstreamStrategy,
    #[ts(type = "number")]
    pub cache_size: u64,
    pub optimistic_cache: bool,
    pub cache_min_ttl_secs: u32,
    pub cache_max_ttl_secs: u32,
    pub cache_prefetch_enabled: bool,
    pub cache_persist_enabled: bool,
    #[ts(type = "number")]
    pub upstream_timeout_ms: u64,
    #[ts(type = "number")]
    pub log_retention_hours: u64,
    #[ts(type = "number")]
    pub log_max_disk_mb: u64,
    pub block_mode: BlockMode,
    pub allow_cidrs: Vec<String>,
    pub deny_cidrs: Vec<String>,
    pub rate_limit_qps: u32,
    pub web_auth_enabled: bool,
    pub web_username: String,
    pub split_dns: Vec<SplitDnsRule>,
    pub upstream_groups: Vec<UpstreamGroup>,
    pub split_dns_match_mode: SplitDnsMatchMode,
    pub split_dns_before_client_upstreams: bool,
    #[ts(type = "number")]
    pub split_dns_refresh_interval_secs: u64,
    pub cname_cloaking_blocking: bool,
    pub doh_enabled: bool,
    pub allow_private_subscriptions: bool,
    pub ecs_enabled: bool,
    pub ecs_custom_ip: Option<String>,
    pub ecs_ipv4_prefix: u8,
    pub ecs_ipv6_prefix: u8,
    pub dnssec_enabled: bool,
    pub dnssec_trust_anchors: Vec<String>,
    pub dnssec_ntas: Vec<DnssecNta>,
    pub hosts_enabled: bool,
    pub hosts_path: Option<String>,
    pub dhcp_leases_enabled: bool,
    pub dhcp_leases_path: Option<String>,
    pub dhcp_leases_forward_enabled: bool,
    pub dhcp_leases_domain: String,
    pub mdns_enabled: bool,
    pub llmnr_enabled: bool,
    pub private_ptr_enabled: bool,
    pub private_ptr_upstreams: Vec<String>,
    pub block_local_domains: bool,
    pub suppress_local_domain_logs: bool,
    pub ddr_enabled: bool,
    pub ddr_hostname: Option<String>,
    pub dns_rebinding_protection: bool,
    pub block_any_queries: bool,
    pub trusted_proxies: Vec<String>,
    pub trusted_forwarders: Vec<String>,
    pub rdns_enabled: bool,
    pub safesearch: SafeSearchConfig,
    pub blocked_services: BlockedServicesConfig,
    pub dns64_enabled: bool,
    pub dns64_prefixes: Vec<String>,
    pub svcb_strip_ech: bool,
    pub svcb_strip_hints: bool,
    pub ede_enabled: bool,
    pub dns_cookies_enabled: bool,
    pub dns_cookies_require_valid: bool,
    pub max_udp_payload_size: u16,
    pub rrl_enabled: bool,
    pub rrl_responses_per_second: u32,
    pub rrl_slip: u32,
    #[ts(type = "number")]
    pub rrl_window_secs: u64,
    pub acme_enabled: bool,
    pub acme_domains: Vec<String>,
    pub acme_email: Option<String>,
    pub acme_directory_url: String,
    pub acme_challenge_type: AcmeChallengeType,
    pub acme_http_listen: Option<String>,
    pub acme_renew_before_days: u32,
    pub cf_cdn: CfCdnConfig,
    pub storage_profile: StorageProfile,
    #[ts(type = "number")]
    pub disk_min_free_mb: u64,
    pub serve_stale_enabled: bool,
    pub dnssec_strict_clock: bool,
    pub dnssec_auto_rollover: bool,
    pub recursive: RecursiveConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[allow(clippy::struct_excessive_bools)]
pub struct ConfigUpdatePayload {
    pub upstreams: Vec<String>,
    #[serde(default)]
    pub bootstrap_dns: Option<Vec<String>>,
    #[serde(default)]
    pub upstream_strategy: Option<UpstreamStrategy>,
    #[ts(type = "number")]
    pub cache_size: u64,
    pub optimistic_cache: bool,
    #[serde(default)]
    pub cache_min_ttl_secs: Option<u32>,
    #[serde(default)]
    pub cache_max_ttl_secs: Option<u32>,
    #[serde(default)]
    pub cache_prefetch_enabled: Option<bool>,
    #[serde(default)]
    pub cache_persist_enabled: Option<bool>,
    #[ts(type = "number")]
    pub upstream_timeout_ms: u64,
    #[ts(type = "number")]
    pub log_retention_hours: u64,
    #[serde(default)]
    #[ts(type = "number | null")]
    pub log_max_disk_mb: Option<u64>,
    #[serde(default)]
    pub block_mode: Option<BlockMode>,
    #[serde(default)]
    pub allow_cidrs: Option<Vec<String>>,
    #[serde(default)]
    pub deny_cidrs: Option<Vec<String>>,
    #[serde(default)]
    pub rate_limit_qps: Option<u32>,
    #[serde(default)]
    pub split_dns: Option<Vec<SplitDnsRule>>,
    #[serde(default)]
    pub upstream_groups: Option<Vec<UpstreamGroup>>,
    #[serde(default)]
    pub split_dns_match_mode: Option<SplitDnsMatchMode>,
    #[serde(default)]
    pub split_dns_before_client_upstreams: Option<bool>,
    #[serde(default)]
    #[ts(type = "number | null")]
    pub split_dns_refresh_interval_secs: Option<u64>,
    #[serde(default)]
    pub cname_cloaking_blocking: Option<bool>,
    #[serde(default)]
    pub doh_enabled: Option<bool>,
    #[serde(default)]
    pub allow_private_subscriptions: Option<bool>,
    #[serde(default)]
    pub ecs_enabled: Option<bool>,
    #[serde(default)]
    pub ecs_custom_ip: Option<String>,
    #[serde(default)]
    pub ecs_ipv4_prefix: Option<u8>,
    #[serde(default)]
    pub ecs_ipv6_prefix: Option<u8>,
    #[serde(default)]
    pub dnssec_enabled: Option<bool>,
    #[serde(default)]
    pub dnssec_trust_anchors: Option<Vec<String>>,
    #[serde(default)]
    pub dnssec_ntas: Option<Vec<DnssecNta>>,
    #[serde(default)]
    pub hosts_enabled: Option<bool>,
    #[serde(default)]
    pub hosts_path: Option<String>,
    #[serde(default)]
    pub dhcp_leases_enabled: Option<bool>,
    #[serde(default)]
    pub dhcp_leases_path: Option<String>,
    #[serde(default)]
    pub dhcp_leases_forward_enabled: Option<bool>,
    #[serde(default)]
    pub dhcp_leases_domain: Option<String>,
    #[serde(default)]
    pub mdns_enabled: Option<bool>,
    #[serde(default)]
    pub llmnr_enabled: Option<bool>,
    #[serde(default)]
    pub sni_client_id_hostnames: Option<Vec<String>>,
    #[serde(default)]
    pub private_ptr_enabled: Option<bool>,
    #[serde(default)]
    pub private_ptr_upstreams: Option<Vec<String>>,
    #[serde(default)]
    pub block_local_domains: Option<bool>,
    #[serde(default)]
    pub suppress_local_domain_logs: Option<bool>,
    #[serde(default)]
    pub ddr_enabled: Option<bool>,
    #[serde(default)]
    pub ddr_hostname: Option<String>,
    #[serde(default)]
    pub dns_rebinding_protection: Option<bool>,
    #[serde(default)]
    pub block_any_queries: Option<bool>,
    #[serde(default)]
    pub trusted_proxies: Option<Vec<String>>,
    #[serde(default)]
    pub trusted_forwarders: Option<Vec<String>>,
    #[serde(default)]
    pub tls_cert_path: Option<String>,
    #[serde(default)]
    pub tls_key_path: Option<String>,
    #[serde(default)]
    pub rdns_enabled: Option<bool>,
    #[serde(default)]
    pub safesearch: Option<SafeSearchConfig>,
    #[serde(default)]
    pub blocked_services: Option<BlockedServicesConfig>,
    #[serde(default)]
    pub dns64_enabled: Option<bool>,
    #[serde(default)]
    pub dns64_prefixes: Option<Vec<String>>,
    #[serde(default)]
    pub svcb_strip_ech: Option<bool>,
    #[serde(default)]
    pub svcb_strip_hints: Option<bool>,
    #[serde(default)]
    pub ede_enabled: Option<bool>,
    #[serde(default)]
    pub dns_cookies_enabled: Option<bool>,
    #[serde(default)]
    pub dns_cookies_require_valid: Option<bool>,
    #[serde(default)]
    pub max_udp_payload_size: Option<u16>,
    #[serde(default)]
    pub rrl_enabled: Option<bool>,
    #[serde(default)]
    pub rrl_responses_per_second: Option<u32>,
    #[serde(default)]
    pub rrl_slip: Option<u32>,
    #[serde(default)]
    #[ts(type = "number | null")]
    pub rrl_window_secs: Option<u64>,
    #[serde(default)]
    pub acme_enabled: Option<bool>,
    #[serde(default)]
    pub acme_domains: Option<Vec<String>>,
    #[serde(default)]
    pub acme_email: Option<String>,
    #[serde(default)]
    pub acme_directory_url: Option<String>,
    #[serde(default)]
    pub acme_challenge_type: Option<AcmeChallengeType>,
    #[serde(default)]
    pub acme_http_listen: Option<String>,
    #[serde(default)]
    pub acme_renew_before_days: Option<u32>,
    #[serde(default)]
    pub cf_cdn: Option<CfCdnConfig>,
    #[serde(default)]
    pub storage_profile: Option<StorageProfile>,
    #[serde(default)]
    #[ts(type = "number | null")]
    pub disk_min_free_mb: Option<u64>,
    #[serde(default)]
    pub serve_stale_enabled: Option<bool>,
    #[serde(default)]
    pub dnssec_strict_clock: Option<bool>,
    #[serde(default)]
    pub dnssec_auto_rollover: Option<bool>,
    #[serde(default)]
    pub recursive: Option<RecursiveConfig>,
    #[serde(default)]
    #[ts(type = "number | null")]
    pub confirm_timeout_secs: Option<u64>,
}

pub async fn get_config(State(state): State<RouterState>) -> Json<ConfigResponse> {
    let cfg = state.app.config.load();
    Json(ConfigResponse::from(cfg.as_ref()))
}

fn clean_string_list(items: Vec<String>) -> Vec<String> {
    items
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn merge_opt_string(incoming: Option<String>, existing: Option<&str>) -> Option<String> {
    match incoming {
        Some(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
        None => existing.map(str::to_string),
    }
}

fn merge_opt_path(incoming: Option<String>, existing: Option<&Path>) -> Option<PathBuf> {
    match incoming {
        Some(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(PathBuf::from(trimmed))
            }
        }
        None => existing.map(Path::to_path_buf),
    }
}

fn bad_request(msg: impl Into<String>) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "error": msg.into() })),
    )
}

#[allow(clippy::needless_pass_by_value)]
fn internal_error(err: impl ToString) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({ "error": err.to_string() })),
    )
}

fn validate_update_payload(
    payload: &ConfigUpdatePayload,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if payload.cache_size == 0
        || payload.upstream_timeout_ms == 0
        || payload.log_retention_hours == 0
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "cache_size, upstream_timeout_ms, and log_retention_hours must be > 0"
            })),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub async fn update_config(
    State(state): State<RouterState>,
    Json(payload): Json<ConfigUpdatePayload>,
) -> Result<Json<ConfigResponse>, (StatusCode, Json<serde_json::Value>)> {
    validate_update_payload(&payload)?;

    let _config_guard = state.app.storage.config_lock().lock().await;
    let _client_guard = state.app.storage.client_lock().lock().await;

    let cleaned_upstreams = clean_string_list(payload.upstreams);
    let current = state.app.config.load_full();
    let bootstrap_dns = clean_string_list(
        payload
            .bootstrap_dns
            .unwrap_or_else(|| current.bootstrap_dns.clone()),
    );
    let strategy = payload
        .upstream_strategy
        .unwrap_or(current.upstream_strategy);
    let block_mode = payload.block_mode.unwrap_or(current.block_mode);
    let allow_cidrs = clean_string_list(
        payload
            .allow_cidrs
            .unwrap_or_else(|| current.allow_cidrs.clone()),
    );
    let deny_cidrs = clean_string_list(
        payload
            .deny_cidrs
            .unwrap_or_else(|| current.deny_cidrs.clone()),
    );
    let rate_limit_qps = payload.rate_limit_qps.unwrap_or(current.rate_limit_qps);
    let split_dns: Vec<SplitDnsRule> = payload
        .split_dns
        .unwrap_or_else(|| current.split_dns.clone())
        .into_iter()
        .map(SplitDnsRule::normalized)
        .filter(SplitDnsRule::has_target)
        .collect();
    let upstream_groups: Vec<UpstreamGroup> = payload
        .upstream_groups
        .unwrap_or_else(|| current.upstream_groups.clone())
        .into_iter()
        .map(UpstreamGroup::normalized)
        .filter(|g| !g.name.is_empty())
        .collect();
    let split_dns_match_mode = payload
        .split_dns_match_mode
        .unwrap_or(current.split_dns_match_mode);
    let split_dns_before_client_upstreams = payload
        .split_dns_before_client_upstreams
        .unwrap_or(current.split_dns_before_client_upstreams);
    let split_dns_refresh_interval_secs = payload
        .split_dns_refresh_interval_secs
        .unwrap_or(current.split_dns_refresh_interval_secs);
    crabdns_core::config::validate_split_dns_refresh_interval(split_dns_refresh_interval_secs)
        .map_err(|err| bad_request(err.to_string()))?;
    let cname_cloaking_blocking = payload
        .cname_cloaking_blocking
        .unwrap_or(current.cname_cloaking_blocking);
    let doh_enabled = payload.doh_enabled.unwrap_or(current.doh_enabled);
    let allow_private_subscriptions = payload
        .allow_private_subscriptions
        .unwrap_or(current.allow_private_subscriptions);
    let ecs_enabled = payload.ecs_enabled.unwrap_or(current.ecs_enabled);
    let ecs_custom_ip = merge_opt_string(payload.ecs_custom_ip, current.ecs_custom_ip.as_deref());
    let ecs_ipv4_prefix = payload.ecs_ipv4_prefix.unwrap_or(current.ecs_ipv4_prefix);
    let ecs_ipv6_prefix = payload.ecs_ipv6_prefix.unwrap_or(current.ecs_ipv6_prefix);
    let dnssec_enabled = payload.dnssec_enabled.unwrap_or(current.dnssec_enabled);
    let dnssec_trust_anchors = clean_string_list(
        payload
            .dnssec_trust_anchors
            .unwrap_or_else(|| current.dnssec_trust_anchors.clone()),
    );
    let dnssec_ntas = normalize_nta_entries(
        &payload
            .dnssec_ntas
            .unwrap_or_else(|| current.dnssec_ntas.clone()),
    )
    .map_err(|err| bad_request(err.to_string()))?;
    let log_max_disk_mb = payload.log_max_disk_mb.unwrap_or(current.log_max_disk_mb);
    if log_max_disk_mb == 0 {
        return Err(bad_request("log_max_disk_mb must be > 0"));
    }
    let hosts_enabled = payload.hosts_enabled.unwrap_or(current.hosts_enabled);
    let hosts_path = merge_opt_string(payload.hosts_path, current.hosts_path.as_deref());
    let dhcp_leases_enabled = payload
        .dhcp_leases_enabled
        .unwrap_or(current.dhcp_leases_enabled);
    let dhcp_leases_path = merge_opt_string(
        payload.dhcp_leases_path,
        current.dhcp_leases_path.as_deref(),
    );
    let dhcp_leases_forward_enabled = payload
        .dhcp_leases_forward_enabled
        .unwrap_or(current.dhcp_leases_forward_enabled);
    let dhcp_leases_domain = payload
        .dhcp_leases_domain
        .map(|d| d.trim().trim_matches('.').to_ascii_lowercase())
        .filter(|d| !d.is_empty())
        .unwrap_or_else(|| current.dhcp_leases_domain.clone());
    let mdns_enabled = payload.mdns_enabled.unwrap_or(current.mdns_enabled);
    let llmnr_enabled = payload.llmnr_enabled.unwrap_or(current.llmnr_enabled);
    let sni_client_id_hostnames = clean_string_list(
        payload
            .sni_client_id_hostnames
            .unwrap_or_else(|| current.sni_client_id_hostnames.clone()),
    );
    let private_ptr_enabled = payload
        .private_ptr_enabled
        .unwrap_or(current.private_ptr_enabled);
    let private_ptr_upstreams = clean_string_list(
        payload
            .private_ptr_upstreams
            .unwrap_or_else(|| current.private_ptr_upstreams.clone()),
    );
    let ddr_enabled = payload.ddr_enabled.unwrap_or(current.ddr_enabled);
    let ddr_hostname = merge_opt_string(payload.ddr_hostname, current.ddr_hostname.as_deref());
    let dns_rebinding_protection = payload
        .dns_rebinding_protection
        .unwrap_or(current.dns_rebinding_protection);
    let block_any_queries = payload
        .block_any_queries
        .unwrap_or(current.block_any_queries);
    let block_local_domains = payload
        .block_local_domains
        .unwrap_or(current.block_local_domains);
    let suppress_local_domain_logs = payload
        .suppress_local_domain_logs
        .unwrap_or(current.suppress_local_domain_logs);
    let trusted_proxies = clean_string_list(
        payload
            .trusted_proxies
            .unwrap_or_else(|| current.trusted_proxies.clone()),
    );
    let trusted_forwarders = clean_string_list(
        payload
            .trusted_forwarders
            .unwrap_or_else(|| current.trusted_forwarders.clone()),
    );
    let tls_cert_path = merge_opt_path(payload.tls_cert_path, current.tls_cert_path.as_deref());
    let tls_key_path = merge_opt_path(payload.tls_key_path, current.tls_key_path.as_deref());
    let rdns_enabled = payload.rdns_enabled.unwrap_or(current.rdns_enabled);
    let safesearch = payload
        .safesearch
        .unwrap_or_else(|| current.safesearch.clone());
    let blocked_services = match payload.blocked_services {
        Some(mut bs) => {
            bs.services = crabdns_core::normalize_service_ids(&bs.services);
            bs
        }
        None => current.blocked_services.clone(),
    };
    let dns64_enabled = payload.dns64_enabled.unwrap_or(current.dns64_enabled);
    let dns64_prefixes = clean_string_list(
        payload
            .dns64_prefixes
            .unwrap_or_else(|| current.dns64_prefixes.clone()),
    );
    let svcb_strip_ech = payload.svcb_strip_ech.unwrap_or(current.svcb_strip_ech);
    let svcb_strip_hints = payload.svcb_strip_hints.unwrap_or(current.svcb_strip_hints);
    let ede_enabled = payload.ede_enabled.unwrap_or(current.ede_enabled);
    let dns_cookies_enabled = payload
        .dns_cookies_enabled
        .unwrap_or(current.dns_cookies_enabled);
    let dns_cookies_require_valid = payload
        .dns_cookies_require_valid
        .unwrap_or(current.dns_cookies_require_valid);
    let max_udp_payload_size = payload
        .max_udp_payload_size
        .unwrap_or(current.max_udp_payload_size)
        .max(512);
    let acme_updates = AcmeConfigUpdates {
        enabled: payload.acme_enabled,
        domains: payload.acme_domains,
        email: payload.acme_email,
        directory_url: payload.acme_directory_url,
        challenge_type: payload.acme_challenge_type,
        http_listen: payload.acme_http_listen,
        renew_before_days: payload.acme_renew_before_days,
    };
    let rrl_enabled = payload.rrl_enabled.unwrap_or(current.rrl_enabled);
    let rrl_responses_per_second = payload
        .rrl_responses_per_second
        .unwrap_or(current.rrl_responses_per_second);
    let rrl_slip = payload.rrl_slip.unwrap_or(current.rrl_slip);
    let rrl_window_secs = payload.rrl_window_secs.unwrap_or(current.rrl_window_secs);

    let cache_min_ttl_secs = payload
        .cache_min_ttl_secs
        .unwrap_or(current.cache_min_ttl_secs)
        .max(1);
    let cache_max_ttl_secs = payload
        .cache_max_ttl_secs
        .unwrap_or(current.cache_max_ttl_secs);
    if cache_max_ttl_secs < cache_min_ttl_secs {
        return Err(bad_request(
            "cache_max_ttl_secs must be >= cache_min_ttl_secs",
        ));
    }
    let cache_prefetch_enabled = payload
        .cache_prefetch_enabled
        .unwrap_or(current.cache_prefetch_enabled);
    let cache_persist_enabled = payload
        .cache_persist_enabled
        .unwrap_or(current.cache_persist_enabled);

    // Phase 1: Validate and build all runtime objects without mutating live state.
    parse_trust_anchors(&dnssec_trust_anchors).map_err(|err| bad_request(err.to_string()))?;
    Dns64Config::compile(dns64_enabled, &dns64_prefixes)
        .map_err(|err| bad_request(err.to_string()))?;
    if let Err(err) = parse_cidr_list(&trusted_proxies) {
        return Err(bad_request(err.to_string()));
    }
    if let Err(err) = parse_cidr_list(&trusted_forwarders) {
        return Err(bad_request(err.to_string()));
    }
    let next_acl = AccessController::new(&allow_cidrs, &deny_cidrs, rate_limit_qps)
        .map_err(|err| bad_request(err.to_string()))?;
    let next_ecs = EcsConfig::from_parts(
        ecs_enabled,
        ecs_custom_ip.as_deref(),
        ecs_ipv4_prefix,
        ecs_ipv6_prefix,
    )
    .map_err(|err| bad_request(err.to_string()))?;
    let next_upstream = UpstreamPool::new_with_bootstrap(
        &cleaned_upstreams,
        payload.upstream_timeout_ms,
        strategy,
        &bootstrap_dns,
    )
    .map_err(|err| bad_request(err.to_string()))?;
    let next_upstream_groups = UpstreamGroupRegistry::compile(
        &upstream_groups,
        payload.upstream_timeout_ms,
        strategy,
        &bootstrap_dns,
    )
    .map_err(|err| bad_request(err.to_string()))?;
    let next_split_dns = SplitUpstreamRouter::new_full(
        &split_dns,
        &next_upstream_groups,
        split_dns_match_mode,
        payload.upstream_timeout_ms,
        strategy,
        &bootstrap_dns,
        |url| state.app.storage.load_split_dns_list(url).ok().flatten(),
    )
    .map_err(|err| bad_request(err.to_string()))?;
    let next_private_ptr = PrivatePtrRouter::new(
        private_ptr_enabled,
        &private_ptr_upstreams,
        payload.upstream_timeout_ms,
        strategy,
        &bootstrap_dns,
    )
    .map_err(|err| bad_request(err.to_string()))?;

    let next_clients = compile_clients_for_config(
        &state,
        &next_upstream_groups,
        payload.upstream_timeout_ms,
        strategy,
        &bootstrap_dns,
    )
    .await?;

    let hosts_table_opt = if hosts_enabled {
        let resolved_hosts = hosts_path.as_deref().unwrap_or("/etc/hosts").to_string();
        let path_for_log = resolved_hosts.clone();
        match tokio::task::spawn_blocking(move || HostsTable::from_file(Path::new(&resolved_hosts)))
            .await
        {
            Ok(Ok(table)) => Some(table),
            Ok(Err(err)) => {
                tracing::warn!(path = %path_for_log, error = %err, "failed to load hosts file");
                None
            }
            Err(err) => {
                tracing::warn!(path = %path_for_log, error = %err, "hosts load task panicked");
                None
            }
        }
    } else {
        None
    };

    let dhcp_table_opt = if dhcp_leases_enabled {
        let resolved_dhcp =
            crabdns_core::resolve_dhcp_leases_path(dhcp_leases_path.as_deref()).to_string();
        let path_for_log = resolved_dhcp.clone();
        match tokio::task::spawn_blocking(move || {
            DhcpLeaseTable::from_file(Path::new(&resolved_dhcp))
        })
        .await
        {
            Ok(Ok(table)) => Some(table),
            Ok(Err(err)) => {
                tracing::warn!(path = %path_for_log, error = %err, "failed to load DHCP leases file");
                None
            }
            Err(err) => {
                tracing::warn!(path = %path_for_log, error = %err, "DHCP leases load task panicked");
                None
            }
        }
    } else {
        None
    };

    if (tls_cert_path != current.tls_cert_path || tls_key_path != current.tls_key_path)
        && let Some(reloader) = &state.app.tls_reloader
        && let Err(err) = reloader.reload(tls_cert_path.as_deref(), tls_key_path.as_deref())
    {
        return Err(bad_request(err));
    }

    let mut next = (*current).clone();
    next.upstreams = cleaned_upstreams;
    next.bootstrap_dns = bootstrap_dns;
    next.upstream_strategy = strategy;
    next.cache_size = payload.cache_size;
    next.optimistic_cache = payload.optimistic_cache;
    next.cache_min_ttl_secs = cache_min_ttl_secs;
    next.cache_max_ttl_secs = cache_max_ttl_secs;
    next.cache_prefetch_enabled = cache_prefetch_enabled;
    next.cache_persist_enabled = cache_persist_enabled;
    next.upstream_timeout_ms = payload.upstream_timeout_ms;
    next.log_retention_hours = payload.log_retention_hours;
    next.log_max_disk_mb = log_max_disk_mb;
    next.block_mode = block_mode;
    next.allow_cidrs = allow_cidrs;
    next.deny_cidrs = deny_cidrs;
    next.rate_limit_qps = rate_limit_qps;
    next.split_dns = split_dns;
    next.upstream_groups = upstream_groups;
    next.split_dns_match_mode = split_dns_match_mode;
    next.split_dns_before_client_upstreams = split_dns_before_client_upstreams;
    next.split_dns_refresh_interval_secs = split_dns_refresh_interval_secs;
    next.cname_cloaking_blocking = cname_cloaking_blocking;
    next.doh_enabled = doh_enabled;
    next.allow_private_subscriptions = allow_private_subscriptions;
    next.ecs_enabled = ecs_enabled;
    next.ecs_custom_ip = ecs_custom_ip;
    next.ecs_ipv4_prefix = ecs_ipv4_prefix;
    next.ecs_ipv6_prefix = ecs_ipv6_prefix;
    next.dnssec_enabled = dnssec_enabled;
    next.dnssec_trust_anchors.clone_from(&dnssec_trust_anchors);
    next.dnssec_ntas.clone_from(&dnssec_ntas);
    next.hosts_enabled = hosts_enabled;
    next.hosts_path = hosts_path;
    next.dhcp_leases_enabled = dhcp_leases_enabled;
    next.dhcp_leases_path = dhcp_leases_path;
    next.dhcp_leases_forward_enabled = dhcp_leases_forward_enabled;
    next.dhcp_leases_domain.clone_from(&dhcp_leases_domain);
    next.mdns_enabled = mdns_enabled;
    next.llmnr_enabled = llmnr_enabled;
    next.sni_client_id_hostnames = sni_client_id_hostnames;
    next.private_ptr_enabled = private_ptr_enabled;
    next.private_ptr_upstreams = private_ptr_upstreams;
    next.block_local_domains = block_local_domains;
    next.suppress_local_domain_logs = suppress_local_domain_logs;
    next.ddr_enabled = ddr_enabled;
    next.ddr_hostname.clone_from(&ddr_hostname);
    next.dns_rebinding_protection = dns_rebinding_protection;
    next.block_any_queries = block_any_queries;
    next.trusted_proxies = trusted_proxies;
    next.trusted_forwarders.clone_from(&trusted_forwarders);
    next.tls_cert_path = tls_cert_path;
    next.tls_key_path = tls_key_path;
    next.rdns_enabled = rdns_enabled;
    next.safesearch = safesearch.clone();
    next.blocked_services = blocked_services.clone();
    next.dns64_enabled = dns64_enabled;
    next.dns64_prefixes.clone_from(&dns64_prefixes);
    next.svcb_strip_ech = svcb_strip_ech;
    next.svcb_strip_hints = svcb_strip_hints;
    next.ede_enabled = ede_enabled;
    next.dns_cookies_enabled = dns_cookies_enabled;
    next.dns_cookies_require_valid = dns_cookies_require_valid;
    next.max_udp_payload_size = max_udp_payload_size;
    next.rrl_enabled = rrl_enabled;
    next.rrl_responses_per_second = rrl_responses_per_second;
    next.rrl_slip = rrl_slip;
    next.rrl_window_secs = rrl_window_secs;
    if let Some(cf_cdn) = payload.cf_cdn {
        next.cf_cdn = cf_cdn;
    }
    if let Some(storage_profile) = payload.storage_profile {
        next.storage_profile = storage_profile;
    }
    if let Some(disk_min_free_mb) = payload.disk_min_free_mb {
        next.disk_min_free_mb = disk_min_free_mb;
    }
    if let Some(serve_stale_enabled) = payload.serve_stale_enabled {
        next.serve_stale_enabled = serve_stale_enabled;
    }
    if let Some(dnssec_strict_clock) = payload.dnssec_strict_clock {
        next.dnssec_strict_clock = dnssec_strict_clock;
    }
    if let Some(dnssec_auto_rollover) = payload.dnssec_auto_rollover {
        next.dnssec_auto_rollover = dnssec_auto_rollover;
    }
    if let Some(recursive) = payload.recursive {
        next.recursive = recursive;
    }
    apply_acme_updates(&mut next, acme_updates)?;

    // Phase 2: Persist config first, then atomically swap all runtime state.
    let storage = Arc::clone(&state.app.storage);
    let to_save = next.clone();
    let prev_snapshot = current.clone();
    let confirm_timeout_secs = payload.confirm_timeout_secs;
    let rollback_snapshot_id =
        tokio::task::spawn_blocking(move || -> crabdns_storage::Result<Option<String>> {
            let rollback_id = if confirm_timeout_secs.is_some() {
                Some(
                    storage
                        .record_config_snapshot(&prev_snapshot, "pre_confirm")?
                        .id,
                )
            } else {
                if storage.list_config_history()?.is_empty() {
                    let _ = storage.record_config_snapshot(&prev_snapshot, "initial");
                }
                None
            };
            storage.save_config(&to_save.runtime)?;
            let _ = storage.record_config_snapshot(&to_save, "settings_update");
            Ok(rollback_id)
        })
        .await
        .map_err(internal_error)?
        .map_err(internal_error)?;

    let pipe = &state.app.pipeline;
    pipe.swap_acl(next_acl);
    pipe.swap_ecs(next_ecs);
    pipe.swap_upstream(next_upstream);
    pipe.swap_upstream_groups(next_upstream_groups);
    pipe.set_split_dns_before_client_upstreams(split_dns_before_client_upstreams);
    pipe.swap_split_dns(next_split_dns);
    pipe.swap_private_ptr(next_private_ptr);
    pipe.swap_clients(next_clients);
    if let Some(table) = hosts_table_opt {
        pipe.reload_hosts_table(table);
    }
    if let Some(dhcp_table) = dhcp_table_opt {
        pipe.reload_dhcp_leases_table(dhcp_table);
    }
    pipe.set_block_mode(block_mode);
    pipe.set_cname_cloaking(cname_cloaking_blocking);
    pipe.set_dnssec_enabled(dnssec_enabled);
    pipe.dnssec_validator()
        .set_strict_clock(next.dnssec_strict_clock);
    pipe.dnssec_validator()
        .set_auto_rollover(next.dnssec_auto_rollover);
    pipe.set_serve_stale_enabled(next.serve_stale_enabled);
    let _ = pipe.reload_dnssec_anchors(&dnssec_trust_anchors, &dnssec_ntas);
    pipe.set_hosts_enabled(hosts_enabled);
    pipe.set_dhcp_leases_enabled(dhcp_leases_enabled);
    pipe.set_dhcp_leases_forward(dhcp_leases_forward_enabled, dhcp_leases_domain);
    pipe.set_mdns_enabled(mdns_enabled);
    pipe.set_llmnr_enabled(llmnr_enabled);
    pipe.set_dns_rebinding_protection(dns_rebinding_protection);
    pipe.set_block_any_queries(block_any_queries);
    pipe.set_block_local_domains(block_local_domains);
    pipe.set_suppress_local_domain_logs(suppress_local_domain_logs);
    pipe.set_rdns_enabled(rdns_enabled);
    pipe.set_safesearch(safesearch);
    pipe.set_blocked_services(blocked_services);
    if let Err(err) = pipe.set_recursive(&next.recursive, payload.upstream_timeout_ms) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": err.to_string() })),
        ));
    }
    let _ = pipe.reload_dns64(dns64_enabled, &dns64_prefixes);
    pipe.set_svcb_sanitization(svcb_strip_ech, svcb_strip_hints);
    pipe.reload_cf_cdn(next.cf_cdn.clone());
    pipe.set_ede_enabled(ede_enabled);
    let _ = pipe.reload_trusted_forwarders(&next.trusted_forwarders);
    pipe.set_dns_cookies(dns_cookies_enabled, dns_cookies_require_valid);
    pipe.set_max_udp_payload_size(max_udp_payload_size);
    pipe.set_rrl(crabdns_core::RrlConfig {
        enabled: rrl_enabled,
        responses_per_second: rrl_responses_per_second,
        slip: rrl_slip,
        window_secs: rrl_window_secs,
    });
    pipe.reload_ddr(DdrConfig {
        enabled: ddr_enabled,
        hostname: ddr_hostname,
        dot_port: current.bootstrap.listen_dot.map(|a| a.port()),
        doq_port: current.bootstrap.listen_doq.map(|a| a.port()),
        doh_enabled,
        doh_port: current
            .bootstrap
            .listen_web_tls
            .map(|a| a.port())
            .or(Some(current.bootstrap.listen_web.port())),
    });

    let split_dns_changed = current.split_dns != next.split_dns
        || current.upstream_groups != next.upstream_groups
        || current.split_dns_match_mode != next.split_dns_match_mode
        || current.split_dns_before_client_upstreams != next.split_dns_before_client_upstreams;

    let cache_changed = current.cache_size != payload.cache_size
        || current.optimistic_cache != payload.optimistic_cache
        || current.cache_min_ttl_secs != cache_min_ttl_secs
        || current.cache_max_ttl_secs != cache_max_ttl_secs
        || current.cache_prefetch_enabled != cache_prefetch_enabled;
    if cache_changed {
        state.app.pipeline.reload_cache_with_options(
            payload.cache_size,
            payload.optimistic_cache,
            cache_min_ttl_secs,
            cache_max_ttl_secs,
            cache_prefetch_enabled,
        );
    } else if split_dns_changed {
        state.app.pipeline.cache().flush();
    }

    crate::split_dns_sync::maybe_spawn_split_dns_sync(&state, &next);
    let response = ConfigResponse::from(&next);
    state.app.config.store(Arc::new(next));
    if let (Some(timeout_secs), Some(snapshot_id)) = (confirm_timeout_secs, rollback_snapshot_id) {
        state
            .config_confirm
            .schedule(state.clone(), snapshot_id, timeout_secs);
    }
    Ok(Json(response))
}

async fn compile_clients_for_config(
    state: &RouterState,
    upstream_groups: &UpstreamGroupRegistry,
    timeout_ms: u64,
    strategy: UpstreamStrategy,
    bootstrap_dns: &[String],
) -> Result<ClientRegistry, (StatusCode, Json<serde_json::Value>)> {
    let storage = Arc::clone(&state.app.storage);
    let (clients, groups) = tokio::task::spawn_blocking(move || {
        Ok::<_, crabdns_storage::StorageError>((
            storage.list_clients()?,
            storage.list_client_groups()?,
        ))
    })
    .await
    .map_err(internal_error)?
    .map_err(internal_error)?;

    ClientRegistry::compile_with_groups(
        &clients,
        &groups,
        upstream_groups,
        timeout_ms,
        strategy,
        bootstrap_dns,
    )
    .map_err(|err| bad_request(err.to_string()))
}
