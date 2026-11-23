use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use crabdns_core::acl::parse_cidr_list;
use crabdns_core::{
    AccessController, AcmeChallengeType, BlockMode, CfCdnConfig, ClientRegistry, Config, DdrConfig,
    DhcpLeaseTable, Dns64Config, EcsConfig, HostsTable, PrivatePtrRouter, SafeSearchConfig,
    SplitDnsRule, SplitUpstreamRouter, UpstreamPool, UpstreamStrategy,
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
    pub block_mode: BlockMode,
    pub allow_cidrs: Vec<String>,
    pub deny_cidrs: Vec<String>,
    pub rate_limit_qps: u32,
    pub web_auth_enabled: bool,
    pub web_username: String,
    pub split_dns: Vec<SplitDnsRule>,
    pub cname_cloaking_blocking: bool,
    pub doh_enabled: bool,
    pub allow_private_subscriptions: bool,
    pub ecs_enabled: bool,
    pub ecs_custom_ip: Option<String>,
    pub ecs_ipv4_prefix: u8,
    pub ecs_ipv6_prefix: u8,
    pub dnssec_enabled: bool,
    pub hosts_enabled: bool,
    pub hosts_path: Option<String>,
    pub dhcp_leases_enabled: bool,
    pub dhcp_leases_path: Option<String>,
    pub dhcp_leases_forward_enabled: bool,
    pub dhcp_leases_domain: String,
    pub mdns_enabled: bool,
    pub private_ptr_enabled: bool,
    pub private_ptr_upstreams: Vec<String>,
    pub block_local_domains: bool,
    pub suppress_local_domain_logs: bool,
    pub ddr_enabled: bool,
    pub ddr_hostname: Option<String>,
    pub dns_rebinding_protection: bool,
    pub block_any_queries: bool,
    pub trusted_proxies: Vec<String>,
    pub rdns_enabled: bool,
    pub safesearch: SafeSearchConfig,
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
}

impl From<&Config> for ConfigResponse {
    fn from(cfg: &Config) -> Self {
        Self {
            listen_dns: cfg.listen_dns.to_string(),
            listen_web: cfg.listen_web.to_string(),
            listen_web_tls: cfg.listen_web_tls.map(|addr| addr.to_string()),
            listen_dot: cfg.listen_dot.map(|addr| addr.to_string()),
            listen_doq: cfg.listen_doq.map(|addr| addr.to_string()),
            listen_doh3: cfg.listen_doh3.map(|addr| addr.to_string()),
            sni_client_id_hostnames: cfg.sni_client_id_hostnames.clone(),
            tls_cert_path: cfg.tls_cert_path.as_ref().map(|p| p.display().to_string()),
            tls_key_path: cfg.tls_key_path.as_ref().map(|p| p.display().to_string()),
            data_dir: cfg.data_dir.display().to_string(),
            upstreams: cfg.upstreams.clone(),
            bootstrap_dns: cfg.bootstrap_dns.clone(),
            upstream_strategy: cfg.upstream_strategy,
            cache_size: cfg.cache_size,
            optimistic_cache: cfg.optimistic_cache,
            cache_min_ttl_secs: cfg.cache_min_ttl_secs,
            cache_max_ttl_secs: cfg.cache_max_ttl_secs,
            cache_prefetch_enabled: cfg.cache_prefetch_enabled,
            cache_persist_enabled: cfg.cache_persist_enabled,
            upstream_timeout_ms: cfg.upstream_timeout_ms,
            log_retention_hours: cfg.log_retention_hours,
            block_mode: cfg.block_mode,
            allow_cidrs: cfg.allow_cidrs.clone(),
            deny_cidrs: cfg.deny_cidrs.clone(),
            rate_limit_qps: cfg.rate_limit_qps,
            web_auth_enabled: cfg.web_auth_enabled,
            web_username: cfg.web_username.clone(),
            split_dns: cfg.split_dns.clone(),
            cname_cloaking_blocking: cfg.cname_cloaking_blocking,
            doh_enabled: cfg.doh_enabled,
            allow_private_subscriptions: cfg.allow_private_subscriptions,
            ecs_enabled: cfg.ecs_enabled,
            ecs_custom_ip: cfg.ecs_custom_ip.clone(),
            ecs_ipv4_prefix: cfg.ecs_ipv4_prefix,
            ecs_ipv6_prefix: cfg.ecs_ipv6_prefix,
            dnssec_enabled: cfg.dnssec_enabled,
            hosts_enabled: cfg.hosts_enabled,
            hosts_path: cfg.hosts_path.clone(),
            dhcp_leases_enabled: cfg.dhcp_leases_enabled,
            dhcp_leases_path: cfg.dhcp_leases_path.clone(),
            dhcp_leases_forward_enabled: cfg.dhcp_leases_forward_enabled,
            dhcp_leases_domain: cfg.dhcp_leases_domain.clone(),
            mdns_enabled: cfg.mdns_enabled,
            private_ptr_enabled: cfg.private_ptr_enabled,
            private_ptr_upstreams: cfg.private_ptr_upstreams.clone(),
            block_local_domains: cfg.block_local_domains,
            suppress_local_domain_logs: cfg.suppress_local_domain_logs,
            ddr_enabled: cfg.ddr_enabled,
            ddr_hostname: cfg.ddr_hostname.clone(),
            dns_rebinding_protection: cfg.dns_rebinding_protection,
            block_any_queries: cfg.block_any_queries,
            trusted_proxies: cfg.trusted_proxies.clone(),
            rdns_enabled: cfg.rdns_enabled,
            safesearch: cfg.safesearch.clone(),
            dns64_enabled: cfg.dns64_enabled,
            dns64_prefixes: cfg.dns64_prefixes.clone(),
            svcb_strip_ech: cfg.svcb_strip_ech,
            svcb_strip_hints: cfg.svcb_strip_hints,
            ede_enabled: cfg.ede_enabled,
            dns_cookies_enabled: cfg.dns_cookies_enabled,
            dns_cookies_require_valid: cfg.dns_cookies_require_valid,
            max_udp_payload_size: cfg.max_udp_payload_size,
            rrl_enabled: cfg.rrl_enabled,
            rrl_responses_per_second: cfg.rrl_responses_per_second,
            rrl_slip: cfg.rrl_slip,
            rrl_window_secs: cfg.rrl_window_secs,
            acme_enabled: cfg.acme_enabled,
            acme_domains: cfg.acme_domains.clone(),
            acme_email: cfg.acme_email.clone(),
            acme_directory_url: cfg.acme_directory_url.clone(),
            acme_challenge_type: cfg.acme_challenge_type,
            acme_http_listen: cfg.acme_http_listen.map(|addr| addr.to_string()),
            acme_renew_before_days: cfg.acme_renew_before_days,
            cf_cdn: cfg.cf_cdn.clone(),
        }
    }
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
    pub tls_cert_path: Option<String>,
    #[serde(default)]
    pub tls_key_path: Option<String>,
    #[serde(default)]
    pub rdns_enabled: Option<bool>,
    #[serde(default)]
    pub safesearch: Option<SafeSearchConfig>,
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

#[allow(clippy::too_many_lines)]
pub async fn update_config(
    State(state): State<RouterState>,
    Json(payload): Json<ConfigUpdatePayload>,
) -> Result<Json<ConfigResponse>, (StatusCode, Json<serde_json::Value>)> {
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
        .map(|rule| SplitDnsRule {
            domain: rule.domain.trim().to_string(),
            domains_file: rule
                .domains_file
                .map(|p| p.trim().to_string())
                .filter(|p| !p.is_empty()),
            domains_url: rule
                .domains_url
                .map(|u| u.trim().to_string())
                .filter(|u| !u.is_empty()),
            upstreams: clean_string_list(rule.upstreams),
            fallback_to_default: rule.fallback_to_default,
            policy: rule.policy.normalized(),
        })
        .filter(|r| !r.domain.is_empty() || r.domains_file.is_some() || r.domains_url.is_some())
        .collect();
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
    let tls_cert_path = merge_opt_path(payload.tls_cert_path, current.tls_cert_path.as_deref());
    let tls_key_path = merge_opt_path(payload.tls_key_path, current.tls_key_path.as_deref());
    let rdns_enabled = payload.rdns_enabled.unwrap_or(current.rdns_enabled);
    let safesearch = payload
        .safesearch
        .unwrap_or_else(|| current.safesearch.clone());
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
    Dns64Config::compile(dns64_enabled, &dns64_prefixes)
        .map_err(|err| bad_request(err.to_string()))?;
    if let Err(err) = parse_cidr_list(&trusted_proxies) {
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
    let next_split_dns = SplitUpstreamRouter::new_with_resolver(
        &split_dns,
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
    next.block_mode = block_mode;
    next.allow_cidrs = allow_cidrs;
    next.deny_cidrs = deny_cidrs;
    next.rate_limit_qps = rate_limit_qps;
    next.split_dns = split_dns;
    next.cname_cloaking_blocking = cname_cloaking_blocking;
    next.doh_enabled = doh_enabled;
    next.allow_private_subscriptions = allow_private_subscriptions;
    next.ecs_enabled = ecs_enabled;
    next.ecs_custom_ip = ecs_custom_ip;
    next.ecs_ipv4_prefix = ecs_ipv4_prefix;
    next.ecs_ipv6_prefix = ecs_ipv6_prefix;
    next.dnssec_enabled = dnssec_enabled;
    next.hosts_enabled = hosts_enabled;
    next.hosts_path = hosts_path;
    next.dhcp_leases_enabled = dhcp_leases_enabled;
    next.dhcp_leases_path = dhcp_leases_path;
    next.dhcp_leases_forward_enabled = dhcp_leases_forward_enabled;
    next.dhcp_leases_domain = dhcp_leases_domain.clone();
    next.mdns_enabled = mdns_enabled;
    next.sni_client_id_hostnames = sni_client_id_hostnames;
    next.private_ptr_enabled = private_ptr_enabled;
    next.private_ptr_upstreams = private_ptr_upstreams;
    next.block_local_domains = block_local_domains;
    next.suppress_local_domain_logs = suppress_local_domain_logs;
    next.ddr_enabled = ddr_enabled;
    next.ddr_hostname = ddr_hostname.clone();
    next.dns_rebinding_protection = dns_rebinding_protection;
    next.block_any_queries = block_any_queries;
    next.trusted_proxies = trusted_proxies;
    next.tls_cert_path = tls_cert_path;
    next.tls_key_path = tls_key_path;
    next.rdns_enabled = rdns_enabled;
    next.safesearch = safesearch.clone();
    next.dns64_enabled = dns64_enabled;
    next.dns64_prefixes = dns64_prefixes.clone();
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
    apply_acme_updates(&mut next, acme_updates)?;

    // Phase 2: Persist config first, then atomically swap all runtime state.
    let storage = Arc::clone(&state.app.storage);
    let to_save = next.clone();
    let prev_snapshot = current.clone();
    tokio::task::spawn_blocking(move || -> crabdns_storage::Result<()> {
        if storage.list_config_history()?.is_empty() {
            let _ = storage.record_config_snapshot(&prev_snapshot, "initial");
        }
        storage.save_config(&to_save)?;
        let _ = storage.record_config_snapshot(&to_save, "settings_update");
        Ok(())
    })
    .await
    .map_err(internal_error)?
    .map_err(internal_error)?;

    let pipe = &state.app.pipeline;
    pipe.swap_acl(next_acl);
    pipe.swap_ecs(next_ecs);
    pipe.swap_upstream(next_upstream);
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
    pipe.set_hosts_enabled(hosts_enabled);
    pipe.set_dhcp_leases_enabled(dhcp_leases_enabled);
    pipe.set_dhcp_leases_forward(dhcp_leases_forward_enabled, dhcp_leases_domain);
    pipe.set_mdns_enabled(mdns_enabled);
    pipe.set_dns_rebinding_protection(dns_rebinding_protection);
    pipe.set_block_any_queries(block_any_queries);
    pipe.set_block_local_domains(block_local_domains);
    pipe.set_suppress_local_domain_logs(suppress_local_domain_logs);
    pipe.set_rdns_enabled(rdns_enabled);
    pipe.set_safesearch(safesearch);
    let _ = pipe.reload_dns64(dns64_enabled, &dns64_prefixes);
    pipe.set_svcb_sanitization(svcb_strip_ech, svcb_strip_hints);
    pipe.reload_cf_cdn(next.cf_cdn.clone());
    pipe.set_ede_enabled(ede_enabled);
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
        dot_port: current.listen_dot.map(|a| a.port()),
        doq_port: current.listen_doq.map(|a| a.port()),
        doh_enabled,
        doh_port: current
            .listen_web_tls
            .map(|a| a.port())
            .or(Some(current.listen_web.port())),
    });

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
    }

    crate::split_dns_sync::maybe_spawn_split_dns_sync(&state, &next);
    let response = ConfigResponse::from(&next);
    state.app.config.store(Arc::new(next));
    Ok(Json(response))
}

async fn compile_clients_for_config(
    state: &RouterState,
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

    ClientRegistry::compile(&clients, &groups, timeout_ms, strategy, bootstrap_dns)
        .map_err(|err| bad_request(err.to_string()))
}
