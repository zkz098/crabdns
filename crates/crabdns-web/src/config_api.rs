use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use crabdns_core::acl::parse_cidr_list;
use crabdns_core::{BlockMode, Config, DdrConfig, SplitDnsRule, UpstreamStrategy};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::RouterState;

#[derive(Debug, Serialize, Deserialize, TS)]
#[ts(export)]
#[allow(clippy::struct_excessive_bools)]
pub struct ConfigResponse {
    pub listen_dns: String,
    pub listen_web: String,
    pub listen_web_tls: Option<String>,
    pub listen_dot: Option<String>,
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
    pub private_ptr_enabled: bool,
    pub private_ptr_upstreams: Vec<String>,
    pub ddr_enabled: bool,
    pub ddr_hostname: Option<String>,
    pub dns_rebinding_protection: bool,
    pub block_any_queries: bool,
    pub trusted_proxies: Vec<String>,
    pub rdns_enabled: bool,
}

impl From<&Config> for ConfigResponse {
    fn from(cfg: &Config) -> Self {
        Self {
            listen_dns: cfg.listen_dns.to_string(),
            listen_web: cfg.listen_web.to_string(),
            listen_web_tls: cfg.listen_web_tls.map(|addr| addr.to_string()),
            listen_dot: cfg.listen_dot.map(|addr| addr.to_string()),
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
            private_ptr_enabled: cfg.private_ptr_enabled,
            private_ptr_upstreams: cfg.private_ptr_upstreams.clone(),
            ddr_enabled: cfg.ddr_enabled,
            ddr_hostname: cfg.ddr_hostname.clone(),
            dns_rebinding_protection: cfg.dns_rebinding_protection,
            block_any_queries: cfg.block_any_queries,
            trusted_proxies: cfg.trusted_proxies.clone(),
            rdns_enabled: cfg.rdns_enabled,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, TS)]
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
    pub private_ptr_enabled: Option<bool>,
    #[serde(default)]
    pub private_ptr_upstreams: Option<Vec<String>>,
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
            upstreams: clean_string_list(rule.upstreams),
        })
        .filter(|rule| !rule.domain.is_empty())
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
    let trusted_proxies = clean_string_list(
        payload
            .trusted_proxies
            .unwrap_or_else(|| current.trusted_proxies.clone()),
    );
    let tls_cert_path = merge_opt_path(payload.tls_cert_path, current.tls_cert_path.as_deref());
    let tls_key_path = merge_opt_path(payload.tls_key_path, current.tls_key_path.as_deref());
    let rdns_enabled = payload.rdns_enabled.unwrap_or(current.rdns_enabled);

    if let Err(err) = parse_cidr_list(&trusted_proxies) {
        return Err(bad_request(err.to_string()));
    }

    if let Err(err) = state
        .app
        .pipeline
        .reload_acl(&allow_cidrs, &deny_cidrs, rate_limit_qps)
    {
        return Err(bad_request(err.to_string()));
    }

    if let Err(err) = state.app.pipeline.reload_ecs(
        ecs_enabled,
        ecs_custom_ip.as_deref(),
        ecs_ipv4_prefix,
        ecs_ipv6_prefix,
    ) {
        return Err(bad_request(err.to_string()));
    }

    if let Err(err) = state.app.pipeline.reload_upstream_with_options(
        &cleaned_upstreams,
        payload.upstream_timeout_ms,
        strategy,
        &bootstrap_dns,
    ) {
        return Err(bad_request(err.to_string()));
    }

    if let Err(err) = state.app.pipeline.reload_split_dns_with_bootstrap(
        &split_dns,
        payload.upstream_timeout_ms,
        strategy,
        &bootstrap_dns,
    ) {
        return Err(bad_request(err.to_string()));
    }

    if let Err(err) = state.app.pipeline.reload_private_ptr(
        private_ptr_enabled,
        &private_ptr_upstreams,
        payload.upstream_timeout_ms,
        strategy,
        &bootstrap_dns,
    ) {
        return Err(bad_request(err.to_string()));
    }

    reload_clients_for_config(
        &state,
        payload.upstream_timeout_ms,
        strategy,
        &bootstrap_dns,
    )?;

    if (tls_cert_path != current.tls_cert_path || tls_key_path != current.tls_key_path)
        && let Some(reloader) = &state.app.tls_reloader
        && let Err(err) = reloader.reload(tls_cert_path.as_deref(), tls_key_path.as_deref())
    {
        return Err(bad_request(err));
    }

    if hosts_enabled {
        let resolved_hosts = hosts_path.as_deref().unwrap_or("/etc/hosts");
        if let Err(err) = state
            .app
            .pipeline
            .reload_hosts_from_path(std::path::Path::new(resolved_hosts))
        {
            tracing::warn!(path = %resolved_hosts, error = %err, "failed to load hosts file");
        }
    }

    state.app.pipeline.set_block_mode(block_mode);
    state
        .app
        .pipeline
        .set_cname_cloaking(cname_cloaking_blocking);
    state.app.pipeline.set_dnssec_enabled(dnssec_enabled);
    state.app.pipeline.set_hosts_enabled(hosts_enabled);
    state
        .app
        .pipeline
        .set_dns_rebinding_protection(dns_rebinding_protection);
    state.app.pipeline.set_block_any_queries(block_any_queries);
    state.app.pipeline.set_rdns_enabled(rdns_enabled);
    state.app.pipeline.reload_ddr(DdrConfig {
        enabled: ddr_enabled,
        hostname: ddr_hostname.clone(),
        dot_port: current.listen_dot.map(|a| a.port()),
        doh_enabled,
        doh_port: current
            .listen_web_tls
            .map(|a| a.port())
            .or(Some(current.listen_web.port())),
    });

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
    next.private_ptr_enabled = private_ptr_enabled;
    next.private_ptr_upstreams = private_ptr_upstreams;
    next.ddr_enabled = ddr_enabled;
    next.ddr_hostname = ddr_hostname;
    next.dns_rebinding_protection = dns_rebinding_protection;
    next.block_any_queries = block_any_queries;
    next.trusted_proxies = trusted_proxies;
    next.tls_cert_path = tls_cert_path;
    next.tls_key_path = tls_key_path;
    next.rdns_enabled = rdns_enabled;

    state.app.storage.save_config(&next).map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": err.to_string() })),
        )
    })?;

    let response = ConfigResponse::from(&next);
    state.app.config.store(Arc::new(next));
    Ok(Json(response))
}

fn reload_clients_for_config(
    state: &RouterState,
    timeout_ms: u64,
    strategy: UpstreamStrategy,
    bootstrap_dns: &[String],
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let clients = state.app.storage.list_clients().map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": err.to_string() })),
        )
    })?;
    let groups = state.app.storage.list_client_groups().map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": err.to_string() })),
        )
    })?;
    state
        .app
        .pipeline
        .reload_clients(&clients, &groups, timeout_ms, strategy, bootstrap_dns)
        .map_err(|err| bad_request(err.to_string()))
}
