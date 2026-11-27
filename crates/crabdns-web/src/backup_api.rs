use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use crabdns_core::acl::parse_cidr_list;
use crabdns_core::{
    AccessController, ClientGroup, ClientProfile, ClientRegistry, Config, DdrConfig,
    DhcpLeaseTable, DnsRewriteEntry, EcsConfig, FilterEngine, HostsTable, PrivatePtrRouter,
    SplitDnsRule, SplitUpstreamRouter, UpstreamGroup, UpstreamGroupRegistry, UpstreamPool,
    validate_client_identifier, validate_dns_rewrite,
};
use crabdns_storage::FilterSubscription;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::RouterState;
use crate::config_api::{ConfigResponse, ConfigUpdatePayload};
use crate::subscriptions::{
    ApiError, rebuild_filter_engine_async, validate_subscription_url_with_policy,
};

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct BackupSubscriptionEntry {
    #[serde(flatten)]
    pub subscription: FilterSubscription,
    #[serde(default)]
    pub content: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SystemBackupPayload {
    pub version: u32,
    pub exported_at: DateTime<Utc>,
    pub config: ConfigUpdatePayload,
    pub custom_rules: String,
    #[serde(default = "default_true")]
    pub custom_rules_enabled: bool,
    #[serde(default)]
    pub subscriptions: Vec<BackupSubscriptionEntry>,
    #[serde(default)]
    pub rewrites: Vec<DnsRewriteEntry>,
    #[serde(default)]
    pub clients: Vec<ClientProfile>,
    #[serde(default)]
    pub client_groups: Vec<ClientGroup>,
}

const fn default_true() -> bool {
    true
}

type ApiResult<T> = std::result::Result<T, (StatusCode, Json<ApiError>)>;

fn err_response(status: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<ApiError>) {
    (status, Json(ApiError { error: msg.into() }))
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
            (!trimmed.is_empty()).then(|| trimmed.to_string())
        }
        None => existing.map(str::to_string),
    }
}

fn merge_opt_path(incoming: Option<String>, existing: Option<&Path>) -> Option<PathBuf> {
    match incoming {
        Some(raw) => {
            let trimmed = raw.trim();
            (!trimmed.is_empty()).then(|| PathBuf::from(trimmed))
        }
        None => existing.map(Path::to_path_buf),
    }
}

fn config_to_update_payload(cfg: &Config) -> ConfigUpdatePayload {
    ConfigUpdatePayload {
        upstreams: cfg.upstreams.clone(),
        bootstrap_dns: Some(cfg.bootstrap_dns.clone()),
        upstream_strategy: Some(cfg.upstream_strategy),
        cache_size: cfg.cache_size,
        optimistic_cache: cfg.optimistic_cache,
        cache_min_ttl_secs: Some(cfg.cache_min_ttl_secs),
        cache_max_ttl_secs: Some(cfg.cache_max_ttl_secs),
        cache_prefetch_enabled: Some(cfg.cache_prefetch_enabled),
        cache_persist_enabled: Some(cfg.cache_persist_enabled),
        upstream_timeout_ms: cfg.upstream_timeout_ms,
        log_retention_hours: cfg.log_retention_hours,
        log_max_disk_mb: Some(cfg.log_max_disk_mb),
        block_mode: Some(cfg.block_mode),
        allow_cidrs: Some(cfg.allow_cidrs.clone()),
        deny_cidrs: Some(cfg.deny_cidrs.clone()),
        rate_limit_qps: Some(cfg.rate_limit_qps),
        split_dns: Some(cfg.split_dns.clone()),
        upstream_groups: Some(cfg.upstream_groups.clone()),
        split_dns_match_mode: Some(cfg.split_dns_match_mode),
        split_dns_before_client_upstreams: Some(cfg.split_dns_before_client_upstreams),
        split_dns_refresh_interval_secs: Some(cfg.split_dns_refresh_interval_secs),
        cname_cloaking_blocking: Some(cfg.cname_cloaking_blocking),
        doh_enabled: Some(cfg.doh_enabled),
        allow_private_subscriptions: Some(cfg.allow_private_subscriptions),
        ecs_enabled: Some(cfg.ecs_enabled),
        ecs_custom_ip: cfg.ecs_custom_ip.clone(),
        ecs_ipv4_prefix: Some(cfg.ecs_ipv4_prefix),
        ecs_ipv6_prefix: Some(cfg.ecs_ipv6_prefix),
        dnssec_enabled: Some(cfg.dnssec_enabled),
        dnssec_trust_anchors: Some(cfg.dnssec_trust_anchors.clone()),
        dnssec_ntas: Some(cfg.dnssec_ntas.clone()),
        hosts_enabled: Some(cfg.hosts_enabled),
        hosts_path: cfg.hosts_path.clone(),
        dhcp_leases_enabled: Some(cfg.dhcp_leases_enabled),
        dhcp_leases_path: cfg.dhcp_leases_path.clone(),
        dhcp_leases_forward_enabled: Some(cfg.dhcp_leases_forward_enabled),
        dhcp_leases_domain: Some(cfg.dhcp_leases_domain.clone()),
        mdns_enabled: Some(cfg.mdns_enabled),
        sni_client_id_hostnames: Some(cfg.sni_client_id_hostnames.clone()),
        private_ptr_enabled: Some(cfg.private_ptr_enabled),
        private_ptr_upstreams: Some(cfg.private_ptr_upstreams.clone()),
        block_local_domains: Some(cfg.block_local_domains),
        suppress_local_domain_logs: Some(cfg.suppress_local_domain_logs),
        ddr_enabled: Some(cfg.ddr_enabled),
        ddr_hostname: cfg.ddr_hostname.clone(),
        dns_rebinding_protection: Some(cfg.dns_rebinding_protection),
        block_any_queries: Some(cfg.block_any_queries),
        trusted_proxies: Some(cfg.trusted_proxies.clone()),
        tls_cert_path: cfg.tls_cert_path.as_ref().map(|p| p.display().to_string()),
        tls_key_path: cfg.tls_key_path.as_ref().map(|p| p.display().to_string()),
        rdns_enabled: Some(cfg.rdns_enabled),
        safesearch: Some(cfg.safesearch.clone()),
        dns64_enabled: Some(cfg.dns64_enabled),
        dns64_prefixes: Some(cfg.dns64_prefixes.clone()),
        svcb_strip_ech: Some(cfg.svcb_strip_ech),
        svcb_strip_hints: Some(cfg.svcb_strip_hints),
        ede_enabled: Some(cfg.ede_enabled),
        dns_cookies_enabled: Some(cfg.dns_cookies_enabled),
        dns_cookies_require_valid: Some(cfg.dns_cookies_require_valid),
        max_udp_payload_size: Some(cfg.max_udp_payload_size),
        rrl_enabled: Some(cfg.rrl_enabled),
        rrl_responses_per_second: Some(cfg.rrl_responses_per_second),
        rrl_slip: Some(cfg.rrl_slip),
        rrl_window_secs: Some(cfg.rrl_window_secs),
        acme_enabled: Some(cfg.acme_enabled),
        acme_domains: Some(cfg.acme_domains.clone()),
        acme_email: cfg.acme_email.clone(),
        acme_directory_url: Some(cfg.acme_directory_url.clone()),
        acme_challenge_type: Some(cfg.acme_challenge_type),
        acme_http_listen: cfg.acme_http_listen.map(|a| a.to_string()),
        acme_renew_before_days: Some(cfg.acme_renew_before_days),
        cf_cdn: Some(cfg.cf_cdn.clone()),
        storage_profile: Some(cfg.storage_profile),
        disk_min_free_mb: Some(cfg.disk_min_free_mb),
        serve_stale_enabled: Some(cfg.serve_stale_enabled),
        dnssec_strict_clock: Some(cfg.dnssec_strict_clock),
        dnssec_auto_rollover: Some(cfg.dnssec_auto_rollover),
        confirm_timeout_secs: None,
    }
}

pub async fn export_backup(
    State(state): State<RouterState>,
) -> ApiResult<Json<SystemBackupPayload>> {
    let cfg = state.app.config.load_full();
    let config_payload = config_to_update_payload(&cfg);
    let fallback_custom_rules = state.app.pipeline.filter().raw_rules_text();

    let storage = Arc::clone(&state.app.storage);
    let (custom_rules, custom_rules_enabled, subscriptions, rewrites, clients, client_groups) =
        tokio::task::spawn_blocking(move || {
            let custom_rules = storage
                .load_custom_rules()?
                .unwrap_or(fallback_custom_rules);
            let custom_rules_enabled = storage.load_custom_rules_enabled()?;
            let raw_subs = storage.list_subscriptions()?;
            let mut subscriptions = Vec::with_capacity(raw_subs.len());
            for sub in raw_subs {
                let content = storage.load_subscription_content(&sub.id)?;
                subscriptions.push(BackupSubscriptionEntry {
                    subscription: sub,
                    content,
                });
            }
            let rewrites = storage.list_dns_rewrites()?;
            let clients = storage.list_clients()?;
            let client_groups = storage.list_client_groups()?;
            Ok::<_, crabdns_storage::StorageError>((
                custom_rules,
                custom_rules_enabled,
                subscriptions,
                rewrites,
                clients,
                client_groups,
            ))
        })
        .await
        .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(SystemBackupPayload {
        version: 1,
        exported_at: Utc::now(),
        config: config_payload,
        custom_rules,
        custom_rules_enabled,
        subscriptions,
        rewrites,
        clients,
        client_groups,
    }))
}

fn validate_backup_rewrites(raw: Vec<DnsRewriteEntry>) -> ApiResult<Vec<DnsRewriteEntry>> {
    let mut out = Vec::with_capacity(raw.len());
    for rw in raw {
        let id = rw.id.trim().to_string();
        if id.is_empty() {
            return Err(err_response(
                StatusCode::BAD_REQUEST,
                "Rewrite entry ID cannot be empty",
            ));
        }
        let (domain, kind, answer) = validate_dns_rewrite(&rw.domain, rw.kind, &rw.answer)
            .map_err(|e| err_response(StatusCode::BAD_REQUEST, e.to_string()))?;
        out.push(DnsRewriteEntry {
            id,
            domain,
            kind,
            answer,
            enabled: rw.enabled,
            comment: rw.comment.trim().to_string(),
        });
    }
    Ok(out)
}

fn validate_backup_subscriptions(
    raw: Vec<BackupSubscriptionEntry>,
    allow_private: bool,
) -> ApiResult<Vec<BackupSubscriptionEntry>> {
    let mut out = Vec::with_capacity(raw.len());
    for mut entry in raw {
        let id = entry.subscription.id.trim().to_string();
        let name = entry.subscription.name.trim().to_string();
        if id.is_empty() || name.is_empty() {
            return Err(err_response(
                StatusCode::BAD_REQUEST,
                "Subscription id and name cannot be empty",
            ));
        }
        let url = validate_subscription_url_with_policy(&entry.subscription.url, allow_private)
            .map_err(|e| err_response(StatusCode::BAD_REQUEST, e))?;
        entry.subscription.id = id;
        entry.subscription.name = name;
        entry.subscription.url = url;
        if let Some(ref text) = entry.content {
            entry.subscription.rule_count = FilterEngine::count_rules_in_text(text).total_rules;
        }
        out.push(entry);
    }
    Ok(out)
}

fn validate_backup_groups(raw: Vec<ClientGroup>) -> ApiResult<Vec<ClientGroup>> {
    let mut out = Vec::with_capacity(raw.len());
    for mut g in raw {
        g.id = g.id.trim().to_string();
        g.name = g.name.trim().to_string();
        if g.id.is_empty() || g.name.is_empty() {
            return Err(err_response(
                StatusCode::BAD_REQUEST,
                "Client group id and name cannot be empty",
            ));
        }
        g.upstreams = clean_string_list(g.upstreams);
        out.push(g);
    }
    Ok(out)
}

fn validate_backup_clients(raw: Vec<ClientProfile>) -> ApiResult<Vec<ClientProfile>> {
    let mut out = Vec::with_capacity(raw.len());
    for mut c in raw {
        c.id = c.id.trim().to_string();
        c.name = c.name.trim().to_string();
        c.identifiers = clean_string_list(c.identifiers);
        if c.id.is_empty() || c.name.is_empty() || c.identifiers.is_empty() {
            return Err(err_response(
                StatusCode::BAD_REQUEST,
                "Client id, name, and identifiers cannot be empty",
            ));
        }
        for ident in &c.identifiers {
            validate_client_identifier(ident)
                .map_err(|e| err_response(StatusCode::BAD_REQUEST, e.to_string()))?;
        }
        c.group_id = c
            .group_id
            .map(|gid| gid.trim().to_string())
            .filter(|gid| !gid.is_empty());
        c.upstreams = clean_string_list(c.upstreams);
        c.tags = clean_string_list(c.tags);
        out.push(c);
    }
    Ok(out)
}

fn merge_config_payload(current: &Config, mut payload: ConfigUpdatePayload) -> ApiResult<Config> {
    if payload.cache_size == 0
        || payload.upstream_timeout_ms == 0
        || payload.log_retention_hours == 0
    {
        return Err(err_response(
            StatusCode::BAD_REQUEST,
            "cache_size, upstream_timeout_ms, and log_retention_hours must be > 0",
        ));
    }
    let cache_min_ttl_secs = payload
        .cache_min_ttl_secs
        .unwrap_or(current.cache_min_ttl_secs)
        .max(1);
    let cache_max_ttl_secs = payload
        .cache_max_ttl_secs
        .unwrap_or(current.cache_max_ttl_secs);
    if cache_max_ttl_secs < cache_min_ttl_secs {
        return Err(err_response(
            StatusCode::BAD_REQUEST,
            "cache_max_ttl_secs must be >= cache_min_ttl_secs",
        ));
    }

    let mut next = current.clone();
    next.upstreams = clean_string_list(std::mem::take(&mut payload.upstreams));
    if let Some(b) = payload.bootstrap_dns.take() {
        next.bootstrap_dns = clean_string_list(b);
    }
    if let Some(s) = payload.upstream_strategy {
        next.upstream_strategy = s;
    }
    next.cache_size = payload.cache_size;
    next.optimistic_cache = payload.optimistic_cache;
    next.cache_min_ttl_secs = cache_min_ttl_secs;
    next.cache_max_ttl_secs = cache_max_ttl_secs;
    if let Some(v) = payload.cache_prefetch_enabled {
        next.cache_prefetch_enabled = v;
    }
    if let Some(v) = payload.cache_persist_enabled {
        next.cache_persist_enabled = v;
    }
    next.upstream_timeout_ms = payload.upstream_timeout_ms;
    next.log_retention_hours = payload.log_retention_hours;
    if let Some(v) = payload.block_mode {
        next.block_mode = v;
    }
    if let Some(v) = payload.allow_cidrs.take() {
        next.allow_cidrs = clean_string_list(v);
    }
    if let Some(v) = payload.deny_cidrs.take() {
        next.deny_cidrs = clean_string_list(v);
    }
    if let Some(v) = payload.rate_limit_qps {
        next.rate_limit_qps = v;
    }
    if let Some(rules) = payload.split_dns.take() {
        next.split_dns = rules
            .into_iter()
            .map(SplitDnsRule::normalized)
            .filter(SplitDnsRule::has_target)
            .collect();
    }
    if let Some(groups) = payload.upstream_groups.take() {
        next.upstream_groups = groups
            .into_iter()
            .map(UpstreamGroup::normalized)
            .filter(|g| !g.name.is_empty())
            .collect();
    }
    if let Some(mode) = payload.split_dns_match_mode {
        next.split_dns_match_mode = mode;
    }
    if let Some(before) = payload.split_dns_before_client_upstreams {
        next.split_dns_before_client_upstreams = before;
    }
    if let Some(interval) = payload.split_dns_refresh_interval_secs
        && (interval == 0 || interval >= 60)
    {
        next.split_dns_refresh_interval_secs = interval;
    }
    apply_optional_flags(&mut next, current, payload);
    Ok(next)
}

#[allow(clippy::too_many_lines)]
fn apply_optional_flags(next: &mut Config, current: &Config, payload: ConfigUpdatePayload) {
    next.cname_cloaking_blocking = payload
        .cname_cloaking_blocking
        .unwrap_or(current.cname_cloaking_blocking);
    next.doh_enabled = payload.doh_enabled.unwrap_or(current.doh_enabled);
    next.allow_private_subscriptions = payload
        .allow_private_subscriptions
        .unwrap_or(current.allow_private_subscriptions);
    next.ecs_enabled = payload.ecs_enabled.unwrap_or(current.ecs_enabled);
    next.ecs_custom_ip = merge_opt_string(payload.ecs_custom_ip, current.ecs_custom_ip.as_deref());
    next.ecs_ipv4_prefix = payload.ecs_ipv4_prefix.unwrap_or(current.ecs_ipv4_prefix);
    next.ecs_ipv6_prefix = payload.ecs_ipv6_prefix.unwrap_or(current.ecs_ipv6_prefix);
    next.dnssec_enabled = payload.dnssec_enabled.unwrap_or(current.dnssec_enabled);
    if let Some(mb) = payload.log_max_disk_mb
        && mb > 0
    {
        next.log_max_disk_mb = mb;
    }
    if let Some(anchors) = payload.dnssec_trust_anchors {
        next.dnssec_trust_anchors = clean_string_list(anchors);
    }
    if let Some(ntas) = payload.dnssec_ntas {
        next.dnssec_ntas = ntas;
    }
    next.hosts_enabled = payload.hosts_enabled.unwrap_or(current.hosts_enabled);
    next.hosts_path = merge_opt_string(payload.hosts_path, current.hosts_path.as_deref());
    next.dhcp_leases_enabled = payload
        .dhcp_leases_enabled
        .unwrap_or(current.dhcp_leases_enabled);
    next.dhcp_leases_path = merge_opt_string(
        payload.dhcp_leases_path,
        current.dhcp_leases_path.as_deref(),
    );
    next.dhcp_leases_forward_enabled = payload
        .dhcp_leases_forward_enabled
        .unwrap_or(current.dhcp_leases_forward_enabled);
    if let Some(domain) = payload.dhcp_leases_domain {
        let trimmed = domain.trim().trim_matches('.').to_ascii_lowercase();
        next.dhcp_leases_domain = if trimmed.is_empty() {
            "lan".to_string()
        } else {
            trimmed
        };
    }
    next.mdns_enabled = payload.mdns_enabled.unwrap_or(current.mdns_enabled);
    if let Some(v) = payload.sni_client_id_hostnames {
        next.sni_client_id_hostnames = clean_string_list(v);
    }
    next.private_ptr_enabled = payload
        .private_ptr_enabled
        .unwrap_or(current.private_ptr_enabled);
    next.block_local_domains = payload
        .block_local_domains
        .unwrap_or(current.block_local_domains);
    next.suppress_local_domain_logs = payload
        .suppress_local_domain_logs
        .unwrap_or(current.suppress_local_domain_logs);
    if let Some(v) = payload.private_ptr_upstreams {
        next.private_ptr_upstreams = clean_string_list(v);
    }
    next.ddr_enabled = payload.ddr_enabled.unwrap_or(current.ddr_enabled);
    next.ddr_hostname = merge_opt_string(payload.ddr_hostname, current.ddr_hostname.as_deref());
    next.dns_rebinding_protection = payload
        .dns_rebinding_protection
        .unwrap_or(current.dns_rebinding_protection);
    next.block_any_queries = payload
        .block_any_queries
        .unwrap_or(current.block_any_queries);
    if let Some(v) = payload.trusted_proxies {
        next.trusted_proxies = clean_string_list(v);
    }
    next.tls_cert_path = merge_opt_path(payload.tls_cert_path, current.tls_cert_path.as_deref());
    next.tls_key_path = merge_opt_path(payload.tls_key_path, current.tls_key_path.as_deref());
    next.rdns_enabled = payload.rdns_enabled.unwrap_or(current.rdns_enabled);
    if let Some(safesearch) = payload.safesearch {
        next.safesearch = safesearch;
    }
    next.dns64_enabled = payload.dns64_enabled.unwrap_or(current.dns64_enabled);
    if let Some(prefixes) = payload.dns64_prefixes {
        next.dns64_prefixes = clean_string_list(prefixes);
    }
    next.svcb_strip_ech = payload.svcb_strip_ech.unwrap_or(current.svcb_strip_ech);
    next.svcb_strip_hints = payload.svcb_strip_hints.unwrap_or(current.svcb_strip_hints);
    next.ede_enabled = payload.ede_enabled.unwrap_or(current.ede_enabled);
    next.dns_cookies_enabled = payload
        .dns_cookies_enabled
        .unwrap_or(current.dns_cookies_enabled);
    next.dns_cookies_require_valid = payload
        .dns_cookies_require_valid
        .unwrap_or(current.dns_cookies_require_valid);
    next.max_udp_payload_size = payload
        .max_udp_payload_size
        .unwrap_or(current.max_udp_payload_size)
        .max(512);
    next.rrl_enabled = payload.rrl_enabled.unwrap_or(current.rrl_enabled);
    next.rrl_responses_per_second = payload
        .rrl_responses_per_second
        .unwrap_or(current.rrl_responses_per_second);
    next.rrl_slip = payload.rrl_slip.unwrap_or(current.rrl_slip);
    next.rrl_window_secs = payload.rrl_window_secs.unwrap_or(current.rrl_window_secs);
    if let Some(cf_cdn) = payload.cf_cdn {
        next.cf_cdn = cf_cdn;
    }
}

pub(crate) struct CompiledRuntime {
    acl: AccessController,
    ecs: EcsConfig,
    upstream: UpstreamPool,
    upstream_groups: UpstreamGroupRegistry,
    split_dns: SplitUpstreamRouter,
    private_ptr: PrivatePtrRouter,
    clients: ClientRegistry,
}

pub(crate) fn compile_runtime_components(
    next: &Config,
    clients: &[ClientProfile],
    groups: &[ClientGroup],
    storage: &crabdns_storage::StorageEngine,
) -> ApiResult<CompiledRuntime> {
    parse_cidr_list(&next.trusted_proxies)
        .map_err(|e| err_response(StatusCode::BAD_REQUEST, e.to_string()))?;
    let acl = AccessController::new(&next.allow_cidrs, &next.deny_cidrs, next.rate_limit_qps)
        .map_err(|e| err_response(StatusCode::BAD_REQUEST, e.to_string()))?;
    let ecs = EcsConfig::from_parts(
        next.ecs_enabled,
        next.ecs_custom_ip.as_deref(),
        next.ecs_ipv4_prefix,
        next.ecs_ipv6_prefix,
    )
    .map_err(|e| err_response(StatusCode::BAD_REQUEST, e.to_string()))?;
    let upstream = UpstreamPool::new_with_bootstrap(
        &next.upstreams,
        next.upstream_timeout_ms,
        next.upstream_strategy,
        &next.bootstrap_dns,
    )
    .map_err(|e| err_response(StatusCode::BAD_REQUEST, e.to_string()))?;
    let upstream_groups = UpstreamGroupRegistry::compile(
        &next.upstream_groups,
        next.upstream_timeout_ms,
        next.upstream_strategy,
        &next.bootstrap_dns,
    )
    .map_err(|e| err_response(StatusCode::BAD_REQUEST, e.to_string()))?;
    let split_dns = SplitUpstreamRouter::new_full(
        &next.split_dns,
        &upstream_groups,
        next.split_dns_match_mode,
        next.upstream_timeout_ms,
        next.upstream_strategy,
        &next.bootstrap_dns,
        |url| storage.load_split_dns_list(url).ok().flatten(),
    )
    .map_err(|e| err_response(StatusCode::BAD_REQUEST, e.to_string()))?;
    let private_ptr = PrivatePtrRouter::new(
        next.private_ptr_enabled,
        &next.private_ptr_upstreams,
        next.upstream_timeout_ms,
        next.upstream_strategy,
        &next.bootstrap_dns,
    )
    .map_err(|e| err_response(StatusCode::BAD_REQUEST, e.to_string()))?;
    let clients = ClientRegistry::compile_with_groups(
        clients,
        groups,
        &upstream_groups,
        next.upstream_timeout_ms,
        next.upstream_strategy,
        &next.bootstrap_dns,
    )
    .map_err(|e| err_response(StatusCode::BAD_REQUEST, e.to_string()))?;
    Ok(CompiledRuntime {
        acl,
        ecs,
        upstream,
        upstream_groups,
        split_dns,
        private_ptr,
        clients,
    })
}

pub(crate) fn apply_compiled_to_pipeline(
    state: &RouterState,
    current: &Config,
    next: &Config,
    compiled: CompiledRuntime,
    hosts_table_opt: Option<HostsTable>,
    dhcp_table_opt: Option<DhcpLeaseTable>,
) {
    let pipe = &state.app.pipeline;
    pipe.swap_acl(compiled.acl);
    pipe.swap_ecs(compiled.ecs);
    pipe.swap_upstream(compiled.upstream);
    pipe.swap_upstream_groups(compiled.upstream_groups);
    pipe.set_split_dns_before_client_upstreams(next.split_dns_before_client_upstreams);
    pipe.swap_split_dns(compiled.split_dns);
    pipe.swap_private_ptr(compiled.private_ptr);
    pipe.swap_clients(compiled.clients);
    if let Some(table) = hosts_table_opt {
        pipe.reload_hosts_table(table);
    }
    if let Some(dhcp_table) = dhcp_table_opt {
        pipe.reload_dhcp_leases_table(dhcp_table);
    }
    pipe.set_block_mode(next.block_mode);
    pipe.set_cname_cloaking(next.cname_cloaking_blocking);
    pipe.set_dnssec_enabled(next.dnssec_enabled);
    pipe.dnssec_validator()
        .set_strict_clock(next.dnssec_strict_clock);
    pipe.dnssec_validator()
        .set_auto_rollover(next.dnssec_auto_rollover);
    pipe.set_serve_stale_enabled(next.serve_stale_enabled);
    let _ = pipe.reload_dnssec_anchors(&next.dnssec_trust_anchors, &next.dnssec_ntas);
    pipe.set_hosts_enabled(next.hosts_enabled);
    pipe.set_dhcp_leases_enabled(next.dhcp_leases_enabled);
    pipe.set_dhcp_leases_forward(
        next.dhcp_leases_forward_enabled,
        next.dhcp_leases_domain.clone(),
    );
    pipe.set_mdns_enabled(next.mdns_enabled);
    pipe.set_dns_rebinding_protection(next.dns_rebinding_protection);
    pipe.set_block_any_queries(next.block_any_queries);
    pipe.set_block_local_domains(next.block_local_domains);
    pipe.set_suppress_local_domain_logs(next.suppress_local_domain_logs);
    pipe.set_rdns_enabled(next.rdns_enabled);
    pipe.set_safesearch(next.safesearch.clone());
    let _ = pipe.reload_dns64(next.dns64_enabled, &next.dns64_prefixes);
    pipe.set_svcb_sanitization(next.svcb_strip_ech, next.svcb_strip_hints);
    pipe.reload_cf_cdn(next.cf_cdn.clone());
    pipe.set_ede_enabled(next.ede_enabled);
    pipe.set_dns_cookies(next.dns_cookies_enabled, next.dns_cookies_require_valid);
    pipe.set_max_udp_payload_size(next.max_udp_payload_size);
    pipe.set_rrl(crabdns_core::RrlConfig {
        enabled: next.rrl_enabled,
        responses_per_second: next.rrl_responses_per_second,
        slip: next.rrl_slip,
        window_secs: next.rrl_window_secs,
    });
    pipe.reload_ddr(DdrConfig {
        enabled: next.ddr_enabled,
        hostname: next.ddr_hostname.clone(),
        dot_port: current.listen_dot.map(|a| a.port()),
        doq_port: current.listen_doq.map(|a| a.port()),
        doh_enabled: next.doh_enabled,
        doh_port: current
            .listen_web_tls
            .map(|a| a.port())
            .or(Some(current.listen_web.port())),
    });
    pipe.reload_cache_with_options(
        next.cache_size,
        next.optimistic_cache,
        next.cache_min_ttl_secs,
        next.cache_max_ttl_secs,
        next.cache_prefetch_enabled,
    );
}

pub async fn import_backup(
    State(state): State<RouterState>,
    Json(backup): Json<SystemBackupPayload>,
) -> ApiResult<Json<ConfigResponse>> {
    if backup.version == 0 || backup.version > 1 {
        return Err(err_response(
            StatusCode::BAD_REQUEST,
            format!("Unsupported backup schema version: {}", backup.version),
        ));
    }

    let _config_guard = state.app.storage.config_lock().lock().await;
    let _client_guard = state.app.storage.client_lock().lock().await;
    let _sub_guard = state.app.storage.subscription_lock().lock().await;
    let _rewrite_guard = state.app.storage.rewrite_lock().lock().await;

    let current = state.app.config.load_full();
    let next = merge_config_payload(&current, backup.config)?;
    let normalized_rewrites = validate_backup_rewrites(backup.rewrites)?;
    let normalized_subs =
        validate_backup_subscriptions(backup.subscriptions, next.allow_private_subscriptions)?;
    let normalized_groups = validate_backup_groups(backup.client_groups)?;
    let normalized_clients = validate_backup_clients(backup.clients)?;
    let compiled = compile_runtime_components(
        &next,
        &normalized_clients,
        &normalized_groups,
        &state.app.storage,
    )?;

    let hosts_table_opt = if next.hosts_enabled {
        let resolved_hosts = next
            .hosts_path
            .as_deref()
            .unwrap_or("/etc/hosts")
            .to_string();
        tokio::task::spawn_blocking(move || HostsTable::from_file(Path::new(&resolved_hosts)))
            .await
            .ok()
            .and_then(Result::ok)
    } else {
        None
    };

    let dhcp_table_opt = if next.dhcp_leases_enabled {
        let resolved_dhcp =
            crabdns_core::resolve_dhcp_leases_path(next.dhcp_leases_path.as_deref()).to_string();
        tokio::task::spawn_blocking(move || DhcpLeaseTable::from_file(Path::new(&resolved_dhcp)))
            .await
            .ok()
            .and_then(Result::ok)
    } else {
        None
    };

    if (next.tls_cert_path != current.tls_cert_path || next.tls_key_path != current.tls_key_path)
        && let Some(reloader) = &state.app.tls_reloader
        && let Err(err) =
            reloader.reload(next.tls_cert_path.as_deref(), next.tls_key_path.as_deref())
    {
        return Err(err_response(StatusCode::BAD_REQUEST, err));
    }

    let storage = Arc::clone(&state.app.storage);
    let to_save_cfg = next.clone();
    let custom_rules = backup.custom_rules;
    let custom_rules_enabled = backup.custom_rules_enabled;
    tokio::task::spawn_blocking(move || -> crabdns_storage::Result<()> {
        storage.save_config(&to_save_cfg)?;
        let _ = storage.record_config_snapshot(&to_save_cfg, "backup_import");
        storage.save_custom_rules(&custom_rules)?;
        storage.save_custom_rules_enabled(custom_rules_enabled)?;
        storage.clear_subscription_contents()?;
        let mut sub_metas = Vec::with_capacity(normalized_subs.len());
        for entry in normalized_subs {
            if let Some(content) = entry.content {
                storage.save_subscription_content(&entry.subscription.id, &content)?;
            }
            sub_metas.push(entry.subscription);
        }
        storage.save_subscriptions(&sub_metas)?;
        storage.save_dns_rewrites(&normalized_rewrites)?;
        storage.save_client_groups(&normalized_groups)?;
        storage.save_clients(&normalized_clients)?;
        Ok(())
    })
    .await
    .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    apply_compiled_to_pipeline(
        &state,
        &current,
        &next,
        compiled,
        hosts_table_opt,
        dhcp_table_opt,
    );

    rebuild_filter_engine_async(&state.app.storage, &state.app.pipeline)
        .await
        .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let response = ConfigResponse::from(&next);
    state.app.config.store(Arc::new(next));
    Ok(Json(response))
}
