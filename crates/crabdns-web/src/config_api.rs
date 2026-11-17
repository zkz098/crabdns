use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use crabdns_core::{BlockMode, Config, SplitDnsRule, UpstreamStrategy};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::RouterState;

#[derive(Debug, Serialize, Deserialize, TS)]
#[ts(export)]
#[allow(clippy::struct_excessive_bools)]
pub struct ConfigResponse {
    pub listen_dns: String,
    pub listen_web: String,
    pub listen_dot: Option<String>,
    pub data_dir: String,
    pub upstreams: Vec<String>,
    pub bootstrap_dns: Vec<String>,
    pub upstream_strategy: UpstreamStrategy,
    #[ts(type = "number")]
    pub cache_size: u64,
    pub optimistic_cache: bool,
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
}

impl From<&Config> for ConfigResponse {
    fn from(cfg: &Config) -> Self {
        Self {
            listen_dns: cfg.listen_dns.to_string(),
            listen_web: cfg.listen_web.to_string(),
            listen_dot: cfg.listen_dot.map(|addr| addr.to_string()),
            data_dir: cfg.data_dir.display().to_string(),
            upstreams: cfg.upstreams.clone(),
            bootstrap_dns: cfg.bootstrap_dns.clone(),
            upstream_strategy: cfg.upstream_strategy,
            cache_size: cfg.cache_size,
            optimistic_cache: cfg.optimistic_cache,
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

    if let Err(err) = state
        .app
        .pipeline
        .reload_acl(&allow_cidrs, &deny_cidrs, rate_limit_qps)
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": err.to_string() })),
        ));
    }

    if let Err(err) = state.app.pipeline.reload_upstream_with_options(
        &cleaned_upstreams,
        payload.upstream_timeout_ms,
        strategy,
        &bootstrap_dns,
    ) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": err.to_string() })),
        ));
    }

    if let Err(err) = state.app.pipeline.reload_split_dns_with_bootstrap(
        &split_dns,
        payload.upstream_timeout_ms,
        strategy,
        &bootstrap_dns,
    ) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": err.to_string() })),
        ));
    }

    state.app.pipeline.set_block_mode(block_mode);
    state
        .app
        .pipeline
        .set_cname_cloaking(cname_cloaking_blocking);

    let cache_changed = current.cache_size != payload.cache_size
        || current.optimistic_cache != payload.optimistic_cache;
    if cache_changed {
        state
            .app
            .pipeline
            .reload_cache(payload.cache_size, payload.optimistic_cache);
    }

    let mut next = (*current).clone();
    next.upstreams = cleaned_upstreams;
    next.bootstrap_dns = bootstrap_dns;
    next.upstream_strategy = strategy;
    next.cache_size = payload.cache_size;
    next.optimistic_cache = payload.optimistic_cache;
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
