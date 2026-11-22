use std::collections::HashSet;
use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use crabdns_core::{Config, DnsPipeline, SplitUpstreamRouter};
use crabdns_storage::StorageEngine;

use crate::RouterState;
use crate::subscriptions::{
    ApiError, build_subscription_http_client, fetch_subscription_text_with_policy,
};

/// Downloads all unique `domains_url` entries from `config.split_dns`, persists them in
/// storage, and atomically reloads the pipeline's `SplitUpstreamRouter`.
pub async fn refresh_split_dns_subscriptions_job(
    client: &reqwest::Client,
    config: &Config,
    storage: &Arc<StorageEngine>,
    pipeline: &Arc<DnsPipeline>,
    allow_private: bool,
) -> Result<usize, String> {
    let mut urls = Vec::new();
    let mut seen = HashSet::new();
    for rule in &config.split_dns {
        if let Some(url) = rule
            .domains_url
            .as_deref()
            .map(str::trim)
            .filter(|u| !u.is_empty())
            && seen.insert(url.to_string())
        {
            urls.push(url.to_string());
        }
    }
    if urls.is_empty() {
        return Ok(0);
    }

    let mut updated = 0_usize;
    for url in &urls {
        match fetch_subscription_text_with_policy(client, url, allow_private).await {
            Ok(content) => {
                let st = Arc::clone(storage);
                let url_owned = url.clone();
                tokio::task::spawn_blocking(move || st.save_split_dns_list(&url_owned, &content))
                    .await
                    .map_err(|err| err.to_string())?
                    .map_err(|err| err.to_string())?;
                updated += 1;
            }
            Err(err) => {
                tracing::warn!(url = %url, error = %err, "failed to refresh split-DNS domain list");
            }
        }
    }

    if updated > 0 {
        let cfg_clone = config.clone();
        let st = Arc::clone(storage);
        let router = tokio::task::spawn_blocking(move || {
            SplitUpstreamRouter::new_with_resolver(
                &cfg_clone.split_dns,
                cfg_clone.upstream_timeout_ms,
                cfg_clone.upstream_strategy,
                &cfg_clone.bootstrap_dns,
                |url| st.load_split_dns_list(url).ok().flatten(),
            )
        })
        .await
        .map_err(|err| err.to_string())?
        .map_err(|err| err.to_string())?;
        pipeline.swap_split_dns(router);
    }

    Ok(updated)
}

pub async fn refresh_split_dns(
    State(state): State<RouterState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let cfg = state.app.config.load_full();
    let client = build_subscription_http_client(cfg.allow_private_subscriptions);
    let updated = refresh_split_dns_subscriptions_job(
        &client,
        &cfg,
        &state.app.storage,
        &state.app.pipeline,
        cfg.allow_private_subscriptions,
    )
    .await
    .map_err(|err| (StatusCode::BAD_GATEWAY, Json(ApiError { error: err })))?;

    Ok(Json(serde_json::json!({ "updated": updated })))
}

pub(crate) fn maybe_spawn_split_dns_sync(state: &RouterState, cfg: &Config) {
    let needs_sync = cfg.split_dns.iter().any(|rule| {
        rule.domains_url
            .as_deref()
            .map(str::trim)
            .filter(|u| !u.is_empty())
            .is_some_and(|u| {
                state
                    .app
                    .storage
                    .load_split_dns_list(u)
                    .ok()
                    .flatten()
                    .is_none()
            })
    });
    if !needs_sync {
        return;
    }
    let cfg_arc = cfg.clone();
    let storage = Arc::clone(&state.app.storage);
    let pipeline = Arc::clone(&state.app.pipeline);
    tokio::spawn(async move {
        let client = build_subscription_http_client(cfg_arc.allow_private_subscriptions);
        let _ = refresh_split_dns_subscriptions_job(
            &client,
            &cfg_arc,
            &storage,
            &pipeline,
            cfg_arc.allow_private_subscriptions,
        )
        .await;
    });
}
