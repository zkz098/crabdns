use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use std::time::UNIX_EPOCH;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use chrono::Utc;
use crabdns_core::{Config, DnsPipeline, SplitUpstreamRouter, UpstreamGroupRegistry};
use crabdns_storage::{SplitDnsListMeta, StorageEngine};
use reqwest::header::{ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::RouterState;
use crate::subscriptions::{
    ApiError, MAX_SUBSCRIPTION_BYTES, build_subscription_http_client, read_response_bounded,
    verify_url_ssrf_policy,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
pub struct SplitDnsSourceStatus {
    pub kind: String,
    pub source: String,
    pub cached: bool,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    #[ts(type = "number | null")]
    pub last_synced_at: Option<i64>,
    #[ts(type = "number | null")]
    pub last_attempt_at: Option<i64>,
    pub last_error: Option<String>,
    pub entry_count: usize,
    #[ts(type = "number")]
    pub bytes: u64,
    pub not_modified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
pub struct SplitDnsRefreshSummary {
    pub updated: usize,
    pub not_modified: usize,
    pub failed: usize,
    pub sources: Vec<SplitDnsSourceStatus>,
}

enum FetchOutcome {
    NotModified {
        etag: Option<String>,
        last_modified: Option<String>,
    },
    Updated {
        content: String,
        etag: Option<String>,
        last_modified: Option<String>,
    },
}

pub fn collect_split_dns_remote_urls(config: &Config) -> Vec<String> {
    let mut urls = Vec::new();
    let mut seen = HashSet::new();
    for rule in config.split_dns.iter().filter(|r| r.enabled) {
        for candidate in [
            rule.domains_url.as_deref(),
            rule.response_ip
                .as_ref()
                .and_then(|r| r.expected_ip_url.as_deref()),
        ] {
            if let Some(url) = candidate.map(str::trim).filter(|u| !u.is_empty())
                && seen.insert(url.to_string())
            {
                urls.push(url.to_string());
            }
        }
    }
    urls
}

pub fn collect_split_dns_local_files(config: &Config) -> Vec<String> {
    let mut files = Vec::new();
    let mut seen = HashSet::new();
    for rule in config.split_dns.iter().filter(|r| r.enabled) {
        for candidate in [
            rule.domains_file.as_deref(),
            rule.response_ip
                .as_ref()
                .and_then(|r| r.expected_ip_file.as_deref()),
        ] {
            if let Some(path) = candidate.map(str::trim).filter(|p| !p.is_empty())
                && seen.insert(path.to_string())
            {
                files.push(path.to_string());
            }
        }
    }
    files
}

fn count_list_entries(content: &str) -> usize {
    content
        .lines()
        .filter(|line| {
            let t = line.trim();
            !t.is_empty() && !t.starts_with('#') && !t.starts_with("//")
        })
        .count()
}

fn header_string(resp: &reqwest::Response, name: reqwest::header::HeaderName) -> Option<String> {
    resp.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
}

async fn fetch_split_dns_conditional_attempt(
    client: &reqwest::Client,
    url: &str,
    allow_private: bool,
    if_none_match: Option<&str>,
    if_modified_since: Option<&str>,
    timeout_override: Option<std::time::Duration>,
) -> Result<FetchOutcome, String> {
    verify_url_ssrf_policy(url, allow_private).await?;

    let mut req = client.get(url);
    if let Some(t) = timeout_override {
        req = req.timeout(t);
    }
    if let Some(etag) = if_none_match {
        req = req.header(IF_NONE_MATCH, etag);
    }
    if let Some(ims) = if_modified_since {
        req = req.header(IF_MODIFIED_SINCE, ims);
    }

    let resp = req
        .send()
        .await
        .map_err(|e| format!("Request failed: {e}"))?;

    let etag = header_string(&resp, ETAG);
    let last_modified = header_string(&resp, LAST_MODIFIED);

    if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
        return Ok(FetchOutcome::NotModified {
            etag,
            last_modified,
        });
    }
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }

    let bytes = read_response_bounded(resp, MAX_SUBSCRIPTION_BYTES).await?;
    let content = String::from_utf8(bytes)
        .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned());
    Ok(FetchOutcome::Updated {
        content,
        etag,
        last_modified,
    })
}

async fn fetch_split_dns_conditional(
    client: &reqwest::Client,
    url: &str,
    allow_private: bool,
    if_none_match: Option<&str>,
    if_modified_since: Option<&str>,
) -> Result<FetchOutcome, String> {
    let candidates = crate::subscriptions::ordered_github_candidates(
        url,
        Some(crate::update_api::GH_PROXY_PREFIX),
        crate::update_api::is_china_deployment(),
    );
    let has_fallback = candidates.len() > 1;
    let mut errors = Vec::new();

    for (idx, (candidate_url, using_mirror)) in candidates.iter().enumerate() {
        let is_last = idx + 1 == candidates.len();
        let timeout_override = if has_fallback && !is_last {
            Some(std::time::Duration::from_secs(12))
        } else {
            None
        };
        match fetch_split_dns_conditional_attempt(
            client,
            candidate_url,
            allow_private,
            if_none_match,
            if_modified_since,
            timeout_override,
        )
        .await
        {
            Ok(outcome) => return Ok(outcome),
            Err(err) => {
                if !is_last {
                    tracing::info!(
                        url = %candidate_url,
                        using_mirror = *using_mirror,
                        error = %err,
                        "split-dns list fetch attempt failed, trying fallback"
                    );
                }
                errors.push(if *using_mirror {
                    format!("gh-proxy mirror failed: {err}")
                } else {
                    err
                });
            }
        }
    }

    Err(errors.join("; "))
}

/// Recompiles `UpstreamGroupRegistry` and `SplitUpstreamRouter` using currently cached
/// remote lists in `storage` and local files on disk, then swaps them atomically onto `pipeline`.
pub async fn reload_split_dns_from_storage(
    config: &Config,
    storage: &Arc<StorageEngine>,
    pipeline: &Arc<DnsPipeline>,
) -> Result<(), String> {
    let cfg_clone = config.clone();
    let st = Arc::clone(storage);
    let (groups, router) = tokio::task::spawn_blocking(move || {
        let groups = UpstreamGroupRegistry::compile(
            &cfg_clone.upstream_groups,
            cfg_clone.upstream_timeout_ms,
            cfg_clone.upstream_strategy,
            &cfg_clone.bootstrap_dns,
        )?;
        let router = SplitUpstreamRouter::new_full(
            &cfg_clone.split_dns,
            &groups,
            cfg_clone.split_dns_match_mode,
            cfg_clone.upstream_timeout_ms,
            cfg_clone.upstream_strategy,
            &cfg_clone.bootstrap_dns,
            |url| st.load_split_dns_list(url).ok().flatten(),
        )?;
        Ok::<_, crabdns_core::CoreError>((groups, router))
    })
    .await
    .map_err(|err| err.to_string())?
    .map_err(|err| err.to_string())?;

    pipeline.swap_upstream_groups(groups);
    pipeline.swap_split_dns(router);
    pipeline.cache().flush();
    Ok(())
}

pub fn collect_split_dns_source_statuses(
    config: &Config,
    storage: &StorageEngine,
) -> Vec<SplitDnsSourceStatus> {
    let mut out = Vec::new();
    for url in collect_split_dns_remote_urls(config) {
        let cached_body = storage.load_split_dns_list(&url).ok().flatten();
        let meta = storage.load_split_dns_list_meta(&url).ok().flatten();
        let entry_count = meta
            .as_ref()
            .filter(|m| m.entry_count > 0 || cached_body.is_none())
            .map_or_else(
                || cached_body.as_deref().map_or(0, count_list_entries),
                |m| m.entry_count,
            );
        let bytes = meta
            .as_ref()
            .filter(|m| m.bytes > 0 || cached_body.is_none())
            .map_or_else(
                || {
                    cached_body
                        .as_deref()
                        .map_or(0, |b| u64::try_from(b.len()).unwrap_or(u64::MAX))
                },
                |m| m.bytes,
            );
        out.push(SplitDnsSourceStatus {
            kind: "url".to_string(),
            source: url,
            cached: cached_body.is_some(),
            etag: meta.as_ref().and_then(|m| m.etag.clone()),
            last_modified: meta.as_ref().and_then(|m| m.last_modified.clone()),
            last_synced_at: meta.as_ref().and_then(|m| m.last_synced_at),
            last_attempt_at: meta.as_ref().and_then(|m| m.last_attempt_at),
            last_error: meta.as_ref().and_then(|m| m.last_error.clone()),
            entry_count,
            bytes,
            not_modified: meta.as_ref().is_some_and(|m| m.not_modified),
        });
    }

    for path in collect_split_dns_local_files(config) {
        let p = Path::new(&path);
        match (std::fs::metadata(p), std::fs::read_to_string(p)) {
            (Ok(fs_meta), Ok(content)) => {
                let mtime_secs = fs_meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .and_then(|d| i64::try_from(d.as_secs()).ok());
                out.push(SplitDnsSourceStatus {
                    kind: "file".to_string(),
                    source: path,
                    cached: true,
                    etag: None,
                    last_modified: None,
                    last_synced_at: mtime_secs,
                    last_attempt_at: mtime_secs,
                    last_error: None,
                    entry_count: count_list_entries(&content),
                    bytes: fs_meta.len(),
                    not_modified: false,
                });
            }
            (Err(err), _) | (_, Err(err)) => {
                out.push(SplitDnsSourceStatus {
                    kind: "file".to_string(),
                    source: path,
                    cached: false,
                    etag: None,
                    last_modified: None,
                    last_synced_at: None,
                    last_attempt_at: None,
                    last_error: Some(err.to_string()),
                    entry_count: 0,
                    bytes: 0,
                    not_modified: false,
                });
            }
        }
    }
    out
}

/// Conditionally downloads all unique remote split-DNS URLs using `ETag` and
/// `If-Modified-Since`, persists updated lists & sync metadata while preserving old
/// cached data on failure, and reloads `SplitUpstreamRouter` when content changes.
#[allow(clippy::too_many_lines)]
pub async fn refresh_split_dns_subscriptions_job(
    client: &reqwest::Client,
    config: &Config,
    storage: &Arc<StorageEngine>,
    pipeline: &Arc<DnsPipeline>,
    allow_private: bool,
) -> Result<SplitDnsRefreshSummary, String> {
    let urls = collect_split_dns_remote_urls(config);
    let mut updated = 0_usize;
    let mut not_modified = 0_usize;
    let mut failed = 0_usize;

    for url in &urls {
        let st_load = Arc::clone(storage);
        let url_load = url.clone();
        let (existing_body, prev_meta) = tokio::task::spawn_blocking(move || {
            let body = st_load.load_split_dns_list(&url_load).ok().flatten();
            let meta = st_load.load_split_dns_list_meta(&url_load).ok().flatten();
            (body, meta)
        })
        .await
        .map_err(|err| err.to_string())?;

        let (cond_etag, cond_ims) = if existing_body.is_some() {
            (
                prev_meta.as_ref().and_then(|m| m.etag.clone()),
                prev_meta.as_ref().and_then(|m| m.last_modified.clone()),
            )
        } else {
            (None, None)
        };

        let attempt_ts = Utc::now().timestamp();
        let outcome = fetch_split_dns_conditional(
            client,
            url,
            allow_private,
            cond_etag.as_deref(),
            cond_ims.as_deref(),
        )
        .await;

        let mut next_body_to_save: Option<String> = None;
        let next_meta = match outcome {
            Ok(FetchOutcome::NotModified {
                etag,
                last_modified,
            }) => {
                not_modified += 1;
                let mut m = prev_meta.unwrap_or_else(|| SplitDnsListMeta {
                    url: url.clone(),
                    ..Default::default()
                });
                if let Some(ref body) = existing_body
                    && (m.entry_count == 0 && m.bytes == 0)
                {
                    m.entry_count = count_list_entries(body);
                    m.bytes = u64::try_from(body.len()).unwrap_or(u64::MAX);
                }
                m.etag = etag.or(m.etag);
                m.last_modified = last_modified.or(m.last_modified);
                m.last_synced_at = Some(attempt_ts);
                m.last_attempt_at = Some(attempt_ts);
                m.last_error = None;
                m.not_modified = true;
                m
            }
            Ok(FetchOutcome::Updated {
                content,
                etag,
                last_modified,
            }) => {
                let entry_count = count_list_entries(&content);
                let bytes = u64::try_from(content.len()).unwrap_or(u64::MAX);
                let unchanged = existing_body.as_deref() == Some(content.as_str());
                if unchanged {
                    not_modified += 1;
                } else {
                    updated += 1;
                    next_body_to_save = Some(content);
                }
                SplitDnsListMeta {
                    url: url.clone(),
                    etag: etag.or_else(|| prev_meta.as_ref().and_then(|m| m.etag.clone())),
                    last_modified: last_modified
                        .or_else(|| prev_meta.as_ref().and_then(|m| m.last_modified.clone())),
                    last_synced_at: Some(attempt_ts),
                    last_attempt_at: Some(attempt_ts),
                    last_error: None,
                    entry_count,
                    bytes,
                    not_modified: unchanged,
                }
            }
            Err(err) => {
                tracing::warn!(
                    url = %url,
                    error = %err,
                    "failed to refresh split-DNS list; keeping existing cached copy"
                );
                failed += 1;
                let mut m = prev_meta.unwrap_or_else(|| SplitDnsListMeta {
                    url: url.clone(),
                    ..Default::default()
                });
                if let Some(ref body) = existing_body
                    && (m.entry_count == 0 && m.bytes == 0)
                {
                    m.entry_count = count_list_entries(body);
                    m.bytes = u64::try_from(body.len()).unwrap_or(u64::MAX);
                }
                m.last_attempt_at = Some(attempt_ts);
                m.last_error = Some(err);
                m.not_modified = false;
                m
            }
        };

        let st_save = Arc::clone(storage);
        let url_save = url.clone();
        tokio::task::spawn_blocking(move || {
            if let Some(body) = next_body_to_save {
                st_save.save_split_dns_list(&url_save, &body)?;
            }
            st_save.save_split_dns_list_meta(&next_meta)
        })
        .await
        .map_err(|err| err.to_string())?
        .map_err(|err| err.to_string())?;
    }

    if updated > 0 {
        reload_split_dns_from_storage(config, storage, pipeline).await?;
    }

    let cfg_status = config.clone();
    let st_status = Arc::clone(storage);
    let sources = tokio::task::spawn_blocking(move || {
        collect_split_dns_source_statuses(&cfg_status, &st_status)
    })
    .await
    .map_err(|err| err.to_string())?;

    Ok(SplitDnsRefreshSummary {
        updated,
        not_modified,
        failed,
        sources,
    })
}

pub async fn refresh_split_dns(
    State(state): State<RouterState>,
) -> Result<Json<SplitDnsRefreshSummary>, (StatusCode, Json<ApiError>)> {
    let cfg = state.app.config.load_full();
    let client = build_subscription_http_client(cfg.allow_private_subscriptions);
    let summary = refresh_split_dns_subscriptions_job(
        &client,
        &cfg,
        &state.app.storage,
        &state.app.pipeline,
        cfg.allow_private_subscriptions,
    )
    .await
    .map_err(|err| (StatusCode::BAD_GATEWAY, Json(ApiError { error: err })))?;

    Ok(Json(summary))
}

pub async fn get_split_dns_status(
    State(state): State<RouterState>,
) -> Result<Json<Vec<SplitDnsSourceStatus>>, (StatusCode, Json<ApiError>)> {
    let cfg = state.app.config.load_full();
    let st = Arc::clone(&state.app.storage);
    let statuses =
        tokio::task::spawn_blocking(move || collect_split_dns_source_statuses(&cfg, &st))
            .await
            .map_err(|err| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ApiError {
                        error: err.to_string(),
                    }),
                )
            })?;
    Ok(Json(statuses))
}

pub(crate) fn maybe_spawn_split_dns_sync(state: &RouterState, cfg: &Config) {
    let needs_sync = collect_split_dns_remote_urls(cfg).into_iter().any(|u| {
        state
            .app
            .storage
            .load_split_dns_list(&u)
            .ok()
            .flatten()
            .is_none()
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
