use std::net::IpAddr;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use crabdns_core::{FilterAction, FilterStats, RewriteAction};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::RouterState;
use crate::subscriptions::{ApiError, rebuild_filter_engine};

#[derive(Debug, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct BlockingStatusResponse {
    pub paused: bool,
    #[ts(type = "number | null")]
    pub remaining_secs: Option<u64>,
}

#[derive(Debug, Deserialize, TS)]
#[ts(export)]
pub struct PauseBlockingPayload {
    #[ts(type = "number | null")]
    pub duration_secs: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum QuickRuleAction {
    Allow,
    Block,
}

#[derive(Debug, Deserialize, TS)]
#[ts(export)]
pub struct QuickRulePayload {
    pub domain: String,
    pub action: QuickRuleAction,
}

#[derive(Debug, Serialize, TS)]
#[ts(export)]
pub struct QuickRuleResponse {
    pub rule: String,
    pub added: bool,
    pub stats: FilterStats,
}

#[derive(Debug, Deserialize, TS)]
#[ts(export)]
pub struct TestRulePayload {
    pub domain: String,
    #[serde(default)]
    pub client_ip: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
}

#[derive(Debug, Serialize, TS)]
#[ts(export)]
pub struct TestRuleResponse {
    pub domain: String,
    pub action: String,
    pub matched_rule: Option<String>,
    pub matched_list: Option<String>,
    pub rewrite: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct OkResponse {
    pub status: &'static str,
}

type ApiResult<T> = Result<T, (StatusCode, Json<ApiError>)>;

fn err_response(status: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<ApiError>) {
    (status, Json(ApiError { error: msg.into() }))
}

pub async fn get_blocking_status(State(state): State<RouterState>) -> Json<BlockingStatusResponse> {
    let (paused, remaining_secs) = state.app.pipeline.blocking_status();
    Json(BlockingStatusResponse {
        paused,
        remaining_secs,
    })
}

pub async fn pause_blocking(
    State(state): State<RouterState>,
    Json(payload): Json<PauseBlockingPayload>,
) -> Json<BlockingStatusResponse> {
    state.app.pipeline.pause_blocking(payload.duration_secs);
    let (paused, remaining_secs) = state.app.pipeline.blocking_status();
    Json(BlockingStatusResponse {
        paused,
        remaining_secs,
    })
}

pub async fn resume_blocking(State(state): State<RouterState>) -> Json<BlockingStatusResponse> {
    state.app.pipeline.resume_blocking();
    let (paused, remaining_secs) = state.app.pipeline.blocking_status();
    Json(BlockingStatusResponse {
        paused,
        remaining_secs,
    })
}

pub async fn flush_cache(State(state): State<RouterState>) -> Json<OkResponse> {
    state.app.pipeline.cache().flush();
    if let Err(err) = state.app.storage.clear_dns_cache() {
        tracing::warn!(error = %err, "failed to clear persisted dns cache");
    }
    Json(OkResponse { status: "ok" })
}

pub async fn quick_rule(
    State(state): State<RouterState>,
    Json(payload): Json<QuickRulePayload>,
) -> ApiResult<Json<QuickRuleResponse>> {
    let clean = payload
        .domain
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if clean.is_empty() || clean.contains(char::is_whitespace) {
        return Err(err_response(StatusCode::BAD_REQUEST, "Invalid domain name"));
    }

    let rule = match payload.action {
        QuickRuleAction::Allow => format!("@@||{clean}^"),
        QuickRuleAction::Block => format!("||{clean}^"),
    };

    let _guard = state.sub_lock.lock().await;
    let existing = state
        .app
        .storage
        .load_custom_rules()
        .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .unwrap_or_default();

    let already_present = existing.lines().any(|line| line.trim() == rule);
    let added = !already_present;
    if added {
        let mut updated = existing.trim_end().to_string();
        if !updated.is_empty() {
            updated.push('\n');
        }
        updated.push_str(&rule);
        updated.push('\n');
        state
            .app
            .storage
            .save_custom_rules(&updated)
            .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    rebuild_filter_engine(&state.app.storage, &state.app.pipeline)
        .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    state.app.pipeline.cache().flush();

    let filter_stats = state.app.pipeline.filter().stats();
    Ok(Json(QuickRuleResponse {
        rule,
        added,
        stats: filter_stats,
    }))
}

pub async fn test_rule(
    State(state): State<RouterState>,
    Json(payload): Json<TestRulePayload>,
) -> ApiResult<Json<TestRuleResponse>> {
    let clean = payload
        .domain
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if clean.is_empty() || clean.contains(char::is_whitespace) {
        return Err(err_response(StatusCode::BAD_REQUEST, "Invalid domain name"));
    }

    let parsed_ip = match payload
        .client_ip
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(raw) => Some(
            raw.parse::<IpAddr>()
                .map_err(|_| err_response(StatusCode::BAD_REQUEST, "Invalid client_ip"))?,
        ),
        None => None,
    };
    let client_id = payload
        .client_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let decision = state
        .app
        .pipeline
        .evaluate_filter_for_client(&clean, parsed_ip, client_id);
    let (action, rewrite) = match decision.action {
        FilterAction::Block => ("block".to_string(), None),
        FilterAction::Allow => {
            if decision.matched_rule.is_some() {
                ("allow".to_string(), None)
            } else {
                ("none".to_string(), None)
            }
        }
        FilterAction::Rewrite(rw) => {
            let desc = match rw {
                RewriteAction::Ip(ip) => format!("IP {ip}"),
                RewriteAction::Cname(cname) => format!("CNAME {cname}"),
                RewriteAction::Txt(txt) => format!("TXT {txt}"),
            };
            ("rewrite".to_string(), Some(desc))
        }
    };

    Ok(Json(TestRuleResponse {
        domain: clean,
        action,
        matched_rule: decision.matched_rule,
        matched_list: decision.matched_list,
        rewrite,
    }))
}
