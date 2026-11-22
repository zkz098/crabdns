use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::Response;
use crabdns_core::{FilterAction, FilterStats, QueryEvent, RewriteAction};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use ts_rs::TS;

use crate::RouterState;
use crate::subscriptions::{ApiError, rebuild_filter_engine_async};

const WS_PING_INTERVAL: Duration = Duration::from_secs(30);
const WS_SEND_TIMEOUT: Duration = Duration::from_secs(10);

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
    pub qtype: Option<String>,
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
    let storage = Arc::clone(&state.app.storage);
    match tokio::task::spawn_blocking(move || storage.clear_dns_cache()).await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            tracing::warn!(error = %err, "failed to clear persisted dns cache");
        }
        Err(err) => {
            tracing::warn!(error = %err, "clear persisted dns cache task panicked");
        }
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

    let _guard = state.app.storage.subscription_lock().lock().await;
    let storage = Arc::clone(&state.app.storage);
    let rule_clone = rule.clone();
    let added = tokio::task::spawn_blocking(move || -> Result<bool, String> {
        let existing = storage
            .load_custom_rules()
            .map_err(|e| e.to_string())?
            .unwrap_or_default();
        let already_present = existing.lines().any(|line| line.trim() == rule_clone);
        let added = !already_present;
        if added {
            let mut updated = existing.trim_end().to_string();
            if !updated.is_empty() {
                updated.push('\n');
            }
            updated.push_str(&rule_clone);
            updated.push('\n');
            storage
                .save_custom_rules(&updated)
                .map_err(|e| e.to_string())?;
        }
        Ok(added)
    })
    .await
    .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    rebuild_filter_engine_async(&state.app.storage, &state.app.pipeline)
        .await
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
        .evaluate_filter_for_client_with_qtype_str(
            &clean,
            payload.qtype.as_deref(),
            parsed_ip,
            client_id,
        )
        .map_err(|e| err_response(StatusCode::BAD_REQUEST, e.to_string()))?;
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

pub async fn ws_logs(ws: WebSocketUpgrade, State(state): State<RouterState>) -> Response {
    ws.on_upgrade(move |socket| handle_ws(socket, state.app.live_tx.subscribe()))
}

async fn handle_ws(mut socket: WebSocket, mut rx: broadcast::Receiver<QueryEvent>) {
    let mut ping_interval = tokio::time::interval(WS_PING_INTERVAL);
    ping_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ping_interval.tick().await;
    loop {
        tokio::select! {
            recv = rx.recv() => {
                match recv {
                    Ok(event) => {
                        let Ok(json) = serde_json::to_string(&event) else {
                            continue;
                        };
                        if !matches!(
                            tokio::time::timeout(
                                WS_SEND_TIMEOUT,
                                socket.send(Message::Text(json.into())),
                            )
                            .await,
                            Ok(Ok(()))
                        ) {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
            incoming = socket.recv() => {
                match incoming {
                    None | Some(Ok(Message::Close(_)) | Err(_)) => break,
                    Some(Ok(_)) => {}
                }
            }
            _ = ping_interval.tick() => {
                if !matches!(
                    tokio::time::timeout(
                        WS_SEND_TIMEOUT,
                        socket.send(Message::Ping(axum::body::Bytes::new())),
                    )
                    .await,
                    Ok(Ok(()))
                ) {
                    break;
                }
            }
        }
    }
}

pub async fn get_cf_cdn_status(
    State(state): State<RouterState>,
) -> Json<crabdns_core::CfCdnStatus> {
    Json(state.app.pipeline.cf_cdn_manager().status())
}

pub async fn trigger_cf_cdn_test(
    State(state): State<RouterState>,
) -> (StatusCode, Json<crabdns_core::CfCdnStatus>) {
    let mgr = std::sync::Arc::clone(state.app.pipeline.cf_cdn_manager());
    if !mgr.is_testing() {
        let mgr_bg = std::sync::Arc::clone(&mgr);
        tokio::spawn(async move {
            let _ = mgr_bg.run_speedtest().await;
        });
    }
    let mut status = mgr.status();
    status.testing = true;
    (StatusCode::ACCEPTED, Json(status))
}
