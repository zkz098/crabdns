use std::time::Duration;

use axum::extract::State;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade, close_code};
use axum::http::HeaderMap;
use axum::response::Response;
use crabdns_core::{CfCdnStatus, QueryEvent};
use crabdns_storage::{CompiledLogsFilter, LogsFilter};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, watch};
use ts_rs::TS;

use crate::controls::BlockingStatusResponse;
use crate::subscriptions::SubscriptionProgressStatus;
use crate::update_api::UpdateStatusResponse;
use crate::{RouterState, StatsResponse, build_stats_response};

const WS_PING_INTERVAL: Duration = Duration::from_secs(30);
const WS_SEND_TIMEOUT: Duration = Duration::from_secs(10);
const WS_STATS_INTERVAL: Duration = Duration::from_secs(3);
const WS_BLOCKING_TICK_INTERVAL: Duration = Duration::from_secs(1);
const WS_MAX_CLIENT_MSG_BYTES: usize = 8 * 1024;

#[derive(Debug)]
pub struct WsEventHub {
    stats_tx: watch::Sender<u64>,
    blocking_tx: watch::Sender<u64>,
}

impl Default for WsEventHub {
    fn default() -> Self {
        let (stats_tx, _) = watch::channel(0);
        let (blocking_tx, _) = watch::channel(0);
        Self {
            stats_tx,
            blocking_tx,
        }
    }
}

impl WsEventHub {
    pub fn notify_stats(&self) {
        self.stats_tx.send_modify(|rev| *rev = rev.wrapping_add(1));
    }

    #[must_use]
    pub fn subscribe_stats(&self) -> watch::Receiver<u64> {
        self.stats_tx.subscribe()
    }

    pub fn notify_blocking(&self) {
        self.blocking_tx
            .send_modify(|rev| *rev = rev.wrapping_add(1));
    }

    #[must_use]
    pub fn subscribe_blocking(&self) -> watch::Receiver<u64> {
        self.blocking_tx.subscribe()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum WsTopic {
    Logs,
    Stats,
    Blocking,
    Update,
    CfCdn,
    Subscriptions,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct WsLogFilter {
    #[serde(default)]
    pub search: Option<String>,
    #[serde(default)]
    pub outcome: Option<String>,
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub qtype: Option<String>,
    #[serde(default)]
    pub client: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(tag = "type", rename_all = "snake_case")]
#[ts(export)]
pub enum WsClientMessage {
    Subscribe {
        topics: Vec<WsTopic>,
        #[serde(default)]
        log_filter: Option<WsLogFilter>,
    },
    SetLogFilter {
        filter: WsLogFilter,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
#[ts(export)]
pub enum WsServerMessage {
    Log(QueryEvent),
    Stats(StatsResponse),
    Blocking(BlockingStatusResponse),
    Update(UpdateStatusResponse),
    CfCdn(CfCdnStatus),
    Subscriptions(SubscriptionProgressStatus),
    Subscribed { topics: Vec<WsTopic> },
    Error { message: String },
}

#[derive(Debug, Clone, Copy, Default)]
struct TopicSet(u8);

impl TopicSet {
    const LOGS_BIT: u8 = 1 << 0;
    const STATS_BIT: u8 = 1 << 1;
    const BLOCKING_BIT: u8 = 1 << 2;
    const UPDATE_BIT: u8 = 1 << 3;
    const CF_CDN_BIT: u8 = 1 << 4;
    const SUBSCRIPTIONS_BIT: u8 = 1 << 5;

    const fn bit(topic: WsTopic) -> u8 {
        match topic {
            WsTopic::Logs => Self::LOGS_BIT,
            WsTopic::Stats => Self::STATS_BIT,
            WsTopic::Blocking => Self::BLOCKING_BIT,
            WsTopic::Update => Self::UPDATE_BIT,
            WsTopic::CfCdn => Self::CF_CDN_BIT,
            WsTopic::Subscriptions => Self::SUBSCRIPTIONS_BIT,
        }
    }

    fn from_slice(topics: &[WsTopic]) -> Self {
        let mut bits = 0_u8;
        for &topic in topics {
            bits |= Self::bit(topic);
        }
        Self(bits)
    }

    const fn contains(self, topic: WsTopic) -> bool {
        (self.0 & Self::bit(topic)) != 0
    }

    fn to_vec(self) -> Vec<WsTopic> {
        let mut out = Vec::new();
        for topic in [
            WsTopic::Logs,
            WsTopic::Stats,
            WsTopic::Blocking,
            WsTopic::Update,
            WsTopic::CfCdn,
            WsTopic::Subscriptions,
        ] {
            if self.contains(topic) {
                out.push(topic);
            }
        }
        out
    }
}

struct WsSessionState {
    topics: TopicSet,
    live_rx: Option<broadcast::Receiver<QueryEvent>>,
    compiled_filter: CompiledLogsFilter,
    blocking_countdown_active: bool,
    stats_rx: watch::Receiver<u64>,
    blocking_rx: watch::Receiver<u64>,
    update_rx: watch::Receiver<u64>,
    cf_cdn_rx: watch::Receiver<u64>,
    subscription_progress_rx: watch::Receiver<u64>,
}

impl WsSessionState {
    fn new(state: &RouterState) -> Self {
        let mut stats_rx = state.events.subscribe_stats();
        let mut blocking_rx = state.events.subscribe_blocking();
        let mut update_rx = state.updater.subscribe_status();
        let mut cf_cdn_rx = state.app.pipeline.cf_cdn_manager().subscribe_status();
        let mut subscription_progress_rx = state.subscription_progress.subscribe_status();
        let _ = stats_rx.borrow_and_update();
        let _ = blocking_rx.borrow_and_update();
        let _ = update_rx.borrow_and_update();
        let _ = cf_cdn_rx.borrow_and_update();
        let _ = subscription_progress_rx.borrow_and_update();

        Self {
            topics: TopicSet::default(),
            live_rx: None,
            compiled_filter: CompiledLogsFilter::default(),
            blocking_countdown_active: false,
            stats_rx,
            blocking_rx,
            update_rx,
            cf_cdn_rx,
            subscription_progress_rx,
        }
    }
}

async fn make_delayed_interval(period: Duration) -> tokio::time::Interval {
    let mut interval = tokio::time::interval(period);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    interval.tick().await;
    interval
}

async fn push_blocking_status(
    socket: &mut WebSocket,
    state: &RouterState,
    session: &mut WsSessionState,
    blocking_tick: Option<&mut tokio::time::Interval>,
) -> bool {
    let bs = current_blocking_status(state);
    session.blocking_countdown_active = bs.paused && bs.remaining_secs.is_some();
    if session.blocking_countdown_active
        && let Some(tick) = blocking_tick
    {
        tick.reset();
    }
    send_ws_message(socket, &WsServerMessage::Blocking(bs)).await
}

async fn handle_ping_tick(
    socket: &mut WebSocket,
    state: &RouterState,
    session_token: Option<&str>,
) -> bool {
    if state.app.config.load().web_auth_enabled
        && session_token
            .and_then(|t| state.sessions.validate(t))
            .is_none()
    {
        send_close_policy(socket, "session expired").await;
        return false;
    }
    matches!(
        tokio::time::timeout(
            WS_SEND_TIMEOUT,
            socket.send(Message::Ping(axum::body::Bytes::new())),
        )
        .await,
        Ok(Ok(()))
    )
}

fn compile_ws_log_filter(filter: &WsLogFilter) -> CompiledLogsFilter {
    LogsFilter {
        search: filter.search.as_deref(),
        outcome: filter.outcome.as_deref(),
        protocol: filter.protocol.as_deref(),
        qtype: filter.qtype.as_deref(),
        client: filter.client.as_deref(),
    }
    .compile()
}

fn current_blocking_status(state: &RouterState) -> BlockingStatusResponse {
    let (paused, remaining_secs) = state.app.pipeline.blocking_status();
    BlockingStatusResponse {
        paused,
        remaining_secs,
    }
}

pub async fn ws_events(
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    State(state): State<RouterState>,
) -> Response {
    let session_token = crate::auth::extract_token(&headers);
    ws.on_upgrade(move |socket| handle_ws_events(socket, state, session_token))
}

async fn send_ws_message(socket: &mut WebSocket, msg: &WsServerMessage) -> bool {
    let Ok(json) = serde_json::to_string(msg) else {
        return true;
    };
    matches!(
        tokio::time::timeout(WS_SEND_TIMEOUT, socket.send(Message::Text(json.into()))).await,
        Ok(Ok(()))
    )
}

async fn send_close_policy(socket: &mut WebSocket, reason: &'static str) {
    let frame = CloseFrame {
        code: close_code::POLICY,
        reason: reason.into(),
    };
    let _ = tokio::time::timeout(WS_SEND_TIMEOUT, socket.send(Message::Close(Some(frame)))).await;
}

async fn recv_live(
    live_rx: &mut Option<broadcast::Receiver<QueryEvent>>,
) -> Result<QueryEvent, broadcast::error::RecvError> {
    match live_rx.as_mut() {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

async fn send_new_topic_snapshots(
    socket: &mut WebSocket,
    state: &RouterState,
    session: &mut WsSessionState,
    prev: TopicSet,
    next: TopicSet,
    stats_interval: &mut tokio::time::Interval,
    blocking_tick: &mut tokio::time::Interval,
) -> bool {
    if next.contains(WsTopic::Stats) && !prev.contains(WsTopic::Stats) {
        let _ = session.stats_rx.borrow_and_update();
        stats_interval.reset();
        if !send_ws_message(socket, &WsServerMessage::Stats(build_stats_response(state))).await {
            return false;
        }
    }
    if next.contains(WsTopic::Blocking) && !prev.contains(WsTopic::Blocking) {
        let _ = session.blocking_rx.borrow_and_update();
        if !push_blocking_status(socket, state, session, Some(blocking_tick)).await {
            return false;
        }
    }
    if next.contains(WsTopic::Update) && !prev.contains(WsTopic::Update) {
        let _ = session.update_rx.borrow_and_update();
        let msg = WsServerMessage::Update(state.updater.status_snapshot());
        if !send_ws_message(socket, &msg).await {
            return false;
        }
    }
    if next.contains(WsTopic::CfCdn) && !prev.contains(WsTopic::CfCdn) {
        let _ = session.cf_cdn_rx.borrow_and_update();
        let msg = WsServerMessage::CfCdn(state.app.pipeline.cf_cdn_manager().status());
        if !send_ws_message(socket, &msg).await {
            return false;
        }
    }
    if next.contains(WsTopic::Subscriptions) && !prev.contains(WsTopic::Subscriptions) {
        let _ = session.subscription_progress_rx.borrow_and_update();
        let msg = WsServerMessage::Subscriptions(state.subscription_progress.status_snapshot());
        if !send_ws_message(socket, &msg).await {
            return false;
        }
    }
    true
}

async fn handle_client_text(
    text: &str,
    socket: &mut WebSocket,
    state: &RouterState,
    session: &mut WsSessionState,
    stats_interval: &mut tokio::time::Interval,
    blocking_tick: &mut tokio::time::Interval,
) -> bool {
    if text.len() > WS_MAX_CLIENT_MSG_BYTES {
        return send_ws_message(
            socket,
            &WsServerMessage::Error {
                message: "control message too large".to_string(),
            },
        )
        .await;
    }

    let Ok(cmd) = serde_json::from_str::<WsClientMessage>(text) else {
        return send_ws_message(
            socket,
            &WsServerMessage::Error {
                message: "invalid control message".to_string(),
            },
        )
        .await;
    };

    match cmd {
        WsClientMessage::Subscribe { topics, log_filter } => {
            let prev = session.topics;
            let next = TopicSet::from_slice(&topics);
            if let Some(f) = log_filter {
                session.compiled_filter = compile_ws_log_filter(&f);
            }
            if next.contains(WsTopic::Logs) {
                if session.live_rx.is_none() {
                    session.live_rx = Some(state.app.live_tx.subscribe());
                }
            } else {
                session.live_rx = None;
            }
            session.topics = next;
            if !next.contains(WsTopic::Blocking) {
                session.blocking_countdown_active = false;
            }

            let ack = WsServerMessage::Subscribed {
                topics: next.to_vec(),
            };
            if !send_ws_message(socket, &ack).await {
                return false;
            }

            send_new_topic_snapshots(
                socket,
                state,
                session,
                prev,
                next,
                stats_interval,
                blocking_tick,
            )
            .await
        }
        WsClientMessage::SetLogFilter { filter } => {
            session.compiled_filter = compile_ws_log_filter(&filter);
            true
        }
    }
}

async fn handle_ws_events(
    mut socket: WebSocket,
    state: RouterState,
    session_token: Option<String>,
) {
    let mut session = WsSessionState::new(&state);
    let mut ping_interval = make_delayed_interval(WS_PING_INTERVAL).await;
    let mut stats_interval = make_delayed_interval(WS_STATS_INTERVAL).await;
    let mut blocking_tick = make_delayed_interval(WS_BLOCKING_TICK_INTERVAL).await;

    loop {
        tokio::select! {
            recv = recv_live(&mut session.live_rx), if session.live_rx.is_some() => {
                match recv {
                    Ok(event) => {
                        if session.compiled_filter.matches(&event)
                            && !send_ws_message(&mut socket, &WsServerMessage::Log(event)).await
                        {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => {
                        session.live_rx = None;
                    }
                }
            }
            incoming = socket.recv() => {
                match incoming {
                    None | Some(Ok(Message::Close(_)) | Err(_)) => break,
                    Some(Ok(Message::Text(text))) => {
                        if !handle_client_text(
                            &text, &mut socket, &state, &mut session, &mut stats_interval, &mut blocking_tick,
                        ).await {
                            break;
                        }
                    }
                    Some(Ok(_)) => {}
                }
            }
            _ = stats_interval.tick(), if session.topics.contains(WsTopic::Stats) => {
                if !send_ws_message(&mut socket, &WsServerMessage::Stats(build_stats_response(&state))).await {
                    break;
                }
            }
            res = session.stats_rx.changed(), if session.topics.contains(WsTopic::Stats) => {
                if res.is_ok() {
                    stats_interval.reset();
                    if !send_ws_message(&mut socket, &WsServerMessage::Stats(build_stats_response(&state))).await {
                        break;
                    }
                }
            }
            res = session.blocking_rx.changed(), if session.topics.contains(WsTopic::Blocking) => {
                if res.is_ok()
                    && !push_blocking_status(&mut socket, &state, &mut session, Some(&mut blocking_tick)).await
                {
                    break;
                }
            }
            _ = blocking_tick.tick(), if session.topics.contains(WsTopic::Blocking) && session.blocking_countdown_active => {
                if !push_blocking_status(&mut socket, &state, &mut session, None).await {
                    break;
                }
            }
            res = session.update_rx.changed(), if session.topics.contains(WsTopic::Update) => {
                if res.is_ok()
                    && !send_ws_message(&mut socket, &WsServerMessage::Update(state.updater.status_snapshot())).await
                {
                    break;
                }
            }
            res = session.cf_cdn_rx.changed(), if session.topics.contains(WsTopic::CfCdn) => {
                if res.is_ok()
                    && !send_ws_message(&mut socket, &WsServerMessage::CfCdn(state.app.pipeline.cf_cdn_manager().status())).await
                {
                    break;
                }
            }
            res = session.subscription_progress_rx.changed(), if session.topics.contains(WsTopic::Subscriptions) => {
                if res.is_ok()
                    && !send_ws_message(&mut socket, &WsServerMessage::Subscriptions(state.subscription_progress.status_snapshot())).await
                {
                    break;
                }
            }
            _ = ping_interval.tick() => {
                if !handle_ping_tick(&mut socket, &state, session_token.as_deref()).await {
                    break;
                }
            }
        }
    }
}
