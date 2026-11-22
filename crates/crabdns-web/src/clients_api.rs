use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use chrono::Utc;
use crabdns_core::{
    BlockMode, ClientGroup, ClientProfile, ClientRegistry, validate_client_identifier,
};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::RouterState;
use crate::subscriptions::ApiError;

static ID_SEQ: AtomicU64 = AtomicU64::new(1);

const fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, TS)]
#[ts(export)]
pub struct DiscoveredClient {
    pub ip: String,
    pub resolved_name: Option<String>,
    pub name_source: String,
    #[ts(type = "number")]
    pub query_count: u64,
    pub profile_id: Option<String>,
    pub group_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, TS)]
#[ts(export)]
pub struct ClientsOverviewResponse {
    pub clients: Vec<ClientProfile>,
    pub groups: Vec<ClientGroup>,
    pub discovered: Vec<DiscoveredClient>,
}

#[derive(Debug, Clone, Deserialize, TS)]
#[ts(export)]
pub struct ClientProfilePayload {
    pub name: String,
    #[serde(default)]
    pub identifiers: Vec<String>,
    #[serde(default)]
    pub group_id: Option<String>,
    #[serde(default)]
    pub blocking_enabled: Option<bool>,
    #[serde(default)]
    pub use_global_rules: Option<bool>,
    #[serde(default)]
    pub custom_rules: String,
    #[serde(default)]
    pub upstreams: Vec<String>,
    #[serde(default)]
    pub block_mode: Option<BlockMode>,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, TS)]
#[ts(export)]
pub struct ClientGroupPayload {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_true")]
    pub blocking_enabled: bool,
    #[serde(default = "default_true")]
    pub use_global_rules: bool,
    #[serde(default)]
    pub custom_rules: String,
    #[serde(default)]
    pub upstreams: Vec<String>,
    #[serde(default)]
    pub block_mode: Option<BlockMode>,
    #[serde(default)]
    pub cname_cloaking_blocking: Option<bool>,
}

type ApiResult<T> = std::result::Result<T, (StatusCode, Json<ApiError>)>;

fn err_response(status: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<ApiError>) {
    (status, Json(ApiError { error: msg.into() }))
}

fn generate_id(prefix: &str) -> String {
    let nanos = Utc::now()
        .timestamp_nanos_opt()
        .unwrap_or(0)
        .cast_unsigned();
    let seq = ID_SEQ.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}-{nanos:x}-{seq}")
}

fn clean_list(items: Vec<String>) -> Vec<String> {
    items
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn normalize_client(id: String, payload: ClientProfilePayload) -> ApiResult<ClientProfile> {
    let name = payload.name.trim().to_string();
    if name.is_empty() {
        return Err(err_response(
            StatusCode::BAD_REQUEST,
            "Client name cannot be empty",
        ));
    }
    let identifiers = clean_list(payload.identifiers);
    if identifiers.is_empty() {
        return Err(err_response(
            StatusCode::BAD_REQUEST,
            "At least one client identifier (IP, CIDR, or ClientID) is required",
        ));
    }
    for ident in &identifiers {
        validate_client_identifier(ident)
            .map_err(|e| err_response(StatusCode::BAD_REQUEST, e.to_string()))?;
    }
    let group_id = payload
        .group_id
        .map(|g| g.trim().to_string())
        .filter(|g| !g.is_empty());

    Ok(ClientProfile {
        id,
        name,
        identifiers,
        group_id,
        blocking_enabled: payload.blocking_enabled,
        use_global_rules: payload.use_global_rules,
        custom_rules: payload.custom_rules,
        upstreams: clean_list(payload.upstreams),
        block_mode: payload.block_mode,
        tags: clean_list(payload.tags),
    })
}

fn normalize_group(id: String, payload: ClientGroupPayload) -> ApiResult<ClientGroup> {
    let name = payload.name.trim().to_string();
    if name.is_empty() {
        return Err(err_response(
            StatusCode::BAD_REQUEST,
            "Group name cannot be empty",
        ));
    }
    Ok(ClientGroup {
        id,
        name,
        description: payload.description.trim().to_string(),
        blocking_enabled: payload.blocking_enabled,
        use_global_rules: payload.use_global_rules,
        custom_rules: payload.custom_rules,
        upstreams: clean_list(payload.upstreams),
        block_mode: payload.block_mode,
        cname_cloaking_blocking: payload.cname_cloaking_blocking,
    })
}

pub(crate) fn compile_pipeline_clients(
    state: &RouterState,
    clients: &[ClientProfile],
    groups: &[ClientGroup],
) -> ApiResult<ClientRegistry> {
    let cfg = state.app.config.load();
    ClientRegistry::compile(
        clients,
        groups,
        cfg.upstream_timeout_ms,
        cfg.upstream_strategy,
        &cfg.bootstrap_dns,
    )
    .map_err(|e| err_response(StatusCode::BAD_REQUEST, e.to_string()))
}

pub async fn list_clients_overview(
    State(state): State<RouterState>,
) -> ApiResult<Json<ClientsOverviewResponse>> {
    let storage = Arc::clone(&state.app.storage);
    let (clients, groups, counts) = tokio::task::spawn_blocking(move || {
        let clients = storage.list_clients()?;
        let groups = storage.list_client_groups()?;
        let counts = storage.client_query_counts();
        Ok::<_, crabdns_storage::StorageError>((clients, groups, counts))
    })
    .await
    .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let discovered = counts
        .into_iter()
        .take(200)
        .map(|(ip_str, query_count)| {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                let (resolved_name, name_source) =
                    state.app.pipeline.resolve_client_display_name(ip, None);
                let matched = state.app.pipeline.match_client_summary(ip);
                DiscoveredClient {
                    ip: ip_str,
                    resolved_name,
                    name_source: name_source.to_string(),
                    query_count,
                    profile_id: matched.as_ref().map(|m| m.0.clone()),
                    group_id: matched.and_then(|m| m.2),
                }
            } else {
                DiscoveredClient {
                    ip: ip_str,
                    resolved_name: None,
                    name_source: "unknown".to_string(),
                    query_count,
                    profile_id: None,
                    group_id: None,
                }
            }
        })
        .collect();

    Ok(Json(ClientsOverviewResponse {
        clients,
        groups,
        discovered,
    }))
}

pub async fn create_client(
    State(state): State<RouterState>,
    Json(payload): Json<ClientProfilePayload>,
) -> ApiResult<(StatusCode, Json<ClientProfile>)> {
    let profile = normalize_client(generate_id("cli"), payload)?;

    let _guard = state.app.storage.client_lock().lock().await;
    let storage = Arc::clone(&state.app.storage);
    let (mut clients, groups) = tokio::task::spawn_blocking(move || {
        Ok::<_, crabdns_storage::StorageError>((
            storage.list_clients()?,
            storage.list_client_groups()?,
        ))
    })
    .await
    .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    clients.push(profile.clone());
    let registry = compile_pipeline_clients(&state, &clients, &groups)?;
    let storage = Arc::clone(&state.app.storage);
    tokio::task::spawn_blocking(move || storage.save_clients(&clients))
        .await
        .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    state.app.pipeline.swap_clients(registry);
    state.app.pipeline.cache().flush();

    Ok((StatusCode::CREATED, Json(profile)))
}

pub async fn update_client(
    State(state): State<RouterState>,
    Path(id): Path<String>,
    Json(payload): Json<ClientProfilePayload>,
) -> ApiResult<Json<ClientProfile>> {
    let updated = normalize_client(id.clone(), payload)?;

    let _guard = state.app.storage.client_lock().lock().await;
    let storage = Arc::clone(&state.app.storage);
    let (mut clients, groups) = tokio::task::spawn_blocking(move || {
        Ok::<_, crabdns_storage::StorageError>((
            storage.list_clients()?,
            storage.list_client_groups()?,
        ))
    })
    .await
    .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let Some(slot) = clients.iter_mut().find(|c| c.id == id) else {
        return Err(err_response(StatusCode::NOT_FOUND, "Client not found"));
    };
    *slot = updated.clone();
    let registry = compile_pipeline_clients(&state, &clients, &groups)?;
    let storage = Arc::clone(&state.app.storage);
    tokio::task::spawn_blocking(move || storage.save_clients(&clients))
        .await
        .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    state.app.pipeline.swap_clients(registry);
    state.app.pipeline.cache().flush();

    Ok(Json(updated))
}

pub async fn delete_client(
    State(state): State<RouterState>,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let _guard = state.app.storage.client_lock().lock().await;
    let storage = Arc::clone(&state.app.storage);
    let (mut clients, groups) = tokio::task::spawn_blocking(move || {
        Ok::<_, crabdns_storage::StorageError>((
            storage.list_clients()?,
            storage.list_client_groups()?,
        ))
    })
    .await
    .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let before = clients.len();
    clients.retain(|c| c.id != id);
    if clients.len() == before {
        return Err(err_response(StatusCode::NOT_FOUND, "Client not found"));
    }

    let registry = compile_pipeline_clients(&state, &clients, &groups)?;
    let storage = Arc::clone(&state.app.storage);
    tokio::task::spawn_blocking(move || storage.save_clients(&clients))
        .await
        .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    state.app.pipeline.swap_clients(registry);
    state.app.pipeline.cache().flush();

    Ok(StatusCode::NO_CONTENT)
}

pub async fn create_group(
    State(state): State<RouterState>,
    Json(payload): Json<ClientGroupPayload>,
) -> ApiResult<(StatusCode, Json<ClientGroup>)> {
    let group = normalize_group(generate_id("grp"), payload)?;

    let _guard = state.app.storage.client_lock().lock().await;
    let storage = Arc::clone(&state.app.storage);
    let (clients, mut groups) = tokio::task::spawn_blocking(move || {
        Ok::<_, crabdns_storage::StorageError>((
            storage.list_clients()?,
            storage.list_client_groups()?,
        ))
    })
    .await
    .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    groups.push(group.clone());
    let registry = compile_pipeline_clients(&state, &clients, &groups)?;
    let storage = Arc::clone(&state.app.storage);
    tokio::task::spawn_blocking(move || storage.save_client_groups(&groups))
        .await
        .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    state.app.pipeline.swap_clients(registry);
    state.app.pipeline.cache().flush();

    Ok((StatusCode::CREATED, Json(group)))
}

pub async fn update_group(
    State(state): State<RouterState>,
    Path(id): Path<String>,
    Json(payload): Json<ClientGroupPayload>,
) -> ApiResult<Json<ClientGroup>> {
    let updated = normalize_group(id.clone(), payload)?;

    let _guard = state.app.storage.client_lock().lock().await;
    let storage = Arc::clone(&state.app.storage);
    let (clients, mut groups) = tokio::task::spawn_blocking(move || {
        Ok::<_, crabdns_storage::StorageError>((
            storage.list_clients()?,
            storage.list_client_groups()?,
        ))
    })
    .await
    .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let Some(slot) = groups.iter_mut().find(|g| g.id == id) else {
        return Err(err_response(
            StatusCode::NOT_FOUND,
            "Client group not found",
        ));
    };
    *slot = updated.clone();
    let registry = compile_pipeline_clients(&state, &clients, &groups)?;
    let storage = Arc::clone(&state.app.storage);
    tokio::task::spawn_blocking(move || storage.save_client_groups(&groups))
        .await
        .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    state.app.pipeline.swap_clients(registry);
    state.app.pipeline.cache().flush();

    Ok(Json(updated))
}

pub async fn delete_group(
    State(state): State<RouterState>,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let _guard = state.app.storage.client_lock().lock().await;
    let storage = Arc::clone(&state.app.storage);
    let (mut clients, mut groups) = tokio::task::spawn_blocking(move || {
        Ok::<_, crabdns_storage::StorageError>((
            storage.list_clients()?,
            storage.list_client_groups()?,
        ))
    })
    .await
    .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let before = groups.len();
    groups.retain(|g| g.id != id);
    if groups.len() == before {
        return Err(err_response(
            StatusCode::NOT_FOUND,
            "Client group not found",
        ));
    }

    let mut clients_modified = false;
    for client in &mut clients {
        if client.group_id.as_deref() == Some(id.as_str()) {
            client.group_id = None;
            clients_modified = true;
        }
    }

    let registry = compile_pipeline_clients(&state, &clients, &groups)?;
    let storage = Arc::clone(&state.app.storage);
    tokio::task::spawn_blocking(move || -> crabdns_storage::Result<()> {
        storage.save_client_groups(&groups)?;
        if clients_modified {
            storage.save_clients(&clients)?;
        }
        Ok(())
    })
    .await
    .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    state.app.pipeline.swap_clients(registry);
    state.app.pipeline.cache().flush();

    Ok(StatusCode::NO_CONTENT)
}
