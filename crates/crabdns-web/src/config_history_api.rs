use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Json;
use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use crabdns_core::{DhcpLeaseTable, HostsTable};
use crabdns_storage::ConfigSnapshotMeta;
use serde::Serialize;
use tokio::task::JoinHandle;
use ts_rs::TS;

use crate::RouterState;
use crate::backup_api::{apply_compiled_to_pipeline, compile_runtime_components};
use crate::config_api::ConfigResponse;
use crate::subscriptions::ApiError;

const MIN_CONFIRM_TIMEOUT_SECS: u64 = 10;
const MAX_CONFIRM_TIMEOUT_SECS: u64 = 600;

struct PendingConfirmState {
    rollback_snapshot_id: String,
    deadline: Instant,
    task: JoinHandle<()>,
}

#[derive(Default)]
pub struct ConfigConfirmManager {
    pending: Mutex<Option<PendingConfirmState>>,
}

#[derive(Debug, Clone, Serialize, TS)]
#[ts(export)]
pub struct PendingConfirmStatus {
    pub pending: bool,
    pub rollback_snapshot_id: Option<String>,
    #[ts(type = "number")]
    pub remaining_secs: u64,
}

#[derive(Debug, Clone, Serialize, TS)]
#[ts(export)]
pub struct ConfirmConfigResponse {
    pub confirmed: bool,
    pub rollback_snapshot_id: Option<String>,
}

impl ConfigConfirmManager {
    pub fn schedule(&self, state: RouterState, rollback_snapshot_id: String, timeout_secs: u64) {
        let clamped = timeout_secs.clamp(MIN_CONFIRM_TIMEOUT_SECS, MAX_CONFIRM_TIMEOUT_SECS);
        let deadline = Instant::now() + Duration::from_secs(clamped);
        let id_for_task = rollback_snapshot_id.clone();

        let task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(clamped)).await;
            tracing::warn!(
                rollback_snapshot_id = %id_for_task,
                timeout_secs = clamped,
                "configuration update was not confirmed in time; rolling back automatically"
            );
            if let Err((_, err)) =
                apply_snapshot_rollback(&state, &id_for_task, "auto_rollback_unconfirmed").await
            {
                tracing::error!(
                    rollback_snapshot_id = %id_for_task,
                    error = %err.error,
                    "automatic commit-confirm rollback failed"
                );
            }
            let mut guard = state
                .config_confirm
                .pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if guard
                .as_ref()
                .is_some_and(|p| p.rollback_snapshot_id == id_for_task)
            {
                *guard = None;
            }
        });

        let mut guard = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(prev) = guard.take() {
            prev.task.abort();
        }
        *guard = Some(PendingConfirmState {
            rollback_snapshot_id,
            deadline,
            task,
        });
    }

    pub fn confirm(&self) -> Option<String> {
        let mut guard = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let entry = guard.take()?;
        entry.task.abort();
        Some(entry.rollback_snapshot_id)
    }

    pub fn status(&self) -> PendingConfirmStatus {
        let guard = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match guard.as_ref() {
            Some(entry) => {
                let remaining = entry
                    .deadline
                    .saturating_duration_since(Instant::now())
                    .as_secs();
                PendingConfirmStatus {
                    pending: true,
                    rollback_snapshot_id: Some(entry.rollback_snapshot_id.clone()),
                    remaining_secs: remaining,
                }
            }
            None => PendingConfirmStatus {
                pending: false,
                rollback_snapshot_id: None,
                remaining_secs: 0,
            },
        }
    }
}

pub async fn confirm_config(State(state): State<RouterState>) -> Json<ConfirmConfigResponse> {
    let snapshot_id = state.config_confirm.confirm();
    Json(ConfirmConfigResponse {
        confirmed: snapshot_id.is_some(),
        rollback_snapshot_id: snapshot_id,
    })
}

pub async fn get_pending_confirm(State(state): State<RouterState>) -> Json<PendingConfirmStatus> {
    Json(state.config_confirm.status())
}

fn err_response(status: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<ApiError>) {
    (status, Json(ApiError { error: msg.into() }))
}

pub async fn list_config_history(
    State(state): State<RouterState>,
) -> Result<Json<Vec<ConfigSnapshotMeta>>, (StatusCode, Json<ApiError>)> {
    let storage = Arc::clone(&state.app.storage);
    let list = tokio::task::spawn_blocking(move || storage.list_config_history())
        .await
        .map_err(|err| err_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?
        .map_err(|err| err_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    Ok(Json(list))
}

pub async fn rollback_config(
    State(state): State<RouterState>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<ConfigResponse>, (StatusCode, Json<ApiError>)> {
    let _ = state.config_confirm.confirm();
    let response = apply_snapshot_rollback(&state, &id, "rollback").await?;
    Ok(Json(response))
}

pub(crate) async fn apply_snapshot_rollback(
    state: &RouterState,
    id: &str,
    reason: &str,
) -> Result<ConfigResponse, (StatusCode, Json<ApiError>)> {
    let id_owned = id.to_string();
    let reason_owned = reason.to_string();
    let storage = Arc::clone(&state.app.storage);
    let snapshot_opt = tokio::task::spawn_blocking(move || storage.get_config_snapshot(&id_owned))
        .await
        .map_err(|err| err_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?
        .map_err(|err| err_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let next = snapshot_opt.ok_or_else(|| {
        err_response(
            StatusCode::NOT_FOUND,
            "configuration snapshot not found".to_string(),
        )
    })?;

    let current = state.app.config.load_full();
    let storage_for_clients = Arc::clone(&state.app.storage);
    let (clients, groups) = tokio::task::spawn_blocking(move || {
        Ok::<_, crabdns_storage::StorageError>((
            storage_for_clients.list_clients()?,
            storage_for_clients.list_client_groups()?,
        ))
    })
    .await
    .map_err(|err| err_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?
    .map_err(|err| err_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let compiled = compile_runtime_components(&next, &clients, &groups, &state.app.storage)?;

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

    let storage_save = Arc::clone(&state.app.storage);
    let to_save = next.clone();
    tokio::task::spawn_blocking(move || -> crabdns_storage::Result<()> {
        storage_save.save_config(&to_save)?;
        let _ = storage_save.record_config_snapshot(&to_save, &reason_owned);
        Ok(())
    })
    .await
    .map_err(|err| err_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?
    .map_err(|err| err_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    apply_compiled_to_pipeline(
        state,
        &current,
        &next,
        compiled,
        hosts_table_opt,
        dhcp_table_opt,
    );

    let response = ConfigResponse::from(&next);
    state.app.config.store(Arc::new(next));
    Ok(response)
}
