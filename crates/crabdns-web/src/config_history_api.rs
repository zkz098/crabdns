use std::path::Path;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use crabdns_core::{DhcpLeaseTable, HostsTable};
use crabdns_storage::ConfigSnapshotMeta;

use crate::RouterState;
use crate::backup_api::{apply_compiled_to_pipeline, compile_runtime_components};
use crate::config_api::ConfigResponse;
use crate::subscriptions::ApiError;

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
    let storage = Arc::clone(&state.app.storage);
    let snapshot_opt = tokio::task::spawn_blocking(move || storage.get_config_snapshot(&id))
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
        let _ = storage_save.record_config_snapshot(&to_save, "rollback");
        Ok(())
    })
    .await
    .map_err(|err| err_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?
    .map_err(|err| err_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    apply_compiled_to_pipeline(
        &state,
        &current,
        &next,
        compiled,
        hosts_table_opt,
        dhcp_table_opt,
    );

    let response = ConfigResponse::from(&next);
    state.app.config.store(Arc::new(next));
    Ok(Json(response))
}
