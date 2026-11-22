use std::path::Path;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::RouterState;

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct TlsStatusResponse {
    pub https_enabled: bool,
    pub https_listen: Option<String>,
    pub dot_enabled: bool,
    pub dot_listen: Option<String>,
    #[serde(default)]
    pub doq_enabled: bool,
    #[serde(default)]
    pub doq_listen: Option<String>,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    pub last_loaded_at: Option<DateTime<Utc>>,
    pub cert_fingerprint_sha256: Option<String>,
    pub cert_count: usize,
    pub last_error: Option<String>,
}

pub trait TlsReloader: Send + Sync {
    fn status(&self) -> TlsStatusResponse;
    fn reload(
        &self,
        cert_path: Option<&Path>,
        key_path: Option<&Path>,
    ) -> std::result::Result<TlsStatusResponse, String>;
}

pub async fn get_tls_status(State(state): State<RouterState>) -> Json<TlsStatusResponse> {
    if let Some(reloader) = &state.app.tls_reloader {
        return Json(reloader.status());
    }
    let cfg = state.app.config.load();
    Json(TlsStatusResponse {
        https_enabled: false,
        https_listen: cfg.listen_web_tls.map(|a| a.to_string()),
        dot_enabled: false,
        dot_listen: cfg.listen_dot.map(|a| a.to_string()),
        doq_enabled: false,
        doq_listen: cfg.listen_doq.map(|a| a.to_string()),
        cert_path: cfg.tls_cert_path.as_ref().map(|p| p.display().to_string()),
        key_path: cfg.tls_key_path.as_ref().map(|p| p.display().to_string()),
        last_loaded_at: None,
        cert_fingerprint_sha256: None,
        cert_count: 0,
        last_error: None,
    })
}

pub async fn reload_tls(
    State(state): State<RouterState>,
) -> std::result::Result<Json<TlsStatusResponse>, (StatusCode, Json<serde_json::Value>)> {
    let Some(reloader) = &state.app.tls_reloader else {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "TLS listeners are not active (configure listen_web_tls or listen_dot)"
            })),
        ));
    };

    let cfg = state.app.config.load();
    reloader
        .reload(cfg.tls_cert_path.as_deref(), cfg.tls_key_path.as_deref())
        .map(Json)
        .map_err(|err| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": err })),
            )
        })
}
