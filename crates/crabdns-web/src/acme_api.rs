use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use axum::Json;
use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use crabdns_core::{AcmeChallengeType, Config, DnsPipeline};
use dashmap::DashMap;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, OrderStatus, RetryPolicy,
};
use rcgen::{CertificateParams, KeyPair};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use ts_rs::TS;
use x509_parser::pem::parse_x509_pem;
use x509_parser::prelude::FromDer;

use crate::RouterState;
use crate::tls_api::TlsReloader;

#[derive(Debug, Clone, Default)]
pub struct AcmeHttpChallengeStore {
    tokens: Arc<DashMap<String, String>>,
}

impl AcmeHttpChallengeStore {
    pub fn set(&self, token: String, key_auth: String) {
        self.tokens.insert(token, key_auth);
    }

    pub fn get(&self, token: &str) -> Option<String> {
        self.tokens.get(token).map(|v| v.value().clone())
    }

    pub fn clear(&self) {
        self.tokens.clear();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct AcmeStatusResponse {
    pub enabled: bool,
    pub domains: Vec<String>,
    pub email: Option<String>,
    pub directory_url: String,
    pub challenge_type: AcmeChallengeType,
    pub renew_before_days: u32,
    pub cert_path: String,
    pub key_path: String,
    pub cert_exists: bool,
    pub cert_expires_at: Option<DateTime<Utc>>,
    pub days_remaining: Option<i64>,
    pub last_renewed_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub in_progress: bool,
}

pub struct AcmeManager {
    pub http_challenges: AcmeHttpChallengeStore,
    issue_lock: Mutex<()>,
    in_progress: AtomicBool,
    last_renewed_at: std::sync::Mutex<Option<DateTime<Utc>>>,
    last_error: std::sync::Mutex<Option<String>>,
}

impl Default for AcmeManager {
    fn default() -> Self {
        Self::new()
    }
}

impl AcmeManager {
    pub fn new() -> Self {
        Self {
            http_challenges: AcmeHttpChallengeStore::default(),
            issue_lock: Mutex::new(()),
            in_progress: AtomicBool::new(false),
            last_renewed_at: std::sync::Mutex::new(None),
            last_error: std::sync::Mutex::new(None),
        }
    }

    pub fn acme_paths(data_dir: &Path) -> (PathBuf, PathBuf, PathBuf) {
        let dir = data_dir.join("acme");
        (
            dir.join("fullchain.pem"),
            dir.join("privkey.pem"),
            dir.join("account.json"),
        )
    }

    pub fn status(&self, cfg: &Config) -> AcmeStatusResponse {
        let (cert_path, key_path, _) = Self::acme_paths(&cfg.data_dir);
        let cert_exists = cert_path.is_file() && key_path.is_file();
        let cert_expires_at = if cert_path.is_file() {
            read_cert_expiry(&cert_path)
        } else {
            None
        };
        let days_remaining = cert_expires_at.map(|exp| (exp - Utc::now()).num_days());
        let last_renewed_at = *self
            .last_renewed_at
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let last_error = self
            .last_error
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();

        AcmeStatusResponse {
            enabled: cfg.acme_enabled,
            domains: cfg.acme_domains.clone(),
            email: cfg.acme_email.clone(),
            directory_url: cfg.acme_directory_url.clone(),
            challenge_type: cfg.acme_challenge_type,
            renew_before_days: cfg.acme_renew_before_days,
            cert_path: cert_path.display().to_string(),
            key_path: key_path.display().to_string(),
            cert_exists,
            cert_expires_at,
            days_remaining,
            last_renewed_at,
            last_error,
            in_progress: self.in_progress.load(Ordering::Relaxed),
        }
    }

    pub fn needs_renewal(&self, cfg: &Config) -> bool {
        if !cfg.acme_enabled || cfg.acme_domains.is_empty() {
            return false;
        }
        let (cert_path, key_path, _) = Self::acme_paths(&cfg.data_dir);
        if !cert_path.is_file() || !key_path.is_file() {
            return true;
        }
        let Some(exp) = read_cert_expiry(&cert_path) else {
            return true;
        };
        let remaining_days = (exp - Utc::now()).num_days();
        remaining_days <= i64::from(cfg.acme_renew_before_days)
    }

    pub async fn issue_or_renew(
        &self,
        cfg: &Config,
        pipeline: &DnsPipeline,
        tls_reloader: Option<&Arc<dyn TlsReloader>>,
        force: bool,
    ) -> Result<AcmeStatusResponse, String> {
        let _guard = self.issue_lock.lock().await;
        if !force && !self.needs_renewal(cfg) {
            return Ok(self.status(cfg));
        }

        let domains: Vec<String> = cfg
            .acme_domains
            .iter()
            .map(|d| d.trim().trim_end_matches('.').to_ascii_lowercase())
            .filter(|d| !d.is_empty())
            .collect();
        if domains.is_empty() {
            return Err("acme_domains must contain at least one domain".to_string());
        }

        self.in_progress.store(true, Ordering::Relaxed);
        let res = self
            .run_acme_order(cfg, &domains, pipeline, tls_reloader)
            .await;
        self.in_progress.store(false, Ordering::Relaxed);
        self.http_challenges.clear();
        pipeline.clear_acme_dns_challenges();

        match res {
            Ok(()) => {
                *self
                    .last_renewed_at
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Utc::now());
                *self
                    .last_error
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
                Ok(self.status(cfg))
            }
            Err(err) => {
                *self
                    .last_error
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(err.clone());
                Err(err)
            }
        }
    }

    async fn run_acme_order(
        &self,
        cfg: &Config,
        domains: &[String],
        pipeline: &DnsPipeline,
        tls_reloader: Option<&Arc<dyn TlsReloader>>,
    ) -> Result<(), String> {
        let (cert_path, key_path, account_path) = Self::acme_paths(&cfg.data_dir);
        if let Some(parent) = cert_path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| format!("failed to create acme directory: {e}"))?;
        }

        let account = load_or_create_account(
            &account_path,
            &cfg.acme_directory_url,
            cfg.acme_email.as_deref(),
        )
        .await?;

        let identifiers: Vec<Identifier> = domains.iter().cloned().map(Identifier::Dns).collect();
        let mut order = account
            .new_order(&NewOrder::new(&identifiers))
            .await
            .map_err(|e| format!("ACME new_order failed: {e}"))?;

        self.complete_authorizations(&mut order, cfg.acme_challenge_type, pipeline)
            .await?;

        let status = order
            .poll_ready(&RetryPolicy::default())
            .await
            .map_err(|e| format!("ACME poll_ready failed: {e}"))?;
        if status != OrderStatus::Ready && status != OrderStatus::Valid {
            return Err(format!("ACME order did not become ready: {status:?}"));
        }

        let key_pair =
            KeyPair::generate().map_err(|e| format!("keypair generation failed: {e}"))?;
        let csr = CertificateParams::new(domains.to_vec())
            .map_err(|e| format!("certificate params failed: {e}"))?
            .serialize_request(&key_pair)
            .map_err(|e| format!("CSR generation failed: {e}"))?;

        order
            .finalize_csr(csr.der())
            .await
            .map_err(|e| format!("ACME finalize_csr failed: {e}"))?;
        let cert_chain_pem = order
            .poll_certificate(&RetryPolicy::default())
            .await
            .map_err(|e| format!("ACME poll_certificate failed: {e}"))?;
        let privkey_pem = key_pair.serialize_pem();

        write_pem_atomic(&cert_path, cert_chain_pem.as_bytes(), false).await?;
        write_pem_atomic(&key_path, privkey_pem.as_bytes(), true).await?;

        if let Some(reloader) = tls_reloader
            && let Err(err) = reloader.reload(Some(&cert_path), Some(&key_path))
        {
            tracing::warn!(error = %err, "ACME issued cert, but TLS reload reported: {err}");
        }
        Ok(())
    }

    async fn complete_authorizations(
        &self,
        order: &mut instant_acme::Order,
        challenge_type: AcmeChallengeType,
        pipeline: &DnsPipeline,
    ) -> Result<(), String> {
        let mut authzs = order.authorizations();
        while let Some(res) = authzs.next().await {
            let mut authz = res.map_err(|e| format!("ACME authorization failed: {e}"))?;
            if authz.status == AuthorizationStatus::Valid {
                continue;
            }
            let ident_name = authz.identifier().to_string();

            let target_type = match challenge_type {
                AcmeChallengeType::Http01 => ChallengeType::Http01,
                AcmeChallengeType::Dns01Local => ChallengeType::Dns01,
            };
            let mut challenge = authz.challenge(target_type.clone()).ok_or_else(|| {
                format!("ACME server did not offer {target_type:?} for {ident_name}")
            })?;

            match challenge_type {
                AcmeChallengeType::Http01 => {
                    let key_auth = challenge.key_authorization().as_str().to_string();
                    self.http_challenges.set(challenge.token.clone(), key_auth);
                }
                AcmeChallengeType::Dns01Local => {
                    let dns_val = challenge.key_authorization().dns_value();
                    let fqdn = format!("_acme-challenge.{ident_name}");
                    pipeline.set_acme_dns_challenge(&fqdn, dns_val);
                }
            }

            challenge
                .set_ready()
                .await
                .map_err(|e| format!("ACME challenge set_ready failed for {ident_name}: {e}"))?;
        }
        if challenge_type == AcmeChallengeType::Dns01Local {
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        Ok(())
    }
}

async fn load_or_create_account(
    account_path: &Path,
    directory_url: &str,
    email: Option<&str>,
) -> Result<Account, String> {
    if account_path.is_file() {
        let raw = tokio::fs::read_to_string(account_path)
            .await
            .map_err(|e| format!("failed to read ACME account: {e}"))?;
        if let Ok(creds) = serde_json::from_str::<AccountCredentials>(&raw) {
            return Account::builder()
                .map_err(|e| format!("ACME account builder failed: {e}"))?
                .from_credentials(creds)
                .await
                .map_err(|e| format!("ACME from_credentials failed: {e}"));
        }
    }

    let contact_str = email
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| format!("mailto:{s}"));
    let contacts: Vec<&str> = contact_str.iter().map(String::as_str).collect();
    let (account, creds) = Account::builder()
        .map_err(|e| format!("ACME account builder failed: {e}"))?
        .create(
            &NewAccount {
                contact: &contacts,
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            directory_url.to_string(),
            None,
        )
        .await
        .map_err(|e| format!("ACME account creation failed: {e}"))?;

    let json = serde_json::to_vec_pretty(&creds)
        .map_err(|e| format!("failed to serialize ACME account: {e}"))?;
    write_pem_atomic(account_path, &json, true).await?;
    Ok(account)
}

async fn write_pem_atomic(path: &Path, bytes: &[u8], secret: bool) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    tokio::fs::write(&tmp, bytes)
        .await
        .map_err(|e| format!("failed to write {}: {e}", tmp.display()))?;
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::PermissionsExt;
        let _ = tokio::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)).await;
    }
    #[cfg(not(unix))]
    let _ = secret;
    tokio::fs::rename(&tmp, path)
        .await
        .map_err(|e| format!("failed to rename {}: {e}", path.display()))?;
    Ok(())
}

pub fn read_cert_expiry(cert_path: &Path) -> Option<DateTime<Utc>> {
    let bytes = std::fs::read(cert_path).ok()?;
    let (_, pem) = parse_x509_pem(&bytes).ok()?;
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(&pem.contents).ok()?;
    let ts = cert.validity().not_after.timestamp();
    DateTime::from_timestamp(ts, 0)
}

pub async fn serve_http01_challenge(
    State(state): State<RouterState>,
    AxumPath(token): AxumPath<String>,
) -> Response {
    serve_http01_from_store(&state.acme.http_challenges, &token)
}

pub fn serve_http01_from_store(store: &AcmeHttpChallengeStore, token: &str) -> Response {
    if let Some(key_auth) = store.get(token) {
        (StatusCode::OK, key_auth).into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

pub async fn get_acme_status(State(state): State<RouterState>) -> Json<AcmeStatusResponse> {
    let cfg = state.app.config.load();
    Json(state.acme.status(&cfg))
}

pub async fn issue_acme_certificate(
    State(state): State<RouterState>,
) -> Result<Json<AcmeStatusResponse>, (StatusCode, Json<serde_json::Value>)> {
    let cfg = state.app.config.load_full();
    if cfg.acme_domains.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(
                serde_json::json!({ "error": "acme_domains is empty; configure at least one domain first" }),
            ),
        ));
    }
    state
        .acme
        .issue_or_renew(
            &cfg,
            &state.app.pipeline,
            state.app.tls_reloader.as_ref(),
            true,
        )
        .await
        .map(Json)
        .map_err(|err| {
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": err })),
            )
        })
}

pub(crate) struct AcmeConfigUpdates {
    pub enabled: Option<bool>,
    pub domains: Option<Vec<String>>,
    pub email: Option<String>,
    pub directory_url: Option<String>,
    pub challenge_type: Option<AcmeChallengeType>,
    pub http_listen: Option<String>,
    pub renew_before_days: Option<u32>,
}

pub(crate) fn apply_acme_updates(
    next: &mut Config,
    updates: AcmeConfigUpdates,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if let Some(enabled) = updates.enabled {
        next.acme_enabled = enabled;
    }
    if let Some(domains) = updates.domains {
        next.acme_domains = domains
            .into_iter()
            .map(|d| d.trim().trim_end_matches('.').to_ascii_lowercase())
            .filter(|d| !d.is_empty())
            .collect();
    }
    if let Some(email) = updates.email {
        let trimmed = email.trim().to_string();
        next.acme_email = if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        };
    }
    if let Some(dir_url) = updates.directory_url {
        let trimmed = dir_url.trim().to_string();
        if !trimmed.is_empty() {
            next.acme_directory_url = trimmed;
        }
    }
    if let Some(ct) = updates.challenge_type {
        next.acme_challenge_type = ct;
    }
    if let Some(raw_listen) = updates.http_listen {
        let trimmed = raw_listen.trim();
        next.acme_http_listen = if trimmed.is_empty() {
            None
        } else {
            let addr: SocketAddr = trimmed.parse().map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": format!("invalid acme_http_listen: {e}") })),
                )
            })?;
            Some(addr)
        };
    }
    if let Some(days) = updates.renew_before_days {
        next.acme_renew_before_days = days.clamp(1, 89);
    }
    Ok(())
}
