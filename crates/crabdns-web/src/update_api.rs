use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sigilup::manifest::{FileEpochStore, KeyPinFile, semver};
use sigilup::transport::ReqwestUpdater;
use sigilup::{
    TrustStore, UpdateDecision, UpdateEvaluator, UrlPolicy, VerificationPolicy, VerifyContext,
};
use ts_rs::TS;

use crate::RouterState;

/// Embedded `sigilup` trust-root pin file (`Ed25519 + ML-DSA-65`).
const EMBEDDED_PINS_JSON: &str = include_str!("sigilup-pins.json");

/// Repository hosting official `CrabDNS` releases.
pub const RELEASE_REPO: &str = "zkz098/crabdns";

/// Mirror prefix used as a fallback when `github.com` is slow or unreachable.
pub const GH_PROXY_PREFIX: &str = "https://gh-proxy.com/";

/// Allowed download URL prefixes for release artifacts.
pub const ALLOWED_DOWNLOAD_PREFIXES: &[&str] = &[
    "https://github.com/zkz098/crabdns/releases/download/",
    "https://gh-proxy.com/https://github.com/zkz098/crabdns/releases/download/",
];

/// Default signed manifest URLs (`latest.hsig.json`), tried in order.
pub const MANIFEST_URLS: &[&str] = &[
    "https://github.com/zkz098/crabdns/releases/latest/download/latest.hsig.json",
    "https://gh-proxy.com/https://github.com/zkz098/crabdns/releases/latest/download/latest.hsig.json",
];

/// Expected asset kind in `SignedManifest`.
pub const EXPECTED_KIND: &str = "portable";

/// Upper bound for an update archive or executable (256 MiB).
pub const MAX_UPDATE_BYTES: u64 = 256 * 1024 * 1024;

/// Subdirectory under `data_dir` used for staging update downloads.
pub const UPDATE_STAGING_DIR: &str = "update-staging";

/// Filename under `data_dir` used by `FileEpochStore` for anti-rollback protection.
pub const EPOCH_STORE_FILE: &str = "sigilup-epoch";

#[cfg(windows)]
pub const EXPECTED_EXE_NAME: &str = "crabdns.exe";
#[cfg(not(windows))]
pub const EXPECTED_EXE_NAME: &str = "crabdns";

/// Available verified update metadata returned by a manifest check.
#[derive(Debug, Clone)]
pub struct AvailableUpdate {
    pub version: String,
    pub notes: String,
    pub asset_url: String,
    pub asset_size: u64,
    pub inner: sigilup::AvailableUpdate,
}

/// Target destination for installing a verified update.
#[derive(Debug, Clone, Default)]
pub enum InstallTarget {
    /// Atomically replace the currently running executable via `sigilup::replace::install_portable_update`.
    #[default]
    CurrentExe,
    /// Write the verified executable to a custom path (used in tests or custom target installations).
    CustomPath(PathBuf),
}

/// Configuration for `sigilup` update checking and installation.
#[derive(Debug, Clone)]
pub struct UpdateConfig {
    pub manifest_urls: Vec<String>,
    pub pins: KeyPinFile,
    pub url_policy: UrlPolicy,
    pub enforce_version_url_prefix: bool,
    pub verify_timestamp_unix: Option<u64>,
    pub install_target: InstallTarget,
}

impl UpdateConfig {
    /// Build the default production update configuration for `crabdns`.
    pub fn default_production() -> Result<Self, String> {
        let pins = load_embedded_pin_file()?;
        let url_policy = UrlPolicy::with_prefixes(ALLOWED_DOWNLOAD_PREFIXES.iter().copied());
        Ok(Self {
            manifest_urls: MANIFEST_URLS.iter().map(|s| (*s).to_string()).collect(),
            pins,
            url_policy,
            enforce_version_url_prefix: true,
            verify_timestamp_unix: None,
            install_target: InstallTarget::CurrentExe,
        })
    }

    /// Override the manifest URLs (e.g. from CLI `--manifest-url`).
    ///
    /// When a custom manifest URL outside official GitHub Releases is provided,
    /// the URL policy is widened to allow the custom origin's prefix if needed.
    #[must_use]
    pub fn with_custom_manifest_url(mut self, url: String) -> Self {
        let is_official = ALLOWED_DOWNLOAD_PREFIXES
            .iter()
            .any(|prefix| url.starts_with(prefix))
            || MANIFEST_URLS.iter().any(|&m| m == url);
        if !is_official && let Some((base, _)) = url.rsplit_once('/') {
            let prefix = format!("{base}/");
            let mut prefixes: Vec<String> = ALLOWED_DOWNLOAD_PREFIXES
                .iter()
                .map(|s| (*s).to_string())
                .collect();
            prefixes.push(prefix);
            let mut policy = UrlPolicy::with_prefixes(prefixes);
            if url.starts_with("http://127.0.0.1:") || url.starts_with("http://localhost:") {
                policy.require_https = false;
            }
            self.url_policy = policy;
            self.enforce_version_url_prefix = false;
        }
        self.manifest_urls = vec![url];
        self
    }
}

/// Load and parse the embedded `sigilup-pins.json` trust store.
pub fn load_embedded_pin_file() -> Result<KeyPinFile, String> {
    KeyPinFile::from_json_str(EMBEDDED_PINS_JSON)
        .map_err(|e| format!("failed to parse embedded sigilup-pins.json: {e}"))
}

/// Construct a `sigilup` [`UpdateEvaluator`] bound to `trust_store`, `current_version`, and `url_policy`.
#[must_use]
pub fn build_evaluator(
    trust_store: TrustStore,
    current_version: semver::Version,
    url_policy: UrlPolicy,
) -> UpdateEvaluator {
    UpdateEvaluator::new(trust_store, current_version)
        .with_policy(VerificationPolicy::strict())
        .with_url_policy(url_policy)
        .with_expected_kind(EXPECTED_KIND)
        .with_channel(EXPECTED_KIND)
}

/// Validate that a release artifact URL belongs to `zkz098/crabdns`'s release tag `v{version}`
/// and ends in a safe plain filename.
pub fn validate_asset_url(url: &str, version: &str) -> Result<(), String> {
    let github_prefix = format!("https://github.com/{RELEASE_REPO}/releases/download/v{version}/");
    let mirror_prefix = format!("{GH_PROXY_PREFIX}{github_prefix}");
    let file_name = url
        .strip_prefix(&github_prefix)
        .or_else(|| url.strip_prefix(&mirror_prefix))
        .ok_or_else(|| {
            format!("artifact URL '{url}' is not under '{github_prefix}' or '{mirror_prefix}'")
        })?;
    let sane = !file_name.is_empty()
        && file_name.len() <= 128
        && file_name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'+'));
    if !sane {
        return Err(format!(
            "artifact URL '{url}' does not end in a valid release asset filename"
        ));
    }
    Ok(())
}

/// Return the parsed `CARGO_PKG_VERSION` of `crabdns`.
pub fn current_pkg_version() -> Result<semver::Version, String> {
    semver::Version::parse(env!("CARGO_PKG_VERSION"))
        .map_err(|e| format!("invalid CARGO_PKG_VERSION: {e}"))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Check for a newer signed release using `sigilup`.
pub async fn check_for_update_with_config(
    client: &reqwest::Client,
    data_dir: &Path,
    cfg: &UpdateConfig,
) -> Result<Option<AvailableUpdate>, String> {
    let current = current_pkg_version()?;
    check_for_update_from_version(client, data_dir, current, cfg).await
}

/// Check for a newer signed release relative to `current_version`.
pub async fn check_for_update_from_version(
    client: &reqwest::Client,
    data_dir: &Path,
    current_version: semver::Version,
    cfg: &UpdateConfig,
) -> Result<Option<AvailableUpdate>, String> {
    fs::create_dir_all(data_dir).map_err(|e| {
        format!(
            "failed to create data directory {}: {e}",
            data_dir.display()
        )
    })?;
    let mut evaluator = build_evaluator(
        cfg.pins.to_trust_store(),
        current_version,
        cfg.url_policy.clone(),
    );
    let mut epoch_store = FileEpochStore::new(data_dir.join(EPOCH_STORE_FILE));
    let updater = ReqwestUpdater::new(client.clone()).with_max_artifact_bytes(MAX_UPDATE_BYTES);
    let ts = cfg.verify_timestamp_unix.unwrap_or_else(unix_now);
    let mut ctx = VerifyContext::at_unix(ts);
    ctx.min_security_epoch = cfg.pins.min_security_epoch;

    let url_refs: Vec<&str> = cfg.manifest_urls.iter().map(String::as_str).collect();
    match updater
        .check_for_update_any::<serde_json::Value, _>(
            &url_refs,
            &mut evaluator,
            &mut epoch_store,
            ctx,
        )
        .await
        .map_err(|e| format!("sigilup update check failed: {e}"))?
    {
        UpdateDecision::UpToDate => Ok(None),
        UpdateDecision::UpdateAvailable(inner) => {
            let version = inner.version.to_string();
            if cfg.enforce_version_url_prefix {
                for url in inner.asset.all_urls() {
                    validate_asset_url(url, &version)?;
                }
            }
            let notes = inner.notes.clone();
            let asset_url = inner.asset.url.clone();
            let asset_size = inner.asset.digest.size;
            Ok(Some(AvailableUpdate {
                version,
                notes,
                asset_url,
                asset_size,
                inner: *inner,
            }))
        }
    }
}

/// Stream-download an [`AvailableUpdate`], verify `BLAKE3 + SHA-512 + size` in flight,
/// and install the replacement executable.
pub async fn download_and_install_update<F>(
    client: &reqwest::Client,
    data_dir: &Path,
    update: &AvailableUpdate,
    cfg: &UpdateConfig,
    on_progress: F,
) -> Result<(), String>
where
    F: FnMut(u64, Option<u64>),
{
    let staging = data_dir.join(UPDATE_STAGING_DIR);
    let _ = fs::remove_dir_all(&staging);
    fs::create_dir_all(&staging)
        .map_err(|e| format!("failed to create update staging directory: {e}"))?;

    let updater = ReqwestUpdater::new(client.clone()).with_max_artifact_bytes(MAX_UPDATE_BYTES);
    let verified_path = updater
        .download_and_verify(&update.inner, &staging, on_progress)
        .await
        .map_err(|e| format!("download or cryptographic verification failed: {e}"))?;

    let extract_dir = staging.join(format!("extracted-{}", update.version));
    let install_res = match &cfg.install_target {
        InstallTarget::CurrentExe => sigilup::replace::install_portable_update(
            &verified_path,
            &extract_dir,
            EXPECTED_EXE_NAME,
            MAX_UPDATE_BYTES,
        )
        .map_err(|e| format!("self-replace failed: {e}")),
        InstallTarget::CustomPath(dest) => {
            install_to_custom_path(&verified_path, &extract_dir, dest)
        }
    };

    let _ = fs::remove_dir_all(&staging);
    install_res
}

fn install_to_custom_path(
    verified_archive: &Path,
    _extract_dir: &Path,
    dest: &Path,
) -> Result<(), String> {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create target parent dir: {e}"))?;
    }
    fs::copy(verified_archive, dest)
        .map_err(|e| format!("failed to write updated binary to {}: {e}", dest.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(dest, fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("failed to set executable permissions: {e}"))?;
    }
    Ok(())
}

// ── Web API State & Handlers ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct UpdateStatusResponse {
    pub current_version: String,
    pub update_available: bool,
    pub latest_version: Option<String>,
    pub notes: Option<String>,
    pub asset_url: Option<String>,
    #[ts(type = "number | null")]
    pub asset_size: Option<u64>,
    pub busy: bool,
    pub restart_pending: bool,
    pub last_checked_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
}

#[derive(Default)]
struct UpdateSnapshot {
    pending: Option<AvailableUpdate>,
    restart_pending: bool,
    last_checked_at: Option<DateTime<Utc>>,
    last_error: Option<String>,
}

pub struct UpdateManager {
    busy: AtomicBool,
    snapshot: Mutex<UpdateSnapshot>,
    config_override: Mutex<Option<UpdateConfig>>,
}

impl Default for UpdateManager {
    fn default() -> Self {
        Self {
            busy: AtomicBool::new(false),
            snapshot: Mutex::new(UpdateSnapshot::default()),
            config_override: Mutex::new(None),
        }
    }
}

struct BusyGuard<'a>(&'a AtomicBool);

impl Drop for BusyGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

impl UpdateManager {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the [`UpdateConfig`] used by Web API handlers (useful for tests or custom update servers).
    pub fn set_config_override(&self, cfg: UpdateConfig) {
        let mut guard = self
            .config_override
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = Some(cfg);
    }

    fn effective_config(&self) -> Result<UpdateConfig, String> {
        let guard = self
            .config_override
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(cfg) = guard.as_ref() {
            Ok(cfg.clone())
        } else {
            UpdateConfig::default_production()
        }
    }

    fn try_acquire_busy(&self) -> Option<BusyGuard<'_>> {
        if self.busy.swap(true, Ordering::SeqCst) {
            None
        } else {
            Some(BusyGuard(&self.busy))
        }
    }

    fn record_check_success(&self, pending: Option<AvailableUpdate>) {
        let mut snap = self
            .snapshot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        snap.pending = pending;
        snap.last_checked_at = Some(Utc::now());
        snap.last_error = None;
    }

    fn record_error(&self, err: String, update_checked_at: bool) {
        let mut snap = self
            .snapshot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if update_checked_at {
            snap.last_checked_at = Some(Utc::now());
        }
        snap.last_error = Some(err);
    }

    fn record_apply_success(&self) {
        let mut snap = self
            .snapshot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        snap.pending = None;
        snap.restart_pending = true;
        snap.last_error = None;
    }

    fn cached_pending(&self) -> Option<AvailableUpdate> {
        let snap = self
            .snapshot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        snap.pending.clone()
    }

    #[must_use]
    pub fn status_snapshot(&self) -> UpdateStatusResponse {
        let busy = self.busy.load(Ordering::SeqCst);
        let snap = self
            .snapshot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        UpdateStatusResponse {
            current_version: env!("CARGO_PKG_VERSION").to_string(),
            update_available: snap.pending.is_some(),
            latest_version: snap.pending.as_ref().map(|u| u.version.clone()),
            notes: snap.pending.as_ref().map(|u| u.notes.clone()),
            asset_url: snap.pending.as_ref().map(|u| u.asset_url.clone()),
            asset_size: snap.pending.as_ref().map(|u| u.asset_size),
            busy,
            restart_pending: snap.restart_pending,
            last_checked_at: snap.last_checked_at,
            last_error: snap.last_error.clone(),
        }
    }
}

/// `GET /api/update/status` — return current version and cached update check state.
pub async fn get_update_status(State(state): State<RouterState>) -> Json<UpdateStatusResponse> {
    Json(state.updater.status_snapshot())
}

/// `POST /api/update/check` — query signed release manifest via `sigilup` and return updated status.
pub async fn check_update(
    State(state): State<RouterState>,
) -> Result<Json<UpdateStatusResponse>, (StatusCode, Json<serde_json::Value>)> {
    let Some(busy_guard) = state.updater.try_acquire_busy() else {
        return Err((
            StatusCode::CONFLICT,
            Json(
                serde_json::json!({ "error": "an update check or installation is already in progress" }),
            ),
        ));
    };

    let cfg = state.updater.effective_config().map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": err })),
        )
    })?;
    let data_dir = state.app.config.load().data_dir.clone();

    match check_for_update_with_config(&state.http_client_private, &data_dir, &cfg).await {
        Ok(found) => {
            state.updater.record_check_success(found);
            drop(busy_guard);
            Ok(Json(state.updater.status_snapshot()))
        }
        Err(err) => {
            state.updater.record_error(err.clone(), true);
            Err((
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": err })),
            ))
        }
    }
}

/// `POST /api/update/apply` — download, stream-verify (`BLAKE3 + SHA-512`), and replace the binary.
pub async fn apply_update(
    State(state): State<RouterState>,
) -> Result<Json<UpdateStatusResponse>, (StatusCode, Json<serde_json::Value>)> {
    let Some(busy_guard) = state.updater.try_acquire_busy() else {
        return Err((
            StatusCode::CONFLICT,
            Json(
                serde_json::json!({ "error": "an update check or installation is already in progress" }),
            ),
        ));
    };

    let cfg = state.updater.effective_config().map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": err })),
        )
    })?;
    let data_dir = state.app.config.load().data_dir.clone();

    let update = if let Some(u) = state.updater.cached_pending() {
        u
    } else {
        match check_for_update_with_config(&state.http_client_private, &data_dir, &cfg).await {
            Ok(Some(u)) => {
                state.updater.record_check_success(Some(u.clone()));
                u
            }
            Ok(None) => {
                state.updater.record_check_success(None);
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": "crabdns is already up to date" })),
                ));
            }
            Err(err) => {
                state.updater.record_error(err.clone(), true);
                return Err((
                    StatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({ "error": err })),
                ));
            }
        }
    };

    if let Err(err) = download_and_install_update(
        &state.http_client_private,
        &data_dir,
        &update,
        &cfg,
        |_, _| {},
    )
    .await
    {
        state.updater.record_error(err.clone(), false);
        return Err((
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({ "error": err })),
        ));
    }

    tracing::info!(
        version = %update.version,
        "crabdns binary updated via sigilup; restart required to apply"
    );
    state.updater.record_apply_success();
    drop(busy_guard);
    Ok(Json(state.updater.status_snapshot()))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use sigilup::core::{ArtifactHasher, SecretKeyBundle};
    use sigilup::manifest::{PlatformAsset, SignedManifest, UpdateManifest, current_platform_base};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    async fn spawn_test_server(routes: Vec<(&'static str, Vec<u8>)>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let routes = Arc::new(routes);

        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let routes = Arc::clone(&routes);
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let n = socket.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let path = req
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or("/");
                    let body = routes
                        .iter()
                        .find(|(p, _)| *p == path)
                        .map(|(_, b)| b.as_slice());
                    let resp = match body {
                        Some(bytes) => {
                            let hdr = format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                bytes.len()
                            );
                            [hdr.as_bytes(), bytes].concat()
                        }
                        None => b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
                    };
                    let _ = socket.write_all(&resp).await;
                });
            }
        });

        format!("http://{addr}")
    }

    fn sign_test_manifest(
        sk: &SecretKeyBundle,
        version: &str,
        epoch: u64,
        asset_url: &str,
        fallback_urls: Vec<String>,
        artifact_bytes: &[u8],
    ) -> Vec<u8> {
        let key = format!("{}-portable", current_platform_base());
        let mut assets = BTreeMap::new();
        assets.insert(
            key,
            PlatformAsset {
                kind: "portable".to_string(),
                url: asset_url.to_string(),
                fallback_urls,
                digest: ArtifactHasher::hash_bytes(artifact_bytes),
                metadata: None::<serde_json::Value>,
            },
        );
        let manifest = UpdateManifest {
            schema_version: 2,
            version: semver::Version::parse(version).expect("semver"),
            security_epoch: epoch,
            min_supported_version: None,
            published_at: 1_760_000_000,
            expires_at: None,
            notes: "CrabDNS post-quantum signed update".to_string(),
            assets,
            key_rotations: Vec::new(),
        };
        let signed = SignedManifest::sign(&manifest, sk, 1_760_000_000).expect("sign");
        serde_json::to_vec(&signed).expect("json")
    }

    #[test]
    fn embedded_pins_and_url_validation_work() {
        let cfg = UpdateConfig::default_production().expect("default production config");
        assert_eq!(cfg.pins.version, 2);
        assert_eq!(cfg.pins.trusted_keys.len(), 1);

        assert!(
            validate_asset_url(
                "https://github.com/zkz098/crabdns/releases/download/v0.2.0/crabdns-linux-x86_64.tar.gz",
                "0.2.0"
            )
            .is_ok()
        );
        assert!(
            validate_asset_url(
                "https://gh-proxy.com/https://github.com/zkz098/crabdns/releases/download/v0.2.0/crabdns-linux-x86_64.tar.gz",
                "0.2.0"
            )
            .is_ok()
        );
        assert!(
            validate_asset_url("https://evil.example/crabdns-linux-x86_64.tar.gz", "0.2.0")
                .is_err()
        );
        assert!(
            validate_asset_url(
                "https://github.com/zkz098/crabdns/releases/download/v0.1.9/crabdns-linux-x86_64.tar.gz",
                "0.2.0"
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn end_to_end_check_download_verify_and_install() {
        let sk = SecretKeyBundle::generate().expect("keygen");
        let pins = KeyPinFile::new(vec![sk.public_key().clone()]);
        let new_binary = b"#!/bin/sh\necho crabdns-v9.9.9\n".to_vec();

        let asset_server = spawn_test_server(vec![("/crabdns-bin", new_binary.clone())]).await;
        let manifest_bytes = sign_test_manifest(
            &sk,
            "9.9.9",
            3,
            &format!("{asset_server}/crabdns-bin"),
            Vec::new(),
            &new_binary,
        );
        let manifest_server = spawn_test_server(vec![("/latest.hsig.json", manifest_bytes)]).await;

        let dir = tempfile::tempdir().expect("tempdir");
        let target_exe = dir.path().join("bin").join(EXPECTED_EXE_NAME);

        let mut url_policy = UrlPolicy::with_prefixes([format!("{asset_server}/")]);
        url_policy.require_https = false;
        let cfg = UpdateConfig {
            manifest_urls: vec![format!("{manifest_server}/latest.hsig.json")],
            pins,
            url_policy,
            enforce_version_url_prefix: false,
            verify_timestamp_unix: Some(1_760_000_000),
            install_target: InstallTarget::CustomPath(target_exe.clone()),
        };

        let client = reqwest::Client::new();
        let update = check_for_update_with_config(&client, dir.path(), &cfg)
            .await
            .expect("check update")
            .expect("update available");
        assert_eq!(update.version, "9.9.9");
        assert_eq!(update.notes, "CrabDNS post-quantum signed update");

        download_and_install_update(&client, dir.path(), &update, &cfg, |_, _| {})
            .await
            .expect("download and install");
        assert_eq!(fs::read(&target_exe).expect("read installed"), new_binary);

        // Anti-rollback check: epoch 2 must now be rejected because epoch 3 was committed
        let rollback_manifest = sign_test_manifest(
            &sk,
            "9.9.10",
            2,
            &format!("{asset_server}/crabdns-bin"),
            Vec::new(),
            &new_binary,
        );
        let rollback_server =
            spawn_test_server(vec![("/latest.hsig.json", rollback_manifest)]).await;
        let mut rollback_cfg = cfg;
        rollback_cfg.manifest_urls = vec![format!("{rollback_server}/latest.hsig.json")];
        let err = check_for_update_with_config(&client, dir.path(), &rollback_cfg)
            .await
            .expect_err("rollback epoch must fail");
        assert!(
            err.to_lowercase().contains("epoch") || err.to_lowercase().contains("rollback"),
            "unexpected error: {err}"
        );
    }
}
