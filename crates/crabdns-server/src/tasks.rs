use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use crabdns_core::{Config, DnsPipeline, NeighborTable};
use crabdns_storage::StorageEngine;
use crabdns_web::acme_api::{AcmeHttpChallengeStore, AcmeManager, serve_http01_from_store};
use crabdns_web::tls_api::TlsReloader;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::tls::TlsManager;

const BYTES_PER_MIB: u64 = 1024 * 1024;

fn current_unix_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}

pub fn current_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

pub fn prune_logs_once(storage: &StorageEngine, retention_hours: u64) -> anyhow::Result<usize> {
    let retention_ms = retention_hours.max(1).saturating_mul(3_600_000);
    let cutoff_ms = current_unix_ms().saturating_sub(retention_ms);
    Ok(storage.prune_older_than(cutoff_ms)?)
}

fn delay_interval(period: Duration) -> tokio::time::Interval {
    let mut interval = tokio::time::interval(period);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    interval
}

pub fn spawn_log_prune_task(
    config: Arc<ArcSwap<Config>>,
    storage: Arc<StorageEngine>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = delay_interval(Duration::from_secs(600));
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
                _ = interval.tick() => {
                    let cfg_now = config.load();
                    let retention_hours = cfg_now.log_retention_hours;
                    let max_disk_bytes = cfg_now.log_max_disk_mb.max(1).saturating_mul(BYTES_PER_MIB);
                    let st = Arc::clone(&storage);
                    match tokio::task::spawn_blocking(move || {
                        let expired = prune_logs_once(&st, retention_hours)?;
                        let oversized = st.prune_oversized_logs(max_disk_bytes)?;
                        Ok::<usize, anyhow::Error>(expired + oversized)
                    })
                    .await
                    {
                        Ok(Ok(removed)) if removed > 0 => {
                            tracing::info!(removed, retention_hours, "pruned expired/oversized query logs");
                        }
                        Ok(Ok(_)) => {}
                        Ok(Err(err)) => {
                            tracing::warn!(error = %err, "scheduled query log pruning failed");
                        }
                        Err(err) => {
                            tracing::warn!(error = %err, "query log pruning task panicked");
                        }
                    }
                }
            }
        }
    })
}

pub fn spawn_subscription_refresh_task(
    config: Arc<ArcSwap<Config>>,
    storage: Arc<StorageEngine>,
    pipeline: Arc<DnsPipeline>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let client_public = crabdns_web::subscriptions::build_subscription_http_client(false);
        let client_private = crabdns_web::subscriptions::build_subscription_http_client(true);
        let mut interval = delay_interval(Duration::from_hours(24));
        interval.tick().await;
        // On startup, immediately fetch any configured split-DNS remote lists not yet cached.
        {
            let cfg_now = config.load_full();
            let missing_split = cfg_now.split_dns.iter().any(|r| {
                [
                    r.domains_url.as_deref(),
                    r.response_ip
                        .as_ref()
                        .and_then(|rip| rip.expected_ip_url.as_deref()),
                ]
                .into_iter()
                .flatten()
                .map(str::trim)
                .filter(|u| !u.is_empty())
                .any(|u| storage.load_split_dns_list(u).ok().flatten().is_none())
            });
            if missing_split {
                let client = if cfg_now.allow_private_subscriptions {
                    &client_private
                } else {
                    &client_public
                };
                if let Err(err) = crabdns_web::split_dns_sync::refresh_split_dns_subscriptions_job(
                    client,
                    &cfg_now,
                    &storage,
                    &pipeline,
                    cfg_now.allow_private_subscriptions,
                )
                .await
                {
                    tracing::warn!(error = %err, "initial split-DNS subscription fetch failed");
                }
            }
        }
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
                _ = interval.tick() => {
                    let cfg_now = config.load_full();
                    let allow_private = cfg_now.allow_private_subscriptions;
                    let client = if allow_private {
                        &client_private
                    } else {
                        &client_public
                    };
                    if let Err(err) =
                        crabdns_web::subscriptions::refresh_enabled_subscriptions_job_with_policy(
                            client,
                            &storage,
                            &pipeline,
                            allow_private,
                        )
                        .await
                    {
                        tracing::warn!(error = %err, "scheduled subscription refresh failed");
                    }
                    if let Err(err) =
                        crabdns_web::split_dns_sync::refresh_split_dns_subscriptions_job(
                            client,
                            &cfg_now,
                            &storage,
                            &pipeline,
                            allow_private,
                        )
                        .await
                    {
                        tracing::warn!(error = %err, "scheduled split-DNS refresh failed");
                    }
                }
            }
        }
    })
}

pub fn spawn_hosts_watch_task(
    config: Arc<ArcSwap<Config>>,
    pipeline: Arc<DnsPipeline>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = delay_interval(Duration::from_secs(30));
        let mut last_mtime: Option<SystemTime> = None;
        interval.tick().await;
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
                _ = interval.tick() => {
                    let cfg = config.load();
                    if !cfg.hosts_enabled {
                        last_mtime = None;
                        continue;
                    }
                    let path_str = cfg.hosts_path.as_deref().unwrap_or("/etc/hosts");
                    let path = std::path::Path::new(path_str);
                    let Ok(meta) = tokio::fs::metadata(path).await else {
                        continue;
                    };
                    let Ok(mtime) = meta.modified() else {
                        continue;
                    };
                    if last_mtime != Some(mtime) {
                        let pipe = Arc::clone(&pipeline);
                        let path_buf = path.to_path_buf();
                        match tokio::task::spawn_blocking(move || pipe.reload_hosts_from_path(&path_buf))
                            .await
                        {
                            Ok(Ok(_)) => {
                                last_mtime = Some(mtime);
                            }
                            Ok(Err(err)) => {
                                tracing::warn!(path = %path_str, error = %err, "failed to reload hosts file");
                            }
                            Err(err) => {
                                tracing::warn!(path = %path_str, error = %err, "hosts reload task panicked");
                            }
                        }
                    }
                }
            }
        }
    })
}

pub fn spawn_dhcp_lease_refresh_task(
    config: Arc<ArcSwap<Config>>,
    pipeline: Arc<DnsPipeline>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = delay_interval(Duration::from_secs(30));
        let mut last_mtime: Option<SystemTime> = None;
        interval.tick().await;
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
                _ = interval.tick() => {
                    let cfg = config.load();
                    if !cfg.dhcp_leases_enabled {
                        last_mtime = None;
                        continue;
                    }
                    let path_str =
                        crabdns_core::resolve_dhcp_leases_path(cfg.dhcp_leases_path.as_deref());
                    let path = std::path::Path::new(path_str);
                    let Ok(meta) = tokio::fs::metadata(path).await else {
                        continue;
                    };
                    let Ok(mtime) = meta.modified() else {
                        continue;
                    };
                    if last_mtime != Some(mtime) {
                        let pipe = Arc::clone(&pipeline);
                        let path_buf = path.to_path_buf();
                        match tokio::task::spawn_blocking(move || {
                            pipe.reload_dhcp_leases_from_path(&path_buf)
                        })
                        .await
                        {
                            Ok(Ok(_)) => {
                                last_mtime = Some(mtime);
                            }
                            Ok(Err(err)) => {
                                tracing::warn!(path = %path_str, error = %err, "failed to reload DHCP leases file");
                            }
                            Err(err) => {
                                tracing::warn!(path = %path_str, error = %err, "DHCP leases reload task panicked");
                            }
                        }
                    }
                }
            }
        }
    })
}

pub fn spawn_neighbor_watch_task(
    pipeline: Arc<DnsPipeline>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = delay_interval(Duration::from_secs(30));
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
                _ = interval.tick() => {
                    let pipe = Arc::clone(&pipeline);
                    let _ = tokio::task::spawn_blocking(move || {
                        pipe.reload_neighbor_table(NeighborTable::load_system());
                    })
                    .await;
                }
            }
        }
    })
}

pub fn spawn_mdns_listener_task(
    config: Arc<ArcSwap<Config>>,
    pipeline: Arc<DnsPipeline>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut socket: Option<tokio::net::UdpSocket> = None;
        let notify = pipeline.mdns_notify();
        let mut buf = [0_u8; 4096];

        loop {
            if !config.load().mdns_enabled {
                socket = None;
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                    () = notify.notified() => {}
                }
                continue;
            }

            if socket.is_none() {
                match bind_mdns_multicast_socket() {
                    Ok(sock) => socket = Some(sock),
                    Err(err) => {
                        tracing::debug!(error = %err, "passive mDNS multicast listener unavailable; using on-demand PTR queries");
                        tokio::select! {
                            _ = shutdown_rx.changed() => {
                                if *shutdown_rx.borrow() {
                                    break;
                                }
                            }
                            () = tokio::time::sleep(Duration::from_secs(30)) => {}
                        }
                        continue;
                    }
                }
            }

            if let Some(ref sock) = socket {
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                    () = notify.notified() => {}
                    recv_res = sock.recv_from(&mut buf) => {
                        match recv_res {
                            Ok((len, _)) => {
                                pipeline.mdns_resolver().ingest_mdns_packet(&buf[..len]);
                            }
                            Err(err) => {
                                tracing::debug!(error = %err, "mDNS multicast recv error");
                                socket = None;
                            }
                        }
                    }
                }
            }
        }
    })
}

fn bind_mdns_multicast_socket() -> std::io::Result<tokio::net::UdpSocket> {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    let domain = socket2::Domain::IPV4;
    let sock = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    #[cfg(unix)]
    sock.set_reuse_port(true)?;
    sock.set_nonblocking(true)?;
    let bind_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 5353));
    sock.bind(&bind_addr.into())?;
    sock.join_multicast_v4(&Ipv4Addr::new(224, 0, 0, 251), &Ipv4Addr::UNSPECIFIED)?;
    let std_sock: std::net::UdpSocket = sock.into();
    tokio::net::UdpSocket::from_std(std_sock)
}

pub fn spawn_cache_persist_task(
    config: Arc<ArcSwap<Config>>,
    pipeline: Arc<DnsPipeline>,
    storage: Arc<StorageEngine>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = delay_interval(Duration::from_secs(300));
        interval.tick().await;
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
                _ = interval.tick() => {
                    if !config.load().cache_persist_enabled {
                        continue;
                    }
                    let now_secs = current_unix_secs();
                    let cache = pipeline.cache();
                    let st = Arc::clone(&storage);
                    match tokio::task::spawn_blocking(move || {
                        let snapshot = cache.export_persisted(now_secs);
                        st.save_dns_cache(&snapshot)
                    })
                    .await
                    {
                        Ok(Ok(_)) => {}
                        Ok(Err(err)) => {
                            tracing::warn!(error = %err, "periodic dns cache persistence failed");
                        }
                        Err(err) => {
                            tracing::warn!(error = %err, "periodic dns cache persistence task panicked");
                        }
                    }
                }
            }
        }
    })
}

async fn file_stamp(path: Option<&PathBuf>) -> Option<(Option<SystemTime>, u64)> {
    let p = path?;
    let meta = tokio::fs::metadata(p).await.ok()?;
    Some((meta.modified().ok(), meta.len()))
}

pub fn spawn_tls_watch_task(
    tls_manager: Arc<TlsManager>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = delay_interval(Duration::from_secs(30));
        let (init_cert, init_key) = tls_manager.paths();
        let mut last_stamps = (
            file_stamp(init_cert.as_ref()).await,
            file_stamp(init_key.as_ref()).await,
        );
        interval.tick().await;
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
                _ = interval.tick() => {
                    let (cert_path, key_path) = tls_manager.paths();
                    if cert_path.is_none() || key_path.is_none() {
                        continue;
                    }
                    let next_stamps = (
                        file_stamp(cert_path.as_ref()).await,
                        file_stamp(key_path.as_ref()).await,
                    );
                    if next_stamps.0.is_some() && next_stamps.1.is_some() && next_stamps != last_stamps {
                        let mgr = Arc::clone(&tls_manager);
                        match tokio::task::spawn_blocking(move || mgr.reload(None, None)).await {
                            Ok(Ok(_)) => {
                                last_stamps = next_stamps;
                            }
                            Ok(Err(err)) => {
                                tracing::warn!(error = %err, "automatic TLS certificate reload failed");
                            }
                            Err(err) => {
                                tracing::warn!(error = %err, "automatic TLS reload task panicked");
                            }
                        }
                    }
                }
            }
        }
    })
}

#[cfg(unix)]
pub fn spawn_sighup_task(
    config: Arc<ArcSwap<Config>>,
    pipeline: Arc<DnsPipeline>,
    tls_manager: Arc<TlsManager>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Option<JoinHandle<()>> {
    use tokio::signal::unix::{SignalKind, signal};
    let Ok(mut sighup) = signal(SignalKind::hangup()) else {
        tracing::warn!("failed to register SIGHUP handler");
        return None;
    };
    Some(tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
                maybe_sig = sighup.recv() => {
                    if maybe_sig.is_none() {
                        break;
                    }
                    tracing::info!("received SIGHUP; reloading TLS certificates and hosts");
                    let (cert, key) = tls_manager.paths();
                    if cert.is_some() && key.is_some() {
                        let mgr = Arc::clone(&tls_manager);
                        match tokio::task::spawn_blocking(move || mgr.reload(None, None)).await {
                            Ok(Ok(_)) => {}
                            Ok(Err(err)) => {
                                tracing::warn!(error = %err, "SIGHUP TLS reload failed");
                            }
                            Err(err) => {
                                tracing::warn!(error = %err, "SIGHUP TLS reload task panicked");
                            }
                        }
                    }
                    let cfg = config.load();
                    if cfg.hosts_enabled {
                        let path_str = cfg.hosts_path.as_deref().unwrap_or("/etc/hosts").to_string();
                        let log_path = path_str.clone();
                        let pipe = Arc::clone(&pipeline);
                        match tokio::task::spawn_blocking(move || {
                            pipe.reload_hosts_from_path(std::path::Path::new(&path_str))
                        })
                        .await
                        {
                            Ok(Ok(_)) => {}
                            Ok(Err(err)) => {
                                tracing::warn!(path = %log_path, error = %err, "SIGHUP hosts reload failed");
                            }
                            Err(err) => {
                                tracing::warn!(path = %log_path, error = %err, "SIGHUP hosts reload task panicked");
                            }
                        }
                    }
                }
            }
        }
    }))
}

#[cfg(not(unix))]
pub fn spawn_sighup_task(
    _config: Arc<ArcSwap<Config>>,
    _pipeline: Arc<DnsPipeline>,
    _tls_manager: Arc<TlsManager>,
    _shutdown_rx: watch::Receiver<bool>,
) -> Option<JoinHandle<()>> {
    None
}

pub fn spawn_acme_renew_task(
    config: Arc<ArcSwap<Config>>,
    pipeline: Arc<DnsPipeline>,
    tls_manager: Arc<TlsManager>,
    acme_manager: Arc<AcmeManager>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = delay_interval(Duration::from_hours(12));
        let reloader: Arc<dyn TlsReloader> = tls_manager;
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
                _ = interval.tick() => {
                    let cfg = config.load_full();
                    if acme_manager.needs_renewal(&cfg) {
                        tracing::info!(domains = ?cfg.acme_domains, "checking/renewing ACME certificate");
                        if let Err(err) = acme_manager
                            .issue_or_renew(&cfg, &pipeline, Some(&reloader), false)
                            .await
                        {
                            tracing::warn!(error = %err, "ACME certificate renewal failed");
                        }
                    }
                }
            }
        }
    })
}

pub async fn start_acme_http_listener(
    addr: Option<std::net::SocketAddr>,
    store: AcmeHttpChallengeStore,
    mut shutdown_rx: watch::Receiver<bool>,
) -> anyhow::Result<Option<JoinHandle<()>>> {
    let Some(bind_addr) = addr else {
        return Ok(None);
    };
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    let app = axum::Router::new().route(
        "/.well-known/acme-challenge/{token}",
        axum::routing::get(
            move |axum::extract::Path(token): axum::extract::Path<String>| {
                let st = store.clone();
                async move { serve_http01_from_store(&st, &token) }
            },
        ),
    );
    let task = tokio::spawn(async move {
        let shutdown = async move {
            if *shutdown_rx.borrow() {
                return;
            }
            while shutdown_rx.changed().await.is_ok() {
                if *shutdown_rx.borrow() {
                    break;
                }
            }
        };
        if let Err(err) = axum::serve(listener, app)
            .with_graceful_shutdown(shutdown)
            .await
        {
            tracing::error!(error = %err, "ACME HTTP-01 listener error");
        }
    });
    Ok(Some(task))
}

pub fn spawn_cf_cdn_speedtest_task(
    config: Arc<ArcSwap<Config>>,
    pipeline: Arc<DnsPipeline>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        // Short initial delay so listeners start up first.
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    return;
                }
            }
            () = tokio::time::sleep(Duration::from_secs(2)) => {}
        }

        let mut interval = delay_interval(Duration::from_secs(30));
        loop {
            let cf_cfg = config.load().cf_cdn.clone();
            if cf_cfg.enabled {
                let status = pipeline.cf_cdn_manager().status();
                let interval_ms = cf_cfg.interval_secs.max(60).saturating_mul(1000);
                let now_ms = current_unix_ms();
                let due = match status.last_run_unix_ms {
                    None => true,
                    Some(last) => now_ms.saturating_sub(last) >= interval_ms,
                };
                if due && !status.testing {
                    let result = pipeline.cf_cdn_manager().run_speedtest().await;
                    tracing::info!(
                        best_ipv4 = ?result.best_ipv4,
                        best_ipv6 = ?result.best_ipv6,
                        error = ?result.last_error,
                        "Cloudflare CDN speed test finished"
                    );
                }
            }

            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
                _ = interval.tick() => {}
            }
        }
    })
}
