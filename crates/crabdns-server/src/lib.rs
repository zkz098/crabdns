use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use axum::serve::ListenerExt;
use crabdns_core::{
    Config, DdrConfig, DnsCache, DnsPipeline, FilterEngine, QueryContext, QueryEvent,
    QueryProtocol, UpstreamPool, build_raw_formerr,
};
use crabdns_storage::{StorageEngine, spawn_log_sink};
use crabdns_web::tls_api::TlsReloader;
use crabdns_web::{AppState, build_router};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, broadcast, mpsc, watch};
use tokio::task::{JoinHandle, JoinSet};

mod dot;
mod tasks;
mod tls;

pub use tasks::prune_logs_once;

const UDP_MAX_INFLIGHT: usize = 2048;
const WEB_MAX_CONNECTIONS: usize = 512;
const MAX_TCP_PIPELINE_INFLIGHT: usize = 32;
const MAX_TCP_CONN_LIFETIME: Duration = Duration::from_secs(300);
const ACCEPT_ERR_BACKOFF: Duration = Duration::from_millis(50);
pub(crate) const GRACEFUL_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
const SHUTDOWN_JOIN_TIMEOUT: Duration = Duration::from_secs(3);

pub(crate) struct ActiveConnGuard {
    pipeline: Arc<DnsPipeline>,
    is_dot: bool,
}

impl ActiveConnGuard {
    pub(crate) fn new_tcp(pipeline: Arc<DnsPipeline>) -> Self {
        pipeline.inc_tcp_active();
        Self {
            pipeline,
            is_dot: false,
        }
    }

    pub(crate) fn new_dot(pipeline: Arc<DnsPipeline>) -> Self {
        pipeline.inc_dot_active();
        Self {
            pipeline,
            is_dot: true,
        }
    }
}

impl Drop for ActiveConnGuard {
    fn drop(&mut self) {
        if self.is_dot {
            self.pipeline.dec_dot_active();
        } else {
            self.pipeline.dec_tcp_active();
        }
    }
}

pub(crate) struct IpConnLimiter {
    global: Arc<Semaphore>,
    per_ip: Arc<Mutex<HashMap<IpAddr, usize>>>,
    max_per_ip: usize,
}

pub(crate) struct IpConnGuard {
    _global: OwnedSemaphorePermit,
    per_ip: Arc<Mutex<HashMap<IpAddr, usize>>>,
    ip: IpAddr,
}

impl Drop for IpConnGuard {
    fn drop(&mut self) {
        let mut guard = self
            .per_ip
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(count) = guard.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                guard.remove(&self.ip);
            }
        }
    }
}

impl IpConnLimiter {
    pub(crate) fn new(max_global: usize, max_per_ip: usize) -> Self {
        Self {
            global: Arc::new(Semaphore::new(max_global.max(1))),
            per_ip: Arc::new(Mutex::new(HashMap::new())),
            max_per_ip: max_per_ip.max(1),
        }
    }

    pub(crate) fn try_acquire(&self, ip: IpAddr) -> Option<IpConnGuard> {
        let global = Arc::clone(&self.global).try_acquire_owned().ok()?;
        let mut guard = self
            .per_ip
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let entry = guard.entry(ip).or_insert(0);
        if *entry >= self.max_per_ip {
            if *entry == 0 {
                guard.remove(&ip);
            }
            return None;
        }
        *entry += 1;
        Some(IpConnGuard {
            _global: global,
            per_ip: Arc::clone(&self.per_ip),
            ip,
        })
    }
}

pub struct RunningServer {
    pub dns_addr: SocketAddr,
    pub web_addr: SocketAddr,
    pub web_tls_addr: Option<SocketAddr>,
    pub dot_addr: Option<SocketAddr>,
    pub pipeline: Arc<DnsPipeline>,
    pub storage: Arc<StorageEngine>,
    config: Arc<ArcSwap<Config>>,
    shutdown_tx: watch::Sender<bool>,
    udp_tasks: Vec<JoinHandle<()>>,
    tcp_task: JoinHandle<()>,
    dot_task: Option<JoinHandle<()>>,
    web_task: JoinHandle<()>,
    web_tls_accept_task: Option<JoinHandle<()>>,
    web_tls_task: Option<JoinHandle<()>>,
    sub_refresh_task: JoinHandle<()>,
    hosts_watch_task: JoinHandle<()>,
    cache_persist_task: JoinHandle<()>,
    log_prune_task: JoinHandle<()>,
    tls_watch_task: Option<JoinHandle<()>>,
    sighup_task: Option<JoinHandle<()>>,
    sink_handle: JoinHandle<()>,
}

impl RunningServer {
    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);

        for task in self.udp_tasks {
            join_with_timeout(task, SHUTDOWN_JOIN_TIMEOUT).await;
        }
        join_with_timeout(self.tcp_task, SHUTDOWN_JOIN_TIMEOUT).await;
        join_opt_with_timeout(self.dot_task, SHUTDOWN_JOIN_TIMEOUT).await;
        join_with_timeout(self.web_task, SHUTDOWN_JOIN_TIMEOUT).await;
        join_opt_with_timeout(self.web_tls_accept_task, SHUTDOWN_JOIN_TIMEOUT).await;
        join_opt_with_timeout(self.web_tls_task, SHUTDOWN_JOIN_TIMEOUT).await;
        join_with_timeout(self.sub_refresh_task, GRACEFUL_DRAIN_TIMEOUT).await;
        join_with_timeout(self.hosts_watch_task, GRACEFUL_DRAIN_TIMEOUT).await;
        join_with_timeout(self.cache_persist_task, GRACEFUL_DRAIN_TIMEOUT).await;
        join_with_timeout(self.log_prune_task, GRACEFUL_DRAIN_TIMEOUT).await;
        join_opt_with_timeout(self.tls_watch_task, GRACEFUL_DRAIN_TIMEOUT).await;
        join_opt_with_timeout(self.sighup_task, GRACEFUL_DRAIN_TIMEOUT).await;

        if self.config.load().cache_persist_enabled {
            let now_secs = tasks::current_unix_secs();
            let cache = self.pipeline.cache();
            let storage = Arc::clone(&self.storage);
            match tokio::task::spawn_blocking(move || {
                let snapshot = cache.export_persisted(now_secs);
                storage.save_dns_cache(&snapshot)
            })
            .await
            {
                Ok(Ok(_)) => {}
                Ok(Err(err)) => {
                    tracing::warn!(error = %err, "failed to persist dns cache on shutdown");
                }
                Err(err) => {
                    tracing::warn!(error = %err, "dns cache shutdown persistence task panicked");
                }
            }
        }

        drop(self.pipeline);
        join_with_timeout(self.sink_handle, Duration::from_secs(5)).await;
        drop(self.storage);
    }
}

pub(crate) async fn drain_join_set(tasks: &mut JoinSet<()>, timeout: Duration) {
    let drain = async { while tasks.join_next().await.is_some() {} };
    if tokio::time::timeout(timeout, drain).await.is_err() {
        tasks.shutdown().await;
    }
}

async fn join_with_timeout(mut handle: JoinHandle<()>, timeout: Duration) {
    if tokio::time::timeout(timeout, &mut handle).await.is_err() {
        handle.abort();
        let _ = handle.await;
    }
}

async fn join_opt_with_timeout(handle: Option<JoinHandle<()>>, timeout: Duration) {
    if let Some(h) = handle {
        join_with_timeout(h, timeout).await;
    }
}

async fn shutdown_signal(mut shutdown_rx: watch::Receiver<bool>) {
    if *shutdown_rx.borrow() {
        return;
    }
    while shutdown_rx.changed().await.is_ok() {
        if *shutdown_rx.borrow() {
            break;
        }
    }
}

fn merge_saved_config(config: &mut Config, saved_cfg: Config) {
    config.upstreams = saved_cfg.upstreams;
    config.bootstrap_dns = saved_cfg.bootstrap_dns;
    config.upstream_strategy = saved_cfg.upstream_strategy;
    config.cache_size = saved_cfg.cache_size;
    config.optimistic_cache = saved_cfg.optimistic_cache;
    config.cache_min_ttl_secs = saved_cfg.cache_min_ttl_secs;
    config.cache_max_ttl_secs = saved_cfg.cache_max_ttl_secs;
    config.cache_prefetch_enabled = saved_cfg.cache_prefetch_enabled;
    config.cache_persist_enabled = saved_cfg.cache_persist_enabled;
    config.upstream_timeout_ms = saved_cfg.upstream_timeout_ms;
    config.log_retention_hours = saved_cfg.log_retention_hours;
    config.block_mode = saved_cfg.block_mode;
    config.allow_cidrs = saved_cfg.allow_cidrs;
    config.deny_cidrs = saved_cfg.deny_cidrs;
    config.rate_limit_qps = saved_cfg.rate_limit_qps;
    config.web_auth_enabled = saved_cfg.web_auth_enabled;
    config.web_username = saved_cfg.web_username;
    config.web_password_hash = saved_cfg.web_password_hash;
    config.split_dns = saved_cfg.split_dns;
    config.cname_cloaking_blocking = saved_cfg.cname_cloaking_blocking;
    config.doh_enabled = saved_cfg.doh_enabled;
    config.allow_private_subscriptions = saved_cfg.allow_private_subscriptions;
    config.ecs_enabled = saved_cfg.ecs_enabled;
    config.ecs_custom_ip = saved_cfg.ecs_custom_ip;
    config.ecs_ipv4_prefix = saved_cfg.ecs_ipv4_prefix;
    config.ecs_ipv6_prefix = saved_cfg.ecs_ipv6_prefix;
    config.dnssec_enabled = saved_cfg.dnssec_enabled;
    config.hosts_enabled = saved_cfg.hosts_enabled;
    config.hosts_path = saved_cfg.hosts_path;
    config.private_ptr_enabled = saved_cfg.private_ptr_enabled;
    config.private_ptr_upstreams = saved_cfg.private_ptr_upstreams;
    config.ddr_enabled = saved_cfg.ddr_enabled;
    config.ddr_hostname = saved_cfg.ddr_hostname;
    config.dns_rebinding_protection = saved_cfg.dns_rebinding_protection;
    config.block_any_queries = saved_cfg.block_any_queries;
    config.trusted_proxies = saved_cfg.trusted_proxies;
    config.rdns_enabled = saved_cfg.rdns_enabled;
    if saved_cfg.tls_cert_path.is_some() {
        config.tls_cert_path = saved_cfg.tls_cert_path;
    }
    if saved_cfg.tls_key_path.is_some() {
        config.tls_key_path = saved_cfg.tls_key_path;
    }
}

fn init_pipeline(
    cfg: &Config,
    storage: &StorageEngine,
    log_tx: mpsc::Sender<QueryEvent>,
) -> anyhow::Result<Arc<DnsPipeline>> {
    let filter = Arc::new(FilterEngine::new(&cfg.custom_rules));
    let custom_rules_text = storage
        .load_custom_rules()?
        .unwrap_or_else(|| cfg.custom_rules.join("\n"));
    let custom_enabled = storage.load_custom_rules_enabled()?;
    let sub_contents = storage.load_enabled_named_subscription_contents()?;
    filter.reload_from_named_sources(&custom_rules_text, custom_enabled, &sub_contents);

    let cache = Arc::new(DnsCache::with_options(
        cfg.cache_size,
        cfg.optimistic_cache,
        cfg.cache_min_ttl_secs,
        cfg.cache_max_ttl_secs,
        cfg.cache_prefetch_enabled,
    ));
    if cfg.cache_persist_enabled {
        let now_secs = tasks::current_unix_secs();
        match storage.load_dns_cache(now_secs, cache.stale_grace_secs()) {
            Ok(entries) => {
                let restored = cache.import_persisted(entries, now_secs);
                if restored > 0 {
                    tracing::info!(restored, "restored persisted dns cache entries");
                }
            }
            Err(err) => {
                tracing::warn!(error = %err, "failed to load persisted dns cache");
            }
        }
    }

    let upstream = Arc::new(UpstreamPool::new_with_bootstrap(
        &cfg.upstreams,
        cfg.upstream_timeout_ms,
        cfg.upstream_strategy,
        &cfg.bootstrap_dns,
    )?);

    let pipeline = Arc::new(DnsPipeline::new(filter, cache, upstream, Some(log_tx)));
    configure_pipeline(&pipeline, cfg, storage)?;
    Ok(pipeline)
}

fn configure_pipeline(
    pipeline: &DnsPipeline,
    cfg: &Config,
    storage: &StorageEngine,
) -> anyhow::Result<()> {
    pipeline.set_block_mode(cfg.block_mode);
    pipeline.set_cname_cloaking(cfg.cname_cloaking_blocking);
    pipeline.set_rdns_enabled(cfg.rdns_enabled);
    pipeline.reload_acl(&cfg.allow_cidrs, &cfg.deny_cidrs, cfg.rate_limit_qps)?;
    pipeline.reload_split_dns_with_bootstrap(
        &cfg.split_dns,
        cfg.upstream_timeout_ms,
        cfg.upstream_strategy,
        &cfg.bootstrap_dns,
    )?;
    pipeline.reload_ecs(
        cfg.ecs_enabled,
        cfg.ecs_custom_ip.as_deref(),
        cfg.ecs_ipv4_prefix,
        cfg.ecs_ipv6_prefix,
    )?;
    pipeline.set_dnssec_enabled(cfg.dnssec_enabled);
    pipeline.set_hosts_enabled(cfg.hosts_enabled);
    if cfg.hosts_enabled {
        let resolved_hosts = cfg.hosts_path.as_deref().unwrap_or("/etc/hosts");
        if let Err(err) = pipeline.reload_hosts_from_path(std::path::Path::new(resolved_hosts)) {
            tracing::warn!(path = %resolved_hosts, error = %err, "failed to load hosts file");
        }
    }
    pipeline.reload_private_ptr(
        cfg.private_ptr_enabled,
        &cfg.private_ptr_upstreams,
        cfg.upstream_timeout_ms,
        cfg.upstream_strategy,
        &cfg.bootstrap_dns,
    )?;
    pipeline.set_dns_rebinding_protection(cfg.dns_rebinding_protection);
    pipeline.set_block_any_queries(cfg.block_any_queries);

    let clients = storage.list_clients()?;
    let groups = storage.list_client_groups()?;
    pipeline.reload_clients(
        &clients,
        &groups,
        cfg.upstream_timeout_ms,
        cfg.upstream_strategy,
        &cfg.bootstrap_dns,
    )?;
    Ok(())
}

struct WebAndTlsHandles {
    dot_addr: Option<SocketAddr>,
    dot_task: Option<JoinHandle<()>>,
    web_addr: SocketAddr,
    web_task: JoinHandle<()>,
    web_tls_addr: Option<SocketAddr>,
    web_tls_accept_task: Option<JoinHandle<()>>,
    web_tls_task: Option<JoinHandle<()>>,
}

#[allow(clippy::too_many_arguments)]
async fn start_web_and_tls(
    config: &Arc<ArcSwap<Config>>,
    pipeline: &Arc<DnsPipeline>,
    storage: &Arc<StorageEngine>,
    tls_manager: &Arc<tls::TlsManager>,
    live_tx: broadcast::Sender<QueryEvent>,
    tcp_max_connections: usize,
    tcp_idle_timeout: Duration,
    shutdown_rx: &watch::Receiver<bool>,
) -> anyhow::Result<WebAndTlsHandles> {
    let current_cfg = config.load_full();

    let (dot_addr, dot_task) = match (current_cfg.listen_dot, tls_manager.dot_acceptor()) {
        (Some(addr), Some(acceptor)) => {
            let dot_listener = dot::bind_dot_listener(addr).await?;
            let bound_dot = dot_listener.local_addr()?;
            let task = tokio::spawn(dot::run_dot_server(
                dot_listener,
                acceptor,
                Arc::clone(config),
                Arc::clone(pipeline),
                tcp_max_connections,
                tcp_idle_timeout,
                shutdown_rx.clone(),
            ));
            (Some(bound_dot), Some(task))
        }
        _ => (None, None),
    };

    let web_listener = TcpListener::bind(current_cfg.listen_web).await?;
    let web_addr = web_listener.local_addr()?;

    let web_tls_listener = match current_cfg.listen_web_tls {
        Some(addr) => Some(TcpListener::bind(addr).await?),
        None => None,
    };
    let bound_web_tls = web_tls_listener.as_ref().and_then(|l| l.local_addr().ok());
    tls_manager.update_bound_addrs(bound_web_tls, dot_addr);

    pipeline.reload_ddr(DdrConfig {
        enabled: current_cfg.ddr_enabled,
        hostname: current_cfg.ddr_hostname.clone(),
        dot_port: dot_addr.map(|a| a.port()),
        doh_enabled: current_cfg.doh_enabled,
        doh_port: bound_web_tls.map(|a| a.port()).or(Some(web_addr.port())),
    });

    let tls_reloader: Option<Arc<dyn TlsReloader>> = Some(Arc::clone(tls_manager) as _);
    let app = build_router(AppState {
        config: Arc::clone(config),
        pipeline: Arc::clone(pipeline),
        storage: Arc::clone(storage),
        live_tx,
        tls_reloader,
    });

    let web_max_connections = tcp_max_connections.max(WEB_MAX_CONNECTIONS);
    let (web_tls_addr, web_tls_accept_task, web_tls_task) =
        match (web_tls_listener, tls_manager.https_acceptor()) {
            (Some(listener), Some(acceptor)) => {
                let (https_listener, addr, accept_task) = tls::HttpsTlsListener::from_tcp_listener(
                    listener,
                    acceptor,
                    shutdown_rx.clone(),
                )?;
                let tls_app = app.clone();
                let tls_shutdown = shutdown_rx.clone();
                let limited_https = tls::PermittedListener::new(
                    https_listener,
                    web_max_connections,
                    Arc::clone(pipeline),
                );
                let serve_task = tokio::spawn(async move {
                    if let Err(err) = axum::serve(
                        limited_https.tap_io(|_| {}),
                        tls_app.into_make_service_with_connect_info::<SocketAddr>(),
                    )
                    .with_graceful_shutdown(shutdown_signal(tls_shutdown))
                    .await
                    {
                        tracing::error!(error = %err, "HTTPS web server error");
                    }
                });
                (Some(addr), Some(accept_task), Some(serve_task))
            }
            _ => (None, None, None),
        };

    let web_shutdown = shutdown_rx.clone();
    let limited_web =
        tls::PermittedListener::new(web_listener, web_max_connections, Arc::clone(pipeline));
    let web_task = tokio::spawn(async move {
        if let Err(err) = axum::serve(
            limited_web.tap_io(|_| {}),
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown_signal(web_shutdown))
        .await
        {
            tracing::error!(error = %err, "web server error");
        }
    });

    Ok(WebAndTlsHandles {
        dot_addr,
        dot_task,
        web_addr,
        web_task,
        web_tls_addr,
        web_tls_accept_task,
        web_tls_task,
    })
}

struct BackgroundTasks {
    sub_refresh: JoinHandle<()>,
    hosts_watch: JoinHandle<()>,
    cache_persist: JoinHandle<()>,
    log_prune: JoinHandle<()>,
    tls_watch: Option<JoinHandle<()>>,
    sighup: Option<JoinHandle<()>>,
}

fn spawn_background_tasks(
    config: Arc<ArcSwap<Config>>,
    pipeline: Arc<DnsPipeline>,
    storage: Arc<StorageEngine>,
    tls_manager: &Arc<tls::TlsManager>,
    tls_active: bool,
    shutdown_rx: &watch::Receiver<bool>,
) -> BackgroundTasks {
    BackgroundTasks {
        tls_watch: tls_active
            .then(|| tasks::spawn_tls_watch_task(Arc::clone(tls_manager), shutdown_rx.clone())),
        sighup: tasks::spawn_sighup_task(
            Arc::clone(&config),
            Arc::clone(&pipeline),
            Arc::clone(tls_manager),
            shutdown_rx.clone(),
        ),
        sub_refresh: tasks::spawn_subscription_refresh_task(
            Arc::clone(&config),
            Arc::clone(&storage),
            Arc::clone(&pipeline),
            shutdown_rx.clone(),
        ),
        hosts_watch: tasks::spawn_hosts_watch_task(
            Arc::clone(&config),
            Arc::clone(&pipeline),
            shutdown_rx.clone(),
        ),
        cache_persist: tasks::spawn_cache_persist_task(
            Arc::clone(&config),
            pipeline,
            Arc::clone(&storage),
            shutdown_rx.clone(),
        ),
        log_prune: tasks::spawn_log_prune_task(config, storage, shutdown_rx.clone()),
    }
}

pub async fn spawn_server(mut config: Config) -> anyhow::Result<RunningServer> {
    let storage = Arc::new(StorageEngine::open(&config.data_dir)?);

    if let Some(saved_cfg) = storage.load_config()? {
        merge_saved_config(&mut config, saved_cfg);
    }

    let config = Arc::new(ArcSwap::from_pointee(config));
    let current_cfg = config.load_full();

    let (log_tx, log_rx) = mpsc::channel::<QueryEvent>(4096);
    let (live_tx, _) = broadcast::channel::<QueryEvent>(512);
    let sink_handle = spawn_log_sink(Arc::clone(&storage), log_rx, live_tx.clone());
    let pipeline = init_pipeline(&current_cfg, &storage, log_tx)?;

    let tls_manager = Arc::new(tls::TlsManager::new(
        current_cfg.listen_web_tls,
        current_cfg.listen_dot,
        current_cfg.tls_cert_path.as_deref(),
        current_cfg.tls_key_path.as_deref(),
    )?);

    let tcp_listener = TcpListener::bind(current_cfg.listen_dns).await?;
    let dns_addr = tcp_listener.local_addr()?;
    let udp_worker_count = std::thread::available_parallelism()
        .map_or(2, std::num::NonZeroUsize::get)
        .clamp(2, 16);
    let udp_sockets = bind_udp_sockets(dns_addr, udp_worker_count)?;

    let tcp_max_connections = current_cfg.tcp_max_connections.max(1);
    let tcp_idle_timeout = Duration::from_secs(current_cfg.tcp_idle_timeout_secs.max(1));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let web_tls = start_web_and_tls(
        &config,
        &pipeline,
        &storage,
        &tls_manager,
        live_tx,
        tcp_max_connections,
        tcp_idle_timeout,
        &shutdown_rx,
    )
    .await?;

    tracing::info!(
        dns = %dns_addr,
        dot = ?web_tls.dot_addr,
        web = %web_tls.web_addr,
        web_tls = ?web_tls.web_tls_addr,
        "crabdns started"
    );

    let udp_limiter = Arc::new(Semaphore::new(UDP_MAX_INFLIGHT));
    let udp_tasks = udp_sockets
        .into_iter()
        .map(|sock| {
            let udp_pipeline = Arc::clone(&pipeline);
            let limiter = Arc::clone(&udp_limiter);
            let rx = shutdown_rx.clone();
            tokio::spawn(run_udp_server(sock, udp_pipeline, limiter, rx))
        })
        .collect();

    let tcp_task = tokio::spawn(run_tcp_server(
        tcp_listener,
        Arc::clone(&pipeline),
        tcp_max_connections,
        tcp_idle_timeout,
        shutdown_rx.clone(),
    ));

    let tls_active = web_tls.dot_addr.is_some() || web_tls.web_tls_addr.is_some();
    let bg = spawn_background_tasks(
        Arc::clone(&config),
        Arc::clone(&pipeline),
        Arc::clone(&storage),
        &tls_manager,
        tls_active,
        &shutdown_rx,
    );

    Ok(RunningServer {
        dns_addr,
        web_addr: web_tls.web_addr,
        web_tls_addr: web_tls.web_tls_addr,
        dot_addr: web_tls.dot_addr,
        pipeline,
        storage,
        config,
        shutdown_tx,
        udp_tasks,
        tcp_task,
        dot_task: web_tls.dot_task,
        web_task: web_tls.web_task,
        web_tls_accept_task: web_tls.web_tls_accept_task,
        web_tls_task: web_tls.web_tls_task,
        sub_refresh_task: bg.sub_refresh,
        hosts_watch_task: bg.hosts_watch,
        cache_persist_task: bg.cache_persist,
        log_prune_task: bg.log_prune,
        tls_watch_task: bg.tls_watch,
        sighup_task: bg.sighup,
        sink_handle,
    })
}

fn bind_udp_sockets(addr: SocketAddr, count: usize) -> anyhow::Result<Vec<Arc<UdpSocket>>> {
    #[cfg(unix)]
    {
        let mut sockets = Vec::with_capacity(count);
        for _ in 0..count {
            let domain = socket2::Domain::for_address(addr);
            let sock =
                socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
            sock.set_reuse_address(true)?;
            sock.set_reuse_port(true)?;
            sock.set_nonblocking(true)?;
            sock.bind(&addr.into())?;
            let std_sock: std::net::UdpSocket = sock.into();
            sockets.push(Arc::new(UdpSocket::from_std(std_sock)?));
        }
        Ok(sockets)
    }
    #[cfg(not(unix))]
    {
        let _ = count;
        let sock = std::net::UdpSocket::bind(addr)?;
        sock.set_nonblocking(true)?;
        Ok(vec![Arc::new(UdpSocket::from_std(sock)?)])
    }
}

async fn run_udp_server(
    socket: Arc<UdpSocket>,
    pipeline: Arc<DnsPipeline>,
    limiter: Arc<Semaphore>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let mut buf = vec![0_u8; 4096];
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    break;
                }
            }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            recv_res = socket.recv_from(&mut buf) => {
                let (len, peer) = match recv_res {
                    Ok(pair) => pair,
                    Err(err) => {
                        tracing::warn!(error = %err, "UDP DNS recv error; backing off");
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        continue;
                    }
                };
                let Ok(permit) = Arc::clone(&limiter).try_acquire_owned() else {
                    pipeline.record_udp_dropped();
                    tracing::warn!(peer = %peer, "UDP DNS query dropped: max inflight reached");
                    continue;
                };
                let packet = buf[..len].to_vec();
                let sock = Arc::clone(&socket);
                let pipe = Arc::clone(&pipeline);
                tasks.spawn(async move {
                    let _permit = permit;
                    match pipe.handle_packet(&packet, peer).await {
                        Ok(resp) => {
                            let _ = sock.send_to(&resp, peer).await;
                        }
                        Err(err) => {
                            tracing::debug!(peer = %peer, error = %err, "failed to handle UDP DNS query");
                        }
                    }
                });
            }
        }
    }
    drain_join_set(&mut tasks, GRACEFUL_DRAIN_TIMEOUT).await;
}

async fn run_tcp_server(
    listener: TcpListener,
    pipeline: Arc<DnsPipeline>,
    max_connections: usize,
    idle_timeout: Duration,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let per_ip_limit = (max_connections / 2).max(8);
    let limiter = IpConnLimiter::new(max_connections.max(1), per_ip_limit);
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    break;
                }
            }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            accept_res = listener.accept() => {
                let (stream, peer) = match accept_res {
                    Ok(pair) => pair,
                    Err(err) => {
                        tracing::warn!(error = %err, "TCP DNS accept error; backing off");
                        tokio::time::sleep(ACCEPT_ERR_BACKOFF).await;
                        continue;
                    }
                };
                let _ = stream.set_nodelay(true);
                let Some(guard) = limiter.try_acquire(peer.ip()) else {
                    pipeline.record_tcp_rejected();
                    tracing::warn!(peer = %peer, "TCP DNS connection rejected: connection limit reached");
                    drop(stream);
                    continue;
                };
                let pipe = Arc::clone(&pipeline);
                let conn_shutdown = shutdown_rx.clone();
                tasks.spawn(async move {
                    let _guard = guard;
                    let _active = ActiveConnGuard::new_tcp(Arc::clone(&pipe));
                    if let Err(err) = handle_dns_stream_with_context(
                        stream,
                        peer,
                        pipe,
                        idle_timeout,
                        QueryProtocol::Tcp,
                        None,
                        conn_shutdown,
                    )
                    .await
                    {
                        tracing::debug!(peer = %peer, error = %err, "TCP DNS connection closed");
                    }
                });
            }
        }
    }
    drain_join_set(&mut tasks, GRACEFUL_DRAIN_TIMEOUT).await;
}

pub(crate) async fn handle_dns_stream_with_context<S>(
    stream: S,
    peer: SocketAddr,
    pipeline: Arc<DnsPipeline>,
    idle_timeout: Duration,
    protocol: QueryProtocol,
    client_id: Option<String>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (resp_tx, mut resp_rx) = mpsc::channel::<Vec<u8>>(MAX_TCP_PIPELINE_INFLIGHT);
    let (write_err_tx, mut write_err_rx) = watch::channel(false);

    let reader_fut = async {
        let mut len_buf = [0_u8; 2];
        let mut inflight = JoinSet::new();
        let inflight_sem = Arc::new(Semaphore::new(MAX_TCP_PIPELINE_INFLIGHT));
        let conn_deadline = tokio::time::Instant::now() + MAX_TCP_CONN_LIFETIME;

        loop {
            let read_res = tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                    continue;
                }
                _ = write_err_rx.changed() => {
                    if *write_err_rx.borrow() {
                        break;
                    }
                    continue;
                }
                () = tokio::time::sleep_until(conn_deadline) => break,
                Some(_) = inflight.join_next(), if !inflight.is_empty() => continue,
                res = tokio::time::timeout(idle_timeout, reader.read_exact(&mut len_buf)) => res,
            };
            let Ok(Ok(_)) = read_res else {
                break;
            };
            let len = usize::from(u16::from_be_bytes(len_buf));
            if len == 0 || len > 65_535 {
                break;
            }
            let mut query = vec![0_u8; len];
            if !matches!(
                tokio::time::timeout(idle_timeout, reader.read_exact(&mut query)).await,
                Ok(Ok(_))
            ) {
                break;
            }

            let permit_res = tokio::select! {
                _ = shutdown_rx.changed() => break,
                _ = write_err_rx.changed() => break,
                res = tokio::time::timeout(idle_timeout, Arc::clone(&inflight_sem).acquire_owned()) => res,
            };
            let Ok(Ok(permit)) = permit_res else {
                break;
            };

            let pipe = Arc::clone(&pipeline);
            let tx = resp_tx.clone();
            let cid = client_id.clone();
            inflight.spawn(async move {
                let _permit = permit;
                let ctx = QueryContext {
                    client_addr: peer,
                    protocol,
                    client_id: cid,
                };
                let resp_opt = match pipe.handle_packet_with_context(&query, ctx).await {
                    Ok(resp) => Some(resp),
                    Err(_) => build_raw_formerr(&query),
                };
                if let Some(resp) = resp_opt {
                    let _ = tx.send(resp).await;
                }
            });
        }
        drop(resp_tx);
        drain_join_set(&mut inflight, GRACEFUL_DRAIN_TIMEOUT).await;
    };

    let writer_fut = async {
        let mut write_buf = Vec::with_capacity(514);
        while let Some(resp) = resp_rx.recv().await {
            let Ok(resp_len) = u16::try_from(resp.len()) else {
                continue;
            };
            write_buf.clear();
            write_buf.extend_from_slice(&resp_len.to_be_bytes());
            write_buf.extend_from_slice(&resp);
            let write_res = tokio::time::timeout(idle_timeout, async {
                writer.write_all(&write_buf).await?;
                writer.flush().await
            })
            .await;
            if !matches!(write_res, Ok(Ok(()))) {
                let _ = write_err_tx.send(true);
                break;
            }
        }
    };

    tokio::join!(reader_fut, writer_fut);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_ip_conn_limiter_enforces_per_ip_and_releases() {
        let limiter = IpConnLimiter::new(8, 2);
        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11));

        let g1 = limiter.try_acquire(ip1).expect("1st ip1");
        let g2 = limiter.try_acquire(ip1).expect("2nd ip1");
        assert!(limiter.try_acquire(ip1).is_none(), "3rd ip1 must fail");
        assert!(
            limiter.try_acquire(ip2).is_some(),
            "other IP must still be allowed"
        );

        drop(g1);
        assert!(
            limiter.try_acquire(ip1).is_some(),
            "released slot must be reusable"
        );
        drop(g2);
    }

    #[tokio::test]
    async fn test_tcp_pipelining_out_of_order_and_formerr_keeps_conn_alive() {
        use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
        use hickory_proto::rr::rdata::A;
        use hickory_proto::rr::{Name, RData, Record, RecordType};

        let upstream_sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind mock");
        let upstream_addr = upstream_sock.local_addr().expect("addr");
        tokio::spawn(async move {
            let mut buf = [0_u8; 2048];
            while let Ok((len, peer)) = upstream_sock.recv_from(&mut buf).await {
                if let Ok(req) = Message::from_vec(&buf[..len]) {
                    let sock = &upstream_sock;
                    let mut resp = Message::new(req.id, MessageType::Response, OpCode::Query);
                    resp.metadata.recursion_available = true;
                    resp.metadata.response_code = ResponseCode::NoError;
                    resp.queries.clone_from(&req.queries);
                    if let Some(q) = req.queries.first() {
                        resp.add_answer(Record::from_rdata(
                            q.name().clone(),
                            60,
                            RData::A(A(Ipv4Addr::new(93, 184, 216, 34))),
                        ));
                    }
                    let wire = resp.to_vec().unwrap();
                    // Delay slow queries by 200ms so pipelined local queries overtake them.
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    let _ = sock.send_to(&wire, peer).await;
                }
            }
        });

        let dir = tempfile::tempdir().expect("tempdir");
        let server = spawn_server(Config {
            listen_dns: "127.0.0.1:0".parse().unwrap(),
            listen_web: "127.0.0.1:0".parse().unwrap(),
            data_dir: dir.path().to_path_buf(),
            upstreams: vec![format!("udp://{upstream_addr}")],
            custom_rules: vec!["||blocked.pipe.test^".to_string()],
            rdns_enabled: false,
            ..Config::default()
        })
        .await
        .expect("spawn server");

        let mut stream = tokio::net::TcpStream::connect(server.dns_addr)
            .await
            .expect("connect tcp");

        let build_q = |id: u16, domain: &str| {
            let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
            msg.metadata.recursion_desired = true;
            msg.add_query(Query::query(
                Name::from_ascii(domain).unwrap(),
                RecordType::A,
            ));
            msg.to_vec().unwrap()
        };

        // Frame 1: slow upstream query (ID 0x1001)
        let q_slow = build_q(0x1001, "slow.pipe.test.");
        // Frame 2: malformed DNS packet >= 12 bytes (ID 0x1002, QDCOUNT=5 with truncated body) -> FORMERR
        let q_malformed = vec![
            0x10, 0x02, 0x01, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF,
        ];
        // Frame 3: locally blocked query (ID 0x1003) -> must overtake q_slow!
        let q_fast = build_q(0x1003, "blocked.pipe.test.");

        let mut pipelined = Vec::new();
        for pkt in [&q_slow, &q_malformed, &q_fast] {
            let len = u16::try_from(pkt.len()).unwrap();
            pipelined.extend_from_slice(&len.to_be_bytes());
            pipelined.extend_from_slice(pkt);
        }
        stream.write_all(&pipelined).await.expect("write pipelined");
        stream.flush().await.expect("flush");

        let mut ids = Vec::new();
        let mut rcodes = Vec::new();
        for _ in 0..3 {
            let mut len_buf = [0_u8; 2];
            tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut len_buf))
                .await
                .expect("read len timeout")
                .expect("read len");
            let rlen = usize::from(u16::from_be_bytes(len_buf));
            let mut rbuf = vec![0_u8; rlen];
            stream.read_exact(&mut rbuf).await.expect("read resp");
            let msg = Message::from_vec(&rbuf).expect("decode resp");
            ids.push(msg.id);
            rcodes.push(msg.response_code);
        }

        // Fast/malformed responses arrived before slow upstream response (0x1001 is last).
        assert_eq!(ids.last().copied(), Some(0x1001));
        let formerr_idx = ids.iter().position(|&id| id == 0x1002).expect("formerr id");
        assert_eq!(rcodes[formerr_idx], ResponseCode::FormErr);
        assert!(ids.contains(&0x1003));

        drop(stream);
        server.shutdown().await;
    }
}
