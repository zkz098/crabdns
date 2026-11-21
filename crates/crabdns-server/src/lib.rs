use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use axum::serve::ListenerExt;
use crabdns_core::{
    Config, DdrConfig, DnsCache, DnsPipeline, FilterEngine, QueryContext, QueryEvent,
    QueryProtocol, UpstreamPool,
};
use crabdns_storage::{StorageEngine, spawn_log_sink};
use crabdns_web::tls_api::TlsReloader;
use crabdns_web::{AppState, build_router};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{Semaphore, broadcast, mpsc};
use tokio::task::JoinHandle;

mod dot;
mod tasks;
mod tls;

pub use tasks::prune_logs_once;

const UDP_MAX_INFLIGHT: usize = 2048;
const ACCEPT_ERR_BACKOFF: Duration = Duration::from_millis(50);

pub struct RunningServer {
    pub dns_addr: SocketAddr,
    pub web_addr: SocketAddr,
    pub web_tls_addr: Option<SocketAddr>,
    pub dot_addr: Option<SocketAddr>,
    pub pipeline: Arc<DnsPipeline>,
    pub storage: Arc<StorageEngine>,
    config: Arc<ArcSwap<Config>>,
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
        for task in &self.udp_tasks {
            task.abort();
        }
        self.tcp_task.abort();
        abort_opt(self.dot_task.as_ref());
        self.web_task.abort();
        abort_opt(self.web_tls_accept_task.as_ref());
        abort_opt(self.web_tls_task.as_ref());
        self.sub_refresh_task.abort();
        self.hosts_watch_task.abort();
        self.cache_persist_task.abort();
        self.log_prune_task.abort();
        abort_opt(self.tls_watch_task.as_ref());
        abort_opt(self.sighup_task.as_ref());

        for task in self.udp_tasks {
            let _ = task.await;
        }
        let _ = self.tcp_task.await;
        await_opt(self.dot_task).await;
        let _ = self.web_task.await;
        await_opt(self.web_tls_accept_task).await;
        await_opt(self.web_tls_task).await;
        let _ = self.sub_refresh_task.await;
        let _ = self.hosts_watch_task.await;
        let _ = self.cache_persist_task.await;
        let _ = self.log_prune_task.await;
        await_opt(self.tls_watch_task).await;
        await_opt(self.sighup_task).await;

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
        let _ = self.sink_handle.await;
        drop(self.storage);
    }
}

fn abort_opt(handle: Option<&JoinHandle<()>>) {
    if let Some(h) = handle {
        h.abort();
    }
}

async fn await_opt(handle: Option<JoinHandle<()>>) {
    if let Some(h) = handle {
        let _ = h.await;
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

async fn start_web_and_tls(
    config: &Arc<ArcSwap<Config>>,
    pipeline: &Arc<DnsPipeline>,
    storage: &Arc<StorageEngine>,
    tls_manager: &Arc<tls::TlsManager>,
    live_tx: broadcast::Sender<QueryEvent>,
    tcp_max_connections: usize,
    tcp_idle_timeout: Duration,
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

    let (web_tls_addr, web_tls_accept_task, web_tls_task) =
        match (web_tls_listener, tls_manager.https_acceptor()) {
            (Some(listener), Some(acceptor)) => {
                let (https_listener, addr, accept_task) =
                    tls::HttpsTlsListener::from_tcp_listener(listener, acceptor)?;
                let tls_app = app.clone();
                let serve_task = tokio::spawn(async move {
                    if let Err(err) = axum::serve(
                        https_listener.tap_io(|_| {}),
                        tls_app.into_make_service_with_connect_info::<SocketAddr>(),
                    )
                    .await
                    {
                        tracing::error!(error = %err, "HTTPS web server error");
                    }
                });
                (Some(addr), Some(accept_task), Some(serve_task))
            }
            _ => (None, None, None),
        };

    let web_task = tokio::spawn(async move {
        if let Err(err) = axum::serve(
            web_listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
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

    let web_tls = start_web_and_tls(
        &config,
        &pipeline,
        &storage,
        &tls_manager,
        live_tx,
        tcp_max_connections,
        tcp_idle_timeout,
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
            tokio::spawn(run_udp_server(sock, udp_pipeline, limiter))
        })
        .collect();

    let tcp_task = tokio::spawn(run_tcp_server(
        tcp_listener,
        Arc::clone(&pipeline),
        tcp_max_connections,
        tcp_idle_timeout,
    ));

    let tls_active = web_tls.dot_addr.is_some() || web_tls.web_tls_addr.is_some();
    let tls_watch_task = tls_active.then(|| tasks::spawn_tls_watch_task(Arc::clone(&tls_manager)));
    let sighup_task = tasks::spawn_sighup_task(
        Arc::clone(&config),
        Arc::clone(&pipeline),
        Arc::clone(&tls_manager),
    );

    Ok(RunningServer {
        dns_addr,
        web_addr: web_tls.web_addr,
        web_tls_addr: web_tls.web_tls_addr,
        dot_addr: web_tls.dot_addr,
        pipeline: Arc::clone(&pipeline),
        storage: Arc::clone(&storage),
        config: Arc::clone(&config),
        udp_tasks,
        tcp_task,
        dot_task: web_tls.dot_task,
        web_task: web_tls.web_task,
        web_tls_accept_task: web_tls.web_tls_accept_task,
        web_tls_task: web_tls.web_tls_task,
        sub_refresh_task: tasks::spawn_subscription_refresh_task(
            Arc::clone(&config),
            Arc::clone(&storage),
            Arc::clone(&pipeline),
        ),
        hosts_watch_task: tasks::spawn_hosts_watch_task(Arc::clone(&config), Arc::clone(&pipeline)),
        cache_persist_task: tasks::spawn_cache_persist_task(
            Arc::clone(&config),
            Arc::clone(&pipeline),
            Arc::clone(&storage),
        ),
        log_prune_task: tasks::spawn_log_prune_task(config, storage),
        tls_watch_task,
        sighup_task,
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
) {
    let mut buf = vec![0_u8; 4096];
    loop {
        let (len, peer) = match socket.recv_from(&mut buf).await {
            Ok(pair) => pair,
            Err(err) => {
                tracing::warn!(error = %err, "UDP DNS recv error; backing off");
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
        };
        let Ok(permit) = Arc::clone(&limiter).try_acquire_owned() else {
            tracing::warn!(peer = %peer, "UDP DNS query dropped: max inflight reached");
            continue;
        };
        let packet = buf[..len].to_vec();
        let sock = Arc::clone(&socket);
        let pipe = Arc::clone(&pipeline);
        tokio::spawn(async move {
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

async fn run_tcp_server(
    listener: TcpListener,
    pipeline: Arc<DnsPipeline>,
    max_connections: usize,
    idle_timeout: Duration,
) {
    let limiter = Arc::new(Semaphore::new(max_connections.max(1)));
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(err) => {
                tracing::warn!(error = %err, "TCP DNS accept error; backing off");
                tokio::time::sleep(ACCEPT_ERR_BACKOFF).await;
                continue;
            }
        };
        let _ = stream.set_nodelay(true);
        let Ok(permit) = Arc::clone(&limiter).try_acquire_owned() else {
            tracing::warn!(peer = %peer, "TCP DNS connection rejected: max connections reached");
            drop(stream);
            continue;
        };
        let pipe = Arc::clone(&pipeline);
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(err) = handle_dns_stream_with_context(
                stream,
                peer,
                pipe,
                idle_timeout,
                QueryProtocol::Tcp,
                None,
            )
            .await
            {
                tracing::debug!(peer = %peer, error = %err, "TCP DNS connection closed");
            }
        });
    }
}

pub(crate) async fn handle_dns_stream_with_context<S>(
    mut stream: S,
    peer: SocketAddr,
    pipeline: Arc<DnsPipeline>,
    idle_timeout: Duration,
    protocol: QueryProtocol,
    client_id: Option<String>,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut len_buf = [0_u8; 2];
    let mut query = Vec::with_capacity(512);
    let mut write_buf = Vec::with_capacity(514);
    while let Ok(Ok(_)) = tokio::time::timeout(idle_timeout, stream.read_exact(&mut len_buf)).await
    {
        let len = usize::from(u16::from_be_bytes(len_buf));
        if len == 0 || len > 65_535 {
            break;
        }
        query.resize(len, 0);
        tokio::time::timeout(idle_timeout, stream.read_exact(&mut query)).await??;
        let resp = pipeline
            .handle_packet_with_context(
                &query,
                QueryContext {
                    client_addr: peer,
                    protocol,
                    client_id: client_id.clone(),
                },
            )
            .await?;
        let resp_len = u16::try_from(resp.len())?;
        write_buf.clear();
        write_buf.extend_from_slice(&resp_len.to_be_bytes());
        write_buf.extend_from_slice(&resp);
        tokio::time::timeout(idle_timeout, async {
            stream.write_all(&write_buf).await?;
            stream.flush().await
        })
        .await??;
    }
    Ok(())
}
