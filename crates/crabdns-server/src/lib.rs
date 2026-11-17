use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use crabdns_core::{Config, DnsCache, DnsPipeline, FilterEngine, QueryEvent, UpstreamPool};
use crabdns_storage::{StorageEngine, spawn_log_sink};
use crabdns_web::{AppState, build_router};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{Semaphore, broadcast, mpsc};
use tokio::task::JoinHandle;

mod dot;

pub struct RunningServer {
    pub dns_addr: SocketAddr,
    pub web_addr: SocketAddr,
    pub dot_addr: Option<SocketAddr>,
    pub pipeline: Arc<DnsPipeline>,
    pub storage: Arc<StorageEngine>,
    udp_tasks: Vec<JoinHandle<()>>,
    tcp_task: JoinHandle<()>,
    dot_task: Option<JoinHandle<()>>,
    web_task: JoinHandle<()>,
    sub_refresh_task: JoinHandle<()>,
    sink_handle: JoinHandle<()>,
}

impl RunningServer {
    pub async fn shutdown(self) {
        for task in &self.udp_tasks {
            task.abort();
        }
        self.tcp_task.abort();
        if let Some(dot_task) = &self.dot_task {
            dot_task.abort();
        }
        self.web_task.abort();
        self.sub_refresh_task.abort();

        for task in self.udp_tasks {
            let _ = task.await;
        }
        let _ = self.tcp_task.await;
        if let Some(dot_task) = self.dot_task {
            let _ = dot_task.await;
        }
        let _ = self.web_task.await;
        let _ = self.sub_refresh_task.await;

        drop(self.pipeline);
        let _ = self.sink_handle.await;
        drop(self.storage);
    }
}

fn merge_saved_config(config: &mut Config, saved_cfg: Config) {
    config.upstreams = saved_cfg.upstreams;
    config.upstream_strategy = saved_cfg.upstream_strategy;
    config.cache_size = saved_cfg.cache_size;
    config.optimistic_cache = saved_cfg.optimistic_cache;
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
}

#[allow(clippy::too_many_lines)]
pub async fn spawn_server(mut config: Config) -> anyhow::Result<RunningServer> {
    let storage = Arc::new(StorageEngine::open(&config.data_dir)?);

    if let Some(saved_cfg) = storage.load_config()? {
        merge_saved_config(&mut config, saved_cfg);
    }

    let config = Arc::new(ArcSwap::from_pointee(config));
    let current_cfg = config.load();

    let filter = Arc::new(FilterEngine::new(&current_cfg.custom_rules));
    let custom_rules_text = storage
        .load_custom_rules()?
        .unwrap_or_else(|| current_cfg.custom_rules.join("\n"));
    let custom_enabled = storage.load_custom_rules_enabled()?;
    let sub_contents = storage.load_enabled_subscription_contents()?;
    filter.reload_from_sources(&custom_rules_text, custom_enabled, &sub_contents);

    let cache = Arc::new(DnsCache::new(
        current_cfg.cache_size,
        current_cfg.optimistic_cache,
    ));
    let upstream = Arc::new(UpstreamPool::new_with_strategy(
        &current_cfg.upstreams,
        current_cfg.upstream_timeout_ms,
        current_cfg.upstream_strategy,
    )?);

    let (log_tx, log_rx) = mpsc::channel::<QueryEvent>(4096);
    let (live_tx, _) = broadcast::channel::<QueryEvent>(512);
    let sink_handle = spawn_log_sink(Arc::clone(&storage), log_rx, live_tx.clone());

    let pipeline = Arc::new(DnsPipeline::new(filter, cache, upstream, Some(log_tx)));
    pipeline.set_block_mode(current_cfg.block_mode);
    pipeline.set_cname_cloaking(current_cfg.cname_cloaking_blocking);
    pipeline.reload_acl(
        &current_cfg.allow_cidrs,
        &current_cfg.deny_cidrs,
        current_cfg.rate_limit_qps,
    )?;
    pipeline.reload_split_dns(
        &current_cfg.split_dns,
        current_cfg.upstream_timeout_ms,
        current_cfg.upstream_strategy,
    )?;

    let tcp_listener = TcpListener::bind(current_cfg.listen_dns).await?;
    let dns_addr = tcp_listener.local_addr()?;
    let udp_worker_count = std::thread::available_parallelism()
        .map_or(2, std::num::NonZeroUsize::get)
        .clamp(2, 16);
    let udp_sockets = bind_udp_sockets(dns_addr, udp_worker_count)?;

    let tcp_max_connections = current_cfg.tcp_max_connections.max(1);
    let tcp_idle_timeout = Duration::from_secs(current_cfg.tcp_idle_timeout_secs.max(1));

    let (dot_addr, dot_task) = match current_cfg.listen_dot {
        Some(addr) => {
            let cert_path = current_cfg.tls_cert_path.as_deref().ok_or_else(|| {
                anyhow::anyhow!("listen_dot requires tls_cert_path to be configured")
            })?;
            let key_path = current_cfg.tls_key_path.as_deref().ok_or_else(|| {
                anyhow::anyhow!("listen_dot requires tls_key_path to be configured")
            })?;
            let acceptor = dot::build_tls_acceptor(cert_path, key_path)?;
            let dot_listener = dot::bind_dot_listener(addr).await?;
            let bound_dot = dot_listener.local_addr()?;
            let dot_pipe = Arc::clone(&pipeline);
            let task = tokio::spawn(dot::run_dot_server(
                dot_listener,
                acceptor,
                dot_pipe,
                tcp_max_connections,
                tcp_idle_timeout,
            ));
            (Some(bound_dot), Some(task))
        }
        None => (None, None),
    };

    let web_listener = TcpListener::bind(current_cfg.listen_web).await?;
    let web_addr = web_listener.local_addr()?;

    tracing::info!(
        dns = %dns_addr,
        dot = ?dot_addr,
        web = %web_addr,
        "crabdns started"
    );

    let udp_tasks = udp_sockets
        .into_iter()
        .map(|sock| {
            let udp_pipeline = Arc::clone(&pipeline);
            tokio::spawn(run_udp_server(sock, udp_pipeline))
        })
        .collect();

    let tcp_pipeline = Arc::clone(&pipeline);
    let tcp_task = tokio::spawn(run_tcp_server(
        tcp_listener,
        tcp_pipeline,
        tcp_max_connections,
        tcp_idle_timeout,
    ));

    let app = build_router(AppState {
        config: Arc::clone(&config),
        pipeline: Arc::clone(&pipeline),
        storage: Arc::clone(&storage),
        live_tx,
    });
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

    let sub_storage = Arc::clone(&storage);
    let sub_pipeline = Arc::clone(&pipeline);
    let sub_config = Arc::clone(&config);
    let sub_refresh_task = tokio::spawn(async move {
        let client = crabdns_web::subscriptions::build_http_client();
        let mut interval = tokio::time::interval(std::time::Duration::from_hours(24));
        interval.tick().await;
        loop {
            interval.tick().await;
            let allow_private = sub_config.load().allow_private_subscriptions;
            if let Err(err) =
                crabdns_web::subscriptions::refresh_enabled_subscriptions_job_with_policy(
                    &client,
                    &sub_storage,
                    &sub_pipeline,
                    allow_private,
                )
                .await
            {
                tracing::warn!(error = %err, "scheduled subscription refresh failed");
            }
        }
    });

    Ok(RunningServer {
        dns_addr,
        web_addr,
        dot_addr,
        pipeline,
        storage,
        udp_tasks,
        tcp_task,
        dot_task,
        web_task,
        sub_refresh_task,
        sink_handle,
    })
}

fn bind_udp_sockets(addr: SocketAddr, count: usize) -> anyhow::Result<Vec<Arc<UdpSocket>>> {
    #[cfg(unix)]
    {
        let mut sockets = Vec::with_capacity(count);
        for _ in 0..count {
            let domain = socket2::Domain::for_address(addr);
            let sock = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
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

async fn run_udp_server(socket: Arc<UdpSocket>, pipeline: Arc<DnsPipeline>) {
    let mut buf = vec![0_u8; 4096];
    loop {
        let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
            continue;
        };
        let packet = buf[..len].to_vec();
        let sock = Arc::clone(&socket);
        let pipe = Arc::clone(&pipeline);
        tokio::spawn(async move {
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
        let Ok((stream, peer)) = listener.accept().await else {
            continue;
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
            if let Err(err) = handle_dns_stream(stream, peer, pipe, idle_timeout).await {
                tracing::debug!(peer = %peer, error = %err, "TCP DNS connection closed");
            }
        });
    }
}

pub(crate) async fn handle_dns_stream<S>(
    mut stream: S,
    peer: SocketAddr,
    pipeline: Arc<DnsPipeline>,
    idle_timeout: Duration,
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
        let resp = pipeline.handle_packet(&query, peer).await?;
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
