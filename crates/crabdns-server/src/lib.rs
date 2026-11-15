use std::net::SocketAddr;
use std::sync::Arc;

use crabdns_core::{Config, DnsCache, DnsPipeline, FilterEngine, QueryEvent, UpstreamPool};
use crabdns_storage::{StorageEngine, spawn_log_sink};
use crabdns_web::{AppState, build_router};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;

pub struct RunningServer {
    pub dns_addr: SocketAddr,
    pub web_addr: SocketAddr,
    pub pipeline: Arc<DnsPipeline>,
    pub storage: Arc<StorageEngine>,
    udp_task: JoinHandle<()>,
    tcp_task: JoinHandle<()>,
    web_task: JoinHandle<()>,
    sink_handle: JoinHandle<()>,
}

impl RunningServer {
    pub async fn shutdown(self) {
        self.udp_task.abort();
        self.tcp_task.abort();
        self.web_task.abort();

        let _ = self.udp_task.await;
        let _ = self.tcp_task.await;
        let _ = self.web_task.await;

        drop(self.pipeline);
        let _ = self.sink_handle.await;
        drop(self.storage);
    }
}

pub async fn spawn_server(config: Config) -> anyhow::Result<RunningServer> {
    let config = Arc::new(config);
    let storage = Arc::new(StorageEngine::open(&config.data_dir)?);

    let filter = Arc::new(FilterEngine::new(&config.custom_rules));
    if let Some(saved_rules) = storage.load_custom_rules()? {
        filter.reload_from_text(&saved_rules);
    }

    let cache = Arc::new(DnsCache::new(config.cache_size, config.optimistic_cache));
    let upstream = Arc::new(UpstreamPool::new(
        &config.upstreams,
        config.upstream_timeout_ms,
    )?);

    let (log_tx, log_rx) = mpsc::channel::<QueryEvent>(4096);
    let (live_tx, _) = broadcast::channel::<QueryEvent>(512);
    let sink_handle = spawn_log_sink(Arc::clone(&storage), log_rx, live_tx.clone());

    let pipeline = Arc::new(DnsPipeline::new(filter, cache, upstream, Some(log_tx)));

    let tcp_listener = TcpListener::bind(config.listen_dns).await?;
    let dns_addr = tcp_listener.local_addr()?;
    let udp_socket = Arc::new(UdpSocket::bind(dns_addr).await?);

    let web_listener = TcpListener::bind(config.listen_web).await?;
    let web_addr = web_listener.local_addr()?;

    tracing::info!(
        dns = %dns_addr,
        web = %web_addr,
        "crabdns started"
    );

    let udp_pipeline = Arc::clone(&pipeline);
    let udp_task = tokio::spawn(run_udp_server(udp_socket, udp_pipeline));

    let tcp_pipeline = Arc::clone(&pipeline);
    let tcp_task = tokio::spawn(run_tcp_server(tcp_listener, tcp_pipeline));

    let app = build_router(AppState {
        config: Arc::clone(&config),
        pipeline: Arc::clone(&pipeline),
        storage: Arc::clone(&storage),
        live_tx,
    });
    let web_task = tokio::spawn(async move {
        if let Err(err) = axum::serve(web_listener, app).await {
            tracing::error!(error = %err, "web server error");
        }
    });

    Ok(RunningServer {
        dns_addr,
        web_addr,
        pipeline,
        storage,
        udp_task,
        tcp_task,
        web_task,
        sink_handle,
    })
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

async fn run_tcp_server(listener: TcpListener, pipeline: Arc<DnsPipeline>) {
    loop {
        let Ok((stream, peer)) = listener.accept().await else {
            continue;
        };
        let pipe = Arc::clone(&pipeline);
        tokio::spawn(async move {
            if let Err(err) = handle_tcp_conn(stream, peer, pipe).await {
                tracing::debug!(peer = %peer, error = %err, "TCP DNS connection closed");
            }
        });
    }
}

async fn handle_tcp_conn(
    mut stream: TcpStream,
    peer: SocketAddr,
    pipeline: Arc<DnsPipeline>,
) -> anyhow::Result<()> {
    let mut len_buf = [0_u8; 2];
    while stream.read_exact(&mut len_buf).await.is_ok() {
        let len = usize::from(u16::from_be_bytes(len_buf));
        if len == 0 || len > 65_535 {
            break;
        }
        let mut query = vec![0_u8; len];
        stream.read_exact(&mut query).await?;
        let resp = pipeline.handle_packet(&query, peer).await?;
        let resp_len = u16::try_from(resp.len())?;
        stream.write_all(&resp_len.to_be_bytes()).await?;
        stream.write_all(&resp).await?;
        stream.flush().await?;
    }
    Ok(())
}
