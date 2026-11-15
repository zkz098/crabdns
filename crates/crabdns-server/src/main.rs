use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use crabdns_core::{Config, DnsCache, DnsPipeline, FilterEngine, QueryEvent, UpstreamPool};
use crabdns_storage::{StorageEngine, spawn_log_sink};
use crabdns_web::{AppState, build_router};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{broadcast, mpsc};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "crabdns", about = "High-performance Rust DNS ad-blocker")]
struct Cli {
    #[arg(short, long)]
    config: Option<PathBuf>,

    #[arg(long)]
    dns_listen: Option<SocketAddr>,

    #[arg(long)]
    web_listen: Option<SocketAddr>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let mut config = Config::load_or_default(cli.config.as_deref())?;
    if let Some(addr) = cli.dns_listen {
        config.listen_dns = addr;
    }
    if let Some(addr) = cli.web_listen {
        config.listen_web = addr;
    }

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
    let _sink_handle = spawn_log_sink(Arc::clone(&storage), log_rx, live_tx.clone());

    let pipeline = Arc::new(DnsPipeline::new(filter, cache, upstream, Some(log_tx)));

    let udp_socket = Arc::new(UdpSocket::bind(config.listen_dns).await?);
    let tcp_listener = TcpListener::bind(config.listen_dns).await?;
    let web_listener = TcpListener::bind(config.listen_web).await?;

    tracing::info!(
        dns = %config.listen_dns,
        web = %config.listen_web,
        "crabdns started"
    );

    let udp_pipeline = Arc::clone(&pipeline);
    let udp_task = tokio::spawn(run_udp_server(udp_socket, udp_pipeline));

    let tcp_pipeline = Arc::clone(&pipeline);
    let tcp_task = tokio::spawn(run_tcp_server(tcp_listener, tcp_pipeline));

    let app = build_router(AppState {
        config: Arc::clone(&config),
        pipeline,
        storage,
        live_tx,
    });
    let web_task = tokio::spawn(async move {
        if let Err(err) = axum::serve(web_listener, app).await {
            tracing::error!(error = %err, "web server error");
        }
    });

    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down crabdns");
    udp_task.abort();
    tcp_task.abort();
    web_task.abort();
    Ok(())
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
