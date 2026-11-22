use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use crabdns_core::{Config, DnsPipeline, QueryContext, QueryProtocol, build_raw_formerr};
use quinn::crypto::rustls::{HandshakeData, QuicServerConfig};
use quinn::{Endpoint, ServerConfig, TransportConfig};
use rustls::ServerConfig as RustlsServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::dot::extract_sni_client_id;
use crate::{GRACEFUL_DRAIN_TIMEOUT, IpConnLimiter, drain_join_set};

const MAX_DOQ_STREAMS_PER_CONN: usize = 32;

pub fn build_doq_server_config(
    cert_path: &Path,
    key_path: &Path,
    idle_timeout: Duration,
) -> anyhow::Result<ServerConfig> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_file_iter(cert_path)?.collect::<std::result::Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        anyhow::bail!("no certificates found in {}", cert_path.display());
    }
    let key = PrivateKeyDer::from_pem_file(key_path)?;
    let mut tls_cfg = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    tls_cfg.alpn_protocols = vec![b"doq".to_vec()];

    let quic_crypto = QuicServerConfig::try_from(tls_cfg)?;
    let mut server_cfg = ServerConfig::with_crypto(Arc::new(quic_crypto));
    let mut transport = TransportConfig::default();
    if let Ok(idle) = quinn::IdleTimeout::try_from(idle_timeout) {
        transport.max_idle_timeout(Some(idle));
    }
    transport.max_concurrent_bidi_streams(64_u32.into());
    server_cfg.transport_config(Arc::new(transport));
    Ok(server_cfg)
}

pub fn bind_doq_endpoint(
    addr: SocketAddr,
    server_config: ServerConfig,
) -> anyhow::Result<Endpoint> {
    Ok(Endpoint::server(server_config, addr)?)
}

struct DoqActiveGuard {
    pipeline: Arc<DnsPipeline>,
}

impl Drop for DoqActiveGuard {
    fn drop(&mut self) {
        self.pipeline.dec_doq_active();
    }
}

pub async fn run_doq_server(
    endpoint: Endpoint,
    config: Arc<ArcSwap<Config>>,
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
            incoming_opt = endpoint.accept() => {
                let Some(incoming) = incoming_opt else {
                    break;
                };
                let peer = incoming.remote_address();
                let Some(guard) = limiter.try_acquire(peer.ip()) else {
                    pipeline.record_doq_rejected();
                    tracing::warn!(peer = %peer, "DoQ connection rejected: connection limit reached");
                    incoming.refuse();
                    continue;
                };
                let cfg = Arc::clone(&config);
                let pipe = Arc::clone(&pipeline);
                let conn_shutdown = shutdown_rx.clone();
                tasks.spawn(async move {
                    let _guard = guard;
                    pipe.inc_doq_active();
                    let _active = DoqActiveGuard { pipeline: Arc::clone(&pipe) };
                    handle_doq_connection(incoming, peer, cfg, pipe, idle_timeout, conn_shutdown).await;
                });
            }
        }
    }

    endpoint.close(0_u32.into(), b"shutdown");
    drain_join_set(&mut tasks, GRACEFUL_DRAIN_TIMEOUT).await;
}

async fn handle_doq_connection(
    incoming: quinn::Incoming,
    peer: SocketAddr,
    config: Arc<ArcSwap<Config>>,
    pipeline: Arc<DnsPipeline>,
    idle_timeout: Duration,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let Ok(Ok(conn)) = tokio::time::timeout(idle_timeout, incoming).await else {
        return;
    };
    let sni = conn
        .handshake_data()
        .and_then(|d| d.downcast::<HandshakeData>().ok())
        .and_then(|hs| hs.server_name);
    let loaded_cfg = config.load();
    let client_id = extract_sni_client_id(
        sni.as_deref(),
        &loaded_cfg.sni_client_id_hostnames,
        loaded_cfg.ddr_hostname.as_deref(),
    );

    let mut stream_tasks = JoinSet::new();
    let stream_limiter = Arc::new(tokio::sync::Semaphore::new(MAX_DOQ_STREAMS_PER_CONN));

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    break;
                }
            }
            Some(_) = stream_tasks.join_next(), if !stream_tasks.is_empty() => {}
            bi_res = conn.accept_bi() => {
                let Ok((send, recv)) = bi_res else {
                    break;
                };
                let Ok(permit) = Arc::clone(&stream_limiter).try_acquire_owned() else {
                    continue;
                };
                let pipe = Arc::clone(&pipeline);
                let cid = client_id.clone();
                stream_tasks.spawn(async move {
                    let _permit = permit;
                    handle_doq_stream(send, recv, peer, pipe, cid, idle_timeout).await;
                });
            }
        }
    }

    conn.close(0_u32.into(), b"closing");
    drain_join_set(&mut stream_tasks, GRACEFUL_DRAIN_TIMEOUT).await;
}

async fn handle_doq_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    peer: SocketAddr,
    pipeline: Arc<DnsPipeline>,
    client_id: Option<String>,
    idle_timeout: Duration,
) {
    let mut len_buf = [0_u8; 2];
    if !matches!(
        tokio::time::timeout(idle_timeout, recv.read_exact(&mut len_buf)).await,
        Ok(Ok(()))
    ) {
        return;
    }
    let len = usize::from(u16::from_be_bytes(len_buf));
    if len == 0 || len > 65_535 {
        return;
    }
    let mut query = vec![0_u8; len];
    if !matches!(
        tokio::time::timeout(idle_timeout, recv.read_exact(&mut query)).await,
        Ok(Ok(()))
    ) {
        return;
    }

    let ctx = QueryContext {
        client_addr: peer,
        protocol: QueryProtocol::Doq,
        client_id,
    };
    let resp_opt = match pipeline.handle_packet_with_context(&query, ctx).await {
        Ok(resp) => Some(resp),
        Err(_) => build_raw_formerr(&query),
    };
    let Some(resp) = resp_opt else {
        return;
    };
    let Ok(resp_len) = u16::try_from(resp.len()) else {
        return;
    };
    let mut out = Vec::with_capacity(2 + resp.len());
    out.extend_from_slice(&resp_len.to_be_bytes());
    out.extend_from_slice(&resp);
    let _ = tokio::time::timeout(idle_timeout, async {
        send.write_all(&out).await?;
        let _ = send.finish();
        Ok::<(), std::io::Error>(())
    })
    .await;
}
