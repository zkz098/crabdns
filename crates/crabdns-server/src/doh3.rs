use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use bytes::{Buf, Bytes};
use crabdns_core::{Config, DnsPipeline, QueryContext, QueryProtocol, validate_client_id};
use crabdns_web::doh::decode_base64url;
use h3::server::RequestStream;
use http::{Method, Request, Response, StatusCode, header};
use quinn::crypto::rustls::{HandshakeData, QuicServerConfig};
use quinn::{Endpoint, ServerConfig, TransportConfig};
use rustls::ServerConfig as RustlsServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::dot::extract_sni_client_id;
use crate::{GRACEFUL_DRAIN_TIMEOUT, IpConnLimiter, drain_join_set};

const MAX_DOH3_PACKET_BYTES: usize = 65_535;
const DOH3_QUERY_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_DOH3_STREAMS_PER_CONN: usize = 64;
const DNS_MESSAGE_MIME: &str = "application/dns-message";

pub fn build_doh3_server_config(
    cert_path: &Path,
    key_path: &Path,
    idle_timeout: Duration,
) -> anyhow::Result<ServerConfig> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_file_iter(cert_path)?.collect::<std::result::Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        anyhow::bail!("no certificates found in {}", cert_path.display());
    }
    let key = PrivateKeyDer::from_pem_file(key_path)?;
    let mut tls_cfg = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    tls_cfg.alpn_protocols = vec![b"h3".to_vec()];

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

pub fn bind_doh3_endpoint(
    addr: SocketAddr,
    server_config: ServerConfig,
) -> anyhow::Result<Endpoint> {
    Ok(Endpoint::server(server_config, addr)?)
}

pub type Doh3ListenerParts = (
    Option<SocketAddr>,
    Option<Endpoint>,
    Option<tokio::task::JoinHandle<()>>,
);

pub fn start_doh3_listener(
    config: &Arc<ArcSwap<Config>>,
    pipeline: &Arc<DnsPipeline>,
    max_connections: usize,
    idle_timeout: Duration,
    shutdown_rx: &watch::Receiver<bool>,
) -> anyhow::Result<Doh3ListenerParts> {
    let cfg = config.load_full();
    let (Some(addr), Some(cert_p), Some(key_p)) = (
        cfg.listen_doh3,
        cfg.tls_cert_path.as_deref(),
        cfg.tls_key_path.as_deref(),
    ) else {
        return Ok((None, None, None));
    };
    let quic_cfg = build_doh3_server_config(cert_p, key_p, idle_timeout)?;
    let endpoint = bind_doh3_endpoint(addr, quic_cfg)?;
    let bound = endpoint.local_addr()?;
    let task = tokio::spawn(run_doh3_server(
        endpoint.clone(),
        Arc::clone(config),
        Arc::clone(pipeline),
        max_connections,
        idle_timeout,
        shutdown_rx.clone(),
    ));
    Ok((Some(bound), Some(endpoint), Some(task)))
}

pub async fn run_doh3_server(
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
                    pipeline.record_doh_rejected();
                    tracing::warn!(peer = %peer, "DoH3 connection rejected: connection limit reached");
                    incoming.refuse();
                    continue;
                };
                let cfg = Arc::clone(&config);
                let pipe = Arc::clone(&pipeline);
                let conn_shutdown = shutdown_rx.clone();
                tasks.spawn(async move {
                    let _guard = guard;
                    handle_doh3_connection(incoming, peer, cfg, pipe, idle_timeout, conn_shutdown).await;
                });
            }
        }
    }

    endpoint.close(0_u32.into(), b"shutdown");
    drain_join_set(&mut tasks, GRACEFUL_DRAIN_TIMEOUT).await;
}

async fn handle_doh3_connection(
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
    let sni_client_id = extract_sni_client_id(
        sni.as_deref(),
        &loaded_cfg.sni_client_id_hostnames,
        loaded_cfg.ddr_hostname.as_deref(),
    );

    let Ok(mut h3_conn) = h3::server::Connection::new(h3_quinn::Connection::new(conn)).await else {
        return;
    };

    let mut stream_tasks = JoinSet::new();
    let stream_limiter = Arc::new(tokio::sync::Semaphore::new(MAX_DOH3_STREAMS_PER_CONN));

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    break;
                }
            }
            Some(_) = stream_tasks.join_next(), if !stream_tasks.is_empty() => {}
            req_res = h3_conn.accept() => {
                let Ok(Some(resolver)) = req_res else {
                    break;
                };
                let Ok(permit) = Arc::clone(&stream_limiter).try_acquire_owned() else {
                    continue;
                };
                let cfg = Arc::clone(&config);
                let pipe = Arc::clone(&pipeline);
                let cid = sni_client_id.clone();
                stream_tasks.spawn(async move {
                    let _permit = permit;
                    let Ok((req, stream)) = resolver.resolve_request().await else {
                        return;
                    };
                    handle_doh3_request(req, stream, peer, cfg, pipe, cid).await;
                });
            }
        }
    }

    drain_join_set(&mut stream_tasks, GRACEFUL_DRAIN_TIMEOUT).await;
}

async fn handle_doh3_request<S>(
    req: Request<()>,
    mut stream: RequestStream<S, Bytes>,
    peer: SocketAddr,
    config: Arc<ArcSwap<Config>>,
    pipeline: Arc<DnsPipeline>,
    sni_client_id: Option<String>,
) where
    S: h3::quic::BidiStream<Bytes>,
{
    if !config.load().doh_enabled {
        send_empty_status(&mut stream, StatusCode::NOT_FOUND).await;
        return;
    }

    let path = req.uri().path();
    let path_client_id = match parse_doh3_path(path) {
        Ok(cid) => cid,
        Err(status) => {
            send_empty_status(&mut stream, status).await;
            return;
        }
    };
    let client_id = path_client_id.or(sni_client_id);

    let packet = match *req.method() {
        Method::GET => match extract_dns_query_param(req.uri().query()) {
            Ok(pkt) => pkt,
            Err(status) => {
                send_empty_status(&mut stream, status).await;
                return;
            }
        },
        Method::POST => {
            if !has_valid_dns_content_type(&req) {
                send_empty_status(&mut stream, StatusCode::UNSUPPORTED_MEDIA_TYPE).await;
                return;
            }
            match read_doh3_body(&mut stream).await {
                Ok(pkt) => pkt,
                Err(status) => {
                    send_empty_status(&mut stream, status).await;
                    return;
                }
            }
        }
        _ => {
            send_empty_status(&mut stream, StatusCode::METHOD_NOT_ALLOWED).await;
            return;
        }
    };

    if packet.is_empty() || packet.len() > MAX_DOH3_PACKET_BYTES {
        send_empty_status(&mut stream, StatusCode::BAD_REQUEST).await;
        return;
    }

    let ctx = QueryContext {
        client_addr: peer,
        protocol: QueryProtocol::Doh3,
        client_id,
    };

    match tokio::time::timeout(
        DOH3_QUERY_TIMEOUT,
        pipeline.handle_packet_with_context(&packet, ctx),
    )
    .await
    {
        Ok(Ok(resp_bytes)) => send_dns_response(&mut stream, resp_bytes).await,
        Ok(Err(_)) => send_empty_status(&mut stream, StatusCode::BAD_REQUEST).await,
        Err(_) => {
            pipeline.record_doh_timeout();
            send_empty_status(&mut stream, StatusCode::GATEWAY_TIMEOUT).await;
        }
    }
}

fn parse_doh3_path(path: &str) -> Result<Option<String>, StatusCode> {
    if path == "/dns-query" {
        return Ok(None);
    }
    if let Some(raw_cid) = path.strip_prefix("/dns-query/")
        && !raw_cid.is_empty()
        && !raw_cid.contains('/')
    {
        return validate_client_id(raw_cid)
            .map(Some)
            .map_err(|_| StatusCode::BAD_REQUEST);
    }
    Err(StatusCode::NOT_FOUND)
}

fn extract_dns_query_param(query: Option<&str>) -> Result<Vec<u8>, StatusCode> {
    let query = query.ok_or(StatusCode::BAD_REQUEST)?;
    for pair in query.split('&') {
        if let Some((key, val)) = pair.split_once('=')
            && key == "dns"
        {
            return decode_base64url(val).ok_or(StatusCode::BAD_REQUEST);
        }
    }
    Err(StatusCode::BAD_REQUEST)
}

fn has_valid_dns_content_type(req: &Request<()>) -> bool {
    let Some(ct) = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
    else {
        return true;
    };
    let media_type = ct.split(';').next().unwrap_or("").trim();
    media_type.eq_ignore_ascii_case(DNS_MESSAGE_MIME)
}

async fn read_doh3_body<S>(stream: &mut RequestStream<S, Bytes>) -> Result<Vec<u8>, StatusCode>
where
    S: h3::quic::RecvStream,
{
    let mut out = Vec::new();
    while let Ok(Some(mut chunk)) = stream.recv_data().await {
        let remaining = chunk.remaining();
        if out.len().saturating_add(remaining) > MAX_DOH3_PACKET_BYTES {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
        let bytes = chunk.copy_to_bytes(remaining);
        out.extend_from_slice(&bytes);
    }
    Ok(out)
}

async fn send_dns_response<S>(stream: &mut RequestStream<S, Bytes>, body: Vec<u8>)
where
    S: h3::quic::SendStream<Bytes>,
{
    let Ok(resp) = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, DNS_MESSAGE_MIME)
        .header(header::CACHE_CONTROL, "no-store")
        .body(())
    else {
        return;
    };
    if stream.send_response(resp).await.is_ok() {
        let _ = stream.send_data(Bytes::from(body)).await;
    }
    let _ = stream.finish().await;
}

async fn send_empty_status<S>(stream: &mut RequestStream<S, Bytes>, status: StatusCode)
where
    S: h3::quic::SendStream<Bytes>,
{
    if let Ok(resp) = Response::builder().status(status).body(()) {
        let _ = stream.send_response(resp).await;
    }
    let _ = stream.finish().await;
}
