use std::fmt::Write as _;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use arc_swap::ArcSwap;
use aws_lc_rs::digest::{SHA256, digest};
use axum::serve::Listener;
use chrono::Utc;
use crabdns_core::DnsPipeline;
use crabdns_web::tls_api::{TlsReloader, TlsStatusResponse};
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc, watch};
use tokio::task::{JoinHandle, JoinSet};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

use crate::doq::build_doq_server_config;
use crate::{IpConnGuard, IpConnLimiter};

const HTTPS_MAX_HANDSHAKES: usize = 256;
const HTTPS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

pub fn build_tls_acceptor_with_meta(
    cert_path: &Path,
    key_path: &Path,
    alpn_protocols: Vec<Vec<u8>>,
) -> anyhow::Result<(TlsAcceptor, String, usize)> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_file_iter(cert_path)?.collect::<std::result::Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        anyhow::bail!("no certificates found in {}", cert_path.display());
    }
    let cert_count = certs.len();
    let fingerprint = sha256_hex(certs[0].as_ref());

    let key = PrivateKeyDer::from_pem_file(key_path)?;
    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    server_config.alpn_protocols = alpn_protocols;

    Ok((
        TlsAcceptor::from(Arc::new(server_config)),
        fingerprint,
        cert_count,
    ))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let sum = digest(&SHA256, bytes);
    let mut out = String::with_capacity(sum.as_ref().len() * 2);
    for byte in sum.as_ref() {
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

pub struct TlsManager {
    dot_acceptor: Option<Arc<ArcSwap<TlsAcceptor>>>,
    https_acceptor: Option<Arc<ArcSwap<TlsAcceptor>>>,
    doq_endpoint: Mutex<Option<quinn::Endpoint>>,
    doq_idle_timeout: Duration,
    cert_path: ArcSwap<Option<PathBuf>>,
    key_path: ArcSwap<Option<PathBuf>>,
    status: ArcSwap<TlsStatusResponse>,
    reload_lock: Mutex<()>,
}

impl TlsManager {
    pub fn new(
        https_listen: Option<SocketAddr>,
        dot_listen: Option<SocketAddr>,
        quic_listen: Option<SocketAddr>,
        doq_idle_timeout: Duration,
        cert_path: Option<&Path>,
        key_path: Option<&Path>,
    ) -> anyhow::Result<Self> {
        let active = https_listen.is_some() || dot_listen.is_some() || quic_listen.is_some();
        if !active {
            let status = TlsStatusResponse {
                https_enabled: false,
                https_listen: None,
                dot_enabled: false,
                dot_listen: None,
                doq_enabled: false,
                doq_listen: None,
                cert_path: cert_path.map(|p| p.display().to_string()),
                key_path: key_path.map(|p| p.display().to_string()),
                last_loaded_at: None,
                cert_fingerprint_sha256: None,
                cert_count: 0,
                last_error: None,
            };
            return Ok(Self {
                dot_acceptor: None,
                https_acceptor: None,
                doq_endpoint: Mutex::new(None),
                doq_idle_timeout,
                cert_path: ArcSwap::from_pointee(cert_path.map(Path::to_path_buf)),
                key_path: ArcSwap::from_pointee(key_path.map(Path::to_path_buf)),
                status: ArcSwap::from_pointee(status),
                reload_lock: Mutex::new(()),
            });
        }

        let cert = cert_path.ok_or_else(|| {
            anyhow::anyhow!("TLS listener requires tls_cert_path to be configured")
        })?;
        let key = key_path.ok_or_else(|| {
            anyhow::anyhow!("TLS listener requires tls_key_path to be configured")
        })?;

        let mut fingerprint = None;
        let mut cert_count = 0;

        let dot_acceptor = if dot_listen.is_some() {
            let (acc, fp, count) = build_tls_acceptor_with_meta(cert, key, vec![b"dot".to_vec()])?;
            fingerprint = Some(fp);
            cert_count = count;
            Some(Arc::new(ArcSwap::from_pointee(acc)))
        } else {
            None
        };

        let https_acceptor = if https_listen.is_some() {
            let (acc, fp, count) = build_tls_acceptor_with_meta(
                cert,
                key,
                vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            )?;
            fingerprint = Some(fp);
            cert_count = count;
            Some(Arc::new(ArcSwap::from_pointee(acc)))
        } else {
            None
        };

        if quic_listen.is_some() && fingerprint.is_none() {
            let (_, fp, count) = build_tls_acceptor_with_meta(cert, key, vec![b"doq".to_vec()])?;
            fingerprint = Some(fp);
            cert_count = count;
        }

        let status = TlsStatusResponse {
            https_enabled: https_listen.is_some(),
            https_listen: https_listen.map(|a| a.to_string()),
            dot_enabled: dot_listen.is_some(),
            dot_listen: dot_listen.map(|a| a.to_string()),
            doq_enabled: quic_listen.is_some(),
            doq_listen: quic_listen.map(|a| a.to_string()),
            cert_path: Some(cert.display().to_string()),
            key_path: Some(key.display().to_string()),
            last_loaded_at: Some(Utc::now()),
            cert_fingerprint_sha256: fingerprint,
            cert_count,
            last_error: None,
        };

        Ok(Self {
            dot_acceptor,
            https_acceptor,
            doq_endpoint: Mutex::new(None),
            doq_idle_timeout,
            cert_path: ArcSwap::from_pointee(Some(cert.to_path_buf())),
            key_path: ArcSwap::from_pointee(Some(key.to_path_buf())),
            status: ArcSwap::from_pointee(status),
            reload_lock: Mutex::new(()),
        })
    }

    pub fn dot_acceptor(&self) -> Option<Arc<ArcSwap<TlsAcceptor>>> {
        self.dot_acceptor.clone()
    }

    pub fn https_acceptor(&self) -> Option<Arc<ArcSwap<TlsAcceptor>>> {
        self.https_acceptor.clone()
    }

    pub fn set_doq_endpoint(&self, endpoint: Option<quinn::Endpoint>) {
        let mut guard = self
            .doq_endpoint
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = endpoint;
    }

    pub fn update_bound_addrs(
        &self,
        https_addr: Option<SocketAddr>,
        dot_addr: Option<SocketAddr>,
        quic_addr: Option<SocketAddr>,
    ) {
        let mut next = self.status.load().as_ref().clone();
        if let Some(addr) = https_addr {
            next.https_listen = Some(addr.to_string());
        }
        if let Some(addr) = dot_addr {
            next.dot_listen = Some(addr.to_string());
        }
        if let Some(addr) = quic_addr {
            next.doq_listen = Some(addr.to_string());
        }
        self.status.store(Arc::new(next));
    }

    pub fn paths(&self) -> (Option<PathBuf>, Option<PathBuf>) {
        (
            self.cert_path.load().as_ref().clone(),
            self.key_path.load().as_ref().clone(),
        )
    }
}

struct BuiltAcceptors {
    dot: Option<TlsAcceptor>,
    https: Option<TlsAcceptor>,
    fingerprint: Option<String>,
    cert_count: usize,
}

impl TlsManager {
    fn try_build_new_acceptors(
        &self,
        cert: &Path,
        key: &Path,
    ) -> std::result::Result<BuiltAcceptors, String> {
        let mut fingerprint = None;
        let mut cert_count = 0;

        let dot = if self.dot_acceptor.is_some() {
            let (acc, fp, count) = build_tls_acceptor_with_meta(cert, key, vec![b"dot".to_vec()])
                .map_err(|e| e.to_string())?;
            fingerprint = Some(fp);
            cert_count = count;
            Some(acc)
        } else {
            None
        };

        let https = if self.https_acceptor.is_some() {
            let (acc, fp, count) =
                build_tls_acceptor_with_meta(cert, key, vec![b"h2".to_vec(), b"http/1.1".to_vec()])
                    .map_err(|e| e.to_string())?;
            fingerprint = Some(fp);
            cert_count = count;
            Some(acc)
        } else {
            None
        };

        Ok(BuiltAcceptors {
            dot,
            https,
            fingerprint,
            cert_count,
        })
    }
}

impl TlsReloader for TlsManager {
    fn status(&self) -> TlsStatusResponse {
        self.status.load().as_ref().clone()
    }

    fn reload(
        &self,
        next_cert_path: Option<&Path>,
        next_key_path: Option<&Path>,
    ) -> std::result::Result<TlsStatusResponse, String> {
        let _guard = self
            .reload_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        if self.dot_acceptor.is_none()
            && self.https_acceptor.is_none()
            && !self.status.load().doq_enabled
        {
            return Err("TLS listeners are not active".to_string());
        }

        let eff_cert = next_cert_path
            .map(Path::to_path_buf)
            .or_else(|| self.cert_path.load().as_ref().clone())
            .ok_or_else(|| "tls_cert_path is not configured".to_string())?;
        let eff_key = next_key_path
            .map(Path::to_path_buf)
            .or_else(|| self.key_path.load().as_ref().clone())
            .ok_or_else(|| "tls_key_path is not configured".to_string())?;

        let built = match self.try_build_new_acceptors(&eff_cert, &eff_key) {
            Ok(ok) => ok,
            Err(err) => {
                let mut failed_status = self.status.load().as_ref().clone();
                failed_status.last_error = Some(err.clone());
                self.status.store(Arc::new(failed_status));
                return Err(err);
            }
        };

        if let (Some(slot), Some(acc)) = (&self.dot_acceptor, built.dot) {
            slot.store(Arc::new(acc));
        }
        if let (Some(slot), Some(acc)) = (&self.https_acceptor, built.https) {
            slot.store(Arc::new(acc));
        }
        if let Some(ep) = self
            .doq_endpoint
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
        {
            let doq_cfg = build_doq_server_config(&eff_cert, &eff_key, self.doq_idle_timeout)
                .map_err(|e| e.to_string())?;
            ep.set_server_config(Some(doq_cfg));
        }
        self.cert_path.store(Arc::new(Some(eff_cert.clone())));
        self.key_path.store(Arc::new(Some(eff_key.clone())));

        let mut updated = self.status.load().as_ref().clone();
        updated.cert_path = Some(eff_cert.display().to_string());
        updated.key_path = Some(eff_key.display().to_string());
        let (fp, count) = (built.fingerprint, built.cert_count);
        updated.last_loaded_at = Some(Utc::now());
        updated.cert_fingerprint_sha256 = fp;
        updated.cert_count = count;
        updated.last_error = None;
        self.status.store(Arc::new(updated.clone()));

        tracing::info!(
            fingerprint = ?updated.cert_fingerprint_sha256,
            "TLS certificate reloaded"
        );
        Ok(updated)
    }
}

pub struct HttpsTlsListener {
    local_addr: SocketAddr,
    rx: mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
}

impl HttpsTlsListener {
    pub fn from_tcp_listener(
        tcp_listener: TcpListener,
        acceptor: Arc<ArcSwap<TlsAcceptor>>,
        mut shutdown_rx: watch::Receiver<bool>,
    ) -> std::io::Result<(Self, SocketAddr, JoinHandle<()>)> {
        let local_addr = tcp_listener.local_addr()?;
        let (tx, rx) = mpsc::channel(HTTPS_MAX_HANDSHAKES);
        let limiter = Arc::new(Semaphore::new(HTTPS_MAX_HANDSHAKES));

        let accept_task = tokio::spawn(async move {
            let mut handshakes = JoinSet::new();
            loop {
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                    Some(_) = handshakes.join_next(), if !handshakes.is_empty() => {}
                    accept_res = tcp_listener.accept() => {
                        let Ok((stream, peer)) = accept_res else {
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            continue;
                        };
                        let _ = stream.set_nodelay(true);
                        let Ok(permit) = Arc::clone(&limiter).try_acquire_owned() else {
                            tracing::warn!(peer = %peer, "HTTPS TLS handshake rejected: capacity reached");
                            drop(stream);
                            continue;
                        };
                        let tls = acceptor.load_full();
                        let tx_inner = tx.clone();
                        handshakes.spawn(async move {
                            let handshake_res = tokio::time::timeout(
                                HTTPS_HANDSHAKE_TIMEOUT,
                                tls.accept(stream),
                            )
                            .await;
                            drop(permit);
                            match handshake_res {
                                Ok(Ok(tls_stream)) => {
                                    let _ = tx_inner.send((tls_stream, peer)).await;
                                }
                                Ok(Err(err)) => {
                                    tracing::debug!(peer = %peer, error = %err, "HTTPS TLS handshake failed");
                                }
                                Err(_) => {
                                    tracing::debug!(peer = %peer, "HTTPS TLS handshake timed out");
                                }
                            }
                        });
                    }
                }
            }
            handshakes.shutdown().await;
        });

        Ok((Self { local_addr, rx }, local_addr, accept_task))
    }
}

impl Listener for HttpsTlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        if let Some(conn) = self.rx.recv().await {
            return conn;
        }
        std::future::pending().await
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.local_addr)
    }
}

/// Stream wrapper holding an active-connection guard and tracking web active connection count.
pub struct PermittedStream<S> {
    inner: S,
    _guard: IpConnGuard,
    pipeline: Arc<DnsPipeline>,
}

impl<S> Drop for PermittedStream<S> {
    fn drop(&mut self) {
        self.pipeline.dec_web_active();
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PermittedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PermittedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

/// Listener wrapper that caps global and per-IP concurrent HTTP/HTTPS connections.
pub struct PermittedListener<L> {
    inner: L,
    limiter: IpConnLimiter,
    pipeline: Arc<DnsPipeline>,
}

impl<L> PermittedListener<L> {
    pub fn new(inner: L, max_connections: usize, pipeline: Arc<DnsPipeline>) -> Self {
        let per_ip = (max_connections / 2).max(16);
        Self {
            inner,
            limiter: IpConnLimiter::new(max_connections.max(1), per_ip),
            pipeline,
        }
    }
}

impl<L> Listener for PermittedListener<L>
where
    L: Listener<Addr = SocketAddr>,
{
    type Io = PermittedStream<L::Io>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (io, addr) = self.inner.accept().await;
            if let Some(guard) = self.limiter.try_acquire(addr.ip()) {
                self.pipeline.inc_web_active();
                return (
                    PermittedStream {
                        inner: io,
                        _guard: guard,
                        pipeline: Arc::clone(&self.pipeline),
                    },
                    addr,
                );
            }
            self.pipeline.record_web_rejected();
            tracing::warn!(peer = %addr, "web connection rejected: connection limit reached");
            drop(io);
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}
