use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use crabdns_core::DnsPipeline;
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;

use crate::handle_dns_stream;

pub fn build_tls_acceptor(cert_path: &Path, key_path: &Path) -> anyhow::Result<TlsAcceptor> {
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_file_iter(cert_path)?.collect::<std::result::Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        anyhow::bail!("no certificates found in {}", cert_path.display());
    }
    let key = PrivateKeyDer::from_pem_file(key_path)?;
    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    server_config.alpn_protocols = vec![b"dot".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

pub async fn run_dot_server(
    listener: TcpListener,
    acceptor: TlsAcceptor,
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
            tracing::warn!(peer = %peer, "DoT connection rejected: max connections reached");
            drop(stream);
            continue;
        };
        let tls = acceptor.clone();
        let pipe = Arc::clone(&pipeline);
        tokio::spawn(async move {
            let _permit = permit;
            match tokio::time::timeout(idle_timeout, tls.accept(stream)).await {
                Ok(Ok(tls_stream)) => {
                    if let Err(err) = handle_dns_stream(tls_stream, peer, pipe, idle_timeout).await
                    {
                        tracing::debug!(peer = %peer, error = %err, "DoT DNS connection closed");
                    }
                }
                Ok(Err(err)) => {
                    tracing::debug!(peer = %peer, error = %err, "DoT TLS handshake failed");
                }
                Err(_) => {
                    tracing::debug!(peer = %peer, "DoT TLS handshake timed out");
                }
            }
        });
    }
}

pub async fn bind_dot_listener(addr: SocketAddr) -> anyhow::Result<TcpListener> {
    Ok(TcpListener::bind(addr).await?)
}
