use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use crabdns_core::{Config, DnsPipeline, QueryProtocol, validate_client_id};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;

use crate::handle_dns_stream_with_context;

fn extract_dot_client_id(sni: Option<&str>, base_hostname: Option<&str>) -> Option<String> {
    let sni = sni?.trim().trim_end_matches('.');
    let base = base_hostname?.trim().trim_end_matches('.');
    if sni.is_empty() || base.is_empty() {
        return None;
    }
    let lower_sni = sni.to_ascii_lowercase();
    let lower_base = base.to_ascii_lowercase();
    let suffix = format!(".{lower_base}");
    let label = lower_sni.strip_suffix(&suffix)?;
    if label.contains('.') {
        return None;
    }
    validate_client_id(label).ok()
}

pub async fn run_dot_server(
    listener: TcpListener,
    acceptor: Arc<ArcSwap<TlsAcceptor>>,
    config: Arc<ArcSwap<Config>>,
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
        let tls = acceptor.load_full();
        let cfg = Arc::clone(&config);
        let pipe = Arc::clone(&pipeline);
        tokio::spawn(async move {
            let _permit = permit;
            match tokio::time::timeout(idle_timeout, tls.accept(stream)).await {
                Ok(Ok(tls_stream)) => {
                    let sni = tls_stream.get_ref().1.server_name().map(str::to_string);
                    let ddr_host = cfg.load().ddr_hostname.clone();
                    let client_id = extract_dot_client_id(sni.as_deref(), ddr_host.as_deref());
                    if let Err(err) = handle_dns_stream_with_context(
                        tls_stream,
                        peer,
                        pipe,
                        idle_timeout,
                        QueryProtocol::Dot,
                        client_id,
                    )
                    .await
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_dot_client_id() {
        assert_eq!(
            extract_dot_client_id(Some("kid-phone.dns.home.arpa"), Some("dns.home.arpa")),
            Some("kid-phone".to_string())
        );
        assert_eq!(
            extract_dot_client_id(Some("dns.home.arpa"), Some("dns.home.arpa")),
            None
        );
        assert_eq!(
            extract_dot_client_id(Some("a.b.dns.home.arpa"), Some("dns.home.arpa")),
            None
        );
        assert_eq!(
            extract_dot_client_id(Some("bad!id.dns.home.arpa"), Some("dns.home.arpa")),
            None
        );
    }
}
