use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

use crate::error::{CoreError, Result};

#[derive(Debug, Clone)]
pub enum UpstreamEndpoint {
    Udp(SocketAddr),
    Tcp(SocketAddr),
    Dot { addr: String, server_name: String },
    Doh { url: String },
}

impl UpstreamEndpoint {
    pub fn parse(raw: &str) -> Result<Self> {
        let trimmed = raw.trim();
        if let Some(rest) = trimmed.strip_prefix("udp://") {
            let addr = parse_socket_addr(rest, 53)?;
            return Ok(Self::Udp(addr));
        }
        if let Some(rest) = trimmed.strip_prefix("tcp://") {
            let addr = parse_socket_addr(rest, 53)?;
            return Ok(Self::Tcp(addr));
        }
        if let Some(rest) = trimmed.strip_prefix("tls://") {
            let (host, port) = split_host_port(rest, 853);
            return Ok(Self::Dot {
                addr: format!("{host}:{port}"),
                server_name: host,
            });
        }
        if trimmed.starts_with("https://") {
            return Ok(Self::Doh {
                url: trimmed.to_string(),
            });
        }

        let addr = parse_socket_addr(trimmed, 53)?;
        Ok(Self::Udp(addr))
    }
}

fn parse_socket_addr(input: &str, default_port: u16) -> Result<SocketAddr> {
    if let Ok(addr) = input.parse::<SocketAddr>() {
        return Ok(addr);
    }
    if let Ok(ip) = input.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, default_port));
    }
    Err(CoreError::Config(format!(
        "invalid upstream socket address: {input}"
    )))
}

fn split_host_port(input: &str, default_port: u16) -> (String, u16) {
    if let Some((host, port_str)) = input.rsplit_once(':')
        && let Ok(port) = port_str.parse::<u16>()
    {
        return (host.to_string(), port);
    }
    (input.to_string(), default_port)
}

pub struct UpstreamPool {
    endpoints: Vec<UpstreamEndpoint>,
    timeout: Duration,
    http_client: reqwest::Client,
    tls_connector: TlsConnector,
}

impl UpstreamPool {
    pub fn new(specs: &[String], timeout_ms: u64) -> Result<Self> {
        let mut endpoints = Vec::with_capacity(specs.len());
        for spec in specs {
            endpoints.push(UpstreamEndpoint::parse(spec)?);
        }
        if endpoints.is_empty() {
            return Err(CoreError::Config(
                "at least one upstream DNS server is required".to_string(),
            ));
        }

        let timeout = Duration::from_millis(timeout_ms);
        let http_client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| CoreError::Upstream(e.to_string()))?;

        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls_config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let tls_connector = TlsConnector::from(Arc::new(tls_config));

        Ok(Self {
            endpoints,
            timeout,
            http_client,
            tls_connector,
        })
    }

    pub async fn exchange(&self, query_wire: &[u8]) -> Result<(Vec<u8>, String)> {
        let mut last_err = CoreError::Upstream("no upstream endpoints configured".to_string());
        for endpoint in &self.endpoints {
            let label = endpoint_label(endpoint);
            match tokio::time::timeout(self.timeout, self.exchange_one(endpoint, query_wire)).await
            {
                Ok(Ok(resp)) => return Ok((resp, label)),
                Ok(Err(err)) => {
                    tracing::warn!(upstream = %label, error = %err, "upstream query failed");
                    last_err = err;
                }
                Err(_) => {
                    tracing::warn!(upstream = %label, "upstream query timed out");
                    last_err = CoreError::Upstream(format!("upstream {label} timed out"));
                }
            }
        }
        Err(last_err)
    }

    async fn exchange_one(
        &self,
        endpoint: &UpstreamEndpoint,
        query_wire: &[u8],
    ) -> Result<Vec<u8>> {
        match endpoint {
            UpstreamEndpoint::Udp(addr) => exchange_udp(*addr, query_wire).await,
            UpstreamEndpoint::Tcp(addr) => exchange_tcp(*addr, query_wire).await,
            UpstreamEndpoint::Dot { addr, server_name } => {
                exchange_dot(&self.tls_connector, addr, server_name, query_wire).await
            }
            UpstreamEndpoint::Doh { url } => exchange_doh(&self.http_client, url, query_wire).await,
        }
    }
}

fn endpoint_label(endpoint: &UpstreamEndpoint) -> String {
    match endpoint {
        UpstreamEndpoint::Udp(addr) => format!("udp://{addr}"),
        UpstreamEndpoint::Tcp(addr) => format!("tcp://{addr}"),
        UpstreamEndpoint::Dot { addr, .. } => format!("tls://{addr}"),
        UpstreamEndpoint::Doh { url } => url.clone(),
    }
}

async fn exchange_udp(addr: SocketAddr, query_wire: &[u8]) -> Result<Vec<u8>> {
    let bind_addr = if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind_addr).await?;
    socket.connect(addr).await?;
    socket.send(query_wire).await?;

    let mut buf = vec![0_u8; 4096];
    let n = socket.recv(&mut buf).await?;
    buf.truncate(n);
    Ok(buf)
}

async fn exchange_tcp(addr: SocketAddr, query_wire: &[u8]) -> Result<Vec<u8>> {
    let mut stream = TcpStream::connect(addr).await?;
    send_tcp_framed(&mut stream, query_wire).await?;
    read_tcp_framed(&mut stream).await
}

async fn exchange_dot(
    connector: &TlsConnector,
    addr: &str,
    server_name: &str,
    query_wire: &[u8],
) -> Result<Vec<u8>> {
    let stream = TcpStream::connect(addr).await?;
    let name = ServerName::try_from(server_name.to_string())
        .map_err(|e| CoreError::Upstream(format!("invalid TLS server name: {e}")))?;
    let mut tls_stream = connector
        .connect(name, stream)
        .await
        .map_err(|e| CoreError::Upstream(format!("TLS handshake failed: {e}")))?;
    send_tcp_framed(&mut tls_stream, query_wire).await?;
    read_tcp_framed(&mut tls_stream).await
}

async fn exchange_doh(client: &reqwest::Client, url: &str, query_wire: &[u8]) -> Result<Vec<u8>> {
    let resp = client
        .post(url)
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .body(query_wire.to_vec())
        .send()
        .await
        .map_err(|e| CoreError::Upstream(format!("DoH request failed: {e}")))?;

    if !resp.status().is_success() {
        return Err(CoreError::Upstream(format!(
            "DoH HTTP status {}",
            resp.status()
        )));
    }
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| CoreError::Upstream(format!("DoH body read failed: {e}")))?;
    Ok(bytes.to_vec())
}

async fn send_tcp_framed<W: AsyncWriteExt + Unpin>(writer: &mut W, payload: &[u8]) -> Result<()> {
    let len = u16::try_from(payload.len())
        .map_err(|_| CoreError::Protocol("DNS message exceeds 65535 bytes".to_string()))?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

async fn read_tcp_framed<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let mut len_buf = [0_u8; 2];
    reader.read_exact(&mut len_buf).await?;
    let len = usize::from(u16::from_be_bytes(len_buf));
    let mut buf = vec![0_u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_upstream_specs() {
        assert!(matches!(
            UpstreamEndpoint::parse("1.1.1.1").expect("valid"),
            UpstreamEndpoint::Udp(_)
        ));
        assert!(matches!(
            UpstreamEndpoint::parse("tcp://8.8.8.8:53").expect("valid"),
            UpstreamEndpoint::Tcp(_)
        ));
        assert!(matches!(
            UpstreamEndpoint::parse("tls://dns.google").expect("valid"),
            UpstreamEndpoint::Dot { .. }
        ));
        assert!(matches!(
            UpstreamEndpoint::parse("https://dns.google/dns-query").expect("valid"),
            UpstreamEndpoint::Doh { .. }
        ));
    }
}
