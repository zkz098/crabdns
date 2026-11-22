use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn::crypto::rustls::QuicClientConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig as RustlsClientConfig, RootCertStore};

use crate::error::{CoreError, Result};

pub(crate) fn parse_socket_addr(input: &str, default_port: u16) -> Result<SocketAddr> {
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

pub(crate) fn split_host_port(input: &str, default_port: u16) -> (String, u16) {
    if let Some((host, port_str)) = input.rsplit_once(':')
        && let Ok(port) = port_str.parse::<u16>()
    {
        return (host.to_string(), port);
    }
    (input.to_string(), default_port)
}

const UDP_SOCKET_POOL_MAX_IDLE: usize = 128;
const CONN_POOL_MAX_IDLE: usize = 32;
const CONN_POOL_IDLE_TTL: Duration = Duration::from_secs(30);
const MAX_POOLED_RETRIES: usize = 2;
const MAX_DOH_RESPONSE_BYTES: usize = 65_535;

#[derive(Debug, Default)]
pub(crate) struct UdpSocketPool {
    sockets: std::sync::Mutex<Vec<UdpSocket>>,
}

impl UdpSocketPool {
    fn pop(&self) -> Option<UdpSocket> {
        self.sockets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pop()
    }

    fn put(&self, sock: UdpSocket) {
        let mut guard = self
            .sockets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard.len() < UDP_SOCKET_POOL_MAX_IDLE {
            guard.push(sock);
        }
    }
}

#[derive(Debug)]
struct PooledConn<S> {
    stream: S,
    last_used: Instant,
}

#[derive(Debug)]
pub(crate) struct ConnPool<S> {
    conns: std::sync::Mutex<Vec<PooledConn<S>>>,
}

impl<S> Default for ConnPool<S> {
    fn default() -> Self {
        Self {
            conns: std::sync::Mutex::new(Vec::new()),
        }
    }
}

impl<S> ConnPool<S> {
    fn pop_fresh(&self) -> Option<S> {
        let mut guard = self
            .conns
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while let Some(item) = guard.pop() {
            if item.last_used.elapsed() < CONN_POOL_IDLE_TTL {
                return Some(item.stream);
            }
        }
        None
    }

    fn put(&self, stream: S) {
        let mut guard = self
            .conns
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.retain(|item| item.last_used.elapsed() < CONN_POOL_IDLE_TTL);
        if guard.len() < CONN_POOL_MAX_IDLE {
            guard.push(PooledConn {
                stream,
                last_used: Instant::now(),
            });
        }
    }
}

fn tx_id_matches(query: &[u8], resp: &[u8]) -> bool {
    query.len() >= 2 && resp.len() >= 2 && query[0..2] == resp[0..2]
}

pub(crate) fn is_udp_truncated(resp: &[u8]) -> bool {
    resp.len() >= 12 && (resp[2] & 0x02) != 0
}

async fn bind_connected_udp(addr: SocketAddr) -> Result<UdpSocket> {
    let bind_addr = if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let sock = UdpSocket::bind(bind_addr).await?;
    sock.connect(addr).await?;
    Ok(sock)
}

async fn udp_roundtrip(socket: &UdpSocket, query_wire: &[u8]) -> Result<Vec<u8>> {
    socket.send(query_wire).await?;
    let mut buf = vec![0_u8; 4096];
    let n = socket.recv(&mut buf).await?;
    buf.truncate(n);
    Ok(buf)
}

pub(crate) async fn exchange_udp(
    addr: SocketAddr,
    pool: &UdpSocketPool,
    query_wire: &[u8],
) -> Result<Vec<u8>> {
    if let Some(sock) = pool.pop()
        && let Ok(resp) = udp_roundtrip(&sock, query_wire).await
        && tx_id_matches(query_wire, &resp)
    {
        pool.put(sock);
        return Ok(resp);
    }

    let fresh = bind_connected_udp(addr).await?;
    let resp = udp_roundtrip(&fresh, query_wire).await?;
    if !tx_id_matches(query_wire, &resp) {
        return Err(CoreError::Upstream(
            "UDP DNS response transaction ID mismatch".to_string(),
        ));
    }
    pool.put(fresh);
    Ok(resp)
}

pub(crate) async fn exchange_tcp(addr: SocketAddr, query_wire: &[u8]) -> Result<Vec<u8>> {
    let mut stream = TcpStream::connect(addr).await?;
    let _ = stream.set_nodelay(true);
    tcp_roundtrip(&mut stream, query_wire).await
}

pub(crate) async fn exchange_tcp_pooled(
    addr: SocketAddr,
    pool: &ConnPool<TcpStream>,
    query_wire: &[u8],
) -> Result<Vec<u8>> {
    for _ in 0..MAX_POOLED_RETRIES {
        let Some(mut stream) = pool.pop_fresh() else {
            break;
        };
        if let Ok(resp) = tcp_roundtrip(&mut stream, query_wire).await
            && tx_id_matches(query_wire, &resp)
        {
            pool.put(stream);
            return Ok(resp);
        }
    }

    let mut stream = TcpStream::connect(addr).await?;
    let _ = stream.set_nodelay(true);
    let resp = tcp_roundtrip(&mut stream, query_wire).await?;
    if !tx_id_matches(query_wire, &resp) {
        return Err(CoreError::Upstream(
            "TCP DNS response transaction ID mismatch".to_string(),
        ));
    }
    pool.put(stream);
    Ok(resp)
}

pub(crate) async fn try_exchange_dot_pooled(
    pool: &ConnPool<TlsStream<TcpStream>>,
    query_wire: &[u8],
) -> Option<Vec<u8>> {
    for _ in 0..MAX_POOLED_RETRIES {
        let mut tls_stream = pool.pop_fresh()?;
        if let Ok(resp) = tcp_roundtrip(&mut tls_stream, query_wire).await
            && tx_id_matches(query_wire, &resp)
        {
            pool.put(tls_stream);
            return Some(resp);
        }
    }
    None
}

pub(crate) async fn exchange_dot_addrs(
    connector: &TlsConnector,
    addrs: &[SocketAddr],
    pool: &ConnPool<TlsStream<TcpStream>>,
    server_name: &str,
    query_wire: &[u8],
) -> Result<Vec<u8>> {
    let stream = TcpStream::connect(addrs).await?;
    let _ = stream.set_nodelay(true);
    let clean_sni = server_name.trim_start_matches('[').trim_end_matches(']');
    let name = ServerName::try_from(clean_sni.to_string())
        .map_err(|e| CoreError::Upstream(format!("invalid TLS server name: {e}")))?;
    let mut tls_stream = connector
        .connect(name, stream)
        .await
        .map_err(|e| CoreError::Upstream(format!("TLS handshake failed: {e}")))?;
    let resp = tcp_roundtrip(&mut tls_stream, query_wire).await?;
    if !tx_id_matches(query_wire, &resp) {
        return Err(CoreError::Upstream(
            "DoT DNS response transaction ID mismatch".to_string(),
        ));
    }
    pool.put(tls_stream);
    Ok(resp)
}

pub(crate) async fn exchange_doh(
    client: &reqwest::Client,
    url: &str,
    query_wire: &[u8],
) -> Result<Vec<u8>> {
    let mut resp = client
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
    if let Some(len) = resp.content_length()
        && len > MAX_DOH_RESPONSE_BYTES as u64
    {
        return Err(CoreError::Upstream(format!(
            "DoH response exceeds {MAX_DOH_RESPONSE_BYTES} bytes limit"
        )));
    }

    let mut out = Vec::with_capacity(
        usize::try_from(resp.content_length().unwrap_or(0))
            .unwrap_or(0)
            .min(MAX_DOH_RESPONSE_BYTES),
    );
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| CoreError::Upstream(format!("DoH body read failed: {e}")))?
    {
        if out.len().saturating_add(chunk.len()) > MAX_DOH_RESPONSE_BYTES {
            return Err(CoreError::Upstream(format!(
                "DoH response exceeds {MAX_DOH_RESPONSE_BYTES} bytes limit"
            )));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

pub(crate) fn build_doq_client_config() -> Result<quinn::ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut tls_config = RustlsClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![b"doq".to_vec()];
    let quic_crypto = QuicClientConfig::try_from(tls_config)
        .map_err(|e| CoreError::Upstream(format!("DoQ TLS config error: {e}")))?;
    let mut client_cfg = quinn::ClientConfig::new(Arc::new(quic_crypto));
    let mut transport = quinn::TransportConfig::default();
    if let Ok(idle) = quinn::IdleTimeout::try_from(CONN_POOL_IDLE_TTL) {
        transport.max_idle_timeout(Some(idle));
    }
    client_cfg.transport_config(Arc::new(transport));
    Ok(client_cfg)
}

async fn doq_roundtrip(conn: &quinn::Connection, query_wire: &[u8]) -> Result<Vec<u8>> {
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| CoreError::Upstream(format!("DoQ open_bi failed: {e}")))?;

    let mut doq_query = query_wire.to_vec();
    if doq_query.len() >= 2 {
        doq_query[0] = 0;
        doq_query[1] = 0;
    }
    let len = u16::try_from(doq_query.len())
        .map_err(|_| CoreError::Protocol("DNS message exceeds 65535 bytes".to_string()))?;
    send.write_all(&len.to_be_bytes())
        .await
        .map_err(|e| CoreError::Upstream(format!("DoQ write len failed: {e}")))?;
    send.write_all(&doq_query)
        .await
        .map_err(|e| CoreError::Upstream(format!("DoQ write body failed: {e}")))?;
    send.finish()
        .map_err(|e| CoreError::Upstream(format!("DoQ finish stream failed: {e}")))?;

    let mut len_buf = [0_u8; 2];
    recv.read_exact(&mut len_buf)
        .await
        .map_err(|e| CoreError::Upstream(format!("DoQ read len failed: {e}")))?;
    let resp_len = usize::from(u16::from_be_bytes(len_buf));
    let mut resp = vec![0_u8; resp_len];
    recv.read_exact(&mut resp)
        .await
        .map_err(|e| CoreError::Upstream(format!("DoQ read body failed: {e}")))?;

    if query_wire.len() >= 2 && resp.len() >= 2 {
        resp[0] = query_wire[0];
        resp[1] = query_wire[1];
    }
    Ok(resp)
}

pub(crate) async fn try_exchange_doq_pooled(
    pool: &ConnPool<quinn::Connection>,
    query_wire: &[u8],
) -> Option<Vec<u8>> {
    for _ in 0..MAX_POOLED_RETRIES {
        let conn = pool.pop_fresh()?;
        if conn.close_reason().is_some() {
            continue;
        }
        if let Ok(resp) = doq_roundtrip(&conn, query_wire).await {
            pool.put(conn);
            return Some(resp);
        }
    }
    None
}

pub(crate) async fn exchange_doq_addrs(
    client_config: &quinn::ClientConfig,
    addrs: &[SocketAddr],
    pool: &ConnPool<quinn::Connection>,
    server_name: &str,
    query_wire: &[u8],
) -> Result<Vec<u8>> {
    let mut last_err = CoreError::Upstream("no resolved socket addresses for DoQ".to_string());
    for &addr in addrs {
        match exchange_doq_one(client_config, addr, pool, server_name, query_wire).await {
            Ok(resp) => return Ok(resp),
            Err(err) => last_err = err,
        }
    }
    Err(last_err)
}

async fn exchange_doq_one(
    client_config: &quinn::ClientConfig,
    addr: SocketAddr,
    pool: &ConnPool<quinn::Connection>,
    server_name: &str,
    query_wire: &[u8],
) -> Result<Vec<u8>> {
    let bind_addr: SocketAddr = if addr.is_ipv4() {
        "0.0.0.0:0".parse().expect("valid v4 bind")
    } else {
        "[::]:0".parse().expect("valid v6 bind")
    };
    let mut endpoint = quinn::Endpoint::client(bind_addr)
        .map_err(|e| CoreError::Upstream(format!("DoQ endpoint bind failed: {e}")))?;
    endpoint.set_default_client_config(client_config.clone());

    let conn = endpoint
        .connect(addr, server_name)
        .map_err(|e| CoreError::Upstream(format!("DoQ connect setup failed: {e}")))?
        .await
        .map_err(|e| CoreError::Upstream(format!("DoQ handshake failed: {e}")))?;

    let resp = doq_roundtrip(&conn, query_wire).await?;
    pool.put(conn);
    Ok(resp)
}

async fn tcp_roundtrip<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
    query_wire: &[u8],
) -> Result<Vec<u8>> {
    send_tcp_framed(stream, query_wire).await?;
    read_tcp_framed(stream).await
}

pub(crate) async fn send_tcp_framed<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    payload: &[u8],
) -> Result<()> {
    let len = u16::try_from(payload.len())
        .map_err(|_| CoreError::Protocol("DNS message exceeds 65535 bytes".to_string()))?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

pub(crate) async fn read_tcp_framed<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_exchange_doh_rejects_oversized_chunked_response() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut req_buf = [0_u8; 1024];
                let mut total = 0;
                while total < req_buf.len() {
                    let Ok(n) = stream.read(&mut req_buf[total..]).await else {
                        break;
                    };
                    if n == 0 {
                        break;
                    }
                    total += n;
                    if let Some(pos) = req_buf[..total].windows(4).position(|w| w == b"\r\n\r\n")
                        && total >= pos + 4 + 3
                    {
                        break;
                    }
                }
                let header = "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nTransfer-Encoding: chunked\r\n\r\n";
                let _ = stream.write_all(header.as_bytes()).await;
                // Two 40KB chunks exceed MAX_DOH_RESPONSE_BYTES (65,535) without Content-Length.
                let chunk_data = vec![b'A'; 40_000];
                let chunk_hdr = format!("{:x}\r\n", chunk_data.len());
                for _ in 0..2 {
                    let _ = stream.write_all(chunk_hdr.as_bytes()).await;
                    let _ = stream.write_all(&chunk_data).await;
                    let _ = stream.write_all(b"\r\n").await;
                }
                let _ = stream.write_all(b"0\r\n\r\n").await;
                let _ = stream.flush().await;
                let _ = done_rx.await;
            }
        });

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .expect("client");
        let err = exchange_doh(&client, &format!("http://{addr}/dns-query"), &[0, 1, 2])
            .await
            .expect_err("oversized chunked DoH response must fail");
        let _ = done_tx.send(());
        assert!(err.to_string().contains("exceeds"), "unexpected err: {err}");
    }
}
