use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::ServerName;

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
        if guard.len() < CONN_POOL_MAX_IDLE {
            guard.push(PooledConn {
                stream,
                last_used: Instant::now(),
            });
        }
    }
}

fn tx_id_matches(query: &[u8], resp: &[u8]) -> bool {
    if query.len() < 2 || resp.len() < 2 {
        return true;
    }
    query[0..2] == resp[0..2]
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
    if tx_id_matches(query_wire, &resp) {
        pool.put(fresh);
    }
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
    if let Some(mut stream) = pool.pop_fresh()
        && let Ok(resp) = tcp_roundtrip(&mut stream, query_wire).await
        && tx_id_matches(query_wire, &resp)
    {
        pool.put(stream);
        return Ok(resp);
    }

    let mut stream = TcpStream::connect(addr).await?;
    let _ = stream.set_nodelay(true);
    let resp = tcp_roundtrip(&mut stream, query_wire).await?;
    if tx_id_matches(query_wire, &resp) {
        pool.put(stream);
    }
    Ok(resp)
}

pub(crate) async fn try_exchange_dot_pooled(
    pool: &ConnPool<TlsStream<TcpStream>>,
    query_wire: &[u8],
) -> Option<Vec<u8>> {
    let mut tls_stream = pool.pop_fresh()?;
    if let Ok(resp) = tcp_roundtrip(&mut tls_stream, query_wire).await
        && tx_id_matches(query_wire, &resp)
    {
        pool.put(tls_stream);
        return Some(resp);
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
    if tx_id_matches(query_wire, &resp) {
        pool.put(tls_stream);
    }
    Ok(resp)
}

pub(crate) async fn exchange_doh(
    client: &reqwest::Client,
    url: &str,
    query_wire: &[u8],
) -> Result<Vec<u8>> {
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
