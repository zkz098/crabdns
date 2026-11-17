use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use futures_util::future::select_ok;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use ts_rs::TS;

use crate::config::UpstreamStrategy;
use crate::error::{CoreError, Result};

const UNHEALTHY_FAILURE_THRESHOLD: u32 = 3;
const UNHEALTHY_COOLDOWN_MS: u64 = 15_000;
const UDP_SOCKET_POOL_MAX_IDLE: usize = 128;

#[derive(Debug, Default)]
struct UdpSocketPool {
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

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct UpstreamStatus {
    pub endpoint: String,
    pub healthy: bool,
    pub consecutive_failures: u32,
    #[ts(type = "number")]
    pub ewma_latency_ms: u64,
    #[ts(type = "number")]
    pub total_requests: u64,
    #[ts(type = "number")]
    pub total_failures: u64,
}

#[derive(Debug, Default)]
struct EndpointHealth {
    consecutive_failures: AtomicU32,
    unhealthy_until_ms: AtomicU64,
    ewma_latency_us: AtomicU64,
    total_requests: AtomicU64,
    total_failures: AtomicU64,
}

impl EndpointHealth {
    fn is_healthy(&self, now_ms: u64) -> bool {
        let until = self.unhealthy_until_ms.load(Ordering::Relaxed);
        until == 0 || now_ms >= until
    }

    fn record_success(&self, elapsed_us: u64) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.consecutive_failures.store(0, Ordering::Relaxed);
        self.unhealthy_until_ms.store(0, Ordering::Relaxed);

        let prev = self.ewma_latency_us.load(Ordering::Relaxed);
        let next = if prev == 0 {
            elapsed_us.max(1)
        } else {
            (prev * 7 + elapsed_us.max(1)) / 8
        };
        self.ewma_latency_us.store(next, Ordering::Relaxed);
    }

    fn record_failure(&self, now_ms: u64) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.total_failures.fetch_add(1, Ordering::Relaxed);
        let fails = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        if fails >= UNHEALTHY_FAILURE_THRESHOLD {
            self.unhealthy_until_ms
                .store(now_ms + UNHEALTHY_COOLDOWN_MS, Ordering::Relaxed);
        }
    }

    fn snapshot(&self, label: String, now_ms: u64) -> UpstreamStatus {
        UpstreamStatus {
            endpoint: label,
            healthy: self.is_healthy(now_ms),
            consecutive_failures: self.consecutive_failures.load(Ordering::Relaxed),
            ewma_latency_ms: self.ewma_latency_us.load(Ordering::Relaxed) / 1000,
            total_requests: self.total_requests.load(Ordering::Relaxed),
            total_failures: self.total_failures.load(Ordering::Relaxed),
        }
    }
}

fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

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
    health: Vec<EndpointHealth>,
    udp_pools: Vec<UdpSocketPool>,
    strategy: UpstreamStrategy,
    timeout: Duration,
    http_client: reqwest::Client,
    tls_connector: TlsConnector,
}

impl UpstreamPool {
    pub fn new(specs: &[String], timeout_ms: u64) -> Result<Self> {
        Self::new_with_strategy(specs, timeout_ms, UpstreamStrategy::Failover)
    }

    pub fn new_with_strategy(
        specs: &[String],
        timeout_ms: u64,
        strategy: UpstreamStrategy,
    ) -> Result<Self> {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let mut endpoints = Vec::with_capacity(specs.len());
        for spec in specs {
            endpoints.push(UpstreamEndpoint::parse(spec)?);
        }
        if endpoints.is_empty() {
            return Err(CoreError::Config(
                "at least one upstream DNS server is required".to_string(),
            ));
        }

        let health = (0..endpoints.len())
            .map(|_| EndpointHealth::default())
            .collect();
        let udp_pools = (0..endpoints.len())
            .map(|_| UdpSocketPool::default())
            .collect();
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
            health,
            udp_pools,
            strategy,
            timeout,
            http_client,
            tls_connector,
        })
    }

    pub fn strategy(&self) -> UpstreamStrategy {
        self.strategy
    }

    pub fn health_snapshot(&self) -> Vec<UpstreamStatus> {
        let now_ms = now_epoch_ms();
        self.endpoints
            .iter()
            .zip(&self.health)
            .map(|(ep, h)| h.snapshot(endpoint_label(ep), now_ms))
            .collect()
    }

    pub async fn probe_all(&self) {
        // Minimal DNS query for root NS (ID=0x4242, RD=1, QDCOUNT=1, QNAME=., QTYPE=NS, QCLASS=IN)
        const PROBE_QUERY: [u8; 17] = [
            0x42, 0x42, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x02, 0x00, 0x01,
        ];
        for idx in 0..self.endpoints.len() {
            let _ = self.try_endpoint(idx, &PROBE_QUERY).await;
        }
    }

    pub async fn exchange(&self, query_wire: &[u8]) -> Result<(Vec<u8>, String)> {
        let candidates = self.ordered_candidates();
        if self.strategy == UpstreamStrategy::Parallel && candidates.len() > 1 {
            return self.exchange_parallel(&candidates, query_wire).await;
        }
        self.exchange_sequential(&candidates, query_wire).await
    }

    fn ordered_candidates(&self) -> Vec<usize> {
        let now_ms = now_epoch_ms();
        let mut healthy: Vec<usize> = (0..self.endpoints.len())
            .filter(|&i| self.health[i].is_healthy(now_ms))
            .collect();
        if healthy.is_empty() {
            healthy = (0..self.endpoints.len()).collect();
        }
        if self.strategy == UpstreamStrategy::LeastLatency {
            healthy.sort_by_key(|&i| {
                let lat = self.health[i].ewma_latency_us.load(Ordering::Relaxed);
                if lat == 0 { 0 } else { lat }
            });
        }
        healthy
    }

    async fn exchange_sequential(
        &self,
        candidates: &[usize],
        query_wire: &[u8],
    ) -> Result<(Vec<u8>, String)> {
        let mut last_err = CoreError::Upstream("no upstream endpoints configured".to_string());
        for &idx in candidates {
            match self.try_endpoint(idx, query_wire).await {
                Ok(ok) => return Ok(ok),
                Err(err) => last_err = err,
            }
        }
        Err(last_err)
    }

    async fn exchange_parallel(
        &self,
        candidates: &[usize],
        query_wire: &[u8],
    ) -> Result<(Vec<u8>, String)> {
        let futs: Vec<_> = candidates
            .iter()
            .map(|&idx| Box::pin(self.try_endpoint(idx, query_wire)))
            .collect();
        match select_ok(futs).await {
            Ok((res, _remaining)) => Ok(res),
            Err(err) => Err(err),
        }
    }

    async fn try_endpoint(&self, idx: usize, query_wire: &[u8]) -> Result<(Vec<u8>, String)> {
        let endpoint = &self.endpoints[idx];
        let health = &self.health[idx];
        let label = endpoint_label(endpoint);
        let start = Instant::now();

        match tokio::time::timeout(self.timeout, self.exchange_one(idx, endpoint, query_wire)).await {
            Ok(Ok(resp)) => {
                let elapsed_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
                health.record_success(elapsed_us);
                Ok((resp, label))
            }
            Ok(Err(err)) => {
                tracing::warn!(upstream = %label, error = %err, "upstream query failed");
                health.record_failure(now_epoch_ms());
                Err(err)
            }
            Err(_) => {
                tracing::warn!(upstream = %label, "upstream query timed out");
                health.record_failure(now_epoch_ms());
                Err(CoreError::Upstream(format!("upstream {label} timed out")))
            }
        }
    }

    async fn exchange_one(
        &self,
        idx: usize,
        endpoint: &UpstreamEndpoint,
        query_wire: &[u8],
    ) -> Result<Vec<u8>> {
        match endpoint {
            UpstreamEndpoint::Udp(addr) => exchange_udp(*addr, &self.udp_pools[idx], query_wire).await,
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

async fn exchange_udp(
    addr: SocketAddr,
    pool: &UdpSocketPool,
    query_wire: &[u8],
) -> Result<Vec<u8>> {
    let socket = if let Some(sock) = pool.pop() {
        sock
    } else {
        let bind_addr = if addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let sock = UdpSocket::bind(bind_addr).await?;
        sock.connect(addr).await?;
        sock
    };

    socket.send(query_wire).await?;

    let mut buf = vec![0_u8; 4096];
    let n = socket.recv(&mut buf).await?;
    buf.truncate(n);
    pool.put(socket);
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

    #[tokio::test]
    async fn test_parallel_strategy_and_circuit_breaker() {
        let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind mock");
        let mock_addr = sock.local_addr().expect("addr");
        tokio::spawn(async move {
            let mut buf = [0_u8; 512];
            while let Ok((len, peer)) = sock.recv_from(&mut buf).await {
                let _ = sock.send_to(&buf[..len], peer).await;
            }
        });

        let pool = UpstreamPool::new_with_strategy(
            &[
                "udp://127.0.0.1:1".to_string(),
                format!("udp://{mock_addr}"),
            ],
            500,
            UpstreamStrategy::Parallel,
        )
        .expect("pool");

        let (resp, label) = pool
            .exchange(&[0x12, 0x34, 0, 0])
            .await
            .expect("parallel ok");
        assert_eq!(resp, vec![0x12, 0x34, 0, 0]);
        assert_eq!(label, format!("udp://{mock_addr}"));

        let snap = pool.health_snapshot();
        assert_eq!(snap.len(), 2);
        assert!(snap[1].healthy);
        assert_eq!(snap[1].total_requests, 1);

        // Trigger circuit breaker on dead endpoint
        let dead_pool =
            UpstreamPool::new(&["udp://127.0.0.1:1".to_string()], 50).expect("dead pool");
        for _ in 0..UNHEALTHY_FAILURE_THRESHOLD {
            assert!(dead_pool.exchange(&[1, 2, 3]).await.is_err());
        }
        let dead_snap = dead_pool.health_snapshot();
        assert!(!dead_snap[0].healthy);
        assert_eq!(
            dead_snap[0].consecutive_failures,
            UNHEALTHY_FAILURE_THRESHOLD
        );
    }
}
