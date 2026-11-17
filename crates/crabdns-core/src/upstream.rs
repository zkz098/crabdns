use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use futures_util::future::select_ok;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
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

#[derive(Debug, Clone)]
enum BootstrapEndpoint {
    Udp(SocketAddr),
    Tcp(SocketAddr),
}

fn parse_bootstrap_endpoint(raw: &str) -> Result<BootstrapEndpoint> {
    let trimmed = raw.trim();
    if let Some(rest) = trimmed.strip_prefix("udp://") {
        return Ok(BootstrapEndpoint::Udp(parse_socket_addr(rest, 53)?));
    }
    if let Some(rest) = trimmed.strip_prefix("tcp://") {
        return Ok(BootstrapEndpoint::Tcp(parse_socket_addr(rest, 53)?));
    }
    if trimmed.starts_with("tls://") || trimmed.starts_with("https://") {
        return Err(CoreError::Config(format!(
            "bootstrap_dns must be IP addresses (udp:// or tcp://): {trimmed}"
        )));
    }
    Ok(BootstrapEndpoint::Udp(parse_socket_addr(trimmed, 53)?))
}

#[derive(Debug, Clone)]
struct CachedIpEntry {
    ips: Vec<IpAddr>,
    expires_at: Instant,
}

#[derive(Debug, Clone)]
struct BootstrapResolver {
    endpoints: Vec<BootstrapEndpoint>,
    timeout: Duration,
    cache: Arc<DashMap<String, CachedIpEntry>>,
}

impl BootstrapResolver {
    fn new(specs: &[String], timeout: Duration) -> Result<Self> {
        let mut endpoints = Vec::with_capacity(specs.len());
        for spec in specs {
            let trimmed = spec.trim();
            if !trimmed.is_empty() {
                endpoints.push(parse_bootstrap_endpoint(trimmed)?);
            }
        }
        Ok(Self {
            endpoints,
            timeout,
            cache: Arc::new(DashMap::new()),
        })
    }

    fn is_empty(&self) -> bool {
        self.endpoints.is_empty()
    }

    async fn resolve_ips(&self, host: &str) -> Result<Vec<IpAddr>> {
        let host_clean = host.trim().trim_start_matches('[').trim_end_matches(']');
        if let Ok(ip) = host_clean.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }

        let key = host_clean.trim_end_matches('.').to_ascii_lowercase();
        if key.is_empty() {
            return Err(CoreError::Upstream("empty upstream hostname".to_string()));
        }

        if let Some(entry) = self.cache.get(&key)
            && Instant::now() < entry.expires_at
        {
            return Ok(entry.ips.clone());
        }

        for endpoint in &self.endpoints {
            if let Ok((ips, ttl_secs)) = query_bootstrap_host(endpoint, &key, self.timeout).await
                && !ips.is_empty()
            {
                let ttl = Duration::from_secs(u64::from(ttl_secs).clamp(30, 3600));
                self.cache.insert(
                    key,
                    CachedIpEntry {
                        ips: ips.clone(),
                        expires_at: Instant::now() + ttl,
                    },
                );
                return Ok(ips);
            }
        }

        Err(CoreError::Upstream(format!(
            "bootstrap DNS failed to resolve '{host_clean}'"
        )))
    }

    async fn resolve_socket_addrs(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>> {
        let host_clean = host.trim().trim_start_matches('[').trim_end_matches(']');
        if let Ok(ip) = host_clean.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }

        if self.is_empty() {
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host_clean, port))
                .await
                .map_err(|e| {
                    CoreError::Upstream(format!("failed to resolve '{host_clean}:{port}': {e}"))
                })?
                .collect();
            if addrs.is_empty() {
                return Err(CoreError::Upstream(format!(
                    "DNS resolution returned no addresses for '{host_clean}'"
                )));
            }
            return Ok(addrs);
        }

        let ips = self.resolve_ips(host_clean).await?;
        Ok(ips
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect())
    }
}

impl reqwest::dns::Resolve for BootstrapResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let this = self.clone();
        let host = name.as_str().to_string();
        Box::pin(async move {
            let ips = this
                .resolve_ips(&host)
                .await
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
            let addrs: reqwest::dns::Addrs =
                Box::new(ips.into_iter().map(|ip| SocketAddr::new(ip, 0)));
            Ok(addrs)
        })
    }
}

async fn query_bootstrap_host(
    endpoint: &BootstrapEndpoint,
    host: &str,
    timeout: Duration,
) -> Result<(Vec<IpAddr>, u32)> {
    let fqdn = format!("{host}.");
    let name = Name::from_ascii(&fqdn)
        .map_err(|e| CoreError::Upstream(format!("invalid hostname '{host}': {e}")))?;

    let (res_a, res_aaaa) = tokio::join!(
        query_bootstrap_record(endpoint, name.clone(), RecordType::A, 0xB001, timeout),
        query_bootstrap_record(endpoint, name, RecordType::AAAA, 0xB002, timeout),
    );

    let mut ips = Vec::new();
    let mut min_ttl = u32::MAX;
    for (found_ips, ttl) in [res_a, res_aaaa].into_iter().flatten() {
        ips.extend(found_ips);
        if let Some(t) = ttl {
            min_ttl = min_ttl.min(t);
        }
    }

    if ips.is_empty() {
        return Err(CoreError::Upstream(format!(
            "no A/AAAA records for '{host}'"
        )));
    }
    let ttl_secs = if min_ttl == u32::MAX { 60 } else { min_ttl };
    Ok((ips, ttl_secs))
}

async fn query_bootstrap_record(
    endpoint: &BootstrapEndpoint,
    name: Name,
    rtype: RecordType,
    tx_id: u16,
    timeout: Duration,
) -> Result<(Vec<IpAddr>, Option<u32>)> {
    let mut msg = Message::new(tx_id, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(name, rtype));
    let wire = msg
        .to_vec()
        .map_err(|e| CoreError::Protocol(format!("failed to encode bootstrap query: {e}")))?;

    let raw_resp = tokio::time::timeout(timeout, async {
        match endpoint {
            BootstrapEndpoint::Udp(addr) => {
                let bind_addr = if addr.is_ipv4() {
                    "0.0.0.0:0"
                } else {
                    "[::]:0"
                };
                let sock = UdpSocket::bind(bind_addr).await?;
                sock.connect(*addr).await?;
                sock.send(&wire).await?;
                let mut buf = vec![0_u8; 4096];
                let n = sock.recv(&mut buf).await?;
                buf.truncate(n);
                Ok::<Vec<u8>, CoreError>(buf)
            }
            BootstrapEndpoint::Tcp(addr) => exchange_tcp(*addr, &wire).await,
        }
    })
    .await
    .map_err(|_| CoreError::Upstream("bootstrap DNS query timed out".to_string()))??;

    let resp = Message::from_vec(&raw_resp)
        .map_err(|e| CoreError::Protocol(format!("invalid bootstrap DNS response: {e}")))?;
    if resp.response_code != ResponseCode::NoError {
        return Err(CoreError::Upstream(format!(
            "bootstrap DNS returned {}",
            resp.response_code
        )));
    }

    let mut ips = Vec::new();
    let mut min_ttl: Option<u32> = None;
    for rec in &resp.answers {
        match &rec.data {
            RData::A(v4) if rtype == RecordType::A => {
                ips.push(IpAddr::V4(v4.0));
                min_ttl = Some(min_ttl.map_or(rec.ttl, |cur| cur.min(rec.ttl)));
            }
            RData::AAAA(v6) if rtype == RecordType::AAAA => {
                ips.push(IpAddr::V6(v6.0));
                min_ttl = Some(min_ttl.map_or(rec.ttl, |cur| cur.min(rec.ttl)));
            }
            _ => {}
        }
    }
    Ok((ips, min_ttl))
}

pub struct UpstreamPool {
    endpoints: Vec<UpstreamEndpoint>,
    health: Vec<EndpointHealth>,
    udp_pools: Vec<UdpSocketPool>,
    strategy: UpstreamStrategy,
    timeout: Duration,
    bootstrap: BootstrapResolver,
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
        Self::new_with_bootstrap(specs, timeout_ms, strategy, &[])
    }

    pub fn new_with_bootstrap(
        specs: &[String],
        timeout_ms: u64,
        strategy: UpstreamStrategy,
        bootstrap_dns: &[String],
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
        let bootstrap = BootstrapResolver::new(bootstrap_dns, timeout)?;

        let mut client_builder = reqwest::Client::builder().timeout(timeout);
        if !bootstrap.is_empty() {
            client_builder = client_builder.dns_resolver(Arc::new(bootstrap.clone()));
        }
        let http_client = client_builder
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
            bootstrap,
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
                exchange_dot(
                    &self.tls_connector,
                    &self.bootstrap,
                    addr,
                    server_name,
                    query_wire,
                )
                .await
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
    bootstrap: &BootstrapResolver,
    addr: &str,
    server_name: &str,
    query_wire: &[u8],
) -> Result<Vec<u8>> {
    let (host, port) = split_host_port(addr, 853);
    let addrs = bootstrap.resolve_socket_addrs(&host, port).await?;
    let stream = TcpStream::connect(addrs.as_slice()).await?;
    let clean_sni = server_name.trim_start_matches('[').trim_end_matches(']');
    let name = ServerName::try_from(clean_sni.to_string())
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

    #[test]
    fn test_bootstrap_endpoint_validation() {
        assert!(BootstrapResolver::new(
            &[
                "1.1.1.1".to_string(),
                "udp://8.8.8.8:53".to_string(),
                "tcp://9.9.9.9:53".to_string(),
                "[2606:4700:4700::1111]:53".to_string(),
            ],
            Duration::from_millis(500),
        )
        .is_ok());

        for invalid in [
            "dns.google",
            "tls://dns.google",
            "https://dns.google/dns-query",
        ] {
            assert!(
                BootstrapResolver::new(&[invalid.to_string()], Duration::from_millis(500)).is_err(),
                "expected {invalid} to be rejected"
            );
        }
    }

    #[tokio::test]
    async fn test_bootstrap_resolver_queries_and_caches() {
        use hickory_proto::rr::Record;
        use hickory_proto::rr::rdata::A;
        use std::net::Ipv4Addr;

        let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind mock");
        let mock_addr = sock.local_addr().expect("addr");
        let hits = Arc::new(AtomicU32::new(0));
        let hits_clone = Arc::clone(&hits);

        tokio::spawn(async move {
            let mut buf = [0_u8; 512];
            while let Ok((len, peer)) = sock.recv_from(&mut buf).await {
                let req = Message::from_vec(&buf[..len]).expect("valid query");
                let q = req.queries.first().expect("question").clone();
                let mut resp = Message::new(req.id, MessageType::Response, OpCode::Query);
                resp.metadata.recursion_desired = true;
                resp.metadata.recursion_available = true;
                resp.metadata.response_code = ResponseCode::NoError;
                resp.add_query(q.clone());
                if q.query_type == RecordType::A {
                    hits_clone.fetch_add(1, Ordering::SeqCst);
                    resp.add_answer(Record::from_rdata(
                        q.name,
                        120,
                        RData::A(A(Ipv4Addr::new(127, 0, 0, 10))),
                    ));
                }
                let wire = resp.to_vec().expect("encode resp");
                let _ = sock.send_to(&wire, peer).await;
            }
        });

        let resolver = BootstrapResolver::new(
            &[format!("udp://{mock_addr}")],
            Duration::from_millis(1000),
        )
        .expect("resolver");

        // IP literals bypass DNS queries.
        let literal = resolver.resolve_ips("127.0.0.1").await.expect("literal");
        assert_eq!(literal, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
        assert_eq!(hits.load(Ordering::SeqCst), 0);

        // First query hits mock bootstrap server; second hits cache.
        let ips1 = resolver
            .resolve_ips("doh.example.test")
            .await
            .expect("resolve 1");
        assert_eq!(ips1, vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 10))]);
        assert_eq!(hits.load(Ordering::SeqCst), 1);

        let ips2 = resolver
            .resolve_ips("doh.example.test")
            .await
            .expect("resolve 2");
        assert_eq!(ips2, vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 10))]);
        assert_eq!(hits.load(Ordering::SeqCst), 1);

        // reqwest::dns::Resolve trait integration.
        let reqwest_name: reqwest::dns::Name = "doh.example.test".parse().expect("reqwest name");
        let addrs: Vec<SocketAddr> = reqwest::dns::Resolve::resolve(&resolver, reqwest_name)
            .await
            .expect("reqwest resolve")
            .collect();
        assert_eq!(addrs, vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 10)), 0)]);
    }
}
