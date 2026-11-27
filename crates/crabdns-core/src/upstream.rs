use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use foldhash::fast::RandomState;
use futures_util::future::select_ok;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use moka::sync::Cache;
use tokio::net::{TcpStream, UdpSocket};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

use crate::clock::monotonic_now_ms;
use crate::config::UpstreamStrategy;
use crate::error::{CoreError, Result};
use crate::singleflight::{FlightRole, Singleflight, wait_follower};
use crate::upstream_health::{EndpointHealth, ProbeGuard, is_upstream_error_rcode, wire_rcode};
use crate::upstream_proxy::{ParsedProxy, exchange_endpoint_via_proxy};
pub use crate::upstream_transport::UpstreamEndpoint;
pub use crate::upstream_transport::UpstreamStatus;
use crate::upstream_transport::{
    ConnPool, H3Session, UdpSocketPool, build_doq_client_config, build_h3_client_config,
    exchange_doh, exchange_doq_addrs, exchange_dot_addrs, exchange_h3_addrs, exchange_tcp,
    exchange_tcp_pooled, exchange_udp, is_udp_truncated, parse_socket_addr,
    try_exchange_doq_pooled, try_exchange_dot_pooled, try_exchange_h3_pooled,
};
pub(crate) use crate::upstream_transport::{
    endpoint_label, read_tcp_framed, send_tcp_framed, split_host_port,
};

const BOOTSTRAP_CACHE_CAPACITY: u64 = 256;

static TX_ID_SEQ: AtomicU64 = AtomicU64::new(0x9E37_79B9_7F4A_7C15);

/// Generates a low-collision DNS transaction ID for internal queries (bootstrap, DNSSEC, rDNS).
pub(crate) fn next_tx_id() -> u16 {
    let nanos = u64::from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos()),
    );
    let seq = TX_ID_SEQ.fetch_add(1, Ordering::Relaxed);
    let mixed = (seq ^ nanos).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    ((mixed >> 32) ^ mixed) as u16
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
    if trimmed.starts_with("tls://")
        || trimmed.starts_with("https://")
        || trimmed.starts_with("quic://")
        || trimmed.starts_with("h3://")
    {
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

#[derive(Clone)]
pub(crate) struct BootstrapResolver {
    endpoints: Vec<BootstrapEndpoint>,
    timeout: Duration,
    cache: Cache<String, CachedIpEntry, RandomState>,
    inflight: Arc<Singleflight<String, Vec<IpAddr>>>,
}

impl BootstrapResolver {
    pub(crate) fn new(specs: &[String], timeout: Duration) -> Result<Self> {
        let mut endpoints = Vec::with_capacity(specs.len());
        for spec in specs {
            let trimmed = spec.trim();
            if !trimmed.is_empty() {
                endpoints.push(parse_bootstrap_endpoint(trimmed)?);
            }
        }
        let cache = Cache::builder()
            .max_capacity(BOOTSTRAP_CACHE_CAPACITY)
            .time_to_live(Duration::from_hours(1))
            .build_with_hasher(RandomState::default());
        Ok(Self {
            endpoints,
            timeout,
            cache,
            inflight: Arc::new(Singleflight::new()),
        })
    }

    pub(crate) fn is_empty(&self) -> bool {
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
            return Ok(entry.ips);
        }

        match self.inflight.acquire(key.clone()) {
            FlightRole::Leader(guard) => {
                if let Some(entry) = self.cache.get(&key)
                    && Instant::now() < entry.expires_at
                {
                    guard.complete(Ok(entry.ips.clone()));
                    return Ok(entry.ips);
                }
                for endpoint in &self.endpoints {
                    if let Ok((ips, ttl_secs)) =
                        query_bootstrap_host(endpoint, &key, self.timeout).await
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
                        guard.complete(Ok(ips.clone()));
                        return Ok(ips);
                    }
                }
                let msg = format!("bootstrap DNS failed to resolve '{host_clean}'");
                guard.complete(Err(msg.clone()));
                Err(CoreError::Upstream(msg))
            }
            FlightRole::Follower(rx) => wait_follower(rx).await.map_err(CoreError::Upstream),
        }
    }

    pub(crate) async fn resolve_socket_addrs(
        &self,
        host: &str,
        port: u16,
    ) -> Result<Vec<SocketAddr>> {
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
        query_bootstrap_record(endpoint, name.clone(), RecordType::A, next_tx_id(), timeout),
        query_bootstrap_record(endpoint, name, RecordType::AAAA, next_tx_id(), timeout),
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
    if resp.id != tx_id {
        return Err(CoreError::Upstream(
            "bootstrap DNS response transaction ID mismatch".to_string(),
        ));
    }
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

enum EndpointAttempt {
    Ok((Vec<u8>, String)),
    ErrorResponse((Vec<u8>, String)),
    TransportErr(CoreError),
}

pub struct UpstreamPool {
    endpoints: Vec<UpstreamEndpoint>,
    health: Vec<EndpointHealth>,
    udp_pools: Vec<UdpSocketPool>,
    tcp_pools: Vec<ConnPool<TcpStream>>,
    dot_pools: Vec<ConnPool<TlsStream<TcpStream>>>,
    doq_pools: Vec<ConnPool<quinn::Connection>>,
    h3_pools: Vec<ConnPool<H3Session>>,
    strategy: UpstreamStrategy,
    timeout: Duration,
    bootstrap: BootstrapResolver,
    http_client: reqwest::Client,
    tls_connector: TlsConnector,
    doq_client_config: quinn::ClientConfig,
    h3_client_config: quinn::ClientConfig,
    proxy: Option<ParsedProxy>,
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
        Self::new_with_options(specs, timeout_ms, strategy, bootstrap_dns, None)
    }

    pub fn new_with_options(
        specs: &[String],
        timeout_ms: u64,
        strategy: UpstreamStrategy,
        bootstrap_dns: &[String],
        proxy_url: Option<&str>,
    ) -> Result<Self> {
        let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
        let mut endpoints = Vec::with_capacity(specs.len());
        for spec in specs {
            endpoints.push(UpstreamEndpoint::parse(spec)?);
        }
        if endpoints.is_empty() {
            return Err(CoreError::Config(
                "at least one upstream DNS server is required".to_string(),
            ));
        }

        let proxy = match proxy_url.map(str::trim).filter(|s| !s.is_empty()) {
            Some(raw) => {
                let parsed = ParsedProxy::parse(raw)?;
                if endpoints.iter().any(|ep| {
                    matches!(
                        ep,
                        UpstreamEndpoint::Udp(_)
                            | UpstreamEndpoint::Doq { .. }
                            | UpstreamEndpoint::Doh3 { .. }
                    )
                }) {
                    return Err(CoreError::Config(
                        "proxy_url only supports tcp://, tls://, and https:// upstreams"
                            .to_string(),
                    ));
                }
                Some(parsed)
            }
            None => None,
        };

        let health = (0..endpoints.len())
            .map(|_| EndpointHealth::default())
            .collect();
        let udp_pools = (0..endpoints.len())
            .map(|_| UdpSocketPool::default())
            .collect();
        let tcp_pools = (0..endpoints.len()).map(|_| ConnPool::default()).collect();
        let dot_pools = (0..endpoints.len()).map(|_| ConnPool::default()).collect();
        let quic_pools = (0..endpoints.len()).map(|_| ConnPool::default()).collect();
        let h3_pools = (0..endpoints.len()).map(|_| ConnPool::default()).collect();
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
        let doq_client_config = build_doq_client_config()?;
        let h3_client_config = build_h3_client_config()?;

        Ok(Self {
            endpoints,
            health,
            udp_pools,
            tcp_pools,
            dot_pools,
            doq_pools: quic_pools,
            h3_pools,
            strategy,
            timeout,
            bootstrap,
            http_client,
            tls_connector,
            doq_client_config,
            h3_client_config,
            proxy,
        })
    }

    pub fn endpoint_labels(&self) -> Vec<String> {
        self.endpoints.iter().map(endpoint_label).collect()
    }

    pub fn strategy(&self) -> UpstreamStrategy {
        self.strategy
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    pub fn query_budget(&self) -> Duration {
        let mult = u32::try_from(self.endpoints.len().clamp(1, 3)).unwrap_or(3);
        self.timeout
            .saturating_mul(mult)
            .clamp(Duration::from_secs(3), Duration::from_secs(30))
    }

    pub fn has_private_endpoint(&self) -> bool {
        self.endpoints.iter().any(|ep| match ep {
            UpstreamEndpoint::Udp(addr) | UpstreamEndpoint::Tcp(addr) => {
                crate::security::is_private_or_special_ip(addr.ip())
            }
            UpstreamEndpoint::Dot { .. }
            | UpstreamEndpoint::Doh { .. }
            | UpstreamEndpoint::Doq { .. }
            | UpstreamEndpoint::Doh3 { .. } => false,
        })
    }

    pub fn health_snapshot(&self) -> Vec<UpstreamStatus> {
        let now_ms = monotonic_now_ms();
        self.endpoints
            .iter()
            .zip(&self.health)
            .map(|(ep, h)| h.snapshot(endpoint_label(ep), now_ms))
            .collect()
    }

    pub fn has_healthy_endpoint(&self) -> bool {
        let now_ms = monotonic_now_ms();
        self.health.iter().any(|h| h.is_healthy(now_ms))
    }

    pub async fn probe_all(&self) {
        // Minimal DNS query for root NS (ID=0x4242, RD=1, QDCOUNT=1, QNAME=., QTYPE=NS, QCLASS=IN)
        const PROBE_QUERY: [u8; 17] = [
            0x42, 0x42, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x02, 0x00, 0x01,
        ];
        for idx in 0..self.endpoints.len() {
            let _ = self.try_endpoint(idx, &PROBE_QUERY, None).await;
        }
    }

    pub async fn exchange(&self, query_wire: &[u8]) -> Result<(Vec<u8>, String)> {
        let candidates = self.ordered_candidates();
        if self.strategy == UpstreamStrategy::Parallel && candidates.len() > 1 {
            return self.exchange_parallel(candidates, query_wire).await;
        }
        self.exchange_sequential(candidates, query_wire).await
    }

    fn ordered_candidates(&self) -> Vec<(usize, Option<ProbeGuard<'_>>)> {
        let now_ms = monotonic_now_ms();
        let mut selected = Vec::with_capacity(self.endpoints.len());
        for (i, health) in self.health.iter().enumerate() {
            let (ok, guard) = health.try_select(now_ms);
            if ok {
                selected.push((i, guard));
            }
        }
        if selected.is_empty() {
            selected = (0..self.endpoints.len()).map(|i| (i, None)).collect();
        }
        if self.strategy == UpstreamStrategy::LeastLatency {
            selected.sort_by_key(|(i, _)| {
                let lat = self.health[*i].ewma_latency_us.load(Ordering::Relaxed);
                let fails = self.health[*i].consecutive_failures.load(Ordering::Relaxed);
                let base = if lat == 0 { 0 } else { lat };
                base.saturating_add(u64::from(fails).saturating_mul(50_000))
            });
        }
        selected
    }

    async fn exchange_sequential(
        &self,
        candidates: Vec<(usize, Option<ProbeGuard<'_>>)>,
        query_wire: &[u8],
    ) -> Result<(Vec<u8>, String)> {
        let mut last_err = CoreError::Upstream("no upstream endpoints configured".to_string());
        let mut fallback_err_resp: Option<(Vec<u8>, String)> = None;
        for (idx, guard) in candidates {
            match self.try_endpoint(idx, query_wire, guard).await {
                EndpointAttempt::Ok(ok) => return Ok(ok),
                EndpointAttempt::ErrorResponse(resp) => {
                    if fallback_err_resp.is_none() {
                        fallback_err_resp = Some(resp);
                    }
                }
                EndpointAttempt::TransportErr(err) => last_err = err,
            }
        }
        if let Some(resp) = fallback_err_resp {
            return Ok(resp);
        }
        Err(last_err)
    }

    async fn exchange_parallel(
        &self,
        candidates: Vec<(usize, Option<ProbeGuard<'_>>)>,
        query_wire: &[u8],
    ) -> Result<(Vec<u8>, String)> {
        let fallback_err_resp: std::sync::Mutex<Option<(Vec<u8>, String)>> =
            std::sync::Mutex::new(None);
        let fallback_ref = &fallback_err_resp;
        let futs: Vec<_> = candidates
            .into_iter()
            .map(|(idx, guard)| {
                Box::pin(async move {
                    match self.try_endpoint(idx, query_wire, guard).await {
                        EndpointAttempt::Ok(ok) => Ok(ok),
                        EndpointAttempt::ErrorResponse(resp) => {
                            let label = resp.1.clone();
                            let rcode = wire_rcode(&resp.0);
                            let mut slot = fallback_ref
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            if slot.is_none() {
                                *slot = Some(resp);
                            }
                            Err(CoreError::Upstream(format!(
                                "upstream {label} returned error rcode {rcode}"
                            )))
                        }
                        EndpointAttempt::TransportErr(err) => Err(err),
                    }
                })
            })
            .collect();
        match select_ok(futs).await {
            Ok((res, _remaining)) => Ok(res),
            Err(err) => {
                if let Some(resp) = fallback_err_resp
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take()
                {
                    return Ok(resp);
                }
                Err(err)
            }
        }
    }

    async fn try_endpoint(
        &self,
        idx: usize,
        query_wire: &[u8],
        mut probe_guard: Option<ProbeGuard<'_>>,
    ) -> EndpointAttempt {
        let endpoint = &self.endpoints[idx];
        let health = &self.health[idx];
        let label = endpoint_label(endpoint);
        let start = Instant::now();

        match tokio::time::timeout(self.timeout, self.exchange_one(idx, endpoint, query_wire)).await
        {
            Ok(Ok(resp)) => {
                if let Some(ref mut g) = probe_guard {
                    g.defused = true;
                }
                if is_upstream_error_rcode(&resp) {
                    let rcode = wire_rcode(&resp);
                    tracing::warn!(
                        upstream = %label,
                        rcode,
                        "upstream returned server error RCODE; marking unhealthy candidate"
                    );
                    health.record_error_response(monotonic_now_ms());
                    return EndpointAttempt::ErrorResponse((resp, label));
                }
                let elapsed_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
                health.record_success(elapsed_us);
                EndpointAttempt::Ok((resp, label))
            }
            Ok(Err(err)) => {
                tracing::warn!(upstream = %label, error = %err, "upstream query failed");
                if let Some(ref mut g) = probe_guard {
                    g.defused = true;
                }
                health.record_failure(monotonic_now_ms());
                EndpointAttempt::TransportErr(err)
            }
            Err(_) => {
                tracing::warn!(upstream = %label, "upstream query timed out");
                if let Some(ref mut g) = probe_guard {
                    g.defused = true;
                }
                health.record_failure(monotonic_now_ms());
                EndpointAttempt::TransportErr(CoreError::Upstream(format!(
                    "upstream {label} timed out"
                )))
            }
        }
    }

    async fn exchange_one(
        &self,
        idx: usize,
        endpoint: &UpstreamEndpoint,
        query_wire: &[u8],
    ) -> Result<Vec<u8>> {
        if let Some(proxy) = &self.proxy {
            return self
                .exchange_one_proxied(idx, endpoint, proxy, query_wire)
                .await;
        }
        match endpoint {
            UpstreamEndpoint::Udp(addr) => {
                let resp = exchange_udp(*addr, &self.udp_pools[idx], query_wire).await?;
                if is_udp_truncated(&resp) {
                    match exchange_tcp_pooled(*addr, &self.tcp_pools[idx], query_wire).await {
                        Ok(tcp_resp) => return Ok(tcp_resp),
                        Err(err) => {
                            tracing::debug!(
                                addr = %addr,
                                error = %err,
                                "UDP TC=1 fallback to TCP failed; returning truncated response"
                            );
                        }
                    }
                }
                Ok(resp)
            }
            UpstreamEndpoint::Tcp(addr) => {
                exchange_tcp_pooled(*addr, &self.tcp_pools[idx], query_wire).await
            }
            UpstreamEndpoint::Dot { addr, server_name } => {
                if let Some(resp) = try_exchange_dot_pooled(&self.dot_pools[idx], query_wire).await
                {
                    return Ok(resp);
                }
                let (host, port) = split_host_port(addr, 853);
                let addrs = self.bootstrap.resolve_socket_addrs(&host, port).await?;
                exchange_dot_addrs(
                    &self.tls_connector,
                    &addrs,
                    &self.dot_pools[idx],
                    server_name,
                    query_wire,
                )
                .await
            }
            UpstreamEndpoint::Doh { url } => exchange_doh(&self.http_client, url, query_wire).await,
            UpstreamEndpoint::Doq { addr, server_name } => {
                if let Some(resp) = try_exchange_doq_pooled(&self.doq_pools[idx], query_wire).await
                {
                    return Ok(resp);
                }
                let (host, port) = split_host_port(addr, 853);
                let addrs = self.bootstrap.resolve_socket_addrs(&host, port).await?;
                exchange_doq_addrs(
                    &self.doq_client_config,
                    &addrs,
                    &self.doq_pools[idx],
                    server_name,
                    query_wire,
                )
                .await
            }
            UpstreamEndpoint::Doh3 { url, host, port } => {
                if let Some(resp) =
                    try_exchange_h3_pooled(&self.h3_pools[idx], url, query_wire).await
                {
                    return Ok(resp);
                }
                let addrs = self.bootstrap.resolve_socket_addrs(host, *port).await?;
                exchange_h3_addrs(
                    &self.h3_client_config,
                    &addrs,
                    &self.h3_pools[idx],
                    host,
                    url,
                    query_wire,
                )
                .await
            }
        }
    }

    async fn exchange_one_proxied(
        &self,
        idx: usize,
        endpoint: &UpstreamEndpoint,
        proxy: &ParsedProxy,
        query_wire: &[u8],
    ) -> Result<Vec<u8>> {
        let (proxy_host, proxy_port) = proxy.proxy_host_port();
        let proxy_addrs = self
            .bootstrap
            .resolve_socket_addrs(proxy_host, proxy_port)
            .await?;
        let resolve_locally = matches!(
            proxy,
            ParsedProxy::Socks5 {
                resolve_remote: false,
                ..
            }
        );
        let resolved_dot_ip =
            if resolve_locally && let UpstreamEndpoint::Dot { addr, .. } = endpoint {
                let (host, port) = split_host_port(addr, 853);
                self.bootstrap
                    .resolve_socket_addrs(&host, port)
                    .await?
                    .into_iter()
                    .next()
                    .map(|sa| sa.ip().to_string())
            } else {
                None
            };
        exchange_endpoint_via_proxy(
            proxy,
            &proxy_addrs,
            &self.tls_connector,
            &self.tcp_pools[idx],
            &self.dot_pools[idx],
            endpoint,
            resolved_dot_ip,
            query_wire,
        )
        .await
    }
}

#[cfg(test)]
#[path = "upstream_tests.rs"]
mod tests;
