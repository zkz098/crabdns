use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption, NSIDPayload};
use hickory_proto::rr::{Name, RecordType};
use serde::{Deserialize, Serialize};
use tokio::net::{TcpStream, UdpSocket};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, ProtocolVersion, RootCertStore};
use ts_rs::TS;

use crate::edns::{apply_ecs_to_message, set_dnssec_ok};
use crate::error::{CoreError, Result};
use crate::upstream::{
    BootstrapResolver, UpstreamEndpoint, read_tcp_framed, send_tcp_framed, split_host_port,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum UpstreamProtocol {
    Udp,
    Tcp,
    Dot,
    Doh,
    Doq,
}

const MAX_DOH_RESPONSE_BYTES: usize = 65_535;
pub(crate) const PROBE_EDNS_UDP_SIZE: u16 = 1232;
pub(crate) const PROBE_ECS_SUBNET: (IpAddr, u8) = (IpAddr::V4(Ipv4Addr::new(203, 0, 113, 0)), 24);
pub(crate) const EDNS_CODE_COOKIE: u16 = 10;
pub(crate) const EDNS_CODE_PADDING: u16 = 12;
pub(crate) const EDNS_CODE_EDE: u16 = 15;

pub(crate) struct ProbeContext {
    pub(crate) timeout: Duration,
    pub(crate) bootstrap: BootstrapResolver,
    pub(crate) http_client: reqwest::Client,
    pub(crate) tls_connector: TlsConnector,
}

impl ProbeContext {
    pub(crate) fn new(bootstrap_dns: &[String], timeout_ms: u64) -> Result<Self> {
        let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
        let timeout = Duration::from_millis(timeout_ms.clamp(200, 15_000));
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
            timeout,
            bootstrap,
            http_client,
            tls_connector,
        })
    }
}

pub(crate) struct ExchangeMeta {
    pub(crate) wire: Vec<u8>,
    pub(crate) latency_ms: u64,
    pub(crate) transport_detail: Option<String>,
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct ProbeQueryOptions {
    pub(crate) with_edns: bool,
    pub(crate) with_do: bool,
    pub(crate) with_nsid: bool,
    pub(crate) client_cookie: Option<[u8; 8]>,
    pub(crate) ecs_subnet: Option<(IpAddr, u8)>,
}

pub(crate) fn make_client_cookie() -> [u8; 8] {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0x0123_4567_89ab_cdef_u128, |d| d.as_nanos());
    let val = (nanos as u64) ^ 0xA5A5_5A5A_C3C3_3C3C;
    val.to_be_bytes()
}

pub(crate) fn extract_nsid(msg: &Message) -> Option<String> {
    let edns = msg.edns.as_ref()?;
    for (code, opt) in edns.options().as_ref() {
        let bytes = match (code, opt) {
            (_, EdnsOption::NSID(payload)) => payload.as_ref(),
            (EdnsCode::NSID, EdnsOption::Unknown(_, data)) => data.as_slice(),
            _ => continue,
        };
        if bytes.is_empty() {
            continue;
        }
        if let Ok(text) = std::str::from_utf8(bytes) {
            let trimmed = text.trim();
            if !trimmed.is_empty() && trimmed.chars().all(|c| !c.is_control()) {
                return Some(trimmed.to_string());
            }
        }
        let mut hex = String::with_capacity(2 + bytes.len() * 2);
        hex.push_str("0x");
        for b in bytes {
            use std::fmt::Write;
            let _ = write!(&mut hex, "{b:02x}");
        }
        return Some(hex);
    }
    None
}

pub(crate) fn has_valid_server_cookie(msg: &Message, client_cookie: [u8; 8]) -> bool {
    msg.edns.as_ref().is_some_and(|edns| {
        edns.options()
            .as_ref()
            .iter()
            .any(|(code, opt)| match (code, opt) {
                (EdnsCode::Cookie, EdnsOption::Unknown(_, data))
                | (_, EdnsOption::Unknown(EDNS_CODE_COOKIE, data)) => {
                    data.len() >= 16 && data.len() <= 40 && data.starts_with(&client_cookie)
                }
                _ => false,
            })
    })
}

pub(crate) fn has_edns_padding(msg: &Message) -> bool {
    msg.edns.as_ref().is_some_and(|edns| {
        edns.options().as_ref().iter().any(|(code, opt)| {
            matches!(code, EdnsCode::Padding)
                || matches!(opt, EdnsOption::Unknown(EDNS_CODE_PADDING, _))
        })
    })
}

pub(crate) fn extract_ede(msg: &Message) -> Option<String> {
    let edns = msg.edns.as_ref()?;
    for (_, opt) in edns.options().as_ref() {
        if let EdnsOption::Unknown(EDNS_CODE_EDE, data) = opt
            && data.len() >= 2
        {
            let info_code = u16::from_be_bytes([data[0], data[1]]);
            let label = ede_code_label(info_code);
            let extra = std::str::from_utf8(&data[2..])
                .ok()
                .map(str::trim)
                .filter(|s| !s.is_empty());
            return Some(match (label, extra) {
                (Some(name), Some(text)) => format!("{info_code}: {name} ({text})"),
                (Some(name), None) => format!("{info_code}: {name}"),
                (None, Some(text)) => format!("{info_code}: {text}"),
                (None, None) => format!("EDE {info_code}"),
            });
        }
    }
    None
}

const fn ede_code_label(code: u16) -> Option<&'static str> {
    match code {
        0 => Some("Other Error"),
        1 => Some("Unsupported DNSKEY Algorithm"),
        2 => Some("Unsupported DS Digest Type"),
        3 => Some("Stale Answer"),
        4 => Some("Forged Answer"),
        5 => Some("DNSSEC Indeterminate"),
        6 => Some("DNSSEC Bogus"),
        7 => Some("Signature Expired"),
        8 => Some("Signature Not Yet Valid"),
        9 => Some("DNSKEY Missing"),
        10 => Some("RRSIGs Missing"),
        11 => Some("No Zone Key Bit Set"),
        12 => Some("NSEC Missing"),
        13 => Some("Cached Error"),
        14 => Some("Not Ready"),
        15 => Some("Blocked"),
        16 => Some("Censored"),
        17 => Some("Filtered"),
        18 => Some("Prohibited"),
        20 => Some("Not Authoritative"),
        21 => Some("Not Supported"),
        22 => Some("No Reachable Authority"),
        23 => Some("Network Error"),
        _ => None,
    }
}

pub(crate) fn build_probe_query(
    domain: &str,
    qtype: RecordType,
    opts: ProbeQueryOptions,
) -> Result<Vec<u8>> {
    let id = (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0x4242, |d| d.subsec_nanos())
        & 0xFFFF) as u16;
    let name = Name::from_ascii(domain)
        .map_err(|e| CoreError::Protocol(format!("invalid probe domain '{domain}': {e}")))?;

    let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(name, qtype));

    let needs_edns = opts.with_edns
        || opts.with_do
        || opts.with_nsid
        || opts.client_cookie.is_some()
        || opts.ecs_subnet.is_some();

    if needs_edns {
        let edns = msg.edns.get_or_insert_with(Edns::new);
        edns.set_max_payload(PROBE_EDNS_UDP_SIZE);
        if opts.with_nsid
            && let Ok(empty_nsid) = NSIDPayload::new(Vec::new())
        {
            edns.options_mut().insert(EdnsOption::NSID(empty_nsid));
        }
        if let Some(cookie) = opts.client_cookie {
            edns.options_mut()
                .insert(EdnsOption::Unknown(EDNS_CODE_COOKIE, cookie.to_vec()));
        }
        if opts.with_do {
            set_dnssec_ok(&mut msg);
        }
        if let Some(subnet) = opts.ecs_subnet {
            apply_ecs_to_message(&mut msg, subnet);
        }
    }

    msg.to_vec()
        .map_err(|e| CoreError::Protocol(format!("failed to encode probe query: {e}")))
}

pub(crate) const fn endpoint_protocol(endpoint: &UpstreamEndpoint) -> UpstreamProtocol {
    match endpoint {
        UpstreamEndpoint::Udp(_) => UpstreamProtocol::Udp,
        UpstreamEndpoint::Tcp(_) => UpstreamProtocol::Tcp,
        UpstreamEndpoint::Dot { .. } => UpstreamProtocol::Dot,
        UpstreamEndpoint::Doh { .. } => UpstreamProtocol::Doh,
        UpstreamEndpoint::Doq { .. } => UpstreamProtocol::Doq,
    }
}

pub(crate) async fn exchange_once(
    ctx: &ProbeContext,
    endpoint: &UpstreamEndpoint,
    query_wire: &[u8],
) -> Result<ExchangeMeta> {
    let start = Instant::now();
    let res = tokio::time::timeout(ctx.timeout, async {
        match endpoint {
            UpstreamEndpoint::Udp(addr) => {
                let wire = probe_udp(*addr, query_wire).await?;
                Ok((wire, None))
            }
            UpstreamEndpoint::Tcp(addr) => {
                let wire = probe_tcp(*addr, query_wire).await?;
                Ok((wire, None))
            }
            UpstreamEndpoint::Dot { addr, server_name } => {
                probe_dot(
                    &ctx.tls_connector,
                    &ctx.bootstrap,
                    addr,
                    server_name,
                    query_wire,
                )
                .await
            }
            UpstreamEndpoint::Doh { url } => probe_doh(&ctx.http_client, url, query_wire).await,
            UpstreamEndpoint::Doq { addr, server_name } => {
                let (host, port) = split_host_port(addr, 853);
                let addrs = ctx.bootstrap.resolve_socket_addrs(&host, port).await?;
                let doq_cfg = crate::upstream_transport::build_doq_client_config()?;
                let pool = crate::upstream_transport::ConnPool::default();
                let wire = crate::upstream_transport::exchange_doq_addrs(
                    &doq_cfg,
                    &addrs,
                    &pool,
                    server_name,
                    query_wire,
                )
                .await?;
                Ok((wire, Some("QUIC (ALPN doq)".to_string())))
            }
        }
    })
    .await
    .map_err(|_| CoreError::Upstream("probe timed out".to_string()))??;

    let latency_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    Ok(ExchangeMeta {
        wire: res.0,
        latency_ms,
        transport_detail: res.1,
    })
}

async fn probe_udp(addr: SocketAddr, query_wire: &[u8]) -> Result<Vec<u8>> {
    let bind_addr = if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let sock = UdpSocket::bind(bind_addr).await?;
    sock.connect(addr).await?;
    sock.send(query_wire).await?;
    let mut buf = vec![0_u8; 4096];
    let n = sock.recv(&mut buf).await?;
    buf.truncate(n);
    Ok(buf)
}

async fn probe_tcp(addr: SocketAddr, query_wire: &[u8]) -> Result<Vec<u8>> {
    let mut stream = TcpStream::connect(addr).await?;
    send_tcp_framed(&mut stream, query_wire).await?;
    read_tcp_framed(&mut stream).await
}

async fn probe_dot(
    connector: &TlsConnector,
    bootstrap: &BootstrapResolver,
    addr: &str,
    server_name: &str,
    query_wire: &[u8],
) -> Result<(Vec<u8>, Option<String>)> {
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

    let tls_ver = tls_stream
        .get_ref()
        .1
        .protocol_version()
        .and_then(|v| match v {
            ProtocolVersion::TLSv1_3 => Some("TLS 1.3".to_string()),
            ProtocolVersion::TLSv1_2 => Some("TLS 1.2".to_string()),
            _ => None,
        });

    send_tcp_framed(&mut tls_stream, query_wire).await?;
    let wire = read_tcp_framed(&mut tls_stream).await?;
    Ok((wire, tls_ver))
}

async fn probe_doh(
    client: &reqwest::Client,
    url: &str,
    query_wire: &[u8],
) -> Result<(Vec<u8>, Option<String>)> {
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

    if let Some(len) = resp.content_length()
        && len > MAX_DOH_RESPONSE_BYTES as u64
    {
        return Err(CoreError::Protocol(
            "DoH response exceeds maximum DNS message size".to_string(),
        ));
    }

    let http_ver = match resp.version() {
        reqwest::Version::HTTP_3 => Some("HTTP/3".to_string()),
        reqwest::Version::HTTP_2 => Some("HTTP/2".to_string()),
        reqwest::Version::HTTP_11 => Some("HTTP/1.1".to_string()),
        reqwest::Version::HTTP_10 => Some("HTTP/1.0".to_string()),
        _ => None,
    };

    let bytes = resp
        .bytes()
        .await
        .map_err(|e| CoreError::Upstream(format!("DoH body read failed: {e}")))?;
    if bytes.len() > MAX_DOH_RESPONSE_BYTES {
        return Err(CoreError::Protocol(
            "DoH response exceeds maximum DNS message size".to_string(),
        ));
    }

    Ok((bytes.to_vec(), http_ver))
}
