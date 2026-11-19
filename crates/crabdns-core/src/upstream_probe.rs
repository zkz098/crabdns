use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use futures_util::future::join_all;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption, NSIDPayload};
use hickory_proto::rr::rdata::svcb::{SVCB, SvcParamKey, SvcParamValue};
use hickory_proto::rr::{Name, RData, RecordType};
use serde::{Deserialize, Serialize};
use tokio::net::{TcpStream, UdpSocket};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, ProtocolVersion, RootCertStore};
use ts_rs::TS;

use crate::edns::{apply_ecs_to_message, set_dnssec_ok};
use crate::error::{CoreError, Result};
use crate::upstream::{
    BootstrapResolver, UpstreamEndpoint, endpoint_label, read_tcp_framed, send_tcp_framed,
    split_host_port,
};

const MAX_DOH_RESPONSE_BYTES: usize = 65_535;
const PROBE_EDNS_UDP_SIZE: u16 = 1232;
const PROBE_ECS_SUBNET: (IpAddr, u8) = (IpAddr::V4(Ipv4Addr::new(203, 0, 113, 0)), 24);
const EDNS_CODE_COOKIE: u16 = 10;
const EDNS_CODE_PADDING: u16 = 12;
const EDNS_CODE_EDE: u16 = 15;
const DNSSEC_BOGUS_DOMAIN: &str = "dnssec-failed.org.";
const ECS_PROBE_DOMAIN: &str = "www.bing.com.";
const DDR_PROBE_DOMAIN: &str = "_dns.resolver.arpa.";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum UpstreamProtocol {
    Udp,
    Tcp,
    Dot,
    Doh,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[allow(clippy::struct_excessive_bools)]
pub struct UpstreamCapabilities {
    pub input: String,
    pub endpoint: String,
    pub protocol: UpstreamProtocol,
    pub encrypted: bool,
    pub transport_detail: Option<String>,
    pub reachable: bool,
    #[ts(type = "number | null")]
    pub latency_ms: Option<u64>,
    pub recursion_available: Option<bool>,
    pub edns: Option<bool>,
    pub edns_udp_size: Option<u16>,
    pub dnssec_aware: Option<bool>,
    pub dnssec_validating: Option<bool>,
    pub ecs: Option<bool>,
    pub nxdomain_hijack: Option<bool>,
    pub ddr_upgrades: Vec<String>,
    pub nsid: Option<String>,
    pub dns_cookies: Option<bool>,
    pub edns_padding: Option<bool>,
    pub ede: Option<bool>,
    pub ede_detail: Option<String>,
    pub error: Option<String>,
}

impl UpstreamCapabilities {
    fn failed(input: String, endpoint: String, protocol: UpstreamProtocol, error: String) -> Self {
        let encrypted = matches!(protocol, UpstreamProtocol::Dot | UpstreamProtocol::Doh);
        Self {
            input,
            endpoint,
            protocol,
            encrypted,
            transport_detail: None,
            reachable: false,
            latency_ms: None,
            recursion_available: None,
            edns: None,
            edns_udp_size: None,
            dnssec_aware: None,
            dnssec_validating: None,
            ecs: None,
            nxdomain_hijack: None,
            ddr_upgrades: Vec::new(),
            nsid: None,
            dns_cookies: None,
            edns_padding: None,
            ede: None,
            ede_detail: None,
            error: Some(error),
        }
    }
}

struct ProbeContext {
    timeout: Duration,
    bootstrap: BootstrapResolver,
    http_client: reqwest::Client,
    tls_connector: TlsConnector,
}

impl ProbeContext {
    fn new(bootstrap_dns: &[String], timeout_ms: u64) -> Result<Self> {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
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

struct ExchangeMeta {
    wire: Vec<u8>,
    latency_ms: u64,
    transport_detail: Option<String>,
}

/// Probes a list of upstream DNS specs concurrently and reports protocol, EDNS, DNSSEC,
/// recursion availability, ECS, NXDOMAIN hijacking, and DDR encrypted upgrade capabilities.
pub async fn probe_upstreams(
    specs: &[String],
    bootstrap_dns: &[String],
    timeout_ms: u64,
) -> Result<Vec<UpstreamCapabilities>> {
    let ctx = Arc::new(ProbeContext::new(bootstrap_dns, timeout_ms)?);
    let futs = specs.iter().map(|spec| {
        let ctx = Arc::clone(&ctx);
        let raw = spec.trim().to_string();
        async move { probe_single(&ctx, raw).await }
    });
    Ok(join_all(futs).await)
}

#[allow(clippy::too_many_lines)]
async fn probe_single(ctx: &ProbeContext, input: String) -> UpstreamCapabilities {
    let endpoint = match UpstreamEndpoint::parse(&input) {
        Ok(ep) => ep,
        Err(err) => {
            return UpstreamCapabilities::failed(
                input.clone(),
                input,
                UpstreamProtocol::Udp,
                err.to_string(),
            );
        }
    };

    let protocol = endpoint_protocol(&endpoint);
    let encrypted = matches!(protocol, UpstreamProtocol::Dot | UpstreamProtocol::Doh);
    let label = endpoint_label(&endpoint);

    // 1. Primary probe: `.` DNSKEY with EDNS0 + DO=1 + NSID + Client Cookie
    let client_cookie = make_client_cookie();
    let primary_opts = ProbeQueryOptions {
        with_edns: true,
        with_do: true,
        with_nsid: true,
        client_cookie: Some(client_cookie),
        ecs_subnet: None,
    };
    let primary_wire = match build_probe_query(".", RecordType::DNSKEY, primary_opts) {
        Ok(w) => w,
        Err(err) => return UpstreamCapabilities::failed(input, label, protocol, err.to_string()),
    };

    let primary_exchange = match exchange_once(ctx, &endpoint, &primary_wire).await {
        Ok(meta) => meta,
        Err(primary_err) => {
            // If EDNS query failed at transport/timeout level, try a plain query once
            // before declaring unreachable (some legacy middleboxes drop EDNS packets).
            let Ok(plain_wire) =
                build_probe_query(".", RecordType::NS, ProbeQueryOptions::default())
            else {
                return UpstreamCapabilities::failed(
                    input,
                    label,
                    protocol,
                    primary_err.to_string(),
                );
            };
            match exchange_once(ctx, &endpoint, &plain_wire).await {
                Ok(plain_meta) => {
                    return finish_plain_only_probe(
                        ctx, &endpoint, input, label, protocol, encrypted, plain_meta,
                    )
                    .await;
                }
                Err(_) => {
                    return UpstreamCapabilities::failed(
                        input,
                        label,
                        protocol,
                        primary_err.to_string(),
                    );
                }
            }
        }
    };

    let Ok(mut primary_msg) = Message::from_vec(&primary_exchange.wire) else {
        return UpstreamCapabilities::failed(
            input,
            label,
            protocol,
            "upstream returned invalid DNS wire message".to_string(),
        );
    };

    let mut latency_ms = primary_exchange.latency_ms;
    let transport_detail = primary_exchange.transport_detail;
    let mut nsid = extract_nsid(&primary_msg);
    let mut padding_seen = has_edns_padding(&primary_msg);
    let mut ede_detail = extract_ede(&primary_msg);
    let mut cookies_supported = has_valid_server_cookie(&primary_msg, client_cookie);

    // RFC 7873: BADCOOKIE proves cookie support; re-query without cookie to inspect DNSKEY/RRSIG.
    if primary_msg.response_code == ResponseCode::BADCOOKIE {
        cookies_supported = true;
        let retry_opts = ProbeQueryOptions {
            with_edns: true,
            with_do: true,
            with_nsid: true,
            client_cookie: None,
            ecs_subnet: None,
        };
        if let Ok(retry_wire) = build_probe_query(".", RecordType::DNSKEY, retry_opts)
            && let Ok(retry_meta) = exchange_once(ctx, &endpoint, &retry_wire).await
            && let Ok(retry_msg) = Message::from_vec(&retry_meta.wire)
        {
            if nsid.is_none() {
                nsid = extract_nsid(&retry_msg);
            }
            padding_seen |= has_edns_padding(&retry_msg);
            if ede_detail.is_none() {
                ede_detail = extract_ede(&retry_msg);
            }
            primary_msg = retry_msg;
        }
    }

    let mut recursion_available = Some(primary_msg.metadata.recursion_available);

    let edns_rejected = matches!(
        primary_msg.response_code,
        ResponseCode::FormErr | ResponseCode::NotImp | ResponseCode::BADVERS
    ) || primary_msg.edns.is_none();

    let (edns, edns_udp_size, dnssec_aware, root_ad_bit) = if edns_rejected {
        // Confirm reachability & RA via non-EDNS query when server rejected EDNS
        if primary_msg.response_code != ResponseCode::NoError
            && let Ok(plain_wire) =
                build_probe_query(".", RecordType::NS, ProbeQueryOptions::default())
            && let Ok(plain_meta) = exchange_once(ctx, &endpoint, &plain_wire).await
            && let Ok(plain_msg) = Message::from_vec(&plain_meta.wire)
        {
            latency_ms = latency_ms.min(plain_meta.latency_ms);
            recursion_available = Some(plain_msg.metadata.recursion_available);
        }
        (Some(false), None, Some(false), false)
    } else {
        let udp_size = primary_msg.edns.as_ref().map(Edns::max_payload);
        // If UDP response was truncated (TC=1), retry via TCP to inspect full RRSIG payload.
        let effective_msg = if primary_msg.metadata.truncation
            && let UpstreamEndpoint::Udp(addr) = endpoint
        {
            let tcp_ep = UpstreamEndpoint::Tcp(addr);
            if let Ok(tcp_meta) = exchange_once(ctx, &tcp_ep, &primary_wire).await
                && let Ok(tcp_msg) = Message::from_vec(&tcp_meta.wire)
            {
                if nsid.is_none() {
                    nsid = extract_nsid(&tcp_msg);
                }
                padding_seen |= has_edns_padding(&tcp_msg);
                if ede_detail.is_none() {
                    ede_detail = extract_ede(&tcp_msg);
                }
                tcp_msg
            } else {
                primary_msg
            }
        } else {
            primary_msg
        };

        let aware = has_rrsig(&effective_msg);
        let ad = effective_msg.metadata.authentic_data;
        (Some(true), udp_size, Some(aware), ad)
    };

    // 2. Concurrent secondary probes: DNSSEC validating (+EDE), NXDOMAIN hijack, ECS, DDR
    let edns_supported = edns != Some(false);
    let probe_ddr_flag = !encrypted;

    let (dnssec_probe, nxdomain_hijack, ecs, ddr_upgrades) = tokio::join!(
        probe_dnssec_validating(
            ctx,
            &endpoint,
            edns_supported,
            dnssec_aware == Some(true),
            root_ad_bit
        ),
        probe_nxdomain_hijack(ctx, &endpoint),
        probe_ecs(ctx, &endpoint, edns_supported),
        probe_ddr(ctx, &endpoint, probe_ddr_flag),
    );

    if ede_detail.is_none() {
        ede_detail = dnssec_probe.ede_detail;
    }
    padding_seen |= dnssec_probe.padding_seen;

    let ede = if ede_detail.is_some() {
        Some(true)
    } else if dnssec_probe.saw_servfail {
        Some(false)
    } else {
        None
    };

    let dns_cookies = if edns_supported {
        Some(cookies_supported)
    } else {
        Some(false)
    };

    let edns_padding = if padding_seen {
        Some(true)
    } else if encrypted && edns_supported {
        Some(false)
    } else {
        None
    };

    UpstreamCapabilities {
        input,
        endpoint: label,
        protocol,
        encrypted,
        transport_detail,
        reachable: true,
        latency_ms: Some(latency_ms),
        recursion_available,
        edns,
        edns_udp_size,
        dnssec_aware,
        dnssec_validating: dnssec_probe.validating,
        ecs,
        nxdomain_hijack,
        ddr_upgrades,
        nsid,
        dns_cookies,
        edns_padding,
        ede,
        ede_detail,
        error: None,
    }
}

async fn finish_plain_only_probe(
    ctx: &ProbeContext,
    endpoint: &UpstreamEndpoint,
    input: String,
    label: String,
    protocol: UpstreamProtocol,
    encrypted: bool,
    plain_meta: ExchangeMeta,
) -> UpstreamCapabilities {
    let Ok(msg) = Message::from_vec(&plain_meta.wire) else {
        return UpstreamCapabilities::failed(
            input,
            label,
            protocol,
            "upstream returned invalid DNS wire message".to_string(),
        );
    };

    let (nxdomain_hijack, ddr_upgrades) = tokio::join!(
        probe_nxdomain_hijack(ctx, endpoint),
        probe_ddr(ctx, endpoint, !encrypted),
    );

    UpstreamCapabilities {
        input,
        endpoint: label,
        protocol,
        encrypted,
        transport_detail: plain_meta.transport_detail,
        reachable: true,
        latency_ms: Some(plain_meta.latency_ms),
        recursion_available: Some(msg.metadata.recursion_available),
        edns: Some(false),
        edns_udp_size: None,
        dnssec_aware: Some(false),
        dnssec_validating: Some(false),
        ecs: Some(false),
        nxdomain_hijack,
        ddr_upgrades,
        nsid: None,
        dns_cookies: Some(false),
        edns_padding: None,
        ede: Some(false),
        ede_detail: None,
        error: None,
    }
}

struct DnssecValidatingProbe {
    validating: Option<bool>,
    saw_servfail: bool,
    ede_detail: Option<String>,
    padding_seen: bool,
}

async fn probe_dnssec_validating(
    ctx: &ProbeContext,
    endpoint: &UpstreamEndpoint,
    edns_supported: bool,
    is_aware: bool,
    root_ad_bit: bool,
) -> DnssecValidatingProbe {
    if !edns_supported {
        return DnssecValidatingProbe {
            validating: Some(false),
            saw_servfail: false,
            ede_detail: None,
            padding_seen: false,
        };
    }
    let opts = ProbeQueryOptions {
        with_edns: true,
        with_do: true,
        ..ProbeQueryOptions::default()
    };
    let Ok(wire) = build_probe_query(DNSSEC_BOGUS_DOMAIN, RecordType::A, opts) else {
        return DnssecValidatingProbe {
            validating: None,
            saw_servfail: false,
            ede_detail: None,
            padding_seen: false,
        };
    };
    let mut saw_servfail = false;
    let mut ede_detail = None;
    let mut padding_seen = false;
    if let Ok(meta) = exchange_once(ctx, endpoint, &wire).await
        && let Ok(resp) = Message::from_vec(&meta.wire)
    {
        ede_detail = extract_ede(&resp);
        padding_seen = has_edns_padding(&resp);
        if resp.response_code == ResponseCode::ServFail {
            saw_servfail = true;
            return DnssecValidatingProbe {
                validating: Some(true),
                saw_servfail,
                ede_detail,
                padding_seen,
            };
        }
        if resp.response_code == ResponseCode::NoError && !resp.answers.is_empty() {
            return DnssecValidatingProbe {
                validating: Some(false),
                saw_servfail,
                ede_detail,
                padding_seen,
            };
        }
    }
    DnssecValidatingProbe {
        validating: (is_aware && root_ad_bit).then_some(true),
        saw_servfail,
        ede_detail,
        padding_seen,
    }
}

async fn probe_nxdomain_hijack(ctx: &ProbeContext, endpoint: &UpstreamEndpoint) -> Option<bool> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0xCAFE, |d| d.subsec_nanos());
    let domain = format!("crabdns-probe-{nonce:08x}.invalid.");
    let wire = build_probe_query(&domain, RecordType::A, ProbeQueryOptions::default()).ok()?;
    let meta = exchange_once(ctx, endpoint, &wire).await.ok()?;
    let resp = Message::from_vec(&meta.wire).ok()?;
    match resp.response_code {
        ResponseCode::NXDomain => Some(false),
        ResponseCode::NoError if !resp.answers.is_empty() => Some(true),
        _ => None,
    }
}

async fn probe_ecs(ctx: &ProbeContext, endpoint: &UpstreamEndpoint, enabled: bool) -> Option<bool> {
    if !enabled {
        return Some(false);
    }
    let opts = ProbeQueryOptions {
        with_edns: true,
        ecs_subnet: Some(PROBE_ECS_SUBNET),
        ..ProbeQueryOptions::default()
    };
    let wire = build_probe_query(ECS_PROBE_DOMAIN, RecordType::A, opts).ok()?;
    let meta = exchange_once(ctx, endpoint, &wire).await.ok()?;
    let resp = Message::from_vec(&meta.wire).ok()?;
    if resp.response_code != ResponseCode::NoError {
        return None;
    }
    let has_subnet = resp.edns.as_ref().is_some_and(|edns| {
        edns.options()
            .as_ref()
            .iter()
            .any(|(_, opt)| matches!(opt, EdnsOption::Subnet(_)))
    });
    Some(has_subnet)
}

async fn probe_ddr(ctx: &ProbeContext, endpoint: &UpstreamEndpoint, enabled: bool) -> Vec<String> {
    if !enabled {
        return Vec::new();
    }
    let opts = ProbeQueryOptions {
        with_edns: true,
        ..ProbeQueryOptions::default()
    };
    let Ok(wire) = build_probe_query(DDR_PROBE_DOMAIN, RecordType::SVCB, opts) else {
        return Vec::new();
    };
    let Ok(meta) = exchange_once(ctx, endpoint, &wire).await else {
        return Vec::new();
    };
    let Ok(resp) = Message::from_vec(&meta.wire) else {
        return Vec::new();
    };
    if resp.response_code != ResponseCode::NoError {
        return Vec::new();
    }
    extract_ddr_upgrades(&resp)
}

fn extract_ddr_upgrades(resp: &Message) -> Vec<String> {
    let mut upgrades = Vec::new();
    for rec in &resp.answers {
        if let RData::SVCB(svcb) = &rec.data {
            for candidate in svcb_to_upstream_urls(svcb) {
                if !upgrades.contains(&candidate) {
                    upgrades.push(candidate);
                }
            }
        }
    }
    upgrades
}

fn svcb_to_upstream_urls(svcb: &SVCB) -> Vec<String> {
    let target = svcb
        .target_name
        .to_ascii()
        .trim_end_matches('.')
        .to_string();
    if target.is_empty() {
        return Vec::new();
    }

    let mut alpns: Vec<String> = Vec::new();
    let mut port: Option<u16> = None;
    let mut dohpath: Option<String> = None;

    for (key, value) in &svcb.svc_params {
        match (key, value) {
            (SvcParamKey::Alpn, SvcParamValue::Alpn(alpn)) => {
                alpns.extend(alpn.0.iter().cloned());
            }
            (SvcParamKey::Port, SvcParamValue::Port(p)) => {
                port = Some(*p);
            }
            (SvcParamKey::Unknown(7), SvcParamValue::Unknown(raw)) => {
                if let Ok(path_str) = std::str::from_utf8(&raw.0) {
                    dohpath = Some(strip_uri_template(path_str));
                }
            }
            _ => {}
        }
    }

    let mut urls = Vec::new();
    if alpns.iter().any(|a| a.eq_ignore_ascii_case("dot")) {
        let url = match port {
            Some(p) if p != 853 => format!("tls://{target}:{p}"),
            _ => format!("tls://{target}"),
        };
        urls.push(url);
    }

    if alpns
        .iter()
        .any(|a| a.eq_ignore_ascii_case("h2") || a.eq_ignore_ascii_case("http/1.1"))
    {
        let path = dohpath.unwrap_or_else(|| "/dns-query".to_string());
        let normalized_path = if path.starts_with('/') {
            path
        } else {
            format!("/{path}")
        };
        let url = match port {
            Some(p) if p != 443 => format!("https://{target}:{p}{normalized_path}"),
            _ => format!("https://{target}{normalized_path}"),
        };
        urls.push(url);
    }

    urls
}

fn strip_uri_template(raw: &str) -> String {
    let trimmed = raw.trim();
    if let Some((prefix, _)) = trimmed.split_once('{')
        && !prefix.is_empty()
    {
        return prefix.to_string();
    }
    if trimmed.is_empty() {
        "/dns-query".to_string()
    } else {
        trimmed.to_string()
    }
}

fn has_rrsig(msg: &Message) -> bool {
    msg.answers
        .iter()
        .chain(&msg.authorities)
        .any(|rec| rec.record_type() == RecordType::RRSIG)
}

#[derive(Debug, Default, Clone, Copy)]
struct ProbeQueryOptions {
    with_edns: bool,
    with_do: bool,
    with_nsid: bool,
    client_cookie: Option<[u8; 8]>,
    ecs_subnet: Option<(IpAddr, u8)>,
}

fn make_client_cookie() -> [u8; 8] {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0x0123_4567_89ab_cdef_u128, |d| d.as_nanos());
    let val = (nanos as u64) ^ 0xA5A5_5A5A_C3C3_3C3C;
    val.to_be_bytes()
}

fn extract_nsid(msg: &Message) -> Option<String> {
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

fn has_valid_server_cookie(msg: &Message, client_cookie: [u8; 8]) -> bool {
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

fn has_edns_padding(msg: &Message) -> bool {
    msg.edns.as_ref().is_some_and(|edns| {
        edns.options().as_ref().iter().any(|(code, opt)| {
            matches!(code, EdnsCode::Padding)
                || matches!(opt, EdnsOption::Unknown(EDNS_CODE_PADDING, _))
        })
    })
}

fn extract_ede(msg: &Message) -> Option<String> {
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

fn build_probe_query(domain: &str, qtype: RecordType, opts: ProbeQueryOptions) -> Result<Vec<u8>> {
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

const fn endpoint_protocol(endpoint: &UpstreamEndpoint) -> UpstreamProtocol {
    match endpoint {
        UpstreamEndpoint::Udp(_) => UpstreamProtocol::Udp,
        UpstreamEndpoint::Tcp(_) => UpstreamProtocol::Tcp,
        UpstreamEndpoint::Dot { .. } => UpstreamProtocol::Dot,
        UpstreamEndpoint::Doh { .. } => UpstreamProtocol::Doh,
    }
}

async fn exchange_once(
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

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::dnssec::Algorithm;
    use hickory_proto::dnssec::rdata::sig::SigInput;
    use hickory_proto::dnssec::rdata::{DNSSECRData, RRSIG};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::rdata::opt::ClientSubnet;
    use hickory_proto::rr::rdata::svcb::{Alpn, Unknown};
    use hickory_proto::rr::{Record, SerialNumber};

    #[allow(clippy::struct_excessive_bools)]
    struct MockBehavior {
        support_edns: bool,
        support_dnssec_aware: bool,
        support_dnssec_validating: bool,
        support_ecs: bool,
        hijack_nxdomain: bool,
        support_ddr: bool,
        recursion_available: bool,
        nsid: Option<&'static str>,
        support_cookies: bool,
        support_padding: bool,
        support_ede: bool,
    }

    #[allow(clippy::too_many_lines)]
    async fn spawn_mock_dns_server(cfg: MockBehavior) -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind mock");
        let addr = sock.local_addr().expect("addr");
        tokio::spawn(async move {
            let mut buf = [0_u8; 4096];
            while let Ok((len, peer)) = sock.recv_from(&mut buf).await {
                let Ok(req) = Message::from_vec(&buf[..len]) else {
                    continue;
                };
                let mut resp = Message::new(req.id, MessageType::Response, OpCode::Query);
                resp.metadata.recursion_desired = req.metadata.recursion_desired;
                resp.metadata.recursion_available = cfg.recursion_available;
                if let Some(q) = req.queries.first() {
                    resp.add_query(q.clone());
                    let qname = q.name().to_ascii().to_ascii_lowercase();
                    let qtype = q.query_type();

                    if req.edns.is_some() && !cfg.support_edns {
                        resp.metadata.response_code = ResponseCode::FormErr;
                    } else {
                        if req.edns.is_some() && cfg.support_edns {
                            let mut edns = Edns::new();
                            edns.set_max_payload(1232);
                            if let Some(nsid_str) = cfg.nsid
                                && req.edns.as_ref().is_some_and(|e| {
                                    e.options().as_ref().iter().any(|(c, o)| {
                                        matches!(c, EdnsCode::NSID)
                                            || matches!(o, EdnsOption::NSID(_))
                                    })
                                })
                                && let Ok(payload) = NSIDPayload::new(nsid_str.as_bytes().to_vec())
                            {
                                edns.options_mut().insert(EdnsOption::NSID(payload));
                            }
                            if cfg.support_cookies
                                && let Some(client_bytes) = req.edns.as_ref().and_then(|e| {
                                    e.options().as_ref().iter().find_map(|(_, o)| match o {
                                        EdnsOption::Unknown(EDNS_CODE_COOKIE, data)
                                            if data.len() >= 8 =>
                                        {
                                            Some(data[..8].to_vec())
                                        }
                                        _ => None,
                                    })
                                })
                            {
                                let mut full_cookie = client_bytes;
                                full_cookie.extend_from_slice(&[
                                    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                ]);
                                edns.options_mut()
                                    .insert(EdnsOption::Unknown(EDNS_CODE_COOKIE, full_cookie));
                            }
                            if cfg.support_padding {
                                edns.options_mut()
                                    .insert(EdnsOption::Unknown(EDNS_CODE_PADDING, vec![0; 16]));
                            }
                            if cfg.support_ecs
                                && req.edns.as_ref().is_some_and(|e| {
                                    e.options()
                                        .as_ref()
                                        .iter()
                                        .any(|(_, o)| matches!(o, EdnsOption::Subnet(_)))
                                })
                            {
                                edns.options_mut()
                                    .insert(EdnsOption::Subnet(ClientSubnet::new(
                                        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 0)),
                                        24,
                                        24,
                                    )));
                            }
                            resp.edns = Some(edns);
                        }

                        if qname == "." && qtype == RecordType::DNSKEY {
                            resp.metadata.response_code = ResponseCode::NoError;
                            if cfg.support_dnssec_aware {
                                resp.metadata.authentic_data = cfg.support_dnssec_validating;
                                let sig = RRSIG::from_sig(
                                    SigInput {
                                        type_covered: RecordType::DNSKEY,
                                        algorithm: Algorithm::ED25519,
                                        num_labels: 0,
                                        original_ttl: 300,
                                        sig_expiration: SerialNumber::new(2_000_000_000),
                                        sig_inception: SerialNumber::new(1_000_000_000),
                                        key_tag: 12345,
                                        signer_name: Name::root(),
                                    },
                                    vec![1, 2, 3, 4],
                                );
                                resp.add_answer(Record::from_rdata(
                                    Name::root(),
                                    300,
                                    RData::DNSSEC(DNSSECRData::RRSIG(sig)),
                                ));
                            }
                        } else if qname == DNSSEC_BOGUS_DOMAIN {
                            if cfg.support_dnssec_validating {
                                resp.metadata.response_code = ResponseCode::ServFail;
                                if cfg.support_ede
                                    && let Some(edns) = resp.edns.as_mut()
                                {
                                    let mut ede_data = 6_u16.to_be_bytes().to_vec();
                                    ede_data.extend_from_slice(b"validation failure");
                                    edns.options_mut()
                                        .insert(EdnsOption::Unknown(EDNS_CODE_EDE, ede_data));
                                }
                            } else {
                                resp.metadata.response_code = ResponseCode::NoError;
                                resp.add_answer(Record::from_rdata(
                                    q.name().clone(),
                                    60,
                                    RData::A(A(Ipv4Addr::new(93, 184, 216, 34))),
                                ));
                            }
                        } else if qname.ends_with(".invalid.") {
                            if cfg.hijack_nxdomain {
                                resp.metadata.response_code = ResponseCode::NoError;
                                resp.add_answer(Record::from_rdata(
                                    q.name().clone(),
                                    60,
                                    RData::A(A(Ipv4Addr::new(198, 51, 100, 1))),
                                ));
                            } else {
                                resp.metadata.response_code = ResponseCode::NXDomain;
                            }
                        } else if qname == DDR_PROBE_DOMAIN && qtype == RecordType::SVCB {
                            resp.metadata.response_code = ResponseCode::NoError;
                            if cfg.support_ddr {
                                let target = Name::from_ascii("dns.example.test.").unwrap();
                                let tls_svcb = SVCB::new(
                                    1,
                                    target.clone(),
                                    vec![(
                                        SvcParamKey::Alpn,
                                        SvcParamValue::Alpn(Alpn(vec!["dot".to_string()])),
                                    )],
                                );
                                let https_svcb = SVCB::new(
                                    2,
                                    target,
                                    vec![
                                        (
                                            SvcParamKey::Alpn,
                                            SvcParamValue::Alpn(Alpn(vec!["h2".to_string()])),
                                        ),
                                        (
                                            SvcParamKey::Unknown(7),
                                            SvcParamValue::Unknown(Unknown(
                                                b"/dns-query{?dns}".to_vec(),
                                            )),
                                        ),
                                    ],
                                );
                                resp.add_answer(Record::from_rdata(
                                    q.name().clone(),
                                    300,
                                    RData::SVCB(tls_svcb),
                                ));
                                resp.add_answer(Record::from_rdata(
                                    q.name().clone(),
                                    300,
                                    RData::SVCB(https_svcb),
                                ));
                            }
                        } else {
                            resp.metadata.response_code = ResponseCode::NoError;
                            resp.add_answer(Record::from_rdata(
                                q.name().clone(),
                                60,
                                RData::A(A(Ipv4Addr::new(204, 79, 197, 200))),
                            ));
                        }
                    }
                }
                if let Ok(wire) = resp.to_vec() {
                    let _ = sock.send_to(&wire, peer).await;
                }
            }
        });
        addr
    }

    #[tokio::test]
    async fn test_probe_full_featured_upstream() {
        let addr = spawn_mock_dns_server(MockBehavior {
            support_edns: true,
            support_dnssec_aware: true,
            support_dnssec_validating: true,
            support_ecs: true,
            hijack_nxdomain: false,
            support_ddr: true,
            recursion_available: true,
            nsid: Some("hkg-edge-01"),
            support_cookies: true,
            support_padding: true,
            support_ede: true,
        })
        .await;
        let results = probe_upstreams(&[format!("udp://{addr}")], &[], 2000)
            .await
            .expect("probe");
        assert_eq!(results.len(), 1);
        let cap = &results[0];
        assert_eq!(cap.protocol, UpstreamProtocol::Udp);
        assert!(!cap.encrypted);
        assert!(cap.reachable);
        assert_eq!(cap.recursion_available, Some(true));
        assert_eq!(cap.edns, Some(true));
        assert_eq!(cap.edns_udp_size, Some(1232));
        assert_eq!(cap.dnssec_aware, Some(true));
        assert_eq!(cap.dnssec_validating, Some(true));
        assert_eq!(cap.ecs, Some(true));
        assert_eq!(cap.nxdomain_hijack, Some(false));
        assert_eq!(cap.nsid.as_deref(), Some("hkg-edge-01"));
        assert_eq!(cap.dns_cookies, Some(true));
        assert_eq!(cap.edns_padding, Some(true));
        assert_eq!(cap.ede, Some(true));
        assert_eq!(
            cap.ede_detail.as_deref(),
            Some("6: DNSSEC Bogus (validation failure)")
        );
        assert_eq!(
            cap.ddr_upgrades,
            vec![
                "tls://dns.example.test".to_string(),
                "https://dns.example.test/dns-query".to_string(),
            ]
        );
    }

    #[tokio::test]
    async fn test_probe_legacy_hijacking_non_recursive_upstream() {
        let addr = spawn_mock_dns_server(MockBehavior {
            support_edns: false,
            support_dnssec_aware: false,
            support_dnssec_validating: false,
            support_ecs: false,
            hijack_nxdomain: true,
            support_ddr: false,
            recursion_available: false,
            nsid: None,
            support_cookies: false,
            support_padding: false,
            support_ede: false,
        })
        .await;
        let results = probe_upstreams(&[format!("udp://{addr}")], &[], 2000)
            .await
            .expect("probe");
        let cap = &results[0];
        assert!(cap.reachable);
        assert_eq!(cap.recursion_available, Some(false));
        assert_eq!(cap.edns, Some(false));
        assert_eq!(cap.dnssec_aware, Some(false));
        assert_eq!(cap.dnssec_validating, Some(false));
        assert_eq!(cap.ecs, Some(false));
        assert_eq!(cap.nxdomain_hijack, Some(true));
        assert_eq!(cap.nsid, None);
        assert_eq!(cap.dns_cookies, Some(false));
        assert_eq!(cap.edns_padding, None);
        assert_eq!(cap.ede, None);
        assert_eq!(cap.ddr_upgrades, Vec::<String>::new());
    }

    #[tokio::test]
    async fn test_probe_invalid_and_unreachable_upstreams() {
        let results = probe_upstreams(
            &[
                "not-an-upstream".to_string(),
                "udp://127.0.0.1:1".to_string(),
            ],
            &[],
            300,
        )
        .await
        .expect("probe");
        assert_eq!(results.len(), 2);
        assert!(!results[0].reachable);
        assert!(results[0].error.is_some());
        assert!(!results[1].reachable);
        assert!(results[1].error.is_some());
    }
}
