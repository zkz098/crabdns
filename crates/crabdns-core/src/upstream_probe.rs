use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use futures_util::future::join_all;
use hickory_proto::op::{Edns, Message, ResponseCode};
use hickory_proto::rr::rdata::opt::EdnsOption;
use hickory_proto::rr::rdata::svcb::{SVCB, SvcParamKey, SvcParamValue};
use hickory_proto::rr::{RData, RecordType};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::error::Result;
use crate::upstream::{UpstreamEndpoint, endpoint_label};
use crate::upstream_probe_wire::{
    ExchangeMeta, PROBE_ECS_SUBNET, ProbeContext, ProbeQueryOptions, build_probe_query,
    endpoint_protocol, exchange_once, extract_ede, extract_nsid, has_edns_padding,
    has_valid_server_cookie, make_client_cookie,
};

const DNSSEC_BOGUS_DOMAIN: &str = "dnssec-failed.org.";
const ECS_PROBE_DOMAIN: &str = "www.bing.com.";
const DDR_PROBE_DOMAIN: &str = "_dns.resolver.arpa.";

pub use crate::upstream_probe_wire::UpstreamProtocol;

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

const fn is_encrypted_protocol(protocol: UpstreamProtocol) -> bool {
    matches!(
        protocol,
        UpstreamProtocol::Dot
            | UpstreamProtocol::Doh
            | UpstreamProtocol::Doq
            | UpstreamProtocol::Doh3
    )
}

impl UpstreamCapabilities {
    fn failed(input: String, endpoint: String, protocol: UpstreamProtocol, error: String) -> Self {
        let encrypted = is_encrypted_protocol(protocol);
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

struct ProbeEdnsState {
    nsid: Option<String>,
    padding_seen: bool,
    ede_detail: Option<String>,
}

impl ProbeEdnsState {
    fn from_msg(msg: &Message) -> Self {
        Self {
            nsid: extract_nsid(msg),
            padding_seen: has_edns_padding(msg),
            ede_detail: extract_ede(msg),
        }
    }

    fn merge_from(&mut self, msg: &Message) {
        if self.nsid.is_none() {
            self.nsid = extract_nsid(msg);
        }
        self.padding_seen |= has_edns_padding(msg);
        if self.ede_detail.is_none() {
            self.ede_detail = extract_ede(msg);
        }
    }
}

async fn try_plain_fallback(
    ctx: &ProbeContext,
    endpoint: &UpstreamEndpoint,
    input: String,
    label: String,
    protocol: UpstreamProtocol,
    encrypted: bool,
    primary_err: String,
) -> UpstreamCapabilities {
    let Ok(plain_wire) = build_probe_query(".", RecordType::NS, ProbeQueryOptions::default())
    else {
        return UpstreamCapabilities::failed(input, label, protocol, primary_err);
    };
    match exchange_once(ctx, endpoint, &plain_wire).await {
        Ok(plain_meta) => {
            finish_plain_only_probe(ctx, endpoint, input, label, protocol, encrypted, plain_meta)
                .await
        }
        Err(_) => UpstreamCapabilities::failed(input, label, protocol, primary_err),
    }
}

async fn retry_without_cookie(
    ctx: &ProbeContext,
    endpoint: &UpstreamEndpoint,
    primary_msg: &mut Message,
    edns_state: &mut ProbeEdnsState,
) {
    let retry_opts = ProbeQueryOptions {
        with_edns: true,
        with_do: true,
        with_nsid: true,
        client_cookie: None,
        ecs_subnet: None,
    };
    if let Ok(retry_wire) = build_probe_query(".", RecordType::DNSKEY, retry_opts)
        && let Ok(retry_meta) = exchange_once(ctx, endpoint, &retry_wire).await
        && let Ok(retry_msg) = Message::from_vec(&retry_meta.wire)
    {
        edns_state.merge_from(&retry_msg);
        *primary_msg = retry_msg;
    }
}

async fn inspect_edns_and_dnssec(
    ctx: &ProbeContext,
    endpoint: &UpstreamEndpoint,
    primary_wire: &[u8],
    primary_msg: Message,
    latency_ms: &mut u64,
    recursion_available: &mut Option<bool>,
    edns_state: &mut ProbeEdnsState,
) -> (Option<bool>, Option<u16>, Option<bool>, bool) {
    let edns_rejected = matches!(
        primary_msg.response_code,
        ResponseCode::FormErr | ResponseCode::NotImp | ResponseCode::BADVERS
    ) || primary_msg.edns.is_none();

    if edns_rejected {
        if primary_msg.response_code != ResponseCode::NoError
            && let Ok(plain_wire) =
                build_probe_query(".", RecordType::NS, ProbeQueryOptions::default())
            && let Ok(plain_meta) = exchange_once(ctx, endpoint, &plain_wire).await
            && let Ok(plain_msg) = Message::from_vec(&plain_meta.wire)
        {
            *latency_ms = (*latency_ms).min(plain_meta.latency_ms);
            *recursion_available = Some(plain_msg.metadata.recursion_available);
        }
        return (Some(false), None, Some(false), false);
    }

    let udp_size = primary_msg.edns.as_ref().map(Edns::max_payload);
    let effective_msg = if primary_msg.metadata.truncation
        && let UpstreamEndpoint::Udp(addr) = *endpoint
    {
        let tcp_ep = UpstreamEndpoint::Tcp(addr);
        if let Ok(tcp_meta) = exchange_once(ctx, &tcp_ep, primary_wire).await
            && let Ok(tcp_msg) = Message::from_vec(&tcp_meta.wire)
        {
            edns_state.merge_from(&tcp_msg);
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
}

struct PrimaryProbeSummary {
    input: String,
    label: String,
    protocol: UpstreamProtocol,
    encrypted: bool,
    transport_detail: Option<String>,
    latency_ms: u64,
    recursion_available: Option<bool>,
    edns: Option<bool>,
    edns_udp_size: Option<u16>,
    dnssec_aware: Option<bool>,
    root_ad_bit: bool,
    cookies_supported: bool,
    edns_state: ProbeEdnsState,
}

async fn finish_with_secondary_probes(
    ctx: &ProbeContext,
    endpoint: &UpstreamEndpoint,
    mut summary: PrimaryProbeSummary,
) -> UpstreamCapabilities {
    let edns_supported = summary.edns != Some(false);
    let (dnssec_probe, nxdomain_hijack, ecs, ddr_upgrades) = tokio::join!(
        probe_dnssec_validating(
            ctx,
            endpoint,
            edns_supported,
            summary.dnssec_aware == Some(true),
            summary.root_ad_bit
        ),
        probe_nxdomain_hijack(ctx, endpoint),
        probe_ecs(ctx, endpoint, edns_supported),
        probe_ddr(ctx, endpoint, !summary.encrypted),
    );

    if summary.edns_state.ede_detail.is_none() {
        summary.edns_state.ede_detail = dnssec_probe.ede_detail;
    }
    summary.edns_state.padding_seen |= dnssec_probe.padding_seen;

    let ede = if summary.edns_state.ede_detail.is_some() {
        Some(true)
    } else if dnssec_probe.saw_servfail {
        Some(false)
    } else {
        None
    };

    let edns_padding = if summary.edns_state.padding_seen {
        Some(true)
    } else if summary.encrypted && edns_supported {
        Some(false)
    } else {
        None
    };

    UpstreamCapabilities {
        input: summary.input,
        endpoint: summary.label,
        protocol: summary.protocol,
        encrypted: summary.encrypted,
        transport_detail: summary.transport_detail,
        reachable: true,
        latency_ms: Some(summary.latency_ms),
        recursion_available: summary.recursion_available,
        edns: summary.edns,
        edns_udp_size: summary.edns_udp_size,
        dnssec_aware: summary.dnssec_aware,
        dnssec_validating: dnssec_probe.validating,
        ecs,
        nxdomain_hijack,
        ddr_upgrades,
        nsid: summary.edns_state.nsid,
        dns_cookies: Some(edns_supported && summary.cookies_supported),
        edns_padding,
        ede,
        ede_detail: summary.edns_state.ede_detail,
        error: None,
    }
}

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
    let encrypted = is_encrypted_protocol(protocol);
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
            return try_plain_fallback(
                ctx,
                &endpoint,
                input,
                label,
                protocol,
                encrypted,
                primary_err.to_string(),
            )
            .await;
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
    let mut edns_state = ProbeEdnsState::from_msg(&primary_msg);
    let mut cookies_supported = has_valid_server_cookie(&primary_msg, client_cookie);

    // RFC 7873: BADCOOKIE proves cookie support; re-query without cookie to inspect DNSKEY/RRSIG.
    if primary_msg.response_code == ResponseCode::BADCOOKIE {
        cookies_supported = true;
        retry_without_cookie(ctx, &endpoint, &mut primary_msg, &mut edns_state).await;
    }

    let mut recursion_available = Some(primary_msg.metadata.recursion_available);
    let (edns, edns_udp_size, dnssec_aware, root_ad_bit) = inspect_edns_and_dnssec(
        ctx,
        &endpoint,
        &primary_wire,
        primary_msg,
        &mut latency_ms,
        &mut recursion_available,
        &mut edns_state,
    )
    .await;

    // 2. Concurrent secondary probes: DNSSEC validating (+EDE), NXDOMAIN hijack, ECS, DDR
    finish_with_secondary_probes(
        ctx,
        &endpoint,
        PrimaryProbeSummary {
            input,
            label,
            protocol,
            encrypted,
            transport_detail,
            latency_ms,
            recursion_available,
            edns,
            edns_udp_size,
            dnssec_aware,
            root_ad_bit,
            cookies_supported,
            edns_state,
        },
    )
    .await
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

#[cfg(test)]
#[path = "upstream_probe_tests.rs"]
mod tests;
