use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use futures_util::future::join_all;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::recursor::{
    DnssecConfig, DnssecPolicy, QNameMinimization, Recursor, RecursorOptions,
};
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use ts_rs::TS;

use crate::edns::has_dnssec_ok;
use crate::error::{CoreError, Result};
use crate::upstream::next_tx_id;
use crate::wire::base_response;

/// QNAME minimization mode (RFC 9156) for the built-in recursive resolver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum RecursiveQnameMinimization {
    Strict,
    #[default]
    Relaxed,
}

/// Configuration for the built-in recursive DNS resolver (`hickory-resolver::recursor`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
#[allow(clippy::struct_excessive_bools)]
pub struct RecursiveConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub qname_minimization: RecursiveQnameMinimization,
    #[serde(default)]
    pub dnssec_validate: bool,
    #[serde(default)]
    pub case_randomization: bool,
}

impl Default for RecursiveConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            qname_minimization: RecursiveQnameMinimization::Relaxed,
            dnssec_validate: false,
            case_randomization: false,
        }
    }
}

/// Reachability and latency result for a single root server endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct RootServerProbeResult {
    pub name: String,
    pub ip: String,
    pub family: String,
    pub reachable: bool,
    #[ts(type = "number | null")]
    pub latency_ms: Option<u64>,
    pub rcode: Option<String>,
    pub error: Option<String>,
}

/// Aggregated reachability report across all 13 IANA root servers (IPv4 + IPv6).
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct RootProbeReport {
    pub total: usize,
    pub reachable_count: usize,
    pub ipv4_reachable: usize,
    pub ipv6_reachable: usize,
    pub results: Vec<RootServerProbeResult>,
}

const ROOT_SERVERS: &[(&str, Ipv4Addr, Ipv6Addr)] = &[
    (
        "a.root-servers.net",
        Ipv4Addr::new(198, 41, 0, 4),
        Ipv6Addr::new(0x2001, 0x0503, 0xba3e, 0, 0, 0, 0x0002, 0x0030),
    ),
    (
        "b.root-servers.net",
        Ipv4Addr::new(170, 247, 170, 2),
        Ipv6Addr::new(0x2801, 0x01b8, 0x0010, 0, 0, 0, 0, 0x000b),
    ),
    (
        "c.root-servers.net",
        Ipv4Addr::new(192, 33, 4, 12),
        Ipv6Addr::new(0x2001, 0x0500, 0x0002, 0, 0, 0, 0, 0x000c),
    ),
    (
        "d.root-servers.net",
        Ipv4Addr::new(199, 7, 91, 13),
        Ipv6Addr::new(0x2001, 0x0500, 0x002d, 0, 0, 0, 0, 0x000d),
    ),
    (
        "e.root-servers.net",
        Ipv4Addr::new(192, 203, 230, 10),
        Ipv6Addr::new(0x2001, 0x0500, 0x00a8, 0, 0, 0, 0, 0x000e),
    ),
    (
        "f.root-servers.net",
        Ipv4Addr::new(192, 5, 5, 241),
        Ipv6Addr::new(0x2001, 0x0500, 0x002f, 0, 0, 0, 0, 0x000f),
    ),
    (
        "g.root-servers.net",
        Ipv4Addr::new(192, 112, 36, 4),
        Ipv6Addr::new(0x2001, 0x0500, 0x0012, 0, 0, 0, 0, 0x0d0d),
    ),
    (
        "h.root-servers.net",
        Ipv4Addr::new(198, 97, 190, 53),
        Ipv6Addr::new(0x2001, 0x0500, 0x0001, 0, 0, 0, 0, 0x0053),
    ),
    (
        "i.root-servers.net",
        Ipv4Addr::new(192, 36, 148, 17),
        Ipv6Addr::new(0x2001, 0x07fe, 0, 0, 0, 0, 0, 0x0053),
    ),
    (
        "j.root-servers.net",
        Ipv4Addr::new(192, 58, 128, 30),
        Ipv6Addr::new(0x2001, 0x0503, 0x0c27, 0, 0, 0, 0x0002, 0x0030),
    ),
    (
        "k.root-servers.net",
        Ipv4Addr::new(193, 0, 14, 129),
        Ipv6Addr::new(0x2001, 0x07fd, 0, 0, 0, 0, 0, 0x0001),
    ),
    (
        "l.root-servers.net",
        Ipv4Addr::new(199, 7, 83, 42),
        Ipv6Addr::new(0x2001, 0x0500, 0x009f, 0, 0, 0, 0, 0x0042),
    ),
    (
        "m.root-servers.net",
        Ipv4Addr::new(202, 12, 27, 33),
        Ipv6Addr::new(0x2001, 0x0dc3, 0, 0, 0, 0, 0, 0x0035),
    ),
];

fn root_hint_ips() -> Vec<IpAddr> {
    let mut ips = Vec::with_capacity(ROOT_SERVERS.len() * 2);
    for &(_, v4, v6) in ROOT_SERVERS {
        ips.push(IpAddr::V4(v4));
        ips.push(IpAddr::V6(v6));
    }
    ips
}

pub const RECURSIVE_UPSTREAM_LABEL: &str = "recursive://builtin";

/// Built-in iterative DNS resolver powered by `hickory_resolver::recursor::Recursor`.
pub struct BuiltinRecursor {
    inner: Recursor<TokioRuntimeProvider>,
    timeout: Duration,
}

impl BuiltinRecursor {
    /// Builds a [`BuiltinRecursor`] from [`RecursiveConfig`] and per-query timeout.
    pub fn new(config: &RecursiveConfig, timeout_ms: u64) -> Result<Self> {
        let dnssec_policy = if config.dnssec_validate {
            DnssecPolicy::ValidateWithStaticKey(DnssecConfig::default())
        } else {
            DnssecPolicy::SecurityUnaware
        };

        let mut options = RecursorOptions {
            case_randomization: config.case_randomization,
            qname_minimization: match config.qname_minimization {
                RecursiveQnameMinimization::Strict => QNameMinimization::Strict,
                RecursiveQnameMinimization::Relaxed => QNameMinimization::Relaxed,
            },
            ..RecursorOptions::default()
        };
        // Keep internal recursor cache bounded for embedded/gateway footprints.
        options.response_cache_size = 65_536;
        options.ns_cache_size = 2_048;

        let roots = root_hint_ips();
        let inner = Recursor::new(
            &roots,
            dnssec_policy,
            None,
            options,
            TokioRuntimeProvider::default(),
        )
        .map_err(|e| {
            CoreError::Upstream(format!("failed to initialize recursive resolver: {e}"))
        })?;

        Ok(Self {
            inner,
            timeout: Duration::from_millis(timeout_ms.max(2_000)),
        })
    }

    /// Resolves a raw DNS wire query iteratively from the root hints.
    pub async fn query_raw(&self, query_bytes: &[u8]) -> Result<(Vec<u8>, String)> {
        let request =
            Message::from_vec(query_bytes).map_err(|e| CoreError::Protocol(e.to_string()))?;
        let Some(question) = request.queries.first() else {
            return Err(CoreError::Protocol("missing DNS question".to_string()));
        };

        let mut fqdn_name = question.name().clone();
        fqdn_name.set_fqdn(true);
        let query = Query::query(fqdn_name, question.query_type());
        let want_do = has_dnssec_ok(&request);

        let res = tokio::time::timeout(
            self.timeout,
            self.inner.resolve(query, Instant::now(), want_do),
        )
        .await
        .map_err(|_| CoreError::Upstream("recursive resolution timed out".to_string()))?;

        match res {
            Ok(mut msg) => {
                msg.metadata.id = request.id;
                msg.metadata.message_type = MessageType::Response;
                msg.metadata.recursion_desired = request.recursion_desired;
                msg.metadata.recursion_available = true;
                msg.queries.clone_from(&request.queries);
                let wire = msg
                    .to_vec()
                    .map_err(|e| CoreError::Protocol(e.to_string()))?;
                Ok((wire, RECURSIVE_UPSTREAM_LABEL.to_string()))
            }
            Err(err) => {
                if err.is_nx_domain() {
                    let mut resp = base_response(&request, ResponseCode::NXDomain);
                    if let Some(soa) = err.into_soa() {
                        resp.add_authority(Record::from_rdata(
                            soa.name,
                            soa.ttl,
                            RData::SOA(soa.data),
                        ));
                    }
                    let wire = resp
                        .to_vec()
                        .map_err(|e| CoreError::Protocol(e.to_string()))?;
                    return Ok((wire, RECURSIVE_UPSTREAM_LABEL.to_string()));
                }
                if err.is_no_records_found() {
                    let mut resp = base_response(&request, ResponseCode::NoError);
                    if let Some(soa) = err.into_soa() {
                        resp.add_authority(Record::from_rdata(
                            soa.name,
                            soa.ttl,
                            RData::SOA(soa.data),
                        ));
                    }
                    let wire = resp
                        .to_vec()
                        .map_err(|e| CoreError::Protocol(e.to_string()))?;
                    return Ok((wire, RECURSIVE_UPSTREAM_LABEL.to_string()));
                }
                Err(CoreError::Upstream(format!(
                    "recursive resolution failed: {err}"
                )))
            }
        }
    }
}

/// Probes reachability and UDP RTT latency for all 13 IANA root servers (IPv4 + IPv6).
pub async fn probe_root_servers(timeout_ms: u64) -> RootProbeReport {
    let timeout = Duration::from_millis(timeout_ms.clamp(300, 5_000));
    let mut tasks = Vec::with_capacity(ROOT_SERVERS.len() * 2);
    for &(name, v4, v6) in ROOT_SERVERS {
        tasks.push(probe_single_root(name, IpAddr::V4(v4), timeout));
        tasks.push(probe_single_root(name, IpAddr::V6(v6), timeout));
    }

    let results = join_all(tasks).await;
    let total = results.len();
    let reachable_count = results.iter().filter(|r| r.reachable).count();
    let ipv4_reachable = results
        .iter()
        .filter(|r| r.reachable && r.family == "ipv4")
        .count();
    let ipv6_reachable = results
        .iter()
        .filter(|r| r.reachable && r.family == "ipv6")
        .count();

    RootProbeReport {
        total,
        reachable_count,
        ipv4_reachable,
        ipv6_reachable,
        results,
    }
}

fn root_probe_err(
    name: &str,
    ip: IpAddr,
    family: &str,
    error: impl Into<String>,
) -> RootServerProbeResult {
    RootServerProbeResult {
        name: name.to_string(),
        ip: ip.to_string(),
        family: family.to_string(),
        reachable: false,
        latency_ms: None,
        rcode: None,
        error: Some(error.into()),
    }
}

async fn probe_single_root(
    name: &'static str,
    ip: IpAddr,
    timeout: Duration,
) -> RootServerProbeResult {
    let family = if ip.is_ipv4() { "ipv4" } else { "ipv6" };
    let bind_addr: SocketAddr = match ip {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };

    let tx_id = next_tx_id();
    let mut msg = Message::new(tx_id, MessageType::Query, OpCode::Query);
    msg.add_query(Query::query(Name::root(), RecordType::NS));
    let Ok(wire) = msg.to_vec() else {
        return root_probe_err(name, ip, family, "failed to encode probe query");
    };

    let sock = match UdpSocket::bind(bind_addr).await {
        Ok(s) => s,
        Err(err) => return root_probe_err(name, ip, family, err.to_string()),
    };

    let start = Instant::now();
    if let Err(err) = sock.send_to(&wire, SocketAddr::new(ip, 53)).await {
        return root_probe_err(name, ip, family, err.to_string());
    }

    let mut buf = [0_u8; 1500];
    let recv = match tokio::time::timeout(timeout, sock.recv_from(&mut buf)).await {
        Ok(Ok((len, _))) => len,
        Ok(Err(err)) => return root_probe_err(name, ip, family, err.to_string()),
        Err(_) => return root_probe_err(name, ip, family, "timeout"),
    };

    let elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    match Message::from_vec(&buf[..recv]) {
        Ok(resp) if resp.id == tx_id && resp.message_type == MessageType::Response => {
            RootServerProbeResult {
                name: name.to_string(),
                ip: ip.to_string(),
                family: family.to_string(),
                reachable: true,
                latency_ms: Some(elapsed_ms),
                rcode: Some(resp.response_code.to_string()),
                error: None,
            }
        }
        Ok(_) => root_probe_err(name, ip, family, "mismatched DNS response"),
        Err(err) => root_probe_err(name, ip, family, err.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_recursor_initializes() {
        let cfg = RecursiveConfig {
            enabled: true,
            qname_minimization: RecursiveQnameMinimization::Strict,
            dnssec_validate: true,
            case_randomization: true,
        };
        let recursor = BuiltinRecursor::new(&cfg, 5000);
        assert!(recursor.is_ok());
    }
}
