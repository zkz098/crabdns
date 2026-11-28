use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use crabdns_core::{QueryContext, QueryOutcome, QueryProtocol};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::task::JoinSet;
use ts_rs::TS;
use x509_parser::pem::parse_x509_pem;
use x509_parser::prelude::FromDer;

use crate::RouterState;
use crate::tls_api::TlsReloader;

const UDP_PROBE_COUNT: usize = 8;
const UDP_PROBE_TIMEOUT: Duration = Duration::from_millis(600);
const TCP_PROBE_TIMEOUT: Duration = Duration::from_millis(1000);
const BOOTSTRAP_PROBE_TIMEOUT: Duration = Duration::from_millis(1500);
const HIGH_LOOPBACK_LATENCY_MS: u64 = 100;
const HIGH_UPSTREAM_LATENCY_MS: u64 = 500;
const TLS_CERT_EXPIRY_WARN_DAYS: i64 = 14;
const MIN_FREE_DISK_MB: u64 = 100;
// 2024-01-01T00:00:00Z in UNIX seconds; used to catch uninitialized RTC clocks.
const MIN_SANE_UNIX_SECS: u64 = 1_704_067_200;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum DiagnosticStatus {
    Ok,
    Warn,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum DiagnosticCategory {
    Listener,
    Upstream,
    Security,
    Storage,
}

#[derive(Debug, Clone, Serialize, TS)]
#[ts(export)]
pub struct DiagnosticItem {
    pub id: String,
    pub category: DiagnosticCategory,
    pub status: DiagnosticStatus,
    pub summary: String,
    pub detail: Option<String>,
    pub hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_tab: Option<String>,
}

#[derive(Debug, Clone, Serialize, TS)]
#[ts(export)]
pub struct SystemDiagnosticsResponse {
    pub overall: DiagnosticStatus,
    #[ts(type = "number")]
    pub checked_at_ms: u64,
    pub listen_dns: String,
    pub items: Vec<DiagnosticItem>,
}

pub async fn run_system_diagnostics(
    State(state): State<RouterState>,
) -> Json<SystemDiagnosticsResponse> {
    let cfg = state.app.config.load();
    let listen_dns = cfg.listen_dns;

    let mdns_item = check_mdns_port_conflict(listen_dns);
    let loopback_item = check_loopback_probe(listen_dns).await;
    let system_dns_item = check_system_dns_takeover(listen_dns);
    let drops_item = check_udp_inflight_drops(&state);
    let upstream_item = check_upstream_health(&state);
    let bootstrap_item = check_bootstrap_dns(&cfg.upstreams, &cfg.bootstrap_dns).await;
    let loop_item = check_forwarding_loop(
        listen_dns,
        &cfg.upstreams,
        &cfg.upstream_groups,
        &cfg.split_dns,
    );
    let auth_item = check_webui_auth(cfg.web_auth_enabled, &cfg.web_password_hash);
    let tls_item = check_tls_cert_health(&cfg, state.app.tls_reloader.as_deref());
    let open_resolver_item = check_open_resolver_risk(&cfg);
    let dnssec_clock_item = check_dnssec_and_clock(&cfg);
    let local_sources_item = check_local_data_sources(&cfg);
    let storage_item = check_data_dir_storage(&cfg);
    let cache_item = check_cache_config(&cfg, &state);

    let items = vec![
        mdns_item,
        loopback_item,
        system_dns_item,
        drops_item,
        upstream_item,
        bootstrap_item,
        loop_item,
        auth_item,
        tls_item,
        open_resolver_item,
        dnssec_clock_item,
        local_sources_item,
        storage_item,
        cache_item,
    ];
    let overall = compute_overall_status(&items);
    let checked_at_ms = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(u64::MAX);

    Json(SystemDiagnosticsResponse {
        overall,
        checked_at_ms,
        listen_dns: listen_dns.to_string(),
        items,
    })
}

fn compute_overall_status(items: &[DiagnosticItem]) -> DiagnosticStatus {
    if items.iter().any(|i| i.status == DiagnosticStatus::Error) {
        DiagnosticStatus::Error
    } else if items.iter().any(|i| i.status == DiagnosticStatus::Warn) {
        DiagnosticStatus::Warn
    } else {
        DiagnosticStatus::Ok
    }
}

fn check_mdns_port_conflict(listen_dns: SocketAddr) -> DiagnosticItem {
    let port = listen_dns.port();
    let foreign_uids = find_foreign_udp_uids(port, listen_dns.is_ipv6());

    if !foreign_uids.is_empty() {
        let uid_list = foreign_uids
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        return DiagnosticItem {
            id: "mdns_port_conflict".to_string(),
            category: DiagnosticCategory::Listener,
            status: DiagnosticStatus::Error,
            summary: format!("Port {port} shared with foreign UID(s): {uid_list}"),
            detail: Some(
                "Detected another process bound to the same UDP port via SO_REUSEPORT.".to_string(),
            ),
            hint: Some(
                "Change listen_dns to a dedicated port (e.g. 5354) or stop the conflicting service."
                    .to_string(),
            ),
            action_tab: Some("settings".to_string()),
        };
    }

    if port == 5353 {
        return DiagnosticItem {
            id: "mdns_port_conflict".to_string(),
            category: DiagnosticCategory::Listener,
            status: DiagnosticStatus::Warn,
            summary: "listen_dns is using mDNS port 5353".to_string(),
            detail: Some(
                "Port 5353 is reserved for mDNS and shares SO_REUSEPORT with mDNS listeners."
                    .to_string(),
            ),
            hint: Some("Switch listen_dns to 5354 (or 53 in takeover mode).".to_string()),
            action_tab: Some("settings".to_string()),
        };
    }

    DiagnosticItem {
        id: "mdns_port_conflict".to_string(),
        category: DiagnosticCategory::Listener,
        status: DiagnosticStatus::Ok,
        summary: format!("No SO_REUSEPORT conflict on port {port}"),
        detail: None,
        hint: None,
        action_tab: None,
    }
}

#[cfg(target_os = "linux")]
fn find_foreign_udp_uids(port: u16, is_ipv6: bool) -> Vec<u32> {
    use std::collections::BTreeSet;
    use std::os::unix::fs::MetadataExt;

    let Ok(self_uid) = std::fs::metadata("/proc/self").map(|m| m.uid()) else {
        return Vec::new();
    };
    let path = if is_ipv6 {
        "/proc/net/udp6"
    } else {
        "/proc/net/udp"
    };
    let Ok(content) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let target_hex = format!("{port:04X}");
    let mut foreign = BTreeSet::new();
    for line in content.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 8 {
            continue;
        }
        let Some((_, local_port)) = cols[1].rsplit_once(':') else {
            continue;
        };
        if !local_port.eq_ignore_ascii_case(&target_hex) || cols[3] != "07" {
            continue;
        }
        if let Ok(uid) = cols[7].parse::<u32>()
            && uid != self_uid
        {
            foreign.insert(uid);
        }
    }
    foreign.into_iter().collect()
}

#[cfg(not(target_os = "linux"))]
fn find_foreign_udp_uids(_port: u16, _is_ipv6: bool) -> Vec<u32> {
    Vec::new()
}

fn loopback_target(listen_dns: SocketAddr) -> SocketAddr {
    if listen_dns.ip().is_unspecified() {
        let ip = if listen_dns.is_ipv6() {
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        } else {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        };
        SocketAddr::new(ip, listen_dns.port())
    } else {
        listen_dns
    }
}

fn build_dns_query(txid: u16, domain: &str) -> Vec<u8> {
    build_dns_query_with_type(txid, domain, 1)
}

fn build_dns_query_with_type(txid: u16, domain: &str, qtype: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32 + domain.len());
    buf.extend_from_slice(&txid.to_be_bytes());
    buf.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in domain.trim_end_matches('.').split('.') {
        if !label.is_empty() && label.len() <= 63 {
            buf.push(u8::try_from(label.len()).unwrap_or(0));
            buf.extend_from_slice(label.as_bytes());
        }
    }
    buf.push(0x00);
    buf.extend_from_slice(&qtype.to_be_bytes());
    buf.extend_from_slice(&[0x00, 0x01]);
    buf
}

async fn probe_udp_once(
    target: SocketAddr,
    txid: u16,
    domain: &str,
    timeout: Duration,
) -> Option<u64> {
    let bind_ip = if target.is_ipv6() {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    } else {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    };
    let sock = UdpSocket::bind(SocketAddr::new(bind_ip, 0)).await.ok()?;
    let query = build_dns_query(txid, domain);
    let start = Instant::now();
    sock.send_to(&query, target).await.ok()?;
    let mut resp = [0_u8; 512];
    let (len, _) = tokio::time::timeout(timeout, sock.recv_from(&mut resp))
        .await
        .ok()?
        .ok()?;
    if len >= 2 && resp[0..2] == txid.to_be_bytes() {
        Some(u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX))
    } else {
        None
    }
}

async fn probe_tcp_once(target: SocketAddr, txid: u16, domain: &str, timeout: Duration) -> bool {
    let Ok(Ok(mut stream)) = tokio::time::timeout(timeout, TcpStream::connect(target)).await else {
        return false;
    };
    let query = build_dns_query(txid, domain);
    let Ok(qlen) = u16::try_from(query.len()) else {
        return false;
    };
    let mut framed = Vec::with_capacity(2 + query.len());
    framed.extend_from_slice(&qlen.to_be_bytes());
    framed.extend_from_slice(&query);
    if tokio::time::timeout(timeout, stream.write_all(&framed))
        .await
        .is_err()
    {
        return false;
    }
    let mut len_buf = [0_u8; 2];
    let Ok(Ok(_)) = tokio::time::timeout(timeout, stream.read_exact(&mut len_buf)).await else {
        return false;
    };
    let resp_len = usize::from(u16::from_be_bytes(len_buf));
    if resp_len < 2 || resp_len > 4096 {
        return false;
    }
    let mut resp = vec![0_u8; resp_len];
    matches!(
        tokio::time::timeout(timeout, stream.read_exact(&mut resp)).await,
        Ok(Ok(_)) if resp[0..2] == txid.to_be_bytes()
    )
}

async fn check_loopback_probe(listen_dns: SocketAddr) -> DiagnosticItem {
    let target = loopback_target(listen_dns);
    let mut set = JoinSet::new();
    for i in 0..UDP_PROBE_COUNT {
        let txid = 0xC000_u16.wrapping_add(u16::try_from(i).unwrap_or(0));
        set.spawn(probe_udp_once(target, txid, "localhost", UDP_PROBE_TIMEOUT));
    }

    let tcp_fut = probe_tcp_once(target, 0xC100, "localhost", TCP_PROBE_TIMEOUT);
    let mut udp_ok = 0_usize;
    let mut latency_sum = 0_u64;
    let tcp_ok = tcp_fut.await;
    while let Some(res) = set.join_next().await {
        if let Ok(Some(ms)) = res {
            udp_ok += 1;
            latency_sum += ms;
        }
    }

    let avg_ms = if udp_ok > 0 {
        latency_sum / u64::try_from(udp_ok).unwrap_or(1)
    } else {
        0
    };
    let tcp_label = if tcp_ok { "OK" } else { "FAIL" };

    if udp_ok == UDP_PROBE_COUNT && tcp_ok {
        if avg_ms >= HIGH_LOOPBACK_LATENCY_MS {
            DiagnosticItem {
                id: "loopback_probe".to_string(),
                category: DiagnosticCategory::Listener,
                status: DiagnosticStatus::Warn,
                summary: format!("UDP {udp_ok}/{UDP_PROBE_COUNT} · TCP {tcp_label} ({avg_ms} ms)"),
                detail: Some(format!(
                    "Target {target} responded slowly (threshold {HIGH_LOOPBACK_LATENCY_MS} ms)."
                )),
                hint: Some(
                    "Local loopback DNS latency is abnormally high; check CPU load or worker stalls."
                        .to_string(),
                ),
                action_tab: None,
            }
        } else {
            DiagnosticItem {
                id: "loopback_probe".to_string(),
                category: DiagnosticCategory::Listener,
                status: DiagnosticStatus::Ok,
                summary: format!("UDP {udp_ok}/{UDP_PROBE_COUNT} · TCP {tcp_label} ({avg_ms} ms)"),
                detail: Some(format!("Target {target}")),
                hint: None,
                action_tab: None,
            }
        }
    } else {
        let hint = if udp_ok > 0 && udp_ok < UDP_PROBE_COUNT {
            "Partial UDP loss suggests SO_REUSEPORT worker stall or port conflict."
        } else {
            "Ensure CrabDNS DNS listener is running and reachable on loopback."
        };
        DiagnosticItem {
            id: "loopback_probe".to_string(),
            category: DiagnosticCategory::Listener,
            status: DiagnosticStatus::Error,
            summary: format!("UDP {udp_ok}/{UDP_PROBE_COUNT} · TCP {tcp_label}"),
            detail: Some(format!("Target {target}")),
            hint: Some(hint.to_string()),
            action_tab: Some("settings".to_string()),
        }
    }
}

fn check_udp_inflight_drops(state: &RouterState) -> DiagnosticItem {
    let drops = state.app.pipeline.runtime_metrics().udp_dropped_inflight;
    if drops == 0 {
        DiagnosticItem {
            id: "udp_inflight_drops".to_string(),
            category: DiagnosticCategory::Listener,
            status: DiagnosticStatus::Ok,
            summary: "0 inflight UDP drops".to_string(),
            detail: None,
            hint: None,
            action_tab: None,
        }
    } else {
        DiagnosticItem {
            id: "udp_inflight_drops".to_string(),
            category: DiagnosticCategory::Listener,
            status: DiagnosticStatus::Warn,
            summary: format!("{drops} UDP queries dropped"),
            detail: Some("Dropped when concurrent inflight UDP queries hit the limit.".to_string()),
            hint: Some("Check upstream latency or reduce burst query load.".to_string()),
            action_tab: None,
        }
    }
}

fn check_upstream_health(state: &RouterState) -> DiagnosticItem {
    let statuses = state.app.pipeline.upstream().health_snapshot();
    let total = statuses.len();
    if total == 0 {
        return DiagnosticItem {
            id: "upstream_health".to_string(),
            category: DiagnosticCategory::Upstream,
            status: DiagnosticStatus::Warn,
            summary: "No upstreams configured".to_string(),
            detail: None,
            hint: Some("Add at least one upstream DNS server in Settings.".to_string()),
            action_tab: Some("settings".to_string()),
        };
    }

    let healthy_list: Vec<_> = statuses.iter().filter(|s| s.healthy).collect();
    let unhealthy_names: Vec<_> = statuses
        .iter()
        .filter(|s| !s.healthy)
        .map(|s| s.endpoint.as_str())
        .collect();

    if unhealthy_names.is_empty() {
        let measured: Vec<u64> = healthy_list
            .iter()
            .filter(|s| s.total_requests > 0)
            .map(|s| s.ewma_latency_ms)
            .collect();
        let avg_lat = if measured.is_empty() {
            0
        } else {
            measured.iter().sum::<u64>() / u64::try_from(measured.len()).unwrap_or(1)
        };
        let slow_upstreams: Vec<String> = healthy_list
            .iter()
            .filter(|s| s.total_requests > 0 && s.ewma_latency_ms >= HIGH_UPSTREAM_LATENCY_MS)
            .map(|s| format!("{} ({} ms)", s.endpoint, s.ewma_latency_ms))
            .collect();
        if !slow_upstreams.is_empty() || avg_lat >= HIGH_UPSTREAM_LATENCY_MS {
            DiagnosticItem {
                id: "upstream_health".to_string(),
                category: DiagnosticCategory::Upstream,
                status: DiagnosticStatus::Warn,
                summary: format!("{total}/{total} healthy (slow: avg {avg_lat} ms)"),
                detail: Some(if slow_upstreams.is_empty() {
                    format!("Average upstream latency {avg_lat} ms exceeds {HIGH_UPSTREAM_LATENCY_MS} ms.")
                } else {
                    format!("High latency: {}", slow_upstreams.join(", "))
                }),
                hint: Some(
                    "Upstream response speed is abnormally slow; check network or switch to lower-latency servers."
                        .to_string(),
                ),
                action_tab: Some("settings".to_string()),
            }
        } else {
            DiagnosticItem {
                id: "upstream_health".to_string(),
                category: DiagnosticCategory::Upstream,
                status: DiagnosticStatus::Ok,
                summary: format!("{total}/{total} healthy (avg {avg_lat} ms)"),
                detail: None,
                hint: None,
                action_tab: None,
            }
        }
    } else if !healthy_list.is_empty() {
        DiagnosticItem {
            id: "upstream_health".to_string(),
            category: DiagnosticCategory::Upstream,
            status: DiagnosticStatus::Warn,
            summary: format!("{}/{total} healthy", healthy_list.len()),
            detail: Some(format!("Degraded: {}", unhealthy_names.join(", "))),
            hint: Some(
                "Check degraded upstream servers or replace unreliable endpoints.".to_string(),
            ),
            action_tab: Some("settings".to_string()),
        }
    } else {
        DiagnosticItem {
            id: "upstream_health".to_string(),
            category: DiagnosticCategory::Upstream,
            status: DiagnosticStatus::Error,
            summary: format!("0/{total} upstreams healthy"),
            detail: Some(format!("Failing: {}", unhealthy_names.join(", "))),
            hint: Some("All upstreams are failing or in circuit-breaker backoff.".to_string()),
            action_tab: Some("settings".to_string()),
        }
    }
}

fn extract_domain_host(spec: &str) -> Option<String> {
    let trimmed = spec.trim();
    let rest = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .or_else(|| trimmed.strip_prefix("tls://"))
        .or_else(|| trimmed.strip_prefix("quic://"))
        .or_else(|| trimmed.strip_prefix("h3://"))?;
    let host_port = rest.split('/').next()?;
    let host = if let Some(inner) = host_port.strip_prefix('[') {
        inner.split(']').next()?
    } else {
        host_port.split(':').next()?
    };
    if host.is_empty() || host.parse::<IpAddr>().is_ok() {
        None
    } else {
        Some(host.to_string())
    }
}

fn parse_bootstrap_socket_addr(spec: &str) -> Option<SocketAddr> {
    let trimmed = spec.trim();
    if let Ok(addr) = trimmed.parse::<SocketAddr>() {
        return Some(addr);
    }
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, 53));
    }
    None
}

async fn check_bootstrap_dns(upstreams: &[String], bootstrap_dns: &[String]) -> DiagnosticItem {
    let domain_host = upstreams.iter().find_map(|u| extract_domain_host(u));
    let Some(host) = domain_host else {
        return DiagnosticItem {
            id: "bootstrap_dns".to_string(),
            category: DiagnosticCategory::Upstream,
            status: DiagnosticStatus::Ok,
            summary: "Not required (IP-based upstreams)".to_string(),
            detail: None,
            hint: None,
            action_tab: None,
        };
    };

    let Some(first_bootstrap) = bootstrap_dns.first() else {
        return DiagnosticItem {
            id: "bootstrap_dns".to_string(),
            category: DiagnosticCategory::Upstream,
            status: DiagnosticStatus::Error,
            summary: "Bootstrap DNS not configured".to_string(),
            detail: Some(format!("Required to resolve upstream host {host}")),
            hint: Some(
                "Add at least one IP-based bootstrap_dns server (e.g. 223.5.5.5).".to_string(),
            ),
            action_tab: Some("settings".to_string()),
        };
    };

    let Some(target) = parse_bootstrap_socket_addr(first_bootstrap) else {
        return DiagnosticItem {
            id: "bootstrap_dns".to_string(),
            category: DiagnosticCategory::Upstream,
            status: DiagnosticStatus::Warn,
            summary: format!("Unrecognized bootstrap address: {first_bootstrap}"),
            detail: None,
            hint: Some("Use an IPv4/IPv6 address for bootstrap_dns.".to_string()),
            action_tab: Some("settings".to_string()),
        };
    };

    if let Some(ms) = probe_udp_once(target, 0xC200, &host, BOOTSTRAP_PROBE_TIMEOUT).await {
        DiagnosticItem {
            id: "bootstrap_dns".to_string(),
            category: DiagnosticCategory::Upstream,
            status: DiagnosticStatus::Ok,
            summary: format!("{target} reachable ({ms} ms)"),
            detail: Some(format!("Resolved {host}")),
            hint: None,
            action_tab: None,
        }
    } else {
        DiagnosticItem {
            id: "bootstrap_dns".to_string(),
            category: DiagnosticCategory::Upstream,
            status: DiagnosticStatus::Error,
            summary: format!("{target} unreachable"),
            detail: Some(format!("Failed to resolve {host} via bootstrap DNS")),
            hint: Some("Verify network reachability to bootstrap_dns.".to_string()),
            action_tab: Some("settings".to_string()),
        }
    }
}

fn points_to_listener(spec: &str, listen_dns: SocketAddr) -> bool {
    let trimmed = spec.trim();
    let stripped = trimmed
        .strip_prefix("udp://")
        .or_else(|| trimmed.strip_prefix("tcp://"))
        .unwrap_or(trimmed);
    let addr = if let Ok(sa) = stripped.parse::<SocketAddr>() {
        sa
    } else if let Ok(ip) = stripped.parse::<IpAddr>() {
        SocketAddr::new(ip, 53)
    } else {
        return false;
    };
    if addr.port() != listen_dns.port() {
        return false;
    }
    addr.ip().is_loopback()
        || addr.ip() == listen_dns.ip()
        || (listen_dns.ip().is_unspecified() && addr.ip().is_unspecified())
}

fn check_forwarding_loop<'a>(
    listen_dns: SocketAddr,
    upstreams: &'a [String],
    upstream_groups: &'a [crabdns_core::UpstreamGroup],
    split_dns: &'a [crabdns_core::SplitDnsRule],
) -> DiagnosticItem {
    let mut looping: Vec<&'a str> = upstreams
        .iter()
        .map(String::as_str)
        .filter(|u| !u.trim().starts_with('@') && points_to_listener(u, listen_dns))
        .collect();
    for group in upstream_groups {
        for u in &group.upstreams {
            if points_to_listener(u, listen_dns) {
                looping.push(u.as_str());
            }
        }
    }
    for rule in split_dns {
        for u in rule.upstreams.iter().chain(&rule.fallback_upstreams).chain(
            rule.response_ip
                .iter()
                .flat_map(|r| r.fallback_upstreams.iter()),
        ) {
            if !u.trim().starts_with('@') && points_to_listener(u, listen_dns) {
                looping.push(u.as_str());
            }
        }
    }

    if looping.is_empty() {
        DiagnosticItem {
            id: "forwarding_loop".to_string(),
            category: DiagnosticCategory::Upstream,
            status: DiagnosticStatus::Ok,
            summary: "No forwarding loop detected".to_string(),
            detail: None,
            hint: None,
            action_tab: None,
        }
    } else {
        DiagnosticItem {
            id: "forwarding_loop".to_string(),
            category: DiagnosticCategory::Upstream,
            status: DiagnosticStatus::Error,
            summary: format!("Forwarding loop: {}", looping.join(", ")),
            detail: Some(format!(
                "Upstream points back to listen_dns ({listen_dns})."
            )),
            hint: Some(
                "Remove self-referencing upstream entries to prevent DNS loops.".to_string(),
            ),
            action_tab: Some("settings".to_string()),
        }
    }
}

fn check_webui_auth(web_auth_enabled: bool, web_password_hash: &str) -> DiagnosticItem {
    if !web_auth_enabled || web_password_hash.trim().is_empty() {
        DiagnosticItem {
            id: "webui_auth".to_string(),
            category: DiagnosticCategory::Security,
            status: DiagnosticStatus::Warn,
            summary: "WebUI password not configured".to_string(),
            detail: Some(
                "WebUI authentication is disabled or no login password is set.".to_string(),
            ),
            hint: Some(
                "Enable WebUI authentication and set a strong password in Settings.".to_string(),
            ),
            action_tab: Some("settings".to_string()),
        }
    } else {
        DiagnosticItem {
            id: "webui_auth".to_string(),
            category: DiagnosticCategory::Security,
            status: DiagnosticStatus::Ok,
            summary: "WebUI authentication enabled".to_string(),
            detail: None,
            hint: None,
            action_tab: None,
        }
    }
}

fn check_tls_cert_health(
    cfg: &crabdns_core::Config,
    tls_reloader: Option<&dyn TlsReloader>,
) -> DiagnosticItem {
    let any_tls_enabled = cfg.listen_web_tls.is_some()
        || cfg.listen_dot.is_some()
        || cfg.listen_doq.is_some()
        || cfg.listen_doh3.is_some();
    if !any_tls_enabled {
        return DiagnosticItem {
            id: "tls_cert_health".to_string(),
            category: DiagnosticCategory::Security,
            status: DiagnosticStatus::Ok,
            summary: "TLS listeners not enabled".to_string(),
            detail: None,
            hint: None,
            action_tab: None,
        };
    }

    let status = tls_reloader.map(TlsReloader::status);
    if let Some(err) = status.as_ref().and_then(|s| s.last_error.as_ref()) {
        return DiagnosticItem {
            id: "tls_cert_health".to_string(),
            category: DiagnosticCategory::Security,
            status: DiagnosticStatus::Error,
            summary: "TLS reload failed".to_string(),
            detail: Some(err.clone()),
            hint: Some("Check TLS certificate/key paths and reload TLS in Settings.".to_string()),
            action_tab: Some("settings".to_string()),
        };
    }

    let cert_path_owned = cfg
        .tls_cert_path
        .clone()
        .or_else(|| status.as_ref().and_then(|s| s.cert_path.as_deref()).map(Path::new).map(Path::to_path_buf));
    let key_path_owned = cfg
        .tls_key_path
        .clone()
        .or_else(|| status.as_ref().and_then(|s| s.key_path.as_deref()).map(Path::new).map(Path::to_path_buf));

    let Some(cert_path) = cert_path_owned else {
        return DiagnosticItem {
            id: "tls_cert_health".to_string(),
            category: DiagnosticCategory::Security,
            status: DiagnosticStatus::Error,
            summary: "TLS certificate path not configured".to_string(),
            detail: Some("Encrypted listeners are enabled without tls_cert_path.".to_string()),
            hint: Some("Configure TLS certificate & key or issue an ACME certificate in Settings.".to_string()),
            action_tab: Some("settings".to_string()),
        };
    };

    if let Some(ref kp) = key_path_owned
        && std::fs::File::open(kp).is_err()
    {
        return DiagnosticItem {
            id: "tls_cert_health".to_string(),
            category: DiagnosticCategory::Security,
            status: DiagnosticStatus::Error,
            summary: "TLS private key unreadable".to_string(),
            detail: Some(format!("Cannot read key file: {}", kp.display())),
            hint: Some("Verify tls_key_path exists and is readable by CrabDNS.".to_string()),
            action_tab: Some("settings".to_string()),
        };
    }

    evaluate_tls_cert_file(&cert_path, Utc::now())
}

fn evaluate_tls_cert_file(cert_path: &Path, now: DateTime<Utc>) -> DiagnosticItem {
    let Ok(bytes) = std::fs::read(cert_path) else {
        return DiagnosticItem {
            id: "tls_cert_health".to_string(),
            category: DiagnosticCategory::Security,
            status: DiagnosticStatus::Error,
            summary: "TLS certificate unreadable".to_string(),
            detail: Some(format!("Cannot read certificate file: {}", cert_path.display())),
            hint: Some("Verify tls_cert_path exists and has read permissions.".to_string()),
            action_tab: Some("settings".to_string()),
        };
    };

    let Ok((_, pem)) = parse_x509_pem(&bytes) else {
        return DiagnosticItem {
            id: "tls_cert_health".to_string(),
            category: DiagnosticCategory::Security,
            status: DiagnosticStatus::Error,
            summary: "Invalid PEM certificate".to_string(),
            detail: Some(format!("Failed to parse PEM in {}", cert_path.display())),
            hint: Some("Provide a valid PEM-encoded X.509 certificate.".to_string()),
            action_tab: Some("settings".to_string()),
        };
    };

    let Ok((_, cert)) = x509_parser::certificate::X509Certificate::from_der(&pem.contents) else {
        return DiagnosticItem {
            id: "tls_cert_health".to_string(),
            category: DiagnosticCategory::Security,
            status: DiagnosticStatus::Error,
            summary: "Invalid X.509 certificate".to_string(),
            detail: Some(format!("Failed to parse DER certificate in {}", cert_path.display())),
            hint: Some("Replace the certificate with a valid X.509 file.".to_string()),
            action_tab: Some("settings".to_string()),
        };
    };

    let Some(not_after) = DateTime::from_timestamp(cert.validity().not_after.timestamp(), 0) else {
        return DiagnosticItem {
            id: "tls_cert_health".to_string(),
            category: DiagnosticCategory::Security,
            status: DiagnosticStatus::Warn,
            summary: "Certificate expiry timestamp invalid".to_string(),
            detail: None,
            hint: None,
            action_tab: Some("settings".to_string()),
        };
    };

    let days_left = (not_after - now).num_days();
    if days_left < 0 {
        DiagnosticItem {
            id: "tls_cert_health".to_string(),
            category: DiagnosticCategory::Security,
            status: DiagnosticStatus::Error,
            summary: format!("Certificate expired ({}d ago)", -days_left),
            detail: Some(format!(
                "Certificate {} expired on {}.",
                cert_path.display(),
                not_after.format("%Y-%m-%d")
            )),
            hint: Some("Renew or replace the TLS certificate immediately in Settings.".to_string()),
            action_tab: Some("settings".to_string()),
        }
    } else if days_left <= TLS_CERT_EXPIRY_WARN_DAYS {
        DiagnosticItem {
            id: "tls_cert_health".to_string(),
            category: DiagnosticCategory::Security,
            status: DiagnosticStatus::Warn,
            summary: format!("Certificate expires in {days_left}d"),
            detail: Some(format!(
                "Certificate {} expires on {}.",
                cert_path.display(),
                not_after.format("%Y-%m-%d")
            )),
            hint: Some("Renew the TLS certificate soon to avoid DoT/DoH/HTTPS interruption.".to_string()),
            action_tab: Some("settings".to_string()),
        }
    } else {
        DiagnosticItem {
            id: "tls_cert_health".to_string(),
            category: DiagnosticCategory::Security,
            status: DiagnosticStatus::Ok,
            summary: format!("Valid ({days_left}d remaining)"),
            detail: Some(format!("Expires {}", not_after.format("%Y-%m-%d"))),
            hint: None,
            action_tab: None,
        }
    }
}

fn check_open_resolver_risk(cfg: &crabdns_core::Config) -> DiagnosticItem {
    let wildcard_bind = cfg.listen_dns.ip().is_unspecified();
    let no_acl = cfg.allow_cidrs.is_empty();
    let no_rate_limit = cfg.rate_limit_qps == 0;

    if wildcard_bind && no_acl && no_rate_limit {
        DiagnosticItem {
            id: "open_resolver_risk".to_string(),
            category: DiagnosticCategory::Security,
            status: DiagnosticStatus::Warn,
            summary: "Unrestricted wildcard DNS listener".to_string(),
            detail: Some(format!(
                "Listening on {} with empty allow_cidrs and rate_limit_qps = 0.",
                cfg.listen_dns
            )),
            hint: Some(
                "If exposed beyond LAN, configure allow_cidrs or rate_limit_qps in Settings to prevent DNS amplification."
                    .to_string(),
            ),
            action_tab: Some("settings".to_string()),
        }
    } else {
        let detail = if !wildcard_bind {
            format!("Bound to specific interface {}", cfg.listen_dns)
        } else if !no_acl {
            format!("{} allowed CIDR(s) configured", cfg.allow_cidrs.len())
        } else {
            format!("Rate limit active ({} QPS)", cfg.rate_limit_qps)
        };
        DiagnosticItem {
            id: "open_resolver_risk".to_string(),
            category: DiagnosticCategory::Security,
            status: DiagnosticStatus::Ok,
            summary: "Access scope protected".to_string(),
            detail: Some(detail),
            hint: None,
            action_tab: None,
        }
    }
}

fn check_system_dns_takeover(listen_dns: SocketAddr) -> DiagnosticItem {
    let Ok(content) = std::fs::read_to_string("/etc/resolv.conf") else {
        return DiagnosticItem {
            id: "system_dns_takeover".to_string(),
            category: DiagnosticCategory::Listener,
            status: DiagnosticStatus::Ok,
            summary: "Host /etc/resolv.conf unavailable".to_string(),
            detail: None,
            hint: None,
            action_tab: None,
        };
    };
    evaluate_resolv_conf(&content, listen_dns)
}

fn evaluate_resolv_conf(content: &str, listen_dns: SocketAddr) -> DiagnosticItem {
    let nameservers: Vec<IpAddr> = content
        .lines()
        .filter_map(|line| {
            let trimmed = line.split('#').next()?.trim();
            let rest = trimmed.strip_prefix("nameserver")?.trim();
            rest.split_whitespace().next()?.parse::<IpAddr>().ok()
        })
        .collect();

    if nameservers.is_empty() {
        return DiagnosticItem {
            id: "system_dns_takeover".to_string(),
            category: DiagnosticCategory::Listener,
            status: DiagnosticStatus::Warn,
            summary: "No nameservers in /etc/resolv.conf".to_string(),
            detail: Some("Host resolver configuration has no active nameserver entries.".to_string()),
            hint: Some("Configure /etc/resolv.conf or router DHCP DNS to point to CrabDNS.".to_string()),
            action_tab: Some("settings".to_string()),
        };
    }

    let points_local = nameservers.iter().any(|ip| {
        ip.is_loopback() || (!listen_dns.ip().is_unspecified() && *ip == listen_dns.ip())
    });

    let ns_list = nameservers
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");

    if listen_dns.port() == 53 && !points_local {
        DiagnosticItem {
            id: "system_dns_takeover".to_string(),
            category: DiagnosticCategory::Listener,
            status: DiagnosticStatus::Warn,
            summary: format!("Host DNS points to {ns_list}"),
            detail: Some(format!(
                "CrabDNS listens on {listen_dns}, but /etc/resolv.conf does not reference local loopback or listen IP."
            )),
            hint: Some("Point host DNS to 127.0.0.1 if local system traffic should use CrabDNS.".to_string()),
            action_tab: Some("settings".to_string()),
        }
    } else {
        DiagnosticItem {
            id: "system_dns_takeover".to_string(),
            category: DiagnosticCategory::Listener,
            status: DiagnosticStatus::Ok,
            summary: if points_local && listen_dns.port() == 53 {
                format!("Host DNS active ({ns_list})")
            } else {
                format!("Custom port :{} · host {ns_list}", listen_dns.port())
            },
            detail: None,
            hint: None,
            action_tab: None,
        }
    }
}

fn check_local_data_sources(cfg: &crabdns_core::Config) -> DiagnosticItem {
    if !cfg.hosts_enabled && !cfg.dhcp_leases_enabled {
        return DiagnosticItem {
            id: "local_data_sources".to_string(),
            category: DiagnosticCategory::Storage,
            status: DiagnosticStatus::Ok,
            summary: "Hosts & DHCP leases disabled".to_string(),
            detail: None,
            hint: None,
            action_tab: None,
        };
    }

    let mut checked = Vec::new();
    let mut missing = Vec::new();

    if cfg.hosts_enabled {
        let path = cfg
            .hosts_path
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("/etc/hosts");
        checked.push(format!("hosts:{path}"));
        if std::fs::File::open(path).is_err() {
            missing.push(path.to_string());
        }
    }

    if cfg.dhcp_leases_enabled {
        let path = crabdns_core::device_names::resolve_dhcp_leases_path(cfg.dhcp_leases_path.as_deref());
        checked.push(format!("dhcp:{path}"));
        if std::fs::File::open(path).is_err() {
            missing.push(path.to_string());
        }
    }

    if missing.is_empty() {
        DiagnosticItem {
            id: "local_data_sources".to_string(),
            category: DiagnosticCategory::Storage,
            status: DiagnosticStatus::Ok,
            summary: format!("{} source(s) readable", checked.len()),
            detail: Some(checked.join(" · ")),
            hint: None,
            action_tab: None,
        }
    } else {
        DiagnosticItem {
            id: "local_data_sources".to_string(),
            category: DiagnosticCategory::Storage,
            status: DiagnosticStatus::Warn,
            summary: format!("{} source(s) unreadable", missing.len()),
            detail: Some(format!("Cannot open: {}", missing.join(", "))),
            hint: Some("Verify file paths and read permissions in Settings.".to_string()),
            action_tab: Some("settings".to_string()),
        }
    }
}

fn check_dnssec_and_clock(cfg: &crabdns_core::Config) -> DiagnosticItem {
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    if now_secs < MIN_SANE_UNIX_SECS {
        return DiagnosticItem {
            id: "dnssec_clock".to_string(),
            category: DiagnosticCategory::Security,
            status: if cfg.dnssec_enabled {
                DiagnosticStatus::Error
            } else {
                DiagnosticStatus::Warn
            },
            summary: "System clock appears unsynchronized".to_string(),
            detail: Some(format!("Current UNIX timestamp ({now_secs}) is before 2024.")),
            hint: Some("Sync system clock via NTP; invalid clocks break DNSSEC and TLS validation.".to_string()),
            action_tab: None,
        };
    }

    if cfg.dnssec_enabled {
        let invalid_anchors = cfg
            .dnssec_trust_anchors
            .iter()
            .filter(|a| a.trim().is_empty())
            .count();
        if invalid_anchors > 0 {
            return DiagnosticItem {
                id: "dnssec_clock".to_string(),
                category: DiagnosticCategory::Security,
                status: DiagnosticStatus::Warn,
                summary: "DNSSEC enabled with blank trust anchor".to_string(),
                detail: Some(format!("{invalid_anchors} empty trust anchor entry found.")),
                hint: Some("Remove empty entries from dnssec_trust_anchors in Settings.".to_string()),
                action_tab: Some("settings".to_string()),
            };
        }
        DiagnosticItem {
            id: "dnssec_clock".to_string(),
            category: DiagnosticCategory::Security,
            status: DiagnosticStatus::Ok,
            summary: "DNSSEC enabled · clock valid".to_string(),
            detail: None,
            hint: None,
            action_tab: None,
        }
    } else {
        DiagnosticItem {
            id: "dnssec_clock".to_string(),
            category: DiagnosticCategory::Security,
            status: DiagnosticStatus::Ok,
            summary: "DNSSEC disabled · clock valid".to_string(),
            detail: None,
            hint: None,
            action_tab: None,
        }
    }
}

fn check_data_dir_storage(cfg: &crabdns_core::Config) -> DiagnosticItem {
    let dir = &cfg.data_dir;
    if !dir.exists() {
        return DiagnosticItem {
            id: "data_dir_storage".to_string(),
            category: DiagnosticCategory::Storage,
            status: DiagnosticStatus::Error,
            summary: "Data directory does not exist".to_string(),
            detail: Some(format!("Path: {}", dir.display())),
            hint: Some("Ensure data_dir exists and is writable by CrabDNS.".to_string()),
            action_tab: Some("settings".to_string()),
        };
    }

    let probe_path = dir.join(".crabdns_diag_write_test");
    if std::fs::write(&probe_path, b"ok").is_err() {
        return DiagnosticItem {
            id: "data_dir_storage".to_string(),
            category: DiagnosticCategory::Storage,
            status: DiagnosticStatus::Error,
            summary: "Data directory not writable".to_string(),
            detail: Some(format!("Write check failed in {}", dir.display())),
            hint: Some("Check filesystem mount options and directory permissions.".to_string()),
            action_tab: None,
        };
    }
    let _ = std::fs::remove_file(&probe_path);

    let avail_mb = query_available_disk_mb(dir);
    match avail_mb {
        Some(free_mb) if free_mb < MIN_FREE_DISK_MB || (cfg.log_max_disk_mb > 0 && free_mb < cfg.log_max_disk_mb) => {
            DiagnosticItem {
                id: "data_dir_storage".to_string(),
                category: DiagnosticCategory::Storage,
                status: DiagnosticStatus::Warn,
                summary: format!("{free_mb} MB free (low disk space)"),
                detail: Some(format!(
                    "Data dir {} has {free_mb} MB free; configured log_max_disk_mb is {} MB.",
                    dir.display(),
                    cfg.log_max_disk_mb
                )),
                hint: Some("Free disk space or lower log_retention_hours / log_max_disk_mb in Settings.".to_string()),
                action_tab: Some("settings".to_string()),
            }
        }
        Some(free_mb) => DiagnosticItem {
            id: "data_dir_storage".to_string(),
            category: DiagnosticCategory::Storage,
            status: DiagnosticStatus::Ok,
            summary: format!("{free_mb} MB free · writable"),
            detail: Some(format!(
                "Path: {} · log cap {} MB",
                dir.display(),
                cfg.log_max_disk_mb
            )),
            hint: None,
            action_tab: None,
        },
        None => DiagnosticItem {
            id: "data_dir_storage".to_string(),
            category: DiagnosticCategory::Storage,
            status: DiagnosticStatus::Ok,
            summary: "Data directory writable".to_string(),
            detail: Some(format!("Path: {}", dir.display())),
            hint: None,
            action_tab: None,
        },
    }
}

fn query_available_disk_mb(path: &Path) -> Option<u64> {
    let output = std::process::Command::new("df")
        .arg("-Pk")
        .arg(path)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    parse_df_pk_avail_mb(&text)
}

fn parse_df_pk_avail_mb(df_output: &str) -> Option<u64> {
    let line = df_output.lines().nth(1)?;
    let cols: Vec<&str> = line.split_whitespace().collect();
    // POSIX df -Pk columns: Filesystem 1024-blocks Used Available Capacity Mounted-on
    let avail_kb = cols.get(3)?.parse::<u64>().ok()?;
    Some(avail_kb / 1024)
}

fn check_cache_config(cfg: &crabdns_core::Config, state: &RouterState) -> DiagnosticItem {
    if cfg.cache_size == 0 {
        return DiagnosticItem {
            id: "cache_config".to_string(),
            category: DiagnosticCategory::Storage,
            status: DiagnosticStatus::Warn,
            summary: "DNS cache disabled (size = 0)".to_string(),
            detail: Some("Every query will be forwarded to upstream resolvers.".to_string()),
            hint: Some("Set cache_size > 0 in Settings for lower latency.".to_string()),
            action_tab: Some("settings".to_string()),
        };
    }

    if cfg.cache_max_ttl_secs > 0 && cfg.cache_min_ttl_secs > cfg.cache_max_ttl_secs {
        return DiagnosticItem {
            id: "cache_config".to_string(),
            category: DiagnosticCategory::Storage,
            status: DiagnosticStatus::Warn,
            summary: "Cache min TTL exceeds max TTL".to_string(),
            detail: Some(format!(
                "cache_min_ttl_secs ({}) > cache_max_ttl_secs ({}).",
                cfg.cache_min_ttl_secs, cfg.cache_max_ttl_secs
            )),
            hint: Some("Adjust cache min/max TTL in Settings so min <= max.".to_string()),
            action_tab: Some("settings".to_string()),
        };
    }

    let entries = state.app.pipeline.cache().entry_count();
    DiagnosticItem {
        id: "cache_config".to_string(),
        category: DiagnosticCategory::Storage,
        status: DiagnosticStatus::Ok,
        summary: format!("{entries}/{} entries cached", cfg.cache_size),
        detail: Some(format!(
            "TTL {}s–{}s · optimistic={} · persist={}",
            cfg.cache_min_ttl_secs,
            cfg.cache_max_ttl_secs,
            cfg.optimistic_cache,
            cfg.cache_persist_enabled
        )),
        hint: None,
        action_tab: None,
    }
}

#[derive(Debug, Deserialize, TS)]
#[ts(export)]
pub struct DomainTraceRequest {
    pub domain: String,
    #[serde(default = "default_trace_qtype")]
    pub qtype: String,
}

fn default_trace_qtype() -> String {
    "A".to_string()
}

#[derive(Debug, Clone, Serialize, TS)]
#[ts(export)]
pub struct DomainTraceStep {
    pub stage: String,
    pub status: DiagnosticStatus,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, TS)]
#[ts(export)]
pub struct DomainTraceResponse {
    pub domain: String,
    pub qtype: String,
    pub rcode: String,
    pub outcome: String,
    pub elapsed_ms: f64,
    pub upstream: Option<String>,
    pub matched_rule: Option<String>,
    pub matched_list: Option<String>,
    pub split_dns_rule: Option<String>,
    pub answers: Vec<String>,
    pub steps: Vec<DomainTraceStep>,
}

fn parse_qtype_code(qtype: &str) -> Option<(&'static str, u16)> {
    match qtype.trim().to_ascii_uppercase().as_str() {
        "" | "A" => Some(("A", 1)),
        "NS" => Some(("NS", 2)),
        "CNAME" => Some(("CNAME", 5)),
        "SOA" => Some(("SOA", 6)),
        "PTR" => Some(("PTR", 12)),
        "MX" => Some(("MX", 15)),
        "TXT" => Some(("TXT", 16)),
        "AAAA" => Some(("AAAA", 28)),
        "SRV" => Some(("SRV", 33)),
        "HTTPS" => Some(("HTTPS", 65)),
        "ANY" => Some(("ANY", 255)),
        _ => None,
    }
}

fn rcode_name(code: u8) -> &'static str {
    match code {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "OTHER",
    }
}

fn outcome_label(outcome: QueryOutcome) -> &'static str {
    match outcome {
        QueryOutcome::Cached => "Cached",
        QueryOutcome::Blocked => "Blocked",
        QueryOutcome::Rewritten => "Rewritten",
        QueryOutcome::Forwarded => "Forwarded",
        QueryOutcome::Error => "Error",
    }
}

fn match_split_dns_rule_summary(
    domain: &str,
    rules: &[crabdns_core::SplitDnsRule],
) -> Option<String> {
    let lower = domain.trim_end_matches('.').to_ascii_lowercase();
    for rule in rules {
        if !rule.enabled {
            continue;
        }
        let pat = rule
            .domain
            .trim()
            .trim_start_matches("*.")
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let matched = !pat.is_empty() && (lower == pat || lower.ends_with(&format!(".{pat}")));
        if matched {
            let upstreams = rule.upstreams.join(", ");
            let label = match rule.name.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                Some(name) => format!("{name} ({upstreams})"),
                None => upstreams,
            };
            return Some(label);
        }
    }
    None
}

pub async fn trace_domain_resolution(
    State(state): State<RouterState>,
    Json(req): Json<DomainTraceRequest>,
) -> Result<Json<DomainTraceResponse>, (StatusCode, Json<serde_json::Value>)> {
    let clean_domain = req.domain.trim().trim_end_matches('.').to_string();
    if clean_domain.is_empty()
        || clean_domain.len() > 253
        || clean_domain.chars().any(char::is_whitespace)
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Invalid domain name" })),
        ));
    }

    let Some((qtype_norm, qtype_code)) = parse_qtype_code(&req.qtype) else {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": format!("Unsupported qtype: {}", req.qtype) })),
        ));
    };

    let cfg = state.app.config.load();
    let split_dns_rule = match_split_dns_rule_summary(&clean_domain, &cfg.split_dns);

    let mut rx = state.app.live_tx.subscribe();
    let query_bytes = build_dns_query_with_type(0xD1A6, &clean_domain, qtype_code);
    let ctx = QueryContext {
        client_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        protocol: QueryProtocol::Doh,
        client_id: Some("diagnostics-trace".to_string()),
    };

    let start = Instant::now();
    let packet_res = state
        .app
        .pipeline
        .handle_packet_with_context(&query_bytes, ctx)
        .await;
    let fallback_elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;

    let mut matched_event = None;
    let deadline = tokio::time::sleep(Duration::from_millis(25));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            biased;
            recv = rx.recv() => {
                match recv {
                    Ok(ev) if ev.domain.eq_ignore_ascii_case(&clean_domain) && ev.qtype == qtype_norm => {
                        matched_event = Some(ev);
                        break;
                    }
                    Ok(_) => continue,
                    Err(_) => break,
                }
            }
            () = &mut deadline => break,
        }
    }

    let (rcode, outcome, elapsed_ms, upstream, matched_rule, matched_list, answers) =
        if let Some(ev) = matched_event {
            #[allow(clippy::cast_precision_loss)]
            let ms = ev.elapsed_us as f64 / 1000.0;
            (
                ev.rcode,
                outcome_label(ev.outcome).to_string(),
                ms,
                ev.upstream,
                ev.matched_rule,
                ev.matched_list,
                ev.answers,
            )
        } else {
            let rcode = match &packet_res {
                Ok(resp) if resp.len() >= 4 => rcode_name(resp[3] & 0x0F).to_string(),
                Ok(_) => "NOERROR".to_string(),
                Err(_) => "SERVFAIL".to_string(),
            };
            let outcome = if packet_res.is_ok() {
                "Completed".to_string()
            } else {
                "Error".to_string()
            };
            (
                rcode,
                outcome,
                fallback_elapsed_ms,
                None,
                None,
                None,
                Vec::new(),
            )
        };

    let mut steps = Vec::new();
    steps.push(DomainTraceStep {
        stage: "filter".to_string(),
        status: if outcome == "Blocked" {
            DiagnosticStatus::Warn
        } else {
            DiagnosticStatus::Ok
        },
        detail: if let Some(ref rule) = matched_rule {
            format!("Matched rule: {rule}")
        } else {
            "No blocking or rewrite rule matched".to_string()
        },
    });

    steps.push(DomainTraceStep {
        stage: "routing".to_string(),
        status: DiagnosticStatus::Ok,
        detail: if let Some(ref split) = split_dns_rule {
            format!("Matched Split DNS: {split}")
        } else if outcome == "Cached" {
            "Served from local DNS cache".to_string()
        } else {
            "Default upstream pool".to_string()
        },
    });

    steps.push(DomainTraceStep {
        stage: "result".to_string(),
        status: if outcome == "Error" || rcode == "SERVFAIL" {
            DiagnosticStatus::Error
        } else {
            DiagnosticStatus::Ok
        },
        detail: format!(
            "{outcome} ({rcode}) in {elapsed_ms:.1} ms{}",
            upstream
                .as_ref()
                .map(|u| format!(" via {u}"))
                .unwrap_or_default()
        ),
    });

    Ok(Json(DomainTraceResponse {
        domain: clean_domain,
        qtype: qtype_norm.to_string(),
        rcode,
        outcome,
        elapsed_ms,
        upstream,
        matched_rule,
        matched_list,
        split_dns_rule,
        answers,
        steps,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn test_mdns_port_5353_warns_or_errors() {
        let addr: SocketAddr = "0.0.0.0:5353".parse().unwrap();
        let item = check_mdns_port_conflict(addr);
        assert_ne!(item.status, DiagnosticStatus::Ok);

        let safe_addr: SocketAddr = "127.0.0.1:5354".parse().unwrap();
        let safe_item = check_mdns_port_conflict(safe_addr);
        assert_eq!(safe_item.status, DiagnosticStatus::Ok);
    }

    #[test]
    fn test_forwarding_loop_detection() {
        let listen: SocketAddr = "0.0.0.0:5354".parse().unwrap();
        let ok = check_forwarding_loop(listen, &["223.5.5.5:53".to_string()], &[], &[]);
        assert_eq!(ok.status, DiagnosticStatus::Ok);

        let looped = check_forwarding_loop(listen, &["127.0.0.1:5354".to_string()], &[], &[]);
        assert_eq!(looped.status, DiagnosticStatus::Error);
    }

    #[test]
    fn test_extract_domain_host() {
        assert_eq!(
            extract_domain_host("https://dns.alidns.com/dns-query"),
            Some("dns.alidns.com".to_string())
        );
        assert_eq!(extract_domain_host("https://1.1.1.1/dns-query"), None);
        assert_eq!(extract_domain_host("223.5.5.5"), None);
    }

    #[tokio::test]
    async fn test_loopback_probe_succeeds_against_local_udp_and_tcp() {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let udp = UdpSocket::bind(addr).await.unwrap();

        let udp_task = tokio::spawn(async move {
            let mut buf = [0_u8; 512];
            for _ in 0..UDP_PROBE_COUNT {
                if let Ok((len, peer)) = udp.recv_from(&mut buf).await {
                    let mut resp = buf[..len].to_vec();
                    if resp.len() >= 3 {
                        resp[2] |= 0x80;
                    }
                    let _ = udp.send_to(&resp, peer).await;
                }
            }
        });

        let tcp_task = tokio::spawn(async move {
            if let Ok((mut stream, _)) = tcp.accept().await {
                let mut len_buf = [0_u8; 2];
                if stream.read_exact(&mut len_buf).await.is_ok() {
                    let qlen = usize::from(u16::from_be_bytes(len_buf));
                    let mut q = vec![0_u8; qlen];
                    if stream.read_exact(&mut q).await.is_ok() {
                        if q.len() >= 3 {
                            q[2] |= 0x80;
                        }
                        let _ = stream.write_all(&len_buf).await;
                        let _ = stream.write_all(&q).await;
                    }
                }
            }
        });

        let item = check_loopback_probe(addr).await;
        assert_eq!(item.status, DiagnosticStatus::Ok, "{item:?}");
        let _ = tokio::join!(udp_task, tcp_task);
    }

    #[test]
    fn test_webui_auth_check() {
        let disabled = check_webui_auth(false, "");
        assert_eq!(disabled.status, DiagnosticStatus::Warn);
        assert_eq!(disabled.category, DiagnosticCategory::Security);

        let empty_hash = check_webui_auth(true, "   ");
        assert_eq!(empty_hash.status, DiagnosticStatus::Warn);

        let enabled = check_webui_auth(true, "$argon2id$v=19$m=19456,t=2,p=1$abc$def");
        assert_eq!(enabled.status, DiagnosticStatus::Ok);
    }

    #[test]
    fn test_open_resolver_risk() {
        let mut cfg = crabdns_core::Config::default();
        cfg.listen_dns = "0.0.0.0:53".parse().unwrap();
        cfg.allow_cidrs.clear();
        cfg.rate_limit_qps = 0;
        let warn = check_open_resolver_risk(&cfg);
        assert_eq!(warn.status, DiagnosticStatus::Warn);
        assert_eq!(warn.action_tab.as_deref(), Some("settings"));

        cfg.rate_limit_qps = 100;
        let ok = check_open_resolver_risk(&cfg);
        assert_eq!(ok.status, DiagnosticStatus::Ok);
    }

    #[test]
    fn test_resolv_conf_takeover() {
        let listen53: SocketAddr = "0.0.0.0:53".parse().unwrap();
        let warn = evaluate_resolv_conf("nameserver 8.8.8.8\n", listen53);
        assert_eq!(warn.status, DiagnosticStatus::Warn);

        let ok = evaluate_resolv_conf("nameserver 127.0.0.1\n", listen53);
        assert_eq!(ok.status, DiagnosticStatus::Ok);

        let listen5354: SocketAddr = "0.0.0.0:5354".parse().unwrap();
        let custom_ok = evaluate_resolv_conf("nameserver 8.8.8.8\n", listen5354);
        assert_eq!(custom_ok.status, DiagnosticStatus::Ok);
    }

    #[test]
    fn test_parse_df_pk_avail_mb() {
        let sample = "Filesystem     1024-blocks      Used Available Capacity Mounted on\n/dev/sda1        104857600  20971520  83886080      20% /\n";
        assert_eq!(parse_df_pk_avail_mb(sample), Some(81920));
    }

    #[test]
    fn test_tls_cert_expiry_evaluation() {
        let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let now_offset = rcgen::date_time_ymd(2026, 1, 1);
        let later_offset = rcgen::date_time_ymd(2026, 2, 1);
        params.not_before = now_offset;
        params.not_after = later_offset;
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        std::fs::write(&cert_path, cert.pem()).unwrap();

        let mid = DateTime::from_timestamp(1_767_571_200, 0).unwrap(); // 2026-01-05
        let item = evaluate_tls_cert_file(&cert_path, mid);
        assert_eq!(item.status, DiagnosticStatus::Ok);

        let near = DateTime::from_timestamp(1_769_558_400, 0).unwrap(); // 2026-01-28 (4d left)
        let warn = evaluate_tls_cert_file(&cert_path, near);
        assert_eq!(warn.status, DiagnosticStatus::Warn);

        let after = DateTime::from_timestamp(1_770_249_600, 0).unwrap(); // 2026-02-05 (expired)
        let expired = evaluate_tls_cert_file(&cert_path, after);
        assert_eq!(expired.status, DiagnosticStatus::Error);
    }

    #[test]
    fn test_parse_qtype_code() {
        assert_eq!(parse_qtype_code("a"), Some(("A", 1)));
        assert_eq!(parse_qtype_code("AAAA"), Some(("AAAA", 28)));
        assert_eq!(parse_qtype_code("HTTPS"), Some(("HTTPS", 65)));
        assert_eq!(parse_qtype_code("INVALID"), None);
    }
}
