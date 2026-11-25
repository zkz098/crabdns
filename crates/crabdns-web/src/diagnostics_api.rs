use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::extract::State;
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::task::JoinSet;
use ts_rs::TS;

use crate::RouterState;

const UDP_PROBE_COUNT: usize = 8;
const UDP_PROBE_TIMEOUT: Duration = Duration::from_millis(600);
const TCP_PROBE_TIMEOUT: Duration = Duration::from_millis(1000);
const BOOTSTRAP_PROBE_TIMEOUT: Duration = Duration::from_millis(1500);

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
    let drops_item = check_udp_inflight_drops(&state);
    let upstream_item = check_upstream_health(&state);
    let bootstrap_item = check_bootstrap_dns(&cfg.upstreams, &cfg.bootstrap_dns).await;
    let loop_item = check_forwarding_loop(listen_dns, &cfg.upstreams, &cfg.split_dns);

    let items = vec![
        mdns_item,
        loopback_item,
        drops_item,
        upstream_item,
        bootstrap_item,
        loop_item,
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
        };
    }

    DiagnosticItem {
        id: "mdns_port_conflict".to_string(),
        category: DiagnosticCategory::Listener,
        status: DiagnosticStatus::Ok,
        summary: format!("No SO_REUSEPORT conflict on port {port}"),
        detail: None,
        hint: None,
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
    buf.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
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
        DiagnosticItem {
            id: "loopback_probe".to_string(),
            category: DiagnosticCategory::Listener,
            status: DiagnosticStatus::Ok,
            summary: format!("UDP {udp_ok}/{UDP_PROBE_COUNT} · TCP {tcp_label} ({avg_ms} ms)"),
            detail: Some(format!("Target {target}")),
            hint: None,
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
        }
    } else {
        DiagnosticItem {
            id: "udp_inflight_drops".to_string(),
            category: DiagnosticCategory::Listener,
            status: DiagnosticStatus::Warn,
            summary: format!("{drops} UDP queries dropped"),
            detail: Some("Dropped when concurrent inflight UDP queries hit the limit.".to_string()),
            hint: Some("Check upstream latency or reduce burst query load.".to_string()),
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
        DiagnosticItem {
            id: "upstream_health".to_string(),
            category: DiagnosticCategory::Upstream,
            status: DiagnosticStatus::Ok,
            summary: format!("{total}/{total} healthy (avg {avg_lat} ms)"),
            detail: None,
            hint: None,
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
        }
    } else {
        DiagnosticItem {
            id: "upstream_health".to_string(),
            category: DiagnosticCategory::Upstream,
            status: DiagnosticStatus::Error,
            summary: format!("0/{total} upstreams healthy"),
            detail: Some(format!("Failing: {}", unhealthy_names.join(", "))),
            hint: Some("All upstreams are failing or in circuit-breaker backoff.".to_string()),
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
        }
    } else {
        DiagnosticItem {
            id: "bootstrap_dns".to_string(),
            category: DiagnosticCategory::Upstream,
            status: DiagnosticStatus::Error,
            summary: format!("{target} unreachable"),
            detail: Some(format!("Failed to resolve {host} via bootstrap DNS")),
            hint: Some("Verify network reachability to bootstrap_dns.".to_string()),
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

fn check_forwarding_loop(
    listen_dns: SocketAddr,
    upstreams: &[String],
    split_dns: &[crabdns_core::SplitDnsRule],
) -> DiagnosticItem {
    let mut looping: Vec<&str> = upstreams
        .iter()
        .map(String::as_str)
        .filter(|u| points_to_listener(u, listen_dns))
        .collect();
    for rule in split_dns {
        for u in &rule.upstreams {
            if points_to_listener(u, listen_dns) {
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
        }
    }
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
        let ok = check_forwarding_loop(listen, &["223.5.5.5:53".to_string()], &[]);
        assert_eq!(ok.status, DiagnosticStatus::Ok);

        let looped = check_forwarding_loop(listen, &["127.0.0.1:5354".to_string()], &[]);
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
}
