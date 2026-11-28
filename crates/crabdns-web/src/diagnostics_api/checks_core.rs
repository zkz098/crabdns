use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::task::JoinSet;

use super::types::{
    DiagnosticCategory, DiagnosticItem, DiagnosticStatus, build_dns_query_with_type,
};
use crate::RouterState;

pub(crate) const UDP_PROBE_COUNT: usize = 8;
const UDP_PROBE_TIMEOUT: Duration = Duration::from_millis(600);
const TCP_PROBE_TIMEOUT: Duration = Duration::from_millis(1000);
const BOOTSTRAP_PROBE_TIMEOUT: Duration = Duration::from_millis(1500);
const HIGH_LOOPBACK_LATENCY_MS: u64 = 100;
const HIGH_UPSTREAM_LATENCY_MS: u64 = 500;

pub(crate) fn check_mdns_port_conflict(listen_dns: SocketAddr) -> DiagnosticItem {
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
    if !(2..=4096).contains(&resp_len) {
        return false;
    }
    let mut resp = vec![0_u8; resp_len];
    matches!(
        tokio::time::timeout(timeout, stream.read_exact(&mut resp)).await,
        Ok(Ok(_)) if resp[0..2] == txid.to_be_bytes()
    )
}

pub(crate) async fn check_loopback_probe(listen_dns: SocketAddr) -> DiagnosticItem {
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

pub(crate) fn check_udp_inflight_drops(state: &RouterState) -> DiagnosticItem {
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

pub(crate) fn check_upstream_health(state: &RouterState) -> DiagnosticItem {
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

pub(crate) fn extract_domain_host(spec: &str) -> Option<String> {
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

pub(crate) async fn check_bootstrap_dns(
    upstreams: &[String],
    bootstrap_dns: &[String],
) -> DiagnosticItem {
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

pub(crate) fn check_forwarding_loop<'a>(
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

pub(crate) fn check_webui_auth(web_auth_enabled: bool, web_password_hash: &str) -> DiagnosticItem {
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
