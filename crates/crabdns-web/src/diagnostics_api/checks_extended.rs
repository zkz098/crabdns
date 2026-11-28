use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Utc};
use x509_parser::pem::parse_x509_pem;
use x509_parser::prelude::FromDer;

use super::types::{DiagnosticCategory, DiagnosticItem, DiagnosticStatus};
use crate::RouterState;
use crate::tls_api::TlsReloader;

const TLS_CERT_EXPIRY_WARN_DAYS: i64 = 14;
const MIN_FREE_DISK_MB: u64 = 100;
// 2024-01-01T00:00:00Z in UNIX seconds; used to catch uninitialized RTC clocks.
const MIN_SANE_UNIX_SECS: u64 = 1_704_067_200;

pub(crate) fn check_tls_cert_health(
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

    let cert_path_owned = cfg.tls_cert_path.clone().or_else(|| {
        status
            .as_ref()
            .and_then(|s| s.cert_path.as_deref())
            .map(Path::new)
            .map(Path::to_path_buf)
    });
    let key_path_owned = cfg.tls_key_path.clone().or_else(|| {
        status
            .as_ref()
            .and_then(|s| s.key_path.as_deref())
            .map(Path::new)
            .map(Path::to_path_buf)
    });

    let Some(cert_path) = cert_path_owned else {
        return DiagnosticItem {
            id: "tls_cert_health".to_string(),
            category: DiagnosticCategory::Security,
            status: DiagnosticStatus::Error,
            summary: "TLS certificate path not configured".to_string(),
            detail: Some("Encrypted listeners are enabled without tls_cert_path.".to_string()),
            hint: Some(
                "Configure TLS certificate & key or issue an ACME certificate in Settings."
                    .to_string(),
            ),
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

pub(crate) fn evaluate_tls_cert_file(cert_path: &Path, now: DateTime<Utc>) -> DiagnosticItem {
    let Ok(bytes) = std::fs::read(cert_path) else {
        return DiagnosticItem {
            id: "tls_cert_health".to_string(),
            category: DiagnosticCategory::Security,
            status: DiagnosticStatus::Error,
            summary: "TLS certificate unreadable".to_string(),
            detail: Some(format!(
                "Cannot read certificate file: {}",
                cert_path.display()
            )),
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
            detail: Some(format!(
                "Failed to parse DER certificate in {}",
                cert_path.display()
            )),
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
            hint: Some(
                "Renew the TLS certificate soon to avoid DoT/DoH/HTTPS interruption.".to_string(),
            ),
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

pub(crate) fn check_open_resolver_risk(cfg: &crabdns_core::Config) -> DiagnosticItem {
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

pub(crate) fn check_system_dns_takeover(listen_dns: SocketAddr) -> DiagnosticItem {
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

pub(crate) fn evaluate_resolv_conf(content: &str, listen_dns: SocketAddr) -> DiagnosticItem {
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
            detail: Some(
                "Host resolver configuration has no active nameserver entries.".to_string(),
            ),
            hint: Some(
                "Configure /etc/resolv.conf or router DHCP DNS to point to CrabDNS.".to_string(),
            ),
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
            hint: Some(
                "Point host DNS to 127.0.0.1 if local system traffic should use CrabDNS."
                    .to_string(),
            ),
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

pub(crate) fn check_local_data_sources(cfg: &crabdns_core::Config) -> DiagnosticItem {
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
        let path =
            crabdns_core::device_names::resolve_dhcp_leases_path(cfg.dhcp_leases_path.as_deref());
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

pub(crate) fn check_dnssec_and_clock(cfg: &crabdns_core::Config) -> DiagnosticItem {
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
            detail: Some(format!(
                "Current UNIX timestamp ({now_secs}) is before 2024."
            )),
            hint: Some(
                "Sync system clock via NTP; invalid clocks break DNSSEC and TLS validation."
                    .to_string(),
            ),
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
                hint: Some(
                    "Remove empty entries from dnssec_trust_anchors in Settings.".to_string(),
                ),
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

pub(crate) fn check_data_dir_storage(cfg: &crabdns_core::Config) -> DiagnosticItem {
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
        Some(free_mb)
            if free_mb < MIN_FREE_DISK_MB
                || (cfg.log_max_disk_mb > 0 && free_mb < cfg.log_max_disk_mb) =>
        {
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
                hint: Some(
                    "Free disk space or lower log_retention_hours / log_max_disk_mb in Settings."
                        .to_string(),
                ),
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

pub(crate) fn parse_df_pk_avail_mb(df_output: &str) -> Option<u64> {
    let line = df_output.lines().nth(1)?;
    let cols: Vec<&str> = line.split_whitespace().collect();
    // POSIX df -Pk columns: Filesystem 1024-blocks Used Available Capacity Mounted-on
    let avail_kb = cols.get(3)?.parse::<u64>().ok()?;
    Some(avail_kb / 1024)
}

pub(crate) fn check_cache_config(
    cfg: &crabdns_core::Config,
    state: &RouterState,
) -> DiagnosticItem {
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
