use std::net::SocketAddr;

use chrono::DateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use super::checks_core::{
    UDP_PROBE_COUNT, check_forwarding_loop, check_loopback_probe, check_mdns_port_conflict,
    check_webui_auth, extract_domain_host,
};
use super::checks_extended::{
    check_open_resolver_risk, evaluate_resolv_conf, evaluate_tls_cert_file, parse_df_pk_avail_mb,
};
use super::trace::parse_qtype_code;
use super::types::{DiagnosticCategory, DiagnosticStatus};

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
    cfg.bootstrap.listen_dns = "0.0.0.0:53".parse().unwrap();
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
