use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use crabdns_core::Config;
use crabdns_server::spawn_server;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use quinn::crypto::rustls::QuicClientConfig;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use rustls::{ClientConfig, RootCertStore};
use serde_json::{Value, json};
use tokio::net::UdpSocket;

fn build_query(id: u16, domain: &str, qtype: RecordType) -> Vec<u8> {
    let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(Name::from_ascii(domain).unwrap(), qtype));
    msg.to_vec().unwrap()
}

async fn spawn_mock_udp_upstream(answer_ip: Ipv4Addr) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind mock udp");
    let addr = socket.local_addr().expect("mock udp addr");
    tokio::spawn(async move {
        let mut buf = [0_u8; 4096];
        while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
            let Ok(req) = Message::from_vec(&buf[..len]) else {
                continue;
            };
            let Some(q) = req.queries.first().cloned() else {
                continue;
            };
            let qname = q.name().clone();
            let qtype = q.query_type();
            let mut resp = Message::new(req.id, MessageType::Response, OpCode::Query);
            resp.metadata.recursion_desired = req.recursion_desired;
            resp.metadata.recursion_available = true;
            resp.metadata.response_code = ResponseCode::NoError;
            resp.add_query(q);
            if qtype == RecordType::A {
                resp.add_answer(Record::from_rdata(qname, 60, RData::A(A(answer_ip))));
            }
            if let Ok(wire) = resp.to_vec() {
                let _ = socket.send_to(&wire, peer).await;
            }
        }
    });
    addr
}

async fn send_udp_query(server_addr: SocketAddr, query: &[u8]) -> Message {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.send_to(query, server_addr).await.unwrap();
    let mut buf = [0_u8; 4096];
    let (len, _) = tokio::time::timeout(Duration::from_secs(3), sock.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    Message::from_vec(&buf[..len]).unwrap()
}

async fn send_doq_query(
    doq_addr: SocketAddr,
    sni: &str,
    cert_pem: &[u8],
    query: &[u8],
) -> anyhow::Result<Message> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(cert_pem).collect::<std::result::Result<Vec<_>, _>>()?;
    let mut roots = RootCertStore::empty();
    for c in certs {
        roots.add(c)?;
    }
    let mut tls_cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls_cfg.alpn_protocols = vec![b"doq".to_vec()];
    let quic_cfg = QuicClientConfig::try_from(tls_cfg)?;
    let mut client_cfg = quinn::ClientConfig::new(Arc::new(quic_cfg));
    client_cfg.transport_config(Arc::new(quinn::TransportConfig::default()));

    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
    endpoint.set_default_client_config(client_cfg);

    let conn = endpoint.connect(doq_addr, sni)?.await?;
    let (mut send, mut recv) = conn.open_bi().await?;
    let len = u16::try_from(query.len())?;
    let mut framed = Vec::with_capacity(2 + query.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(query);
    send.write_all(&framed).await?;
    send.finish()?;

    let mut len_buf = [0_u8; 2];
    tokio::time::timeout(Duration::from_secs(3), recv.read_exact(&mut len_buf)).await??;
    let resp_len = usize::from(u16::from_be_bytes(len_buf));
    let mut resp_buf = vec![0_u8; resp_len];
    tokio::time::timeout(Duration::from_secs(3), recv.read_exact(&mut resp_buf)).await??;
    conn.close(0_u32.into(), b"done");
    endpoint.wait_idle().await;
    Ok(Message::from_vec(&resp_buf)?)
}

fn generate_test_cert(dir: &Path, name: &str) -> (PathBuf, PathBuf, Vec<u8>) {
    use std::ffi::OsStr;

    let run = |args: &[&OsStr]| {
        let out = Command::new("openssl").args(args).output().unwrap();
        assert!(
            out.status.success(),
            "openssl failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    };

    let ca_key = dir.join(format!("{name}-ca-key.pem"));
    let ca_cert = dir.join(format!("{name}-ca-cert.pem"));
    let leaf_key = dir.join(format!("{name}-key.pem"));
    let leaf_csr = dir.join(format!("{name}.csr"));
    let leaf_cert = dir.join(format!("{name}-cert.pem"));
    let ext_file = dir.join(format!("{name}-ext.cnf"));

    run(&[
        OsStr::new("req"),
        OsStr::new("-x509"),
        OsStr::new("-newkey"),
        OsStr::new("rsa:2048"),
        OsStr::new("-nodes"),
        OsStr::new("-keyout"),
        ca_key.as_os_str(),
        OsStr::new("-out"),
        ca_cert.as_os_str(),
        OsStr::new("-days"),
        OsStr::new("7"),
        OsStr::new("-subj"),
        OsStr::new(&format!("/CN={name}-ca")),
        OsStr::new("-addext"),
        OsStr::new("basicConstraints=critical,CA:TRUE"),
        OsStr::new("-addext"),
        OsStr::new("keyUsage=critical,digitalSignature,keyCertSign,cRLSign"),
    ]);
    run(&[
        OsStr::new("req"),
        OsStr::new("-new"),
        OsStr::new("-newkey"),
        OsStr::new("rsa:2048"),
        OsStr::new("-nodes"),
        OsStr::new("-keyout"),
        leaf_key.as_os_str(),
        OsStr::new("-out"),
        leaf_csr.as_os_str(),
        OsStr::new("-subj"),
        OsStr::new(&format!("/CN={name}")),
    ]);
    std::fs::write(
        &ext_file,
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1,DNS:localhost,DNS:doq.local,DNS:*.doq.local\n",
    )
    .unwrap();
    run(&[
        OsStr::new("x509"),
        OsStr::new("-req"),
        OsStr::new("-in"),
        leaf_csr.as_os_str(),
        OsStr::new("-CA"),
        ca_cert.as_os_str(),
        OsStr::new("-CAkey"),
        ca_key.as_os_str(),
        OsStr::new("-CAcreateserial"),
        OsStr::new("-out"),
        leaf_cert.as_os_str(),
        OsStr::new("-days"),
        OsStr::new("7"),
        OsStr::new("-extfile"),
        ext_file.as_os_str(),
    ]);
    let ca_pem = std::fs::read(&ca_cert).unwrap();
    (leaf_cert, leaf_key, ca_pem)
}

fn first_a_ip(msg: &Message) -> Option<Ipv4Addr> {
    msg.answers.iter().find_map(|r| match &r.data {
        RData::A(a) => Some(a.0),
        _ => None,
    })
}

fn first_aaaa_ip(msg: &Message) -> Option<Ipv6Addr> {
    msg.answers.iter().find_map(|r| match &r.data {
        RData::AAAA(aaaa) => Some(aaaa.0),
        _ => None,
    })
}

async fn api_send_json(
    client: &reqwest::Client,
    method: reqwest::Method,
    url: &str,
    body: &Value,
) -> (reqwest::StatusCode, Value) {
    let resp = client
        .request(method, url)
        .header("content-type", "application/json")
        .body(serde_json::to_string(body).unwrap())
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.bytes().await.unwrap();
    let val = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, val)
}

async fn api_get_json<T: serde::de::DeserializeOwned>(client: &reqwest::Client, url: &str) -> T {
    let resp = client.get(url).send().await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let bytes = resp.bytes().await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn test_rewrites_crud_resolution_and_persistence() {
    let dir = tempfile::tempdir().unwrap();
    let upstream = spawn_mock_udp_upstream(Ipv4Addr::new(10, 0, 0, 1)).await;

    let cfg = Config {
        listen_dns: "127.0.0.1:0".parse().unwrap(),
        listen_web: "127.0.0.1:0".parse().unwrap(),
        data_dir: dir.path().to_path_buf(),
        upstreams: vec![format!("udp://{upstream}")],
        rdns_enabled: false,
        ..Config::default()
    };
    let server = spawn_server(cfg.clone()).await.unwrap();
    let base = format!("http://{}", server.web_addr);
    let http = reqwest::Client::new();

    // Create A + AAAA + CNAME + TXT + wildcard rewrites
    let (s1, r1) = api_send_json(
        &http,
        reqwest::Method::POST,
        &format!("{base}/api/rewrites"),
        &json!({
            "domain": "nas.local",
            "kind": "a",
            "answer": "192.168.50.10",
            "enabled": true,
            "comment": "NAS v4"
        }),
    )
    .await;
    assert_eq!(s1, reqwest::StatusCode::CREATED);
    let r1_id = r1["id"].as_str().unwrap().to_string();

    for payload in [
        json!({ "domain": "nas.local", "kind": "aaaa", "answer": "fd00::50", "enabled": true }),
        json!({ "domain": "alias.local", "kind": "cname", "answer": "nas.local", "enabled": true }),
        json!({ "domain": "info.local", "kind": "txt", "answer": "crabdns-ok", "enabled": true }),
        json!({ "domain": "*.home.test", "kind": "auto", "answer": "10.20.30.40", "enabled": true }),
    ] {
        let (st, _) = api_send_json(
            &http,
            reqwest::Method::POST,
            &format!("{base}/api/rewrites"),
            &payload,
        )
        .await;
        assert_eq!(st, reqwest::StatusCode::CREATED);
    }

    assert_eq!(
        first_a_ip(
            &send_udp_query(
                server.dns_addr,
                &build_query(1, "nas.local.", RecordType::A)
            )
            .await
        ),
        Some(Ipv4Addr::new(192, 168, 50, 10))
    );
    assert_eq!(
        first_aaaa_ip(
            &send_udp_query(
                server.dns_addr,
                &build_query(2, "nas.local.", RecordType::AAAA)
            )
            .await
        ),
        Some("fd00::50".parse().unwrap())
    );
    let cname_resp = send_udp_query(
        server.dns_addr,
        &build_query(3, "alias.local.", RecordType::A),
    )
    .await;
    assert!(
        cname_resp
            .answers
            .iter()
            .any(|r| matches!(r.data, RData::CNAME(_)))
    );
    let txt_resp = send_udp_query(
        server.dns_addr,
        &build_query(4, "info.local.", RecordType::TXT),
    )
    .await;
    assert!(
        txt_resp
            .answers
            .iter()
            .any(|r| matches!(r.data, RData::TXT(_)))
    );
    assert_eq!(
        first_a_ip(
            &send_udp_query(
                server.dns_addr,
                &build_query(5, "app.home.test.", RecordType::A)
            )
            .await
        ),
        Some(Ipv4Addr::new(10, 20, 30, 40))
    );

    // Disable A rewrite and verify update
    let (upd_status, _) = api_send_json(
        &http,
        reqwest::Method::PUT,
        &format!("{base}/api/rewrites/{r1_id}"),
        &json!({
            "domain": "nas.local",
            "kind": "a",
            "answer": "192.168.50.10",
            "enabled": false,
            "comment": "disabled"
        }),
    )
    .await;
    assert_eq!(upd_status, reqwest::StatusCode::OK);
    // Restart and confirm persistence of rewrites
    server.shutdown().await;
    let server2 = spawn_server(cfg).await.unwrap();
    let base2 = format!("http://{}", server2.web_addr);
    let list: Vec<Value> = api_get_json(&http, &format!("{base2}/api/rewrites")).await;
    assert_eq!(list.len(), 5);
    assert_eq!(
        first_a_ip(
            &send_udp_query(
                server2.dns_addr,
                &build_query(6, "app.home.test.", RecordType::A)
            )
            .await
        ),
        Some(Ipv4Addr::new(10, 20, 30, 40))
    );

    let del = http
        .delete(format!("{base2}/api/rewrites/{r1_id}"))
        .send()
        .await
        .unwrap();
    assert_eq!(del.status(), reqwest::StatusCode::NO_CONTENT);
    server2.shutdown().await;
}

#[tokio::test]
async fn test_adguard_modifiers_regex_and_rule_tester_e2e() {
    let dir = tempfile::tempdir().unwrap();
    let upstream = spawn_mock_udp_upstream(Ipv4Addr::new(93, 184, 216, 34)).await;

    let server = spawn_server(Config {
        listen_dns: "127.0.0.1:0".parse().unwrap(),
        listen_web: "127.0.0.1:0".parse().unwrap(),
        data_dir: dir.path().to_path_buf(),
        upstreams: vec![format!("udp://{upstream}")],
        custom_rules: vec![
            "||aaaa-only.test^$dnstype=AAAA".to_string(),
            "||shop.test^$denyallow=pay.shop.test".to_string(),
            "||local-client-block.test^$client=127.0.0.1".to_string(),
            r"/^ad-[0-9]+\.rx\.test$/".to_string(),
        ],
        rdns_enabled: false,
        ..Config::default()
    })
    .await
    .unwrap();
    let base = format!("http://{}", server.web_addr);
    let http = reqwest::Client::new();

    // $dnstype=AAAA blocks AAAA, forwards A
    let resp_a = send_udp_query(
        server.dns_addr,
        &build_query(10, "aaaa-only.test.", RecordType::A),
    )
    .await;
    assert_eq!(first_a_ip(&resp_a), Some(Ipv4Addr::new(93, 184, 216, 34)));
    let resp_aaaa = send_udp_query(
        server.dns_addr,
        &build_query(11, "aaaa-only.test.", RecordType::AAAA),
    )
    .await;
    assert_eq!(first_aaaa_ip(&resp_aaaa), Some(Ipv6Addr::UNSPECIFIED));

    // $denyallow allows pay.shop.test, blocks shop.test
    assert_eq!(
        first_a_ip(
            &send_udp_query(
                server.dns_addr,
                &build_query(12, "shop.test.", RecordType::A)
            )
            .await
        ),
        Some(Ipv4Addr::UNSPECIFIED)
    );
    assert_eq!(
        first_a_ip(
            &send_udp_query(
                server.dns_addr,
                &build_query(13, "pay.shop.test.", RecordType::A)
            )
            .await
        ),
        Some(Ipv4Addr::new(93, 184, 216, 34))
    );

    // $client=127.0.0.1 and regex
    assert_eq!(
        first_a_ip(
            &send_udp_query(
                server.dns_addr,
                &build_query(14, "local-client-block.test.", RecordType::A)
            )
            .await
        ),
        Some(Ipv4Addr::UNSPECIFIED)
    );
    assert_eq!(
        first_a_ip(
            &send_udp_query(
                server.dns_addr,
                &build_query(15, "ad-42.rx.test.", RecordType::A)
            )
            .await
        ),
        Some(Ipv4Addr::UNSPECIFIED)
    );

    // /api/rules/test with qtype
    let (st_aaaa, test_aaaa) = api_send_json(
        &http,
        reqwest::Method::POST,
        &format!("{base}/api/rules/test"),
        &json!({ "domain": "aaaa-only.test", "qtype": "AAAA" }),
    )
    .await;
    assert_eq!(st_aaaa, reqwest::StatusCode::OK);
    assert_eq!(test_aaaa["action"], "block");

    let (st_a, test_a) = api_send_json(
        &http,
        reqwest::Method::POST,
        &format!("{base}/api/rules/test"),
        &json!({ "domain": "aaaa-only.test", "qtype": "A" }),
    )
    .await;
    assert_eq!(st_a, reqwest::StatusCode::OK);
    assert_eq!(test_a["action"], "none");

    server.shutdown().await;
}

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn test_doq_sni_client_id_dhcp_leases_and_client_activity_stats() {
    let dir = tempfile::tempdir().unwrap();
    let (cert_path, key_path, cert_pem) = generate_test_cert(dir.path(), "doq-test");
    let leases_path = dir.path().join("dnsmasq.leases");
    std::fs::write(
        &leases_path,
        "1760000000 aa:bb:cc:dd:ee:ff 127.0.0.1 my-workstation *\n",
    )
    .unwrap();

    let up_default = spawn_mock_udp_upstream(Ipv4Addr::new(10, 0, 0, 1)).await;
    let up_vip = spawn_mock_udp_upstream(Ipv4Addr::new(10, 0, 0, 99)).await;

    let server = spawn_server(Config {
        listen_dns: "127.0.0.1:0".parse().unwrap(),
        listen_web: "127.0.0.1:0".parse().unwrap(),
        listen_doq: Some("127.0.0.1:0".parse().unwrap()),
        sni_client_id_hostnames: vec!["doq.local".to_string()],
        tls_cert_path: Some(cert_path),
        tls_key_path: Some(key_path),
        data_dir: dir.path().to_path_buf(),
        upstreams: vec![format!("udp://{up_default}")],
        dhcp_leases_enabled: true,
        dhcp_leases_path: Some(leases_path.display().to_string()),
        rdns_enabled: false,
        ..Config::default()
    })
    .await
    .unwrap();

    let doq_addr = server.doq_addr.expect("doq addr");
    let base = format!("http://{}", server.web_addr);
    let http = reqwest::Client::new();

    // Create a client profile matched ONLY by client_id = "laptop-1" (not by IP!)
    let (st_cli, created_cli) = api_send_json(
        &http,
        reqwest::Method::POST,
        &format!("{base}/api/clients"),
        &json!({
            "name": "Alice Laptop",
            "identifiers": ["laptop-1"],
            "custom_rules": "||laptop-blocked.test^\n",
            "upstreams": [format!("udp://{up_vip}")]
        }),
    )
    .await;
    assert_eq!(st_cli, reqwest::StatusCode::CREATED);
    let profile_id = created_cli["id"].as_str().unwrap().to_string();

    // DoQ query with SNI laptop-1.doq.local -> routed to up_vip and client rule applies!
    let doq_ok = send_doq_query(
        doq_addr,
        "laptop-1.doq.local",
        &cert_pem,
        &build_query(21, "routed.test.", RecordType::A),
    )
    .await
    .expect("doq query");
    assert_eq!(first_a_ip(&doq_ok), Some(Ipv4Addr::new(10, 0, 0, 99)));

    let doq_blk = send_doq_query(
        doq_addr,
        "laptop-1.doq.local",
        &cert_pem,
        &build_query(22, "laptop-blocked.test.", RecordType::A),
    )
    .await
    .expect("doq blocked query");
    assert_eq!(first_a_ip(&doq_blk), Some(Ipv4Addr::UNSPECIFIED));

    // Also send a UDP query (without client_id, so 127.0.0.1 is unconfigured & resolves via DHCP!)
    let udp_ok = send_udp_query(
        server.dns_addr,
        &build_query(23, "lan-check.test.", RecordType::A),
    )
    .await;
    assert_eq!(first_a_ip(&udp_ok), Some(Ipv4Addr::new(10, 0, 0, 1)));
    // Second UDP query hits cache
    let udp_cached = send_udp_query(
        server.dns_addr,
        &build_query(24, "lan-check.test.", RecordType::A),
    )
    .await;
    assert_eq!(first_a_ip(&udp_cached), Some(Ipv4Addr::new(10, 0, 0, 1)));

    // Wait for async log batch flush (250ms interval)
    let mut overview = json!({});
    for _ in 0..30 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        overview = api_get_json(&http, &format!("{base}/api/clients")).await;
        let total = overview["discovered"][0]["query_count"]
            .as_u64()
            .unwrap_or(0);
        if total >= 4 {
            break;
        }
    }

    let disc = &overview["discovered"][0];
    assert_eq!(disc["ip"], "127.0.0.1");
    assert_eq!(disc["resolved_name"], "my-workstation");
    assert_eq!(disc["name_source"], "dhcp");
    assert_eq!(disc["query_count"], 4);
    assert_eq!(disc["blocked_count"], 1);
    assert_eq!(disc["cached_count"], 1);
    assert_eq!(disc["protocols"]["doq"], 2);
    assert_eq!(disc["protocols"]["udp"], 2);
    assert!(disc["last_seen"].as_str().is_some());
    assert_ne!(disc["top_domains"].as_array().unwrap().len(), 0);
    assert_ne!(disc["top_blocked"].as_array().unwrap().len(), 0);

    let p_stats = &overview["profile_stats"][&profile_id];
    assert_eq!(p_stats["total_queries"], 2);
    assert_eq!(p_stats["blocked_queries"], 1);
    assert_eq!(p_stats["protocols"]["doq"], 2);
    assert_eq!(p_stats["last_client_id"], "laptop-1");

    server.shutdown().await;
}
