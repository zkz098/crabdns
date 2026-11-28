use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use chrono::{Duration as ChronoDuration, Utc};
use crabdns_core::{Config, QueryEvent, QueryOutcome, QueryProtocol};
use crabdns_server::{RunningServer, prune_logs_once, spawn_server};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_rustls::TlsConnector;

fn build_query(id: u16, domain: &str, qtype: RecordType) -> Vec<u8> {
    let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    let name = Name::from_ascii(domain).expect("valid domain");
    msg.add_query(Query::query(name, qtype));
    msg.to_vec().expect("encode query")
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

fn base_test_config(data_dir: &Path, upstream: SocketAddr) -> Config {
    let mut cfg = Config::default();
    cfg.bootstrap.listen_dns = "127.0.0.1:0".parse().expect("dns addr");
    cfg.bootstrap.listen_web = "127.0.0.1:0".parse().expect("web addr");
    cfg.bootstrap.data_dir = data_dir.to_path_buf();
    cfg.upstreams = vec![format!("udp://{upstream}")];
    cfg.allow_cidrs = vec!["127.0.0.1/32".to_string()];
    cfg
}

async fn send_udp_query(server_addr: SocketAddr, query: &[u8]) -> Message {
    let sock = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind client udp");
    sock.send_to(query, server_addr).await.expect("send udp");
    let mut buf = [0_u8; 4096];
    let (len, _) = tokio::time::timeout(Duration::from_secs(3), sock.recv_from(&mut buf))
        .await
        .expect("udp recv timeout")
        .expect("udp recv");
    Message::from_vec(&buf[..len]).expect("decode udp response")
}

async fn send_tcp_query(server_addr: SocketAddr, query: &[u8]) -> Message {
    let mut stream = TcpStream::connect(server_addr).await.expect("connect tcp");
    let q_len = u16::try_from(query.len()).expect("len u16");
    stream
        .write_all(&q_len.to_be_bytes())
        .await
        .expect("write len");
    stream.write_all(query).await.expect("write body");
    stream.flush().await.expect("flush tcp");

    let mut len_buf = [0_u8; 2];
    tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut len_buf))
        .await
        .expect("tcp len timeout")
        .expect("read len");
    let resp_len = usize::from(u16::from_be_bytes(len_buf));
    let mut resp_buf = vec![0_u8; resp_len];
    tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut resp_buf))
        .await
        .expect("tcp body timeout")
        .expect("read body");
    Message::from_vec(&resp_buf).expect("decode tcp response")
}

async fn send_doh_query(client: &reqwest::Client, url: &str, query: &[u8]) -> Message {
    let resp = client
        .post(url)
        .header("content-type", "application/dns-message")
        .body(query.to_vec())
        .send()
        .await
        .expect("doh post");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let bytes = resp.bytes().await.expect("doh bytes");
    Message::from_vec(&bytes).expect("decode doh response")
}

async fn send_dot_query(
    dot_addr: SocketAddr,
    sni: &str,
    cert_pem: &[u8],
    query: &[u8],
) -> anyhow::Result<Message> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(cert_pem).collect::<std::result::Result<Vec<_>, _>>()?;
    let mut roots = RootCertStore::empty();
    for c in certs {
        roots.add(c)?;
    }
    let mut client_cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_cfg.alpn_protocols = vec![b"dot".to_vec()];
    let connector = TlsConnector::from(Arc::new(client_cfg));
    let server_name = ServerName::try_from(sni.to_string())?;

    let tcp = TcpStream::connect(dot_addr).await?;
    let mut tls = tokio::time::timeout(Duration::from_secs(3), connector.connect(server_name, tcp))
        .await
        .map_err(|_| anyhow::anyhow!("dot handshake timeout"))??;

    let q_len = u16::try_from(query.len())?;
    tls.write_all(&q_len.to_be_bytes()).await?;
    tls.write_all(query).await?;
    tls.flush().await?;

    let mut len_buf = [0_u8; 2];
    tokio::time::timeout(Duration::from_secs(3), tls.read_exact(&mut len_buf))
        .await
        .map_err(|_| anyhow::anyhow!("dot len timeout"))??;
    let resp_len = usize::from(u16::from_be_bytes(len_buf));
    let mut resp_buf = vec![0_u8; resp_len];
    tokio::time::timeout(Duration::from_secs(3), tls.read_exact(&mut resp_buf))
        .await
        .map_err(|_| anyhow::anyhow!("dot body timeout"))??;
    Ok(Message::from_vec(&resp_buf)?)
}

fn run_openssl(args: &[&std::ffi::OsStr]) {
    let output = Command::new("openssl")
        .args(args)
        .output()
        .expect("run openssl");
    assert!(
        output.status.success(),
        "openssl {:?} failed: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
}

fn generate_test_cert(dir: &Path, name: &str) -> (PathBuf, PathBuf, Vec<u8>) {
    use std::ffi::OsStr;

    let ca_key = dir.join(format!("{name}-ca-key.pem"));
    let ca_cert = dir.join(format!("{name}-ca-cert.pem"));
    let leaf_key = dir.join(format!("{name}-key.pem"));
    let leaf_csr = dir.join(format!("{name}.csr"));
    let leaf_cert = dir.join(format!("{name}-cert.pem"));
    let ext_file = dir.join(format!("{name}-ext.cnf"));

    run_openssl(&[
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

    run_openssl(&[
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
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1,DNS:localhost,DNS:dns.local,DNS:*.dns.local\n",
    )
    .expect("write ext file");

    run_openssl(&[
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

    let ca_pem = std::fs::read(&ca_cert).expect("read generated CA cert");
    (leaf_cert, leaf_key, ca_pem)
}

fn build_tls_http_client(cert_pem: &[u8]) -> reqwest::Client {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let cert = reqwest::Certificate::from_pem(cert_pem).expect("parse reqwest cert");
    reqwest::Client::builder()
        .tls_certs_only([cert])
        .timeout(Duration::from_secs(3))
        .build()
        .expect("build tls reqwest client")
}

async fn api_get_json<T: serde::de::DeserializeOwned>(client: &reqwest::Client, url: &str) -> T {
    let resp = client.get(url).send().await.expect("GET request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let bytes = resp.bytes().await.expect("GET bytes");
    serde_json::from_slice(&bytes).expect("decode GET json")
}

async fn api_send_json(
    client: &reqwest::Client,
    method: reqwest::Method,
    url: &str,
    body: &Value,
) -> (reqwest::StatusCode, Value) {
    let raw = serde_json::to_vec(body).expect("encode json");
    let resp = client
        .request(method, url)
        .header("content-type", "application/json")
        .body(raw)
        .send()
        .await
        .expect("HTTP json request");
    let status = resp.status();
    let bytes = resp.bytes().await.expect("response bytes");
    let parsed = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, parsed)
}

fn first_a_ip(msg: &Message) -> Option<Ipv4Addr> {
    msg.answers.iter().find_map(|rec| match &rec.data {
        RData::A(a) => Some(a.0),
        _ => None,
    })
}

async fn wait_for_log_count(
    client: &reqwest::Client,
    base: &str,
    expected: usize,
) -> Vec<QueryEvent> {
    for _ in 0..40 {
        let logs: Vec<QueryEvent> =
            api_get_json(client, &format!("{base}/api/logs?limit=50")).await;
        if logs.len() >= expected {
            return logs;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for {expected} logs");
}

#[tokio::test]
async fn test_log_retention_pruning_e2e() {
    let data_dir = tempfile::tempdir().expect("tempdir");
    let upstream = spawn_mock_udp_upstream(Ipv4Addr::new(93, 184, 216, 34)).await;
    let mut cfg = base_test_config(data_dir.path(), upstream);
    cfg.log_retention_hours = 24;

    let server = spawn_server(cfg).await.expect("spawn server");
    let now = Utc::now();
    let old_event = QueryEvent {
        timestamp: now - ChronoDuration::hours(48),
        client_ip: "192.168.10.20".to_string(),
        client_name: None,
        client_id: None,
        profile_id: None,
        protocol: QueryProtocol::Udp,
        domain: "expired.example.com".to_string(),
        qtype: "A".to_string(),
        outcome: QueryOutcome::Forwarded,
        matched_rule: None,
        matched_list: None,
        upstream: Some("udp://127.0.0.1:53".to_string()),
        elapsed_us: 100,
        rcode: "NoError".to_string(),
        answers: vec!["1.1.1.1".to_string()],
    };
    let fresh_event = QueryEvent {
        timestamp: now - ChronoDuration::hours(1),
        client_ip: "192.168.10.21".to_string(),
        client_name: Some("nas.lan".to_string()),
        client_id: None,
        profile_id: None,
        protocol: QueryProtocol::Tcp,
        domain: "fresh.example.com".to_string(),
        qtype: "A".to_string(),
        outcome: QueryOutcome::Forwarded,
        matched_rule: None,
        matched_list: None,
        upstream: Some("udp://127.0.0.1:53".to_string()),
        elapsed_us: 80,
        rcode: "NoError".to_string(),
        answers: vec!["93.184.216.34".to_string()],
    };
    server
        .storage
        .record_batch(&[old_event, fresh_event])
        .expect("record batch");

    let removed = prune_logs_once(&server.storage, 24).expect("prune old logs");
    assert_eq!(removed, 1);

    let http = reqwest::Client::new();
    let base = format!("http://{}", server.web_addr);
    let logs: Vec<QueryEvent> = api_get_json(&http, &format!("{base}/api/logs?limit=20")).await;
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].domain, "fresh.example.com");

    server.shutdown().await;
}

#[tokio::test]
async fn test_enriched_query_logs_udp_tcp_doh_and_hosts_ptr() {
    let dir = tempfile::tempdir().expect("tempdir");
    let hosts_file = dir.path().join("hosts");
    std::fs::write(&hosts_file, "127.0.0.1 my-local-host.lan\n").expect("write hosts");

    let upstream = spawn_mock_udp_upstream(Ipv4Addr::new(93, 184, 216, 34)).await;
    let mut cfg = base_test_config(dir.path(), upstream);
    cfg.hosts_enabled = true;
    cfg.hosts_path = Some(hosts_file.display().to_string());
    cfg.bootstrap.custom_rules = vec!["||ad.test^".to_string()];

    let server = spawn_server(cfg).await.expect("spawn server");
    let http = reqwest::Client::new();
    let base = format!("http://{}", server.web_addr);

    let udp_resp = send_udp_query(
        server.dns_addr,
        &build_query(1, "ok-udp.test.", RecordType::A),
    )
    .await;
    assert_eq!(first_a_ip(&udp_resp), Some(Ipv4Addr::new(93, 184, 216, 34)));

    let tcp_resp = send_tcp_query(
        server.dns_addr,
        &build_query(2, "ok-tcp.test.", RecordType::A),
    )
    .await;
    assert_eq!(first_a_ip(&tcp_resp), Some(Ipv4Addr::new(93, 184, 216, 34)));

    let doh_resp = send_doh_query(
        &http,
        &format!("{base}/dns-query"),
        &build_query(3, "ad.test.", RecordType::A),
    )
    .await;
    assert_eq!(first_a_ip(&doh_resp), Some(Ipv4Addr::UNSPECIFIED));

    let logs = wait_for_log_count(&http, &base, 3).await;
    let udp_log = logs
        .iter()
        .find(|l| l.domain == "ok-udp.test")
        .expect("udp log");
    assert_eq!(udp_log.protocol, QueryProtocol::Udp);
    assert!(udp_log.answers.iter().any(|a| a.contains("93.184.216.34")));
    assert_eq!(udp_log.client_name.as_deref(), Some("my-local-host.lan"));

    let tcp_log = logs
        .iter()
        .find(|l| l.domain == "ok-tcp.test")
        .expect("tcp log");
    assert_eq!(tcp_log.protocol, QueryProtocol::Tcp);
    assert!(tcp_log.answers.iter().any(|a| a.contains("93.184.216.34")));

    let doh_log = logs
        .iter()
        .find(|l| l.domain == "ad.test")
        .expect("doh log");
    assert_eq!(doh_log.protocol, QueryProtocol::Doh);
    assert_eq!(doh_log.outcome, QueryOutcome::Blocked);
    assert_eq!(doh_log.matched_list.as_deref(), Some("custom"));

    server.shutdown().await;
}

#[tokio::test]
async fn test_native_https_doh_dot_and_tls_hot_reload() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (cert1_path, key1_path, cert1_pem) = generate_test_cert(dir.path(), "cert1");
    let (cert2_path, key2_path, cert2_pem) = generate_test_cert(dir.path(), "cert2");

    let active_cert = dir.path().join("active-cert.pem");
    let active_key = dir.path().join("active-key.pem");
    std::fs::copy(&cert1_path, &active_cert).expect("copy cert1");
    std::fs::copy(&key1_path, &active_key).expect("copy key1");

    let upstream = spawn_mock_udp_upstream(Ipv4Addr::new(10, 20, 30, 40)).await;
    let mut cfg = base_test_config(dir.path(), upstream);
    cfg.bootstrap.listen_web_tls = Some("127.0.0.1:0".parse().expect("web tls addr"));
    cfg.bootstrap.listen_dot = Some("127.0.0.1:0".parse().expect("dot addr"));
    cfg.tls_cert_path = Some(active_cert.clone());
    cfg.tls_key_path = Some(active_key.clone());
    cfg.ddr_hostname = Some("dns.local".to_string());

    let server = spawn_server(cfg).await.expect("spawn tls server");
    let https_addr = server.web_tls_addr.expect("https bound");
    let dot_addr = server.dot_addr.expect("dot bound");
    let tls_web_url = format!("https://127.0.0.1:{}", https_addr.port());
    let plain_web_url = format!("http://{}", server.web_addr);

    let client1 = build_tls_http_client(&cert1_pem);
    let status1: Value = api_get_json(&client1, &format!("{tls_web_url}/api/tls/status")).await;
    assert_eq!(status1["https_enabled"], true);
    assert_eq!(status1["dot_enabled"], true);
    let fp1 = status1["cert_fingerprint_sha256"]
        .as_str()
        .expect("fp1")
        .to_string();

    let https_dns_v1 = send_doh_query(
        &client1,
        &format!("{tls_web_url}/dns-query"),
        &build_query(11, "https-v1.test.", RecordType::A),
    )
    .await;
    assert_eq!(
        first_a_ip(&https_dns_v1),
        Some(Ipv4Addr::new(10, 20, 30, 40))
    );

    let tls_dns_v1 = send_dot_query(
        dot_addr,
        "localhost",
        &cert1_pem,
        &build_query(12, "dot-v1.test.", RecordType::A),
    )
    .await
    .expect("dot v1 query");
    assert_eq!(first_a_ip(&tls_dns_v1), Some(Ipv4Addr::new(10, 20, 30, 40)));

    // Swap cert/key files on disk and hot-reload without restarting server
    std::fs::copy(&cert2_path, &active_cert).expect("overwrite cert2");
    std::fs::copy(&key2_path, &active_key).expect("overwrite key2");
    let http_plain = reqwest::Client::new();
    let (reload_status, reload_json) = api_send_json(
        &http_plain,
        reqwest::Method::POST,
        &format!("{plain_web_url}/api/tls/reload"),
        &json!({}),
    )
    .await;
    assert_eq!(reload_status, reqwest::StatusCode::OK);
    let fp2 = reload_json["cert_fingerprint_sha256"]
        .as_str()
        .expect("fp2");
    assert_ne!(fp1, fp2);

    // Build fresh cert1-only client (fresh TLS connection) -> must fail verification
    let stale_client1 = build_tls_http_client(&cert1_pem);
    assert!(
        stale_client1
            .get(format!("{tls_web_url}/api/tls/status"))
            .send()
            .await
            .is_err()
    );

    // Cert2-only client -> HTTPS & DoH & DoT must all succeed
    let client2 = build_tls_http_client(&cert2_pem);
    let status2: Value = api_get_json(&client2, &format!("{tls_web_url}/api/tls/status")).await;
    assert_eq!(status2["cert_fingerprint_sha256"], fp2);

    let https_dns_v2 = send_doh_query(
        &client2,
        &format!("{tls_web_url}/dns-query"),
        &build_query(13, "https-v2.test.", RecordType::A),
    )
    .await;
    assert_eq!(
        first_a_ip(&https_dns_v2),
        Some(Ipv4Addr::new(10, 20, 30, 40))
    );

    let tls_dns_v2 = send_dot_query(
        dot_addr,
        "localhost",
        &cert2_pem,
        &build_query(14, "dot-v2.test.", RecordType::A),
    )
    .await
    .expect("dot v2 query");
    assert_eq!(first_a_ip(&tls_dns_v2), Some(Ipv4Addr::new(10, 20, 30, 40)));

    server.shutdown().await;
}

async fn setup_client_policies(
    http: &reqwest::Client,
    base: &str,
    up_vip: SocketAddr,
) -> (String, String, String) {
    let (s, kids_group) = api_send_json(
        http,
        reqwest::Method::POST,
        &format!("{base}/api/client-groups"),
        &json!({
            "name": "kids",
            "description": "restricted",
            "blocking_enabled": true,
            "use_global_rules": true,
            "custom_rules": "||games.test^\n",
            "upstreams": []
        }),
    )
    .await;
    assert_eq!(s, reqwest::StatusCode::CREATED);
    let group_id = kids_group["id"].as_str().expect("group id").to_string();

    let (s, laptop) = api_send_json(
        http,
        reqwest::Method::POST,
        &format!("{base}/api/clients"),
        &json!({
            "name": "laptop",
            "identifiers": ["laptop-1"],
            "group_id": group_id,
            "custom_rules": "@@||games.test^\n||social.test^\n",
            "upstreams": [format!("udp://{up_vip}")]
        }),
    )
    .await;
    assert_eq!(s, reqwest::StatusCode::CREATED);
    let laptop_id = laptop["id"].as_str().expect("laptop id").to_string();

    let (s, kid_pad) = api_send_json(
        http,
        reqwest::Method::POST,
        &format!("{base}/api/clients"),
        &json!({
            "name": "kid-pad",
            "identifiers": ["kid-pad-1"],
            "group_id": group_id
        }),
    )
    .await;
    assert_eq!(s, reqwest::StatusCode::CREATED);
    let pad_id = kid_pad["id"].as_str().expect("pad id").to_string();

    let (s, _) = api_send_json(
        http,
        reqwest::Method::POST,
        &format!("{base}/api/clients"),
        &json!({
            "name": "bypass",
            "identifiers": ["bypass-1"],
            "blocking_enabled": false
        }),
    )
    .await;
    assert_eq!(s, reqwest::StatusCode::CREATED);

    (group_id, laptop_id, pad_id)
}

async fn verify_client_routing(
    http: &reqwest::Client,
    base: &str,
    dot_addr: SocketAddr,
    cert_pem: &[u8],
) {
    // 1. bypass-1 skips global block rules and forwards to default upstream
    let bypass_resp = send_doh_query(
        http,
        &format!("{base}/dns-query/bypass-1"),
        &build_query(21, "global-blocked.test.", RecordType::A),
    )
    .await;
    assert_eq!(first_a_ip(&bypass_resp), Some(Ipv4Addr::new(10, 0, 0, 1)));

    // 2. kid-pad-1 inherits kids group block on games.test
    let pad_resp = send_doh_query(
        http,
        &format!("{base}/dns-query/kid-pad-1"),
        &build_query(22, "games.test.", RecordType::A),
    )
    .await;
    assert_eq!(first_a_ip(&pad_resp), Some(Ipv4Addr::UNSPECIFIED));

    // 3. laptop-1 overrides kids group block via @@||games.test^ AND routes to up_vip (10.0.0.99)
    let laptop_games = send_doh_query(
        http,
        &format!("{base}/dns-query/laptop-1"),
        &build_query(23, "games.test.", RecordType::A),
    )
    .await;
    assert_eq!(first_a_ip(&laptop_games), Some(Ipv4Addr::new(10, 0, 0, 99)));

    // 4. Default client resolves games.test from up_default (10.0.0.1) -> isolated cache!
    let default_games = send_doh_query(
        http,
        &format!("{base}/dns-query"),
        &build_query(24, "games.test.", RecordType::A),
    )
    .await;
    assert_eq!(first_a_ip(&default_games), Some(Ipv4Addr::new(10, 0, 0, 1)));

    // 5. laptop-1 blocks social.test both via DoH client_id and via DoT SNI laptop-1.dns.local
    let laptop_social = send_doh_query(
        http,
        &format!("{base}/dns-query/laptop-1"),
        &build_query(25, "social.test.", RecordType::A),
    )
    .await;
    assert_eq!(first_a_ip(&laptop_social), Some(Ipv4Addr::UNSPECIFIED));

    let dot_laptop = send_dot_query(
        dot_addr,
        "laptop-1.dns.local",
        cert_pem,
        &build_query(26, "dot-vip.test.", RecordType::A),
    )
    .await
    .expect("dot sni client query");
    assert_eq!(first_a_ip(&dot_laptop), Some(Ipv4Addr::new(10, 0, 0, 99)));
}

async fn restart_with_clients_config(
    data_dir: &Path,
    cert_path: PathBuf,
    key_path: PathBuf,
    up_default: SocketAddr,
) -> RunningServer {
    let mut cfg = base_test_config(data_dir, up_default);
    cfg.bootstrap.listen_dot = Some("127.0.0.1:0".parse().expect("dot addr"));
    cfg.tls_cert_path = Some(cert_path);
    cfg.tls_key_path = Some(key_path);
    cfg.ddr_hostname = Some("dns.local".to_string());
    cfg.bootstrap.custom_rules = vec!["||global-blocked.test^".to_string()];
    spawn_server(cfg).await.expect("spawn server")
}

#[tokio::test]
async fn test_client_management_crud_policies_doh_client_id_and_persistence() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (cert_path, key_path, cert_pem) = generate_test_cert(dir.path(), "clients-test");
    let up_default = spawn_mock_udp_upstream(Ipv4Addr::new(10, 0, 0, 1)).await;
    let up_vip = spawn_mock_udp_upstream(Ipv4Addr::new(10, 0, 0, 99)).await;

    let server =
        restart_with_clients_config(dir.path(), cert_path.clone(), key_path.clone(), up_default)
            .await;
    let dot_addr = server.dot_addr.expect("dot addr");
    let base = format!("http://{}", server.web_addr);
    let http = reqwest::Client::new();

    let (group_id, laptop_id, pad_id) = setup_client_policies(&http, &base, up_vip).await;
    verify_client_routing(&http, &base, dot_addr, &cert_pem).await;

    // Rule tester with client_id context
    let (s, test_resp) = api_send_json(
        &http,
        reqwest::Method::POST,
        &format!("{base}/api/rules/test"),
        &json!({ "domain": "social.test", "client_id": "laptop-1" }),
    )
    .await;
    assert_eq!(s, reqwest::StatusCode::OK);
    assert_eq!(test_resp["action"], "block");
    assert!(
        test_resp["matched_list"]
            .as_str()
            .is_some_and(|m| m.contains("laptop"))
    );

    // Discovered clients includes 127.0.0.1
    wait_for_log_count(&http, &base, 5).await;
    let overview: Value = api_get_json(&http, &format!("{base}/api/clients")).await;
    assert_eq!(overview["groups"].as_array().map(Vec::len), Some(1));
    assert_eq!(overview["clients"].as_array().map(Vec::len), Some(3));
    assert!(
        overview["discovered"]
            .as_array()
            .is_some_and(|d| d.iter().any(|item| item["ip"] == "127.0.0.1"))
    );

    // Shutdown and restart against same data_dir to confirm persistence
    server.shutdown().await;
    let server2 = restart_with_clients_config(dir.path(), cert_path, key_path, up_default).await;
    let base2 = format!("http://{}", server2.web_addr);
    let dot_addr2 = server2.dot_addr.expect("dot addr 2");
    verify_client_routing(&http, &base2, dot_addr2, &cert_pem).await;

    // Update & Delete CRUD lifecycle
    let (s, updated) = api_send_json(
        &http,
        reqwest::Method::PUT,
        &format!("{base2}/api/clients/{laptop_id}"),
        &json!({
            "name": "laptop-renamed",
            "identifiers": ["laptop-1"],
            "group_id": group_id,
            "custom_rules": "@@||games.test^\n",
            "upstreams": [format!("udp://{up_vip}")]
        }),
    )
    .await;
    assert_eq!(s, reqwest::StatusCode::OK);
    assert_eq!(updated["name"], "laptop-renamed");

    for path in [
        format!("/api/clients/{laptop_id}"),
        format!("/api/clients/{pad_id}"),
        format!("/api/client-groups/{group_id}"),
    ] {
        let resp = http
            .delete(format!("{base2}{path}"))
            .send()
            .await
            .expect("delete");
        assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);
    }

    let final_overview: Value = api_get_json(&http, &format!("{base2}/api/clients")).await;
    assert_eq!(final_overview["groups"].as_array().map(Vec::len), Some(0));
    assert_eq!(final_overview["clients"].as_array().map(Vec::len), Some(1));

    server2.shutdown().await;
}
