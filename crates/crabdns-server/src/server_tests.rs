use std::net::IpAddr;

use super::*;
use std::net::Ipv4Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

#[test]
fn test_ip_conn_limiter_enforces_per_ip_and_releases() {
    let limiter = IpConnLimiter::new(8, 2);
    let ip1 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    let ip2 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11));

    let g1 = limiter.try_acquire(ip1).expect("1st ip1");
    let g2 = limiter.try_acquire(ip1).expect("2nd ip1");
    assert!(limiter.try_acquire(ip1).is_none(), "3rd ip1 must fail");
    assert!(
        limiter.try_acquire(ip2).is_some(),
        "other IP must still be allowed"
    );

    drop(g1);
    assert!(
        limiter.try_acquire(ip1).is_some(),
        "released slot must be reusable"
    );
    drop(g2);
}

#[tokio::test]
async fn test_tcp_pipelining_out_of_order_and_formerr_keeps_conn_alive() {
    use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, Record, RecordType};

    let upstream_sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind mock");
    let upstream_addr = upstream_sock.local_addr().expect("addr");
    tokio::spawn(async move {
        let mut buf = [0_u8; 2048];
        while let Ok((len, peer)) = upstream_sock.recv_from(&mut buf).await {
            if let Ok(req) = Message::from_vec(&buf[..len]) {
                let sock = &upstream_sock;
                let mut resp = Message::new(req.id, MessageType::Response, OpCode::Query);
                resp.metadata.recursion_available = true;
                resp.metadata.response_code = ResponseCode::NoError;
                resp.queries.clone_from(&req.queries);
                if let Some(q) = req.queries.first() {
                    resp.add_answer(Record::from_rdata(
                        q.name().clone(),
                        60,
                        RData::A(A(Ipv4Addr::new(93, 184, 216, 34))),
                    ));
                }
                let wire = resp.to_vec().unwrap();
                // Delay slow queries by 200ms so pipelined local queries overtake them.
                tokio::time::sleep(Duration::from_millis(200)).await;
                let _ = sock.send_to(&wire, peer).await;
            }
        }
    });

    let dir = tempfile::tempdir().expect("tempdir");
    let server = spawn_server(Config {
        listen_dns: "127.0.0.1:0".parse().unwrap(),
        listen_web: "127.0.0.1:0".parse().unwrap(),
        data_dir: dir.path().to_path_buf(),
        upstreams: vec![format!("udp://{upstream_addr}")],
        custom_rules: vec!["||blocked.pipe.test^".to_string()],
        rdns_enabled: false,
        ..Config::default()
    })
    .await
    .expect("spawn server");

    let mut stream = tokio::net::TcpStream::connect(server.dns_addr)
        .await
        .expect("connect tcp");

    let build_q = |id: u16, domain: &str| {
        let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
        msg.metadata.recursion_desired = true;
        msg.add_query(Query::query(
            Name::from_ascii(domain).unwrap(),
            RecordType::A,
        ));
        msg.to_vec().unwrap()
    };

    // Frame 1: slow upstream query (ID 0x1001)
    let q_slow = build_q(0x1001, "slow.pipe.test.");
    // Frame 2: malformed DNS packet >= 12 bytes (ID 0x1002, QDCOUNT=5 with truncated body) -> FORMERR
    let q_malformed = vec![
        0x10, 0x02, 0x01, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF,
    ];
    // Frame 3: locally blocked query (ID 0x1003) -> must overtake q_slow!
    let q_fast = build_q(0x1003, "blocked.pipe.test.");

    let mut pipelined = Vec::new();
    for pkt in [&q_slow, &q_malformed, &q_fast] {
        let len = u16::try_from(pkt.len()).unwrap();
        pipelined.extend_from_slice(&len.to_be_bytes());
        pipelined.extend_from_slice(pkt);
    }
    stream.write_all(&pipelined).await.expect("write pipelined");
    stream.flush().await.expect("flush");

    let mut ids = Vec::new();
    let mut rcodes = Vec::new();
    for _ in 0..3 {
        let mut len_buf = [0_u8; 2];
        tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut len_buf))
            .await
            .expect("read len timeout")
            .expect("read len");
        let rlen = usize::from(u16::from_be_bytes(len_buf));
        let mut rbuf = vec![0_u8; rlen];
        stream.read_exact(&mut rbuf).await.expect("read resp");
        let msg = Message::from_vec(&rbuf).expect("decode resp");
        ids.push(msg.id);
        rcodes.push(msg.response_code);
    }

    // Fast/malformed responses arrived before slow upstream response (0x1001 is last).
    assert_eq!(ids.last().copied(), Some(0x1001));
    let formerr_idx = ids.iter().position(|&id| id == 0x1002).expect("formerr id");
    assert_eq!(rcodes[formerr_idx], ResponseCode::FormErr);
    assert!(ids.contains(&0x1003));

    drop(stream);
    server.shutdown().await;
}
