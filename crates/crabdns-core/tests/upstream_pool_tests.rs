use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crabdns_core::UpstreamPool;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

fn make_query(id: u16, domain: &str) -> Vec<u8> {
    let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(
        Name::from_ascii(domain).unwrap(),
        RecordType::A,
    ));
    msg.to_vec().unwrap()
}

async fn read_tcp_framed(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0_u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let len = usize::from(u16::from_be_bytes(len_buf));
    let mut buf = vec![0_u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn send_tcp_framed(stream: &mut TcpStream, payload: &[u8]) -> std::io::Result<()> {
    let len = u16::try_from(payload.len()).expect("len u16");
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(payload).await?;
    stream.flush().await
}

#[tokio::test]
async fn test_tcp_pool_reuses_connections_and_recovers_on_close() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepts = Arc::new(AtomicUsize::new(0));
    let accepts_bg = Arc::clone(&accepts);

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let conn_num = accepts_bg.fetch_add(1, Ordering::SeqCst) + 1;
            tokio::spawn(async move {
                while let Ok(q) = read_tcp_framed(&mut stream).await {
                    let req = Message::from_vec(&q).unwrap();
                    let mut resp = Message::new(req.id, MessageType::Response, OpCode::Query);
                    resp.queries.clone_from(&req.queries);
                    if let Some(q0) = req.queries.first() {
                        resp.add_answer(Record::from_rdata(
                            q0.name().clone(),
                            60,
                            RData::A(A(Ipv4Addr::new(10, 0, 0, conn_num as u8))),
                        ));
                    }
                    let wire = resp.to_vec().unwrap();
                    if send_tcp_framed(&mut stream, &wire).await.is_err() {
                        break;
                    }
                    if conn_num == 2 {
                        break;
                    }
                }
            });
        }
    });

    let pool = UpstreamPool::new(&[format!("tcp://{addr}")], 1000).unwrap();
    for i in 1_u16..=5 {
        let (resp, _) = pool.exchange(&make_query(i, "pool.test.")).await.unwrap();
        let msg = Message::from_vec(&resp).unwrap();
        assert_eq!(msg.id, i);
    }
    assert_eq!(accepts.load(Ordering::SeqCst), 1);

    let listener2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr2 = listener2.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener2.accept().await {
            tokio::spawn(async move {
                if let Ok(q) = read_tcp_framed(&mut stream).await {
                    let req = Message::from_vec(&q).unwrap();
                    let mut resp = Message::new(req.id, MessageType::Response, OpCode::Query);
                    resp.queries.clone_from(&req.queries);
                    let _ = send_tcp_framed(&mut stream, &resp.to_vec().unwrap()).await;
                }
            });
        }
    });

    let pool2 = UpstreamPool::new(&[format!("tcp://{addr2}")], 1000).unwrap();
    let (r1, _) = pool2
        .exchange(&make_query(10, "close.test."))
        .await
        .unwrap();
    assert_eq!(Message::from_vec(&r1).unwrap().id, 10);
    let (r2, _) = pool2
        .exchange(&make_query(11, "close.test."))
        .await
        .unwrap();
    assert_eq!(Message::from_vec(&r2).unwrap().id, 11);
}

#[tokio::test]
async fn test_udp_truncated_response_falls_back_to_tcp() {
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp_listener.local_addr().unwrap();
    let udp_sock = UdpSocket::bind(addr).await.unwrap();
    let tcp_hits = Arc::new(AtomicUsize::new(0));
    let tcp_hits_bg = Arc::clone(&tcp_hits);

    tokio::spawn(async move {
        let mut buf = [0_u8; 2048];
        while let Ok((len, peer)) = udp_sock.recv_from(&mut buf).await {
            if let Ok(req) = Message::from_vec(&buf[..len]) {
                let mut resp = Message::new(req.id, MessageType::Response, OpCode::Query);
                resp.metadata.truncation = true;
                resp.metadata.recursion_available = true;
                resp.queries.clone_from(&req.queries);
                let _ = udp_sock.send_to(&resp.to_vec().unwrap(), peer).await;
            }
        }
    });

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = tcp_listener.accept().await {
            let hits = Arc::clone(&tcp_hits_bg);
            tokio::spawn(async move {
                if let Ok(q) = read_tcp_framed(&mut stream).await {
                    hits.fetch_add(1, Ordering::SeqCst);
                    let req = Message::from_vec(&q).unwrap();
                    let mut resp = Message::new(req.id, MessageType::Response, OpCode::Query);
                    resp.metadata.recursion_available = true;
                    resp.metadata.response_code = ResponseCode::NoError;
                    resp.queries.clone_from(&req.queries);
                    if let Some(q0) = req.queries.first() {
                        resp.add_answer(Record::from_rdata(
                            q0.name().clone(),
                            120,
                            RData::A(A(Ipv4Addr::new(93, 184, 216, 34))),
                        ));
                    }
                    let _ = send_tcp_framed(&mut stream, &resp.to_vec().unwrap()).await;
                }
            });
        }
    });

    let pool = UpstreamPool::new(&[format!("udp://{addr}")], 1000).unwrap();
    let (resp_bytes, _) = pool
        .exchange(&make_query(0x7788, "tc.test."))
        .await
        .unwrap();
    let resp = Message::from_vec(&resp_bytes).unwrap();
    assert!(!resp.metadata.truncation);
    assert_eq!(resp.answers.len(), 1);
    assert_eq!(tcp_hits.load(Ordering::SeqCst), 1);
}
