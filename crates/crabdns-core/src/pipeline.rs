use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use chrono::{DateTime, Utc};
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use ts_rs::TS;

use crate::cache::{CacheKey, DnsCache};
use crate::error::{CoreError, Result};
use crate::filter::{FilterAction, FilterEngine};
use crate::upstream::UpstreamPool;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum QueryOutcome {
    Forwarded,
    Cached,
    Blocked,
    Rewritten,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct QueryEvent {
    pub timestamp: DateTime<Utc>,
    pub client_ip: String,
    pub domain: String,
    pub qtype: String,
    pub outcome: QueryOutcome,
    pub matched_rule: Option<String>,
    pub upstream: Option<String>,
    #[ts(type = "number")]
    pub elapsed_us: u64,
    pub rcode: String,
}

pub struct DnsPipeline {
    filter: Arc<FilterEngine>,
    cache: Arc<DnsCache>,
    upstream: Arc<UpstreamPool>,
    log_tx: Option<mpsc::Sender<QueryEvent>>,
}

impl DnsPipeline {
    pub fn new(
        filter: Arc<FilterEngine>,
        cache: Arc<DnsCache>,
        upstream: Arc<UpstreamPool>,
        log_tx: Option<mpsc::Sender<QueryEvent>>,
    ) -> Self {
        Self {
            filter,
            cache,
            upstream,
            log_tx,
        }
    }

    pub fn filter(&self) -> &Arc<FilterEngine> {
        &self.filter
    }

    pub fn cache(&self) -> &Arc<DnsCache> {
        &self.cache
    }

    pub async fn handle_packet(
        &self,
        raw_query: &[u8],
        client_addr: SocketAddr,
    ) -> Result<Vec<u8>> {
        let start = Instant::now();
        let request = Message::from_vec(raw_query)
            .map_err(|e| CoreError::Protocol(format!("invalid DNS packet: {e}")))?;

        let Some(question) = request.queries.first().cloned() else {
            return build_error_response(&request, ResponseCode::FormErr);
        };

        let qname = question.name().to_utf8();
        let clean_domain = qname.trim_end_matches('.').to_string();
        let qtype = question.query_type();
        let qclass = u16::from(question.query_class());

        let decision = self.filter.evaluate(&clean_domain);
        match decision.action {
            FilterAction::Block => {
                let resp = build_blocked_response(&request, qtype)?;
                self.emit_log(
                    client_addr,
                    clean_domain,
                    qtype,
                    QueryOutcome::Blocked,
                    decision.matched_rule,
                    None,
                    start,
                    "NOERROR",
                );
                return Ok(resp);
            }
            FilterAction::Rewrite(ip) => {
                let resp = build_rewrite_response(&request, qtype, ip)?;
                self.emit_log(
                    client_addr,
                    clean_domain,
                    qtype,
                    QueryOutcome::Rewritten,
                    decision.matched_rule,
                    None,
                    start,
                    "NOERROR",
                );
                return Ok(resp);
            }
            FilterAction::Allow => {}
        }

        let cache_key = CacheKey {
            qname: qname.to_ascii_lowercase(),
            qtype: u16::from(qtype),
            qclass,
        };

        if let Some(hit) = self.cache.get(&cache_key, request.id) {
            if hit.is_stale {
                self.spawn_background_refresh(raw_query.to_vec(), cache_key.clone());
            }
            self.emit_log(
                client_addr,
                clean_domain,
                qtype,
                QueryOutcome::Cached,
                decision.matched_rule,
                Some("cache".to_string()),
                start,
                "NOERROR",
            );
            return Ok(hit.wire_bytes);
        }

        self.forward_to_upstream(
            &request,
            raw_query,
            client_addr,
            clean_domain,
            qtype,
            cache_key,
            decision.matched_rule,
            start,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn forward_to_upstream(
        &self,
        request: &Message,
        raw_query: &[u8],
        client_addr: SocketAddr,
        clean_domain: String,
        qtype: RecordType,
        cache_key: CacheKey,
        matched_rule: Option<String>,
        start: Instant,
    ) -> Result<Vec<u8>> {
        match self.upstream.exchange(raw_query).await {
            Ok((resp_bytes, upstream_label)) => {
                if let Some(blocked) = self.check_cname_cloaking(request, &resp_bytes, qtype)? {
                    self.emit_log(
                        client_addr,
                        clean_domain,
                        qtype,
                        QueryOutcome::Blocked,
                        Some(blocked.1),
                        Some(upstream_label),
                        start,
                        "NOERROR",
                    );
                    return Ok(blocked.0);
                }

                let rcode_str = cache_upstream_response(&self.cache, cache_key, &resp_bytes);
                self.emit_log(
                    client_addr,
                    clean_domain,
                    qtype,
                    QueryOutcome::Forwarded,
                    matched_rule,
                    Some(upstream_label),
                    start,
                    &rcode_str,
                );
                Ok(resp_bytes)
            }
            Err(err) => {
                tracing::warn!(domain = %clean_domain, error = %err, "all upstreams failed");
                self.emit_log(
                    client_addr,
                    clean_domain,
                    qtype,
                    QueryOutcome::Error,
                    None,
                    None,
                    start,
                    "SERVFAIL",
                );
                build_error_response(request, ResponseCode::ServFail)
            }
        }
    }

    fn check_cname_cloaking(
        &self,
        request: &Message,
        resp_bytes: &[u8],
        qtype: RecordType,
    ) -> Result<Option<(Vec<u8>, String)>> {
        let Ok(resp_msg) = Message::from_vec(resp_bytes) else {
            return Ok(None);
        };
        for answer in &resp_msg.answers {
            if let RData::CNAME(cname) = &answer.data {
                let target = cname.to_utf8();
                let target_clean = target.trim_end_matches('.');
                let decision = self.filter.evaluate(target_clean);
                if decision.action == FilterAction::Block {
                    let blocked_bytes = build_blocked_response(request, qtype)?;
                    let rule = decision
                        .matched_rule
                        .unwrap_or_else(|| format!("cname:{target_clean}"));
                    return Ok(Some((blocked_bytes, rule)));
                }
            }
        }
        Ok(None)
    }

    fn spawn_background_refresh(&self, query_wire: Vec<u8>, key: CacheKey) {
        let upstream = Arc::clone(&self.upstream);
        let cache = Arc::clone(&self.cache);
        tokio::spawn(async move {
            if let Ok((resp_bytes, _)) = upstream.exchange(&query_wire).await {
                let _ = cache_upstream_response(&cache, key, &resp_bytes);
            }
        });
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_log(
        &self,
        client_addr: SocketAddr,
        domain: String,
        qtype: RecordType,
        outcome: QueryOutcome,
        matched_rule: Option<String>,
        upstream: Option<String>,
        start: Instant,
        rcode: &str,
    ) {
        let Some(tx) = &self.log_tx else {
            return;
        };
        let elapsed_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
        let event = QueryEvent {
            timestamp: Utc::now(),
            client_ip: client_addr.ip().to_string(),
            domain,
            qtype: qtype.to_string(),
            outcome,
            matched_rule,
            upstream,
            elapsed_us,
            rcode: rcode.to_string(),
        };
        let _ = tx.try_send(event);
    }
}

fn cache_upstream_response(cache: &DnsCache, key: CacheKey, resp_bytes: &[u8]) -> String {
    let Ok(msg) = Message::from_vec(resp_bytes) else {
        return "UNKNOWN".to_string();
    };
    let rcode = msg.response_code;
    if rcode == ResponseCode::NoError || rcode == ResponseCode::NXDomain {
        let min_ttl = msg.answers.iter().map(|r| r.ttl).min().unwrap_or(60);
        cache.insert(key, resp_bytes.to_vec(), min_ttl);
    }
    rcode.to_string()
}

fn base_response(request: &Message, rcode: ResponseCode) -> Message {
    let mut resp = Message::new(request.id, MessageType::Response, request.op_code);
    resp.metadata.recursion_desired = request.recursion_desired;
    resp.metadata.recursion_available = true;
    resp.metadata.response_code = rcode;
    resp.queries.clone_from(&request.queries);
    resp
}

fn build_error_response(request: &Message, rcode: ResponseCode) -> Result<Vec<u8>> {
    base_response(request, rcode)
        .to_vec()
        .map_err(|e| CoreError::Protocol(e.to_string()))
}

fn build_blocked_response(request: &Message, qtype: RecordType) -> Result<Vec<u8>> {
    let mut resp = base_response(request, ResponseCode::NoError);
    if let Some(q) = request.queries.first() {
        let name = q.name().clone();
        match qtype {
            RecordType::A => {
                resp.add_answer(Record::from_rdata(
                    name,
                    60,
                    RData::A(A(Ipv4Addr::UNSPECIFIED)),
                ));
            }
            RecordType::AAAA => {
                resp.add_answer(Record::from_rdata(
                    name,
                    60,
                    RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED)),
                ));
            }
            _ => {
                resp.metadata.response_code = ResponseCode::NXDomain;
            }
        }
    }
    resp.to_vec()
        .map_err(|e| CoreError::Protocol(e.to_string()))
}

fn build_rewrite_response(request: &Message, qtype: RecordType, ip: IpAddr) -> Result<Vec<u8>> {
    let mut resp = base_response(request, ResponseCode::NoError);
    if let Some(q) = request.queries.first() {
        let name = q.name().clone();
        match (qtype, ip) {
            (RecordType::A, IpAddr::V4(v4)) => {
                resp.add_answer(Record::from_rdata(name, 60, RData::A(A(v4))));
            }
            (RecordType::AAAA, IpAddr::V6(v6)) => {
                resp.add_answer(Record::from_rdata(name, 60, RData::AAAA(AAAA(v6))));
            }
            _ => {}
        }
    }
    resp.to_vec()
        .map_err(|e| CoreError::Protocol(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{OpCode, Query};
    use hickory_proto::rr::Name;
    use hickory_proto::rr::rdata::CNAME;
    use tokio::net::UdpSocket;

    fn build_query(id: u16, domain: &str, qtype: RecordType) -> Vec<u8> {
        let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
        msg.metadata.recursion_desired = true;
        let name = Name::from_ascii(domain).expect("valid domain");
        msg.add_query(Query::query(name, qtype));
        msg.to_vec().expect("encode query")
    }

    async fn spawn_mock_udp_upstream(cname_target: Option<&'static str>) -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind mock");
        let addr = socket.local_addr().expect("local addr");
        tokio::spawn(async move {
            let mut buf = [0_u8; 2048];
            while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
                let req = Message::from_vec(&buf[..len]).expect("valid req");
                let q = req.queries.first().expect("question");
                let mut resp = Message::new(req.id, MessageType::Response, OpCode::Query);
                resp.metadata.recursion_available = true;
                resp.queries.clone_from(&req.queries);
                if let Some(target) = cname_target {
                    let cname = Name::from_ascii(target).expect("valid cname");
                    resp.add_answer(Record::from_rdata(
                        q.name().clone(),
                        60,
                        RData::CNAME(CNAME(cname)),
                    ));
                } else {
                    resp.add_answer(Record::from_rdata(
                        q.name().clone(),
                        120,
                        RData::A(A(Ipv4Addr::new(93, 184, 216, 34))),
                    ));
                }
                let bytes = resp.to_vec().expect("encode resp");
                let _ = socket.send_to(&bytes, peer).await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn test_pipeline_block_rewrite_and_invalid() {
        let filter = Arc::new(FilterEngine::new(&[
            "||ads.test^".to_string(),
            "||nas.local^$dnsrewrite=10.0.0.2".to_string(),
        ]));
        let cache = Arc::new(DnsCache::new(64, true));
        let upstream =
            Arc::new(UpstreamPool::new(&["udp://127.0.0.1:1".to_string()], 200).unwrap());
        let (tx, mut rx) = mpsc::channel(16);
        let pipeline = DnsPipeline::new(filter, cache, upstream, Some(tx));
        let client: SocketAddr = "127.0.0.1:12345".parse().expect("addr");

        let blocked_q = build_query(0x1001, "ads.test.", RecordType::A);
        let resp = Message::from_vec(&pipeline.handle_packet(&blocked_q, client).await.unwrap())
            .expect("decode");
        assert_eq!(resp.answers.len(), 1);
        assert_eq!(rx.recv().await.unwrap().outcome, QueryOutcome::Blocked);

        let blocked_txt = build_query(0x1002, "ads.test.", RecordType::TXT);
        let resp_txt =
            Message::from_vec(&pipeline.handle_packet(&blocked_txt, client).await.unwrap())
                .expect("decode");
        assert_eq!(resp_txt.response_code, ResponseCode::NXDomain);
        let _ = rx.recv().await;

        let rewrite_q = build_query(0x1003, "nas.local.", RecordType::A);
        let resp_rw = Message::from_vec(&pipeline.handle_packet(&rewrite_q, client).await.unwrap())
            .expect("decode");
        assert_eq!(resp_rw.answers.len(), 1);
        assert_eq!(rx.recv().await.unwrap().outcome, QueryOutcome::Rewritten);

        assert!(pipeline.handle_packet(&[0, 1, 2], client).await.is_err());
    }

    #[tokio::test]
    async fn test_pipeline_forward_cache_and_cname_cloaking() {
        let mock_addr = spawn_mock_udp_upstream(None).await;
        let filter = Arc::new(FilterEngine::new(&["||evil-cname.test^".to_string()]));
        let cache = Arc::new(DnsCache::new(64, true));
        let upstream =
            Arc::new(UpstreamPool::new(&[format!("udp://{mock_addr}")], 1000).expect("pool"));
        let (tx, mut rx) = mpsc::channel(16);
        let pipeline = DnsPipeline::new(filter, cache, upstream, Some(tx));
        let client: SocketAddr = "127.0.0.1:54321".parse().expect("addr");

        let q1 = build_query(0x2001, "example.org.", RecordType::A);
        let r1 = Message::from_vec(&pipeline.handle_packet(&q1, client).await.unwrap()).unwrap();
        assert_eq!(r1.id, 0x2001);
        assert_eq!(rx.recv().await.unwrap().outcome, QueryOutcome::Forwarded);

        let q2 = build_query(0x2002, "example.org.", RecordType::A);
        let r2 = Message::from_vec(&pipeline.handle_packet(&q2, client).await.unwrap()).unwrap();
        assert_eq!(r2.id, 0x2002);
        assert_eq!(rx.recv().await.unwrap().outcome, QueryOutcome::Cached);

        let cname_addr = spawn_mock_udp_upstream(Some("evil-cname.test.")).await;
        let upstream2 =
            Arc::new(UpstreamPool::new(&[format!("udp://{cname_addr}")], 1000).expect("pool"));
        let (tx2, mut rx2) = mpsc::channel(16);
        let pipeline2 = DnsPipeline::new(
            Arc::clone(pipeline.filter()),
            Arc::new(DnsCache::new(64, false)),
            upstream2,
            Some(tx2),
        );
        let q3 = build_query(0x3001, "cloaked.example.", RecordType::A);
        let _ = pipeline2.handle_packet(&q3, client).await.unwrap();
        assert_eq!(rx2.recv().await.unwrap().outcome, QueryOutcome::Blocked);
    }

    #[tokio::test]
    async fn test_pipeline_upstream_timeout_servfail() {
        let filter = Arc::new(FilterEngine::new(&[]));
        let cache = Arc::new(DnsCache::new(64, false));
        let upstream = Arc::new(UpstreamPool::new(&["udp://127.0.0.1:1".to_string()], 50).unwrap());
        let pipeline = DnsPipeline::new(filter, cache, upstream, None);
        let client: SocketAddr = "127.0.0.1:9999".parse().expect("addr");

        let q = build_query(0x4001, "unreachable.example.", RecordType::A);
        let resp = Message::from_vec(&pipeline.handle_packet(&q, client).await.unwrap()).unwrap();
        assert_eq!(resp.response_code, ResponseCode::ServFail);
    }
}
