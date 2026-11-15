use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};

use crate::config::BlockMode;
use crate::error::{CoreError, Result};
use crate::filter::RewriteAction;

pub(crate) fn base_response(request: &Message, rcode: ResponseCode) -> Message {
    let mut resp = Message::new(request.id, MessageType::Response, request.op_code);
    resp.metadata.recursion_desired = request.recursion_desired;
    resp.metadata.recursion_available = true;
    resp.metadata.response_code = rcode;
    resp.queries.clone_from(&request.queries);
    resp
}

pub(crate) fn build_error_response(request: &Message, rcode: ResponseCode) -> Result<Vec<u8>> {
    base_response(request, rcode)
        .to_vec()
        .map_err(|e| CoreError::Protocol(e.to_string()))
}

pub(crate) fn build_blocked_response(
    request: &Message,
    qtype: RecordType,
    mode: BlockMode,
) -> Result<(Vec<u8>, &'static str)> {
    let mut resp = match mode {
        BlockMode::NxDomain => {
            let bytes = build_error_response(request, ResponseCode::NXDomain)?;
            return Ok((bytes, "NXDOMAIN"));
        }
        BlockMode::NoData => {
            let bytes = build_error_response(request, ResponseCode::NoError)?;
            return Ok((bytes, "NOERROR"));
        }
        BlockMode::ZeroIp => base_response(request, ResponseCode::NoError),
    };

    let mut rcode = "NOERROR";
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
                rcode = "NXDOMAIN";
            }
        }
    }
    let bytes = resp
        .to_vec()
        .map_err(|e| CoreError::Protocol(e.to_string()))?;
    Ok((bytes, rcode))
}

pub(crate) fn build_rewrite_response(
    request: &Message,
    qtype: RecordType,
    rewrite: &RewriteAction,
) -> Result<Vec<u8>> {
    let mut resp = base_response(request, ResponseCode::NoError);
    if let Some(q) = request.queries.first() {
        let name = q.name().clone();
        match (qtype, rewrite) {
            (RecordType::A, RewriteAction::Ip(IpAddr::V4(v4))) => {
                resp.add_answer(Record::from_rdata(name, 60, RData::A(A(*v4))));
            }
            (RecordType::AAAA, RewriteAction::Ip(IpAddr::V6(v6))) => {
                resp.add_answer(Record::from_rdata(name, 60, RData::AAAA(AAAA(*v6))));
            }
            (_, RewriteAction::Cname(target)) => {
                let fqdn = format!("{}.", target.trim_end_matches('.'));
                if let Ok(cname_name) = Name::from_ascii(&fqdn) {
                    resp.add_answer(Record::from_rdata(
                        name,
                        60,
                        RData::CNAME(CNAME(cname_name)),
                    ));
                }
            }
            (RecordType::TXT, RewriteAction::Txt(text)) => {
                resp.add_answer(Record::from_rdata(
                    name,
                    60,
                    RData::TXT(TXT::new(vec![text.clone()])),
                ));
            }
            _ => {}
        }
    }
    resp.to_vec()
        .map_err(|e| CoreError::Protocol(e.to_string()))
}
