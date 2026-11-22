use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};

use crate::config::BlockMode;
use crate::error::{CoreError, Result};
use crate::filter::RewriteAction;

const OPT_RECORD_TYPE: u16 = 41;
const DEFAULT_CACHE_TTL_SECS: u32 = 60;
const MAX_LOG_ANSWERS: usize = 8;
const MAX_TXT_SUMMARY_LEN: usize = 120;

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

/// Builds a minimal 12-byte `FORMERR` response directly from raw header bytes when full DNS parsing fails.
pub fn build_raw_formerr(raw_query: &[u8]) -> Option<Vec<u8>> {
    if raw_query.len() < 12 {
        return None;
    }
    let mut out = vec![0_u8; 12];
    out[0] = raw_query[0];
    out[1] = raw_query[1];
    // QR=1, preserve OPCODE (bits 6..3) and RD (bit 0).
    out[2] = 0x80 | (raw_query[2] & 0x79);
    // RA=1, RCODE=1 (FORMERR).
    out[3] = 0x81;
    Some(out)
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

fn skip_dns_name(wire: &[u8], start: usize) -> Option<usize> {
    let mut pos = start;
    for _ in 0..128 {
        let len_byte = *wire.get(pos)?;
        if len_byte == 0 {
            return Some(pos + 1);
        }
        match len_byte & 0xC0 {
            0xC0 => {
                return (pos + 2 <= wire.len()).then_some(pos + 2);
            }
            0x00 => {
                let label_len = usize::from(len_byte);
                pos = pos.checked_add(1 + label_len)?;
                if pos > wire.len() {
                    return None;
                }
            }
            _ => return None,
        }
    }
    None
}

/// Scans a raw DNS wire response and records `(ttl_offset, clamped_ttl)` for every non-OPT RR.
pub(crate) fn scan_rr_ttl_offsets(wire: &[u8], min_ttl: u32, max_ttl: u32) -> Vec<(usize, u32)> {
    if wire.len() < 12 || (wire[2] & 0x80) == 0 {
        return Vec::new();
    }
    let qdcount = usize::from(u16::from_be_bytes([wire[4], wire[5]]));
    let answer_count = usize::from(u16::from_be_bytes([wire[6], wire[7]]));
    let ns_count = usize::from(u16::from_be_bytes([wire[8], wire[9]]));
    let additional_count = usize::from(u16::from_be_bytes([wire[10], wire[11]]));
    let total_rrs = answer_count + ns_count + additional_count;
    if total_rrs == 0 {
        return Vec::new();
    }

    let mut pos = 12_usize;
    for _ in 0..qdcount {
        let Some(next) = skip_dns_name(wire, pos) else {
            return Vec::new();
        };
        pos = next + 4;
        if pos > wire.len() {
            return Vec::new();
        }
    }

    let mut offsets = Vec::with_capacity(total_rrs.min(16));
    for _ in 0..total_rrs {
        let Some(next) = skip_dns_name(wire, pos) else {
            return Vec::new();
        };
        if next + 10 > wire.len() {
            return Vec::new();
        }
        let rtype = u16::from_be_bytes([wire[next], wire[next + 1]]);
        let ttl_offset = next + 4;
        let orig_ttl = u32::from_be_bytes([
            wire[ttl_offset],
            wire[ttl_offset + 1],
            wire[ttl_offset + 2],
            wire[ttl_offset + 3],
        ]);
        let rdlength = usize::from(u16::from_be_bytes([wire[next + 8], wire[next + 9]]));
        pos = next + 10 + rdlength;
        if pos > wire.len() {
            return Vec::new();
        }
        if rtype != OPT_RECORD_TYPE {
            offsets.push((ttl_offset, orig_ttl.clamp(min_ttl, max_ttl)));
        }
    }

    if pos != wire.len() {
        return Vec::new();
    }
    offsets
}

/// Updates RR TTL fields in-place inside `wire` using either remaining TTL or a fixed stale TTL.
pub(crate) fn patch_wire_ttls(
    wire: &mut [u8],
    offsets: &[(usize, u32)],
    elapsed_secs: u32,
    stale_ttl: Option<u32>,
) {
    for &(offset, clamped_orig) in offsets {
        if offset + 4 <= wire.len() {
            let ttl = match stale_ttl {
                Some(s) => s,
                None => clamped_orig.saturating_sub(elapsed_secs).max(1),
            };
            wire[offset..offset + 4].copy_from_slice(&ttl.to_be_bytes());
        }
    }
}

/// Computes the cache TTL for a DNS response, following RFC 2308 SOA minimum TTL for negative answers.
pub fn compute_response_cache_ttl(msg: &Message) -> Option<u32> {
    if !matches!(
        msg.response_code,
        ResponseCode::NoError | ResponseCode::NXDomain
    ) {
        return None;
    }

    let ans_min_ttl = msg.answers.iter().map(|r| r.ttl).min();
    let soa_min_ttl = msg
        .authorities
        .iter()
        .filter_map(|r| match &r.data {
            RData::SOA(soa) => Some(r.ttl.min(soa.minimum)),
            _ => None,
        })
        .min();

    let is_negative = msg.response_code == ResponseCode::NXDomain || msg.answers.is_empty();
    if is_negative {
        let ttl = match (ans_min_ttl, soa_min_ttl) {
            (Some(a), Some(s)) => a.min(s),
            (Some(a), None) => a,
            (None, Some(s)) => s,
            (None, None) => DEFAULT_CACHE_TTL_SECS,
        };
        return Some(ttl);
    }

    Some(ans_min_ttl.unwrap_or(DEFAULT_CACHE_TTL_SECS))
}

/// Formats concise human-readable summaries of DNS answer records for query logging.
pub fn extract_answer_summaries(wire: &[u8]) -> Vec<String> {
    let Ok(msg) = Message::from_vec(wire) else {
        return Vec::new();
    };
    extract_answer_summaries_msg(&msg)
}

/// Formats concise human-readable summaries from an already-parsed DNS `Message`.
pub fn extract_answer_summaries_msg(msg: &Message) -> Vec<String> {
    let mut out = Vec::with_capacity(msg.answers.len().min(MAX_LOG_ANSWERS));
    for record in msg.answers.iter().take(MAX_LOG_ANSWERS) {
        out.push(format_rdata_summary(record));
    }
    out
}

fn format_rdata_summary(record: &Record) -> String {
    match &record.data {
        RData::A(a) => a.0.to_string(),
        RData::AAAA(aaaa) => aaaa.0.to_string(),
        RData::CNAME(cname) => {
            let host = cname.to_utf8();
            format!("CNAME {}", host.trim_end_matches('.'))
        }
        RData::PTR(ptr) => {
            let host = ptr.to_utf8();
            format!("PTR {}", host.trim_end_matches('.'))
        }
        RData::TXT(txt) => {
            let mut joined = String::new();
            for chunk in &txt.txt_data {
                joined.push_str(&String::from_utf8_lossy(chunk));
            }
            if joined.chars().count() > MAX_TXT_SUMMARY_LEN {
                let truncated: String = joined.chars().take(MAX_TXT_SUMMARY_LEN).collect();
                format!("TXT {truncated}...")
            } else {
                format!("TXT {joined}")
            }
        }
        RData::MX(mx) => {
            let exch = mx.exchange.to_utf8();
            format!("MX {} {}", mx.preference, exch.trim_end_matches('.'))
        }
        RData::SVCB(svcb) | RData::HTTPS(hickory_proto::rr::rdata::HTTPS(svcb)) => {
            let target = svcb.target_name.to_utf8();
            let clean = target.trim_end_matches('.');
            if clean.is_empty() {
                "SVCB .".to_string()
            } else {
                format!("SVCB {clean}")
            }
        }
        RData::HINFO(_) => "HINFO RFC8482".to_string(),
        _ => record.record_type().to_string(),
    }
}
