use crate::config::BlockMode;
use crate::edns::EDE_BLOCKED;

const OPT_RECORD_TYPE: u16 = 41;
const EDE_OPTION_CODE: u16 = 15;
const BLOCKED_EDE_TEXT: &[u8] = b"Blocked by filter rule";
const DEFAULT_BLOCK_TTL_BYTES: [u8; 4] = 60_u32.to_be_bytes();

/// Zero-allocation parsed view of a standard single-question DNS query packet.
pub(crate) struct FastQuery {
    pub tx_id: u16,
    pub rd: bool,
    pub cd: bool,
    pub question_end: usize,
    pub qname_buf: [u8; 256],
    pub qname_len: usize,
    pub qtype: u16,
    pub qclass: u16,
    pub has_edns: bool,
    pub edns_udp_payload: u16,
}

impl FastQuery {
    /// Lowercase domain name without trailing dot (e.g. `"example.com"`).
    #[inline]
    pub(crate) fn clean_domain(&self) -> &str {
        let end = self.qname_len.saturating_sub(1);
        // SAFETY invariant: `parse_fast_query` only writes ASCII bytes into `qname_buf`.
        std::str::from_utf8(&self.qname_buf[..end]).unwrap_or("")
    }

    /// Lowercase domain name with trailing dot (e.g. `"example.com."`), matching `Message::to_utf8()`.
    #[inline]
    pub(crate) fn qname_fqdn(&self) -> &str {
        std::str::from_utf8(&self.qname_buf[..self.qname_len]).unwrap_or("")
    }
}

/// Attempts to parse a standard single-question DNS query without heap allocation.
/// Returns `None` if the packet is malformed, compressed, non-ASCII, non-standard,
/// or contains non-trivial EDNS0 options (which fall back to the full parser).
pub(crate) fn parse_fast_query(raw: &[u8]) -> Option<FastQuery> {
    if raw.len() < 17 {
        return None;
    }
    let flags0 = raw[2];
    let flags1 = raw[3];
    // Must be standard query (QR=0, OPCODE=0).
    if (flags0 & 0xF8) != 0 {
        return None;
    }
    let qdcount = u16::from_be_bytes([raw[4], raw[5]]);
    let answer_count = u16::from_be_bytes([raw[6], raw[7]]);
    let nscount = u16::from_be_bytes([raw[8], raw[9]]);
    let additional_count = u16::from_be_bytes([raw[10], raw[11]]);
    if qdcount != 1 || answer_count != 0 || nscount != 0 || additional_count > 1 {
        return None;
    }

    let (qname_buf, qname_len, pos) = parse_uncompressed_qname(raw, 12)?;
    if pos + 4 > raw.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([raw[pos], raw[pos + 1]]);
    let qclass = u16::from_be_bytes([raw[pos + 2], raw[pos + 3]]);
    let question_end = pos + 4;

    let (has_edns, edns_udp_payload) = if additional_count == 0 {
        if question_end != raw.len() {
            return None;
        }
        (false, 512)
    } else {
        parse_simple_opt(raw, question_end)?
    };

    Some(FastQuery {
        tx_id: u16::from_be_bytes([raw[0], raw[1]]),
        rd: (flags0 & 0x01) != 0,
        cd: (flags1 & 0x10) != 0,
        question_end,
        qname_buf,
        qname_len,
        qtype,
        qclass,
        has_edns,
        edns_udp_payload,
    })
}

fn parse_uncompressed_qname(raw: &[u8], start: usize) -> Option<([u8; 256], usize, usize)> {
    let mut buf = [0_u8; 256];
    let mut out_len = 0_usize;
    let mut pos = start;

    loop {
        let len_byte = *raw.get(pos)?;
        if len_byte == 0 {
            pos += 1;
            if out_len == 0 {
                buf[0] = b'.';
                out_len = 1;
            }
            return Some((buf, out_len, pos));
        }
        // Reject compression pointers or extended labels in queries.
        if (len_byte & 0xC0) != 0 || len_byte > 63 {
            return None;
        }
        let label_len = usize::from(len_byte);
        pos += 1;
        let label_end = pos.checked_add(label_len)?;
        let label = raw.get(pos..label_end)?;
        if out_len + label_len + 1 > buf.len() {
            return None;
        }
        for &b in label {
            if !b.is_ascii() || b == 0 {
                return None;
            }
            buf[out_len] = b.to_ascii_lowercase();
            out_len += 1;
        }
        buf[out_len] = b'.';
        out_len += 1;
        pos = label_end;
    }
}

fn parse_simple_opt(raw: &[u8], pos: usize) -> Option<(bool, u16)> {
    // Minimal OPT record: root name (1) + type (2) + class (2) + ttl (4) + rdlen (2) = 11 bytes.
    if pos + 11 != raw.len() {
        return None;
    }
    if raw[pos] != 0 {
        return None;
    }
    let rr_type = u16::from_be_bytes([raw[pos + 1], raw[pos + 2]]);
    if rr_type != OPT_RECORD_TYPE {
        return None;
    }
    let rdlen = u16::from_be_bytes([raw[pos + 9], raw[pos + 10]]);
    // Any EDNS options (e.g. ECS, DNS Cookies) fall back to full parser.
    if rdlen != 0 {
        return None;
    }
    let udp_payload = u16::from_be_bytes([raw[pos + 3], raw[pos + 4]]).max(512);
    Some((true, udp_payload))
}

fn write_header(
    out: &mut Vec<u8>,
    tx_id: u16,
    rd: bool,
    rcode: u8,
    answer_count: u16,
    additional_count: u16,
) {
    out.clear();
    out.extend_from_slice(&tx_id.to_be_bytes());
    out.push(0x80 | u8::from(rd)); // QR=1, OPCODE=0, AA=0, TC=0, RD
    out.push(0x80 | (rcode & 0x0F)); // RA=1, Z=0, RCODE
    out.extend_from_slice(&1_u16.to_be_bytes()); // QDCOUNT=1
    out.extend_from_slice(&answer_count.to_be_bytes());
    out.extend_from_slice(&0_u16.to_be_bytes()); // NSCOUNT=0
    out.extend_from_slice(&additional_count.to_be_bytes());
}

/// Writes a `REFUSED` DNS response directly into `out`.
pub(crate) fn write_refused_wire_response(raw_query: &[u8], q: &FastQuery, out: &mut Vec<u8>) {
    write_header(out, q.tx_id, q.rd, 5, 0, 0);
    out.extend_from_slice(&raw_query[12..q.question_end]);
}

/// Writes a blocked DNS response directly into `out` and returns the rcode string.
pub(crate) fn write_blocked_wire_response(
    raw_query: &[u8],
    q: &FastQuery,
    mode: BlockMode,
    attach_ede: bool,
    out: &mut Vec<u8>,
) -> &'static str {
    let (rcode_byte, rcode_str, add_zero_ip) = match mode {
        BlockMode::NxDomain => (3_u8, "NXDOMAIN", false),
        BlockMode::NoData => (0_u8, "NOERROR", false),
        BlockMode::ZeroIp => match q.qtype {
            1 | 28 => (0_u8, "NOERROR", true),
            _ => (3_u8, "NXDOMAIN", false),
        },
    };
    let answer_count = u16::from(add_zero_ip);
    let has_ede = attach_ede && q.has_edns;
    let additional_count = u16::from(has_ede);

    write_header(
        out,
        q.tx_id,
        q.rd,
        rcode_byte,
        answer_count,
        additional_count,
    );
    out.extend_from_slice(&raw_query[12..q.question_end]);

    if add_zero_ip {
        // Pointer to QNAME at offset 12 (0xC00C).
        out.extend_from_slice(&[0xC0, 0x0C]);
        out.extend_from_slice(&q.qtype.to_be_bytes());
        out.extend_from_slice(&q.qclass.to_be_bytes());
        out.extend_from_slice(&DEFAULT_BLOCK_TTL_BYTES);
        if q.qtype == 1 {
            out.extend_from_slice(&4_u16.to_be_bytes());
            out.extend_from_slice(&[0, 0, 0, 0]);
        } else {
            out.extend_from_slice(&16_u16.to_be_bytes());
            out.extend_from_slice(&[0; 16]);
        }
    }

    if has_ede {
        append_ede_opt(out, EDE_BLOCKED, BLOCKED_EDE_TEXT);
    }

    rcode_str
}

fn append_ede_opt(out: &mut Vec<u8>, info_code: u16, extra_text: &[u8]) {
    let opt_len = u16::try_from(2 + extra_text.len()).unwrap_or(2);
    let rdlen = 4 + opt_len;
    out.push(0x00); // Root name
    out.extend_from_slice(&OPT_RECORD_TYPE.to_be_bytes());
    out.extend_from_slice(&1232_u16.to_be_bytes()); // UDP payload size
    out.extend_from_slice(&[0, 0, 0, 0]); // Extended RCODE & flags
    out.extend_from_slice(&rdlen.to_be_bytes());
    out.extend_from_slice(&EDE_OPTION_CODE.to_be_bytes());
    out.extend_from_slice(&opt_len.to_be_bytes());
    out.extend_from_slice(&info_code.to_be_bytes());
    out.extend_from_slice(extra_text);
}

/// Truncates a wire response with `TC=1` when it exceeds `max_udp` (or `force_tc` is set),
/// preserving only Header + Question when truncation occurs.
#[inline]
pub(crate) fn apply_udp_tc_in_place(out: &mut Vec<u8>, max_udp: usize, force_tc: bool) {
    if !force_tc && out.len() <= max_udp {
        return;
    }
    if out.len() < 12 {
        return;
    }
    // Set TC=1 (bit 1 of flags0) and clear answer/authority/additional counts.
    out[2] |= 0x02;
    let qdcount = u16::from_be_bytes([out[4], out[5]]);
    out[6..12].fill(0);
    if qdcount == 0 {
        out.truncate(12);
        return;
    }
    let mut pos = 12_usize;
    for _ in 0..qdcount {
        let Some(next) = skip_name_simple(out, pos) else {
            out.truncate(12);
            return;
        };
        pos = next + 4;
        if pos > out.len() {
            out.truncate(12);
            return;
        }
    }
    out.truncate(pos);
}

fn skip_name_simple(wire: &[u8], start: usize) -> Option<usize> {
    let mut pos = start;
    for _ in 0..128 {
        let len_byte = *wire.get(pos)?;
        if len_byte == 0 {
            return Some(pos + 1);
        }
        match len_byte & 0xC0 {
            0xC0 => return (pos + 2 <= wire.len()).then_some(pos + 2),
            0x00 => {
                pos = pos.checked_add(1 + usize::from(len_byte))?;
                if pos > wire.len() {
                    return None;
                }
            }
            _ => return None,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::{Name, RData, RecordType};

    use super::*;

    #[test]
    fn test_parse_fast_query_and_blocked_wire_roundtrip() {
        let mut msg = Message::new(0x4242, MessageType::Query, OpCode::Query);
        msg.metadata.recursion_desired = true;
        msg.add_query(Query::query(
            Name::from_ascii("Ads.Example.COM.").unwrap(),
            RecordType::A,
        ));
        let mut edns = Edns::new();
        edns.set_max_payload(1232);
        msg.edns = Some(edns);
        let raw = msg.to_vec().unwrap();

        let fq = parse_fast_query(&raw).expect("standard EDNS query should parse");
        assert_eq!(fq.tx_id, 0x4242);
        assert!(fq.rd);
        assert_eq!(fq.clean_domain(), "ads.example.com");
        assert_eq!(fq.qname_fqdn(), "ads.example.com.");
        assert_eq!(fq.qtype, 1);
        assert!(fq.has_edns);
        assert_eq!(fq.edns_udp_payload, 1232);

        let mut out = Vec::new();
        let rcode = write_blocked_wire_response(&raw, &fq, BlockMode::ZeroIp, true, &mut out);
        assert_eq!(rcode, "NOERROR");

        let parsed = Message::from_vec(&out).expect("fast blocked response must be valid wire");
        assert_eq!(parsed.id, 0x4242);
        assert_eq!(parsed.response_code, ResponseCode::NoError);
        assert_eq!(parsed.answers.len(), 1);
        assert!(matches!(parsed.answers[0].data, RData::A(_)));
        assert!(parsed.edns.is_some());

        apply_udp_tc_in_place(&mut out, 20, false);
        let truncated = Message::from_vec(&out).expect("truncated response must be valid wire");
        assert!(truncated.truncation);
        assert_eq!(truncated.answers.len(), 0);
        assert_eq!(truncated.queries.len(), 1);
    }
}
