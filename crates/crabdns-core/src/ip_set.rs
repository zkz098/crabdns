use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use hickory_proto::op::Message;
use hickory_proto::rr::RData;
use hickory_proto::rr::rdata::svcb::{SVCB, SvcParamValue};

use crate::error::{CoreError, Result};

trait IpInt: Copy + Ord {
    fn saturating_add_one(self) -> Option<Self>;
    fn saturating_sub_one(self) -> Option<Self>;
}

impl IpInt for u32 {
    fn saturating_add_one(self) -> Option<Self> {
        self.checked_add(1)
    }

    fn saturating_sub_one(self) -> Option<Self> {
        self.checked_sub(1)
    }
}

impl IpInt for u128 {
    fn saturating_add_one(self) -> Option<Self> {
        self.checked_add(1)
    }

    fn saturating_sub_one(self) -> Option<Self> {
        self.checked_sub(1)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IpSet {
    v4: Box<[(u32, u32)]>,
    v6: Box<[(u128, u128)]>,
}

impl IpSet {
    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                contains_range(&self.v4, &u32::from(v4))
                    || contains_range(&self.v6, &u128::from(v4.to_ipv6_mapped()))
            }
            IpAddr::V6(v6) => {
                contains_range(&self.v6, &u128::from(v6))
                    || v6
                        .to_ipv4_mapped()
                        .is_some_and(|v4| contains_range(&self.v4, &u32::from(v4)))
            }
        }
    }
}

fn contains_range<T: Ord>(ranges: &[(T, T)], val: &T) -> bool {
    let idx = ranges.partition_point(|(start, _)| start <= val);
    idx > 0 && *val <= ranges[idx - 1].1
}

#[derive(Debug, Default)]
pub struct IpSetBuilder {
    pos_v4: Vec<(u32, u32)>,
    neg_v4: Vec<(u32, u32)>,
    pos_v6: Vec<(u128, u128)>,
    neg_v6: Vec<(u128, u128)>,
}

#[derive(Clone, Copy)]
enum ParsedCidrRange {
    V4(u32, u32),
    V6(u128, u128),
}

impl IpSetBuilder {
    pub fn insert_cidr(&mut self, raw: &str) -> Result<()> {
        let trimmed = raw.trim();
        let (is_neg, body) = if let Some(rest) = trimmed.strip_prefix('!') {
            (true, rest.trim())
        } else if let Some(rest) = trimmed.strip_prefix('-') {
            (true, rest.trim())
        } else {
            (false, trimmed)
        };
        let range = parse_cidr_range(body)?;
        self.push_range(range, is_neg);
        Ok(())
    }

    pub fn insert_text(&mut self, content: &str) {
        for raw_line in content.lines() {
            let line = strip_comment(raw_line).trim();
            if line.is_empty() {
                continue;
            }
            let (is_neg, body) = if let Some(rest) = line.strip_prefix('!') {
                (true, rest.trim())
            } else if let Some(rest) = line.strip_prefix('-') {
                (true, rest.trim())
            } else {
                (false, line)
            };
            let Some(cidr_token) = extract_cidr_token(body) else {
                continue;
            };
            if let Ok(range) = parse_cidr_range(cidr_token) {
                self.push_range(range, is_neg);
            }
        }
    }

    fn push_range(&mut self, range: ParsedCidrRange, is_neg: bool) {
        match range {
            ParsedCidrRange::V4(s, e) => {
                if is_neg {
                    self.neg_v4.push((s, e));
                } else {
                    self.pos_v4.push((s, e));
                }
            }
            ParsedCidrRange::V6(s, e) => {
                if is_neg {
                    self.neg_v6.push((s, e));
                } else {
                    self.pos_v6.push((s, e));
                }
            }
        }
    }

    pub fn build(self) -> IpSet {
        let v4 = subtract_ranges(coalesce_ranges(self.pos_v4), &coalesce_ranges(self.neg_v4));
        let v6 = subtract_ranges(coalesce_ranges(self.pos_v6), &coalesce_ranges(self.neg_v6));
        IpSet {
            v4: v4.into_boxed_slice(),
            v6: v6.into_boxed_slice(),
        }
    }
}

fn strip_comment(line: &str) -> &str {
    let mut end = line.len();
    for marker in ["#", "//", ";"] {
        if let Some(idx) = line.find(marker) {
            end = end.min(idx);
        }
    }
    &line[..end]
}

fn extract_cidr_token(body: &str) -> Option<&str> {
    let lower_prefix = body.get(..8).map(str::to_ascii_lowercase);
    if let Some(ref p) = lower_prefix
        && (p.starts_with("ip-cidr,") || p.starts_with("ip-cidr6"))
    {
        let (_, rest) = body.split_once(',')?;
        let token = rest.split(',').next()?.trim();
        return (!token.is_empty()).then_some(token);
    }
    let token = body.split_whitespace().next()?.trim();
    (!token.is_empty()).then_some(token)
}

fn parse_cidr_range(raw: &str) -> Result<ParsedCidrRange> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(CoreError::Config("empty CIDR entry".to_string()));
    }
    let (ip, prefix_opt) = if let Some((ip_str, prefix_str)) = trimmed.split_once('/') {
        let ip: IpAddr = ip_str
            .trim()
            .parse()
            .map_err(|_| CoreError::Config(format!("invalid CIDR IP: {trimmed}")))?;
        let prefix: u8 = prefix_str
            .trim()
            .parse()
            .map_err(|_| CoreError::Config(format!("invalid CIDR prefix: {trimmed}")))?;
        (ip, Some(prefix))
    } else {
        let ip: IpAddr = trimmed
            .parse()
            .map_err(|_| CoreError::Config(format!("invalid IP/CIDR: {trimmed}")))?;
        (ip, None)
    };

    match ip {
        IpAddr::V4(v4) => parse_v4_range(v4, prefix_opt.unwrap_or(32), trimmed),
        IpAddr::V6(v6) => parse_v6_range(v6, prefix_opt.unwrap_or(128), trimmed),
    }
}

fn parse_v4_range(v4: Ipv4Addr, prefix: u8, raw: &str) -> Result<ParsedCidrRange> {
    if prefix > 32 {
        return Err(CoreError::Config(format!("invalid IPv4 prefix: {raw}")));
    }
    let mask = if prefix == 0 {
        0_u32
    } else {
        !0_u32 << (32 - u32::from(prefix))
    };
    let start = u32::from(v4) & mask;
    let end = start | !mask;
    Ok(ParsedCidrRange::V4(start, end))
}

fn parse_v6_range(v6: Ipv6Addr, prefix: u8, raw: &str) -> Result<ParsedCidrRange> {
    if prefix > 128 {
        return Err(CoreError::Config(format!("invalid IPv6 prefix: {raw}")));
    }
    let mask = if prefix == 0 {
        0_u128
    } else {
        !0_u128 << (128 - u32::from(prefix))
    };
    let start = u128::from(v6) & mask;
    let end = start | !mask;
    Ok(ParsedCidrRange::V6(start, end))
}

fn coalesce_ranges<T: IpInt>(mut ranges: Vec<(T, T)>) -> Vec<(T, T)> {
    if ranges.is_empty() {
        return ranges;
    }
    ranges.sort_unstable();
    let mut merged = Vec::with_capacity(ranges.len());
    let mut cur = ranges[0];
    for &(s, e) in &ranges[1..] {
        let adjacent = cur.1.saturating_add_one().is_some_and(|next| s <= next);
        if s <= cur.1 || adjacent {
            if e > cur.1 {
                cur.1 = e;
            }
        } else {
            merged.push(cur);
            cur = (s, e);
        }
    }
    merged.push(cur);
    merged
}

fn subtract_ranges<T: IpInt>(pos: Vec<(T, T)>, neg: &[(T, T)]) -> Vec<(T, T)> {
    if pos.is_empty() || neg.is_empty() {
        return pos;
    }
    let mut out = Vec::with_capacity(pos.len());
    let mut ni = 0_usize;
    for (mut ps, pe) in pos {
        while ni < neg.len() && neg[ni].1 < ps {
            ni += 1;
        }
        let mut idx = ni;
        while idx < neg.len() && neg[idx].0 <= pe {
            let (ns, ne) = neg[idx];
            if ns > ps
                && let Some(left_end) = ns.saturating_sub_one()
            {
                out.push((ps, left_end.min(pe)));
            }
            if ne >= pe {
                ps = pe;
                break;
            }
            let Some(next_start) = ne.saturating_add_one() else {
                ps = pe;
                break;
            };
            ps = ps.max(next_start);
            idx += 1;
        }
        if ps < pe || (ps == pe && !contains_range(neg, &ps)) {
            out.push((ps, pe));
        }
    }
    out
}

pub fn extract_response_ips(msg: &Message) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    for rec in &msg.answers {
        match &rec.data {
            RData::A(a) => ips.push(IpAddr::V4(a.0)),
            RData::AAAA(aaaa) => ips.push(IpAddr::V6(aaaa.0)),
            RData::HTTPS(https) => collect_svcb_ips(&https.0, &mut ips),
            RData::SVCB(svcb) => collect_svcb_ips(svcb, &mut ips),
            _ => {}
        }
    }
    ips
}

fn collect_svcb_ips(svcb: &SVCB, out: &mut Vec<IpAddr>) {
    for (_, val) in &svcb.svc_params {
        match val {
            SvcParamValue::Ipv4Hint(hint) => {
                for a in &hint.0 {
                    out.push(IpAddr::V4(a.0));
                }
            }
            SvcParamValue::Ipv6Hint(hint) => {
                for aaaa in &hint.0 {
                    out.push(IpAddr::V6(aaaa.0));
                }
            }
            _ => {}
        }
    }
}

pub fn extract_response_cnames(msg: &Message) -> Vec<String> {
    let mut out = Vec::new();
    for rec in &msg.answers {
        if let RData::CNAME(cname) = &rec.data {
            let clean = cname.to_utf8();
            let trimmed = clean.trim().trim_end_matches('.').to_ascii_lowercase();
            if !trimmed.is_empty() {
                out.push(trimmed);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use hickory_proto::op::{MessageType, OpCode, ResponseCode};
    use hickory_proto::rr::rdata::svcb::{IpHint, SvcParamKey};
    use hickory_proto::rr::rdata::{A, AAAA, CNAME, HTTPS};
    use hickory_proto::rr::{Name, Record};

    use super::*;

    #[test]
    fn test_ip_set_coalesce_and_exclude() {
        let mut builder = IpSetBuilder::default();
        builder.insert_cidr("192.168.0.0/25").unwrap();
        builder.insert_cidr("192.168.0.128/25").unwrap();
        builder.insert_cidr("!192.168.0.50/32").unwrap();
        builder.insert_cidr("2408:8000::/20").unwrap();
        builder.insert_cidr("-2408:8000::1/128").unwrap();
        let set = builder.build();

        assert_eq!(set.v4.len(), 2);
        assert!(set.contains("192.168.0.1".parse().unwrap()));
        assert!(!set.contains("192.168.0.50".parse().unwrap()));
        assert!(set.contains("192.168.0.200".parse().unwrap()));
        assert!(!set.contains("192.168.1.1".parse().unwrap()));

        assert!(set.contains("2408:8000::2".parse().unwrap()));
        assert!(!set.contains("2408:8000::1".parse().unwrap()));
    }

    #[test]
    fn test_ip_set_text_formats() {
        let mut builder = IpSetBuilder::default();
        builder.insert_text(
            "# comment\n\
             // another\n\
             1.0.1.0/24\n\
             IP-CIDR,223.5.5.0/24,no-resolve\n\
             IP-CIDR6,2400:3200::/32,no-resolve\n\
             DOMAIN-SUFFIX,qq.com\n\
             !1.0.1.5\n",
        );
        let set = builder.build();
        assert!(set.contains("1.0.1.1".parse().unwrap()));
        assert!(!set.contains("1.0.1.5".parse().unwrap()));
        assert!(set.contains("223.5.5.5".parse().unwrap()));
        assert!(set.contains("2400:3200::1".parse().unwrap()));
        assert!(!set.contains("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn test_extract_response_ips_and_cnames() {
        let mut msg = Message::new(1, MessageType::Response, OpCode::Query);
        msg.metadata.response_code = ResponseCode::NoError;
        let name = Name::from_ascii("www.example.com.").unwrap();
        msg.add_answer(Record::from_rdata(
            name.clone(),
            60,
            RData::CNAME(CNAME(Name::from_ascii("cdn.example.net.").unwrap())),
        ));
        msg.add_answer(Record::from_rdata(
            name.clone(),
            60,
            RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
        ));
        msg.add_answer(Record::from_rdata(
            name.clone(),
            60,
            RData::AAAA(AAAA("2400:3200::1".parse().unwrap())),
        ));
        let svcb = SVCB::new(
            1,
            Name::from_ascii(".").unwrap(),
            vec![(
                SvcParamKey::Ipv4Hint,
                SvcParamValue::Ipv4Hint(IpHint(vec![A(Ipv4Addr::new(5, 6, 7, 8))])),
            )],
        );
        msg.add_answer(Record::from_rdata(name, 60, RData::HTTPS(HTTPS(svcb))));

        let ips = extract_response_ips(&msg);
        assert_eq!(
            ips,
            vec![
                IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
                IpAddr::V6("2400:3200::1".parse().unwrap()),
                IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
            ]
        );
        let cnames = extract_response_cnames(&msg);
        assert_eq!(cnames, vec!["cdn.example.net"]);
    }
}
