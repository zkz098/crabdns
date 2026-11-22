use hickory_proto::op::Message;
use hickory_proto::rr::rdata::HTTPS;
use hickory_proto::rr::rdata::svcb::{SVCB, SvcParamKey};
use hickory_proto::rr::{RData, Record, RecordType};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SvcbSanitizeOptions {
    pub strip_ech: bool,
    pub strip_hints: bool,
}

impl SvcbSanitizeOptions {
    pub const fn is_active(self) -> bool {
        self.strip_ech || self.strip_hints
    }
}

fn should_strip_param(key: SvcParamKey, opts: SvcbSanitizeOptions) -> bool {
    (opts.strip_ech && matches!(key, SvcParamKey::EchConfigList))
        || (opts.strip_hints && matches!(key, SvcParamKey::Ipv4Hint | SvcParamKey::Ipv6Hint))
}

fn sanitize_svcb_inner(svcb: &SVCB, opts: SvcbSanitizeOptions) -> Option<SVCB> {
    let orig_len = svcb.svc_params.len();
    let filtered: Vec<_> = svcb
        .svc_params
        .iter()
        .filter(|(key, _)| !should_strip_param(*key, opts))
        .cloned()
        .collect();
    if filtered.len() == orig_len {
        return None;
    }
    Some(SVCB::new(
        svcb.svc_priority,
        svcb.target_name.clone(),
        filtered,
    ))
}

fn sanitize_record_slice(records: &mut Vec<Record>, opts: SvcbSanitizeOptions) -> bool {
    let mut changed = false;
    for rec in records.iter_mut() {
        match &rec.data {
            RData::SVCB(svcb) => {
                if let Some(next) = sanitize_svcb_inner(svcb, opts) {
                    rec.data = RData::SVCB(next);
                    changed = true;
                }
            }
            RData::HTTPS(https) => {
                if let Some(next) = sanitize_svcb_inner(&https.0, opts) {
                    rec.data = RData::HTTPS(HTTPS(next));
                    changed = true;
                }
            }
            _ => {}
        }
    }
    if changed {
        records.retain(|rec| rec.record_type() != RecordType::RRSIG);
    }
    changed
}

/// Sanitizes `HTTPS` and `SVCB` records in `msg`, returning `true` if any record was modified.
pub fn sanitize_svcb_message(msg: &mut Message, opts: SvcbSanitizeOptions) -> bool {
    if !opts.is_active() {
        return false;
    }
    let ans_changed = sanitize_record_slice(&mut msg.answers, opts);
    let add_changed = sanitize_record_slice(&mut msg.additionals, opts);
    ans_changed || add_changed
}

/// Parses and sanitizes `HTTPS`/`SVCB` records in raw DNS wire bytes if needed.
/// Returns `Some(updated_bytes)` only when at least one record was modified.
pub fn sanitize_svcb_bytes(bytes: &[u8], opts: SvcbSanitizeOptions) -> Option<Vec<u8>> {
    if !opts.is_active() {
        return None;
    }
    let mut msg = Message::from_vec(bytes).ok()?;
    if !sanitize_svcb_message(&mut msg, opts) {
        return None;
    }
    msg.to_vec().ok()
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use hickory_proto::op::{MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::Name;
    use hickory_proto::rr::rdata::svcb::{Alpn, EchConfigList, IpHint, SvcParamValue};

    use super::*;
    use crate::wire::base_response;

    #[test]
    fn test_sanitize_https_ech_and_hints() {
        let name = Name::from_ascii("example.com.").unwrap();
        let mut req = Message::new(7, MessageType::Query, OpCode::Query);
        req.add_query(Query::query(name.clone(), RecordType::HTTPS));

        let params = vec![
            (
                SvcParamKey::Alpn,
                SvcParamValue::Alpn(Alpn(vec!["h2".to_string()])),
            ),
            (
                SvcParamKey::Ipv4Hint,
                SvcParamValue::Ipv4Hint(IpHint(vec![Ipv4Addr::new(1, 2, 3, 4).into()])),
            ),
            (
                SvcParamKey::EchConfigList,
                SvcParamValue::EchConfigList(EchConfigList(vec![1, 2, 3])),
            ),
            (
                SvcParamKey::Ipv6Hint,
                SvcParamValue::Ipv6Hint(IpHint(vec![Ipv6Addr::LOCALHOST.into()])),
            ),
        ];
        let mut resp = base_response(&req, ResponseCode::NoError);
        resp.add_answer(Record::from_rdata(
            name,
            300,
            RData::HTTPS(HTTPS(SVCB::new(1, Name::root(), params))),
        ));
        let raw = resp.to_vec().unwrap();

        let only_ech = sanitize_svcb_bytes(
            &raw,
            SvcbSanitizeOptions {
                strip_ech: true,
                strip_hints: false,
            },
        )
        .unwrap();
        let parsed_ech = Message::from_vec(&only_ech).unwrap();
        let RData::HTTPS(https) = &parsed_ech.answers[0].data else {
            panic!("expected HTTPS");
        };
        assert_eq!(https.0.svc_params.len(), 3);
        assert!(
            !https
                .0
                .svc_params
                .iter()
                .any(|(k, _)| *k == SvcParamKey::EchConfigList)
        );

        let both = sanitize_svcb_bytes(
            &raw,
            SvcbSanitizeOptions {
                strip_ech: true,
                strip_hints: true,
            },
        )
        .unwrap();
        let parsed_both = Message::from_vec(&both).unwrap();
        let RData::HTTPS(https2) = &parsed_both.answers[0].data else {
            panic!("expected HTTPS");
        };
        assert_eq!(https2.0.svc_params.len(), 1);
        assert_eq!(https2.0.svc_params[0].0, SvcParamKey::Alpn);
    }
}
