use std::cmp::Ordering;

use aws_lc_rs::digest::{Context, SHA1_FOR_LEGACY_USE_ONLY};
use hickory_proto::dnssec::rdata::{DNSKEY, DNSSECRData, NSEC, NSEC3, RRSIG};
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};

const MAX_NSEC3_ITERATIONS: u16 = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NegativeOutcome {
    Secure,
    Insecure,
    Bogus,
}

type VerifyRrsetFn = fn(&Name, DNSClass, &RRSIG, &[&Record], &[DNSKEY], u32) -> bool;

/// Validates an unsigned/negative DNS response (`NXDOMAIN` or `NODATA`) from a signed zone
/// using `NSEC` or `NSEC3` records in the Authority section (RFC 4035 / RFC 5155).
pub(crate) fn validate_negative_response(
    msg: &Message,
    qname: &Name,
    qtype: RecordType,
    keys: &[DNSKEY],
    now_secs: u32,
    verify_rrset: VerifyRrsetFn,
) -> NegativeOutcome {
    if !matches!(
        msg.response_code,
        ResponseCode::NoError | ResponseCode::NXDomain
    ) {
        return NegativeOutcome::Insecure;
    }

    if !verify_authority_rrsigs(&msg.authorities, keys, now_secs, verify_rrset) {
        return NegativeOutcome::Bogus;
    }

    let nsec_records = collect_nsecs(&msg.authorities);
    let hashed_denials = collect_nsec3s(&msg.authorities);

    if nsec_records.is_empty() && hashed_denials.is_empty() {
        return NegativeOutcome::Bogus;
    }

    if !nsec_records.is_empty() {
        return if validate_nsec_negative(msg.response_code, qname, qtype, &nsec_records) {
            NegativeOutcome::Secure
        } else {
            NegativeOutcome::Bogus
        };
    }

    validate_nsec3_negative(msg.response_code, qname, qtype, &hashed_denials)
}

fn verify_authority_rrsigs(
    authorities: &[Record],
    keys: &[DNSKEY],
    now_secs: u32,
    verify_rrset: VerifyRrsetFn,
) -> bool {
    let rrsigs: Vec<(&Record, &RRSIG)> = authorities
        .iter()
        .filter_map(|r| match &r.data {
            RData::DNSSEC(DNSSECRData::RRSIG(sig)) => Some((r, sig)),
            _ => None,
        })
        .collect();
    if rrsigs.is_empty() {
        return false;
    }

    for (sig_record, rrsig) in rrsigs {
        let input = rrsig.input();
        let covered: Vec<&Record> = authorities
            .iter()
            .filter(|r| {
                r.name == sig_record.name
                    && r.record_type() == input.type_covered
                    && r.dns_class == sig_record.dns_class
            })
            .collect();
        if covered.is_empty()
            || !verify_rrset(
                &sig_record.name,
                sig_record.dns_class,
                rrsig,
                &covered,
                keys,
                now_secs,
            )
        {
            return false;
        }
    }
    true
}

fn collect_nsecs(records: &[Record]) -> Vec<(&Name, &NSEC)> {
    records
        .iter()
        .filter_map(|r| match &r.data {
            RData::DNSSEC(DNSSECRData::NSEC(nsec)) => Some((&r.name, nsec)),
            _ => None,
        })
        .collect()
}

fn collect_nsec3s(records: &[Record]) -> Vec<(&Name, &NSEC3)> {
    records
        .iter()
        .filter_map(|r| match &r.data {
            RData::DNSSEC(DNSSECRData::NSEC3(nsec3)) => Some((&r.name, nsec3)),
            _ => None,
        })
        .collect()
}

/// Canonical DNS name comparison (RFC 4034 Section 6.1): compare labels right-to-left,
/// case-insensitively.
fn cmp_canonical_name(a: &Name, b: &Name) -> Ordering {
    let a_labels: Vec<Vec<u8>> = a.iter().map(<[u8]>::to_ascii_lowercase).collect();
    let b_labels: Vec<Vec<u8>> = b.iter().map(<[u8]>::to_ascii_lowercase).collect();
    let mut ai = a_labels.len();
    let mut bi = b_labels.len();
    while ai > 0 && bi > 0 {
        ai -= 1;
        bi -= 1;
        let ord = a_labels[ai].cmp(&b_labels[bi]);
        if ord != Ordering::Equal {
            return ord;
        }
    }
    a_labels.len().cmp(&b_labels.len())
}

fn nsec_covers(owner: &Name, next: &Name, target: &Name) -> bool {
    let cmp_owner_next = cmp_canonical_name(owner, next);
    let cmp_owner_target = cmp_canonical_name(owner, target);
    let cmp_target_next = cmp_canonical_name(target, next);

    match cmp_owner_next {
        Ordering::Less => cmp_owner_target == Ordering::Less && cmp_target_next == Ordering::Less,
        Ordering::Greater => {
            // Wrap-around at the end of the zone.
            cmp_owner_target == Ordering::Less || cmp_target_next == Ordering::Less
        }
        Ordering::Equal => {
            // Single-NSEC zone (e.g., only apex exists): covers everything except owner itself.
            cmp_owner_target != Ordering::Equal
        }
    }
}

fn validate_nsec_negative(
    rcode: ResponseCode,
    qname: &Name,
    qtype: RecordType,
    nsecs: &[(&Name, &NSEC)],
) -> bool {
    if rcode == ResponseCode::NoError {
        if let Some((_, nsec)) = nsecs
            .iter()
            .find(|(owner, _)| cmp_canonical_name(owner, qname) == Ordering::Equal)
        {
            return !nsec
                .type_bit_maps()
                .any(|t| t == qtype || t == RecordType::CNAME);
        }
        // Empty non-terminal or wildcard NODATA: qname is covered and wildcard has no qtype.
        let qname_covered = nsecs
            .iter()
            .any(|(owner, nsec)| nsec_covers(owner, nsec.next_domain_name(), qname));
        if !qname_covered {
            return false;
        }
        if let Some(wildcard) = wildcard_for_closest_encloser(qname, nsecs)
            && let Some((_, wc_nsec)) = nsecs
                .iter()
                .find(|(owner, _)| cmp_canonical_name(owner, &wildcard) == Ordering::Equal)
        {
            return !wc_nsec
                .type_bit_maps()
                .any(|t| t == qtype || t == RecordType::CNAME);
        }
        return false;
    }

    // NXDOMAIN: must prove qname does not exist AND wildcard at closest encloser does not exist.
    let qname_covered = nsecs
        .iter()
        .any(|(owner, nsec)| nsec_covers(owner, nsec.next_domain_name(), qname));
    if !qname_covered {
        return false;
    }
    let Some(wildcard) = wildcard_for_closest_encloser(qname, nsecs) else {
        return false;
    };
    nsecs
        .iter()
        .any(|(owner, nsec)| nsec_covers(owner, nsec.next_domain_name(), &wildcard))
}

fn wildcard_for_closest_encloser(qname: &Name, nsecs: &[(&Name, &NSEC)]) -> Option<Name> {
    let mut candidate = qname.clone();
    while !candidate.is_root() {
        candidate = candidate.base_name();
        let is_covered = nsecs
            .iter()
            .any(|(owner, nsec)| nsec_covers(owner, nsec.next_domain_name(), &candidate));
        if !is_covered {
            let star = Name::from_ascii("*").ok()?;
            return star.append_domain(&candidate).ok();
        }
    }
    None
}

fn validate_nsec3_negative(
    rcode: ResponseCode,
    qname: &Name,
    qtype: RecordType,
    nsec3s: &[(&Name, &NSEC3)],
) -> NegativeOutcome {
    let Some((_, first)) = nsec3s.first() else {
        return NegativeOutcome::Bogus;
    };
    if first.iterations() > MAX_NSEC3_ITERATIONS {
        return NegativeOutcome::Insecure;
    }
    let salt = first.salt();
    let iterations = first.iterations();

    let Some(qhash) = nsec3_hash(qname, salt, iterations) else {
        return NegativeOutcome::Bogus;
    };

    if rcode == ResponseCode::NoError {
        if let Some((_, nsec3)) = find_nsec3_exact(nsec3s, &qhash) {
            return if nsec3
                .type_bit_maps()
                .any(|t| t == qtype || t == RecordType::CNAME)
            {
                NegativeOutcome::Bogus
            } else {
                NegativeOutcome::Secure
            };
        }
        if qtype == RecordType::DS
            && find_nsec3_covering(nsec3s, &qhash).is_some_and(NSEC3::opt_out)
        {
            return NegativeOutcome::Insecure;
        }
        return NegativeOutcome::Bogus;
    }

    // NXDOMAIN: find closest encloser, prove next_closer is covered, and prove wildcard is covered.
    let Some((ce, next_closer)) = find_nsec3_closest_encloser(qname, salt, iterations, nsec3s)
    else {
        return NegativeOutcome::Bogus;
    };
    let Some(nc_hash) = nsec3_hash(&next_closer, salt, iterations) else {
        return NegativeOutcome::Bogus;
    };
    let Some(nc_cover) = find_nsec3_covering(nsec3s, &nc_hash) else {
        return NegativeOutcome::Bogus;
    };

    let Ok(star) = Name::from_ascii("*") else {
        return NegativeOutcome::Bogus;
    };
    let Ok(wildcard) = star.append_domain(&ce) else {
        return NegativeOutcome::Bogus;
    };
    let Some(wc_hash) = nsec3_hash(&wildcard, salt, iterations) else {
        return NegativeOutcome::Bogus;
    };
    let wc_covered = find_nsec3_covering(nsec3s, &wc_hash).is_some() || nc_cover.opt_out();
    if wc_covered {
        NegativeOutcome::Secure
    } else {
        NegativeOutcome::Bogus
    }
}

fn find_nsec3_closest_encloser(
    qname: &Name,
    salt: &[u8],
    iterations: u16,
    nsec3s: &[(&Name, &NSEC3)],
) -> Option<(Name, Name)> {
    let mut child = qname.clone();
    while !child.is_root() {
        let parent = child.base_name();
        let parent_hash = nsec3_hash(&parent, salt, iterations)?;
        if find_nsec3_exact(nsec3s, &parent_hash).is_some() {
            return Some((parent, child));
        }
        child = parent;
    }
    None
}

fn find_nsec3_exact<'a>(
    nsec3s: &[(&'a Name, &'a NSEC3)],
    target_hash: &[u8; 20],
) -> Option<(&'a Name, &'a NSEC3)> {
    for (owner, nsec3) in nsec3s {
        if let Some(owner_hash) = decode_nsec3_owner_hash(owner)
            && owner_hash == *target_hash
        {
            return Some((owner, nsec3));
        }
    }
    None
}

fn find_nsec3_covering<'a>(
    nsec3s: &[(&Name, &'a NSEC3)],
    target_hash: &[u8; 20],
) -> Option<&'a NSEC3> {
    for (owner, nsec3) in nsec3s {
        let Some(owner_hash) = decode_nsec3_owner_hash(owner) else {
            continue;
        };
        let next_hash = nsec3.next_hashed_owner_name();
        if next_hash.len() != 20 {
            continue;
        }
        let covers = match owner_hash.as_slice().cmp(next_hash) {
            Ordering::Less => {
                owner_hash.as_slice() < target_hash.as_slice() && target_hash.as_slice() < next_hash
            }
            Ordering::Greater => {
                owner_hash.as_slice() < target_hash.as_slice() || target_hash.as_slice() < next_hash
            }
            Ordering::Equal => owner_hash.as_slice() != target_hash.as_slice(),
        };
        if covers {
            return Some(nsec3);
        }
    }
    None
}

fn nsec3_hash(name: &Name, salt: &[u8], iterations: u16) -> Option<[u8; 20]> {
    let mut wire = Vec::with_capacity(256);
    for label in name {
        let len = u8::try_from(label.len()).ok()?;
        wire.push(len);
        for &b in label {
            wire.push(b.to_ascii_lowercase());
        }
    }
    wire.push(0);

    let mut digest = sha1_with_salt(&wire, salt);
    for _ in 0..iterations {
        digest = sha1_with_salt(&digest, salt);
    }
    Some(digest)
}

fn sha1_with_salt(data: &[u8], salt: &[u8]) -> [u8; 20] {
    let mut ctx = Context::new(&SHA1_FOR_LEGACY_USE_ONLY);
    ctx.update(data);
    ctx.update(salt);
    let out = ctx.finish();
    let mut buf = [0_u8; 20];
    buf.copy_from_slice(out.as_ref());
    buf
}

fn decode_nsec3_owner_hash(owner: &Name) -> Option<[u8; 20]> {
    let first_label = owner.iter().next()?;
    if first_label.len() != 32 {
        return None;
    }
    let mut out = [0_u8; 20];
    let mut acc: u32 = 0;
    let mut bits: u8 = 0;
    let mut idx = 0;
    for &b in first_label {
        let val = match b.to_ascii_uppercase() {
            b'0'..=b'9' => b - b'0',
            b'A'..=b'V' => b - b'A' + 10,
            _ => return None,
        };
        acc = (acc << 5) | u32::from(val);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out[idx] = ((acc >> bits) & 0xff) as u8;
            idx += 1;
        }
    }
    (idx == 20 && bits == 0).then_some(out)
}
