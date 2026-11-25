use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use foldhash::fast::RandomState;
use hickory_proto::dnssec::rdata::{DNSKEY, DNSSECRData, DS, RRSIG};
use hickory_proto::dnssec::{TrustAnchors, Verifier};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use moka::sync::Cache;

use crate::dnssec_anchors::{DnssecNta, NtaList, parse_trust_anchors};
use crate::error::{CoreError, Result};
use crate::singleflight::{FlightRole, Singleflight, wait_follower};
use crate::upstream::{UpstreamPool, next_tx_id};

const ZONE_CACHE_CAPACITY: u64 = 4096;
const ZONE_CACHE_TTL: Duration = Duration::from_hours(1);
const MIN_ZONE_CACHE_TTL_SECS: u32 = 60;
const MAX_ZONE_CACHE_TTL_SECS: u32 = 3600;
const MIN_PLAUSIBLE_UNIX_SECS: u64 = 1_700_000_000;

#[derive(Debug, Clone)]
enum ZoneState {
    Secure(Vec<DNSKEY>),
    Insecure,
}

#[derive(Debug, Clone)]
struct ZoneCacheEntry {
    state: ZoneState,
    expires_at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationOutcome {
    Secure,
    Insecure,
    Bogus,
}

pub struct DnssecValidator {
    trust_anchors: ArcSwap<TrustAnchors>,
    ntas: ArcSwap<NtaList>,
    zone_cache: Cache<String, ZoneCacheEntry, RandomState>,
    zone_inflight: Arc<Singleflight<String, Option<Vec<DNSKEY>>>>,
    unsynced_clock_warned: AtomicBool,
}

impl Default for DnssecValidator {
    fn default() -> Self {
        Self::new(TrustAnchors::default())
    }
}

impl DnssecValidator {
    pub fn new(trust_anchors: TrustAnchors) -> Self {
        let zone_cache = Cache::builder()
            .max_capacity(ZONE_CACHE_CAPACITY)
            .time_to_live(ZONE_CACHE_TTL)
            .build_with_hasher(RandomState::default());
        Self {
            trust_anchors: ArcSwap::from_pointee(trust_anchors),
            ntas: ArcSwap::from_pointee(NtaList::default()),
            zone_cache,
            zone_inflight: Arc::new(Singleflight::new()),
            unsynced_clock_warned: AtomicBool::new(false),
        }
    }

    /// Atomically reloads root trust anchors and RFC 7646 Negative Trust Anchors,
    /// invalidating cached zone keys so changes take effect immediately.
    pub fn reload_anchors(&self, trust_anchor_lines: &[String], ntas: &[DnssecNta]) -> Result<()> {
        let parsed_anchors = parse_trust_anchors(trust_anchor_lines)?;
        let compiled_ntas = NtaList::compile(ntas)?;
        self.trust_anchors.store(Arc::new(parsed_anchors));
        self.ntas.store(Arc::new(compiled_ntas));
        self.zone_cache.invalidate_all();
        Ok(())
    }

    pub fn is_nta_covered(&self, domain: &str, now_unix_secs: i64) -> bool {
        self.ntas.load().is_covered(domain, now_unix_secs)
    }

    fn get_cached_zone(&self, zone: &str) -> Option<ZoneState> {
        let entry = self.zone_cache.get(zone)?;
        if Instant::now() < entry.expires_at {
            Some(entry.state)
        } else {
            self.zone_cache.invalidate(zone);
            None
        }
    }

    fn put_cached_zone(&self, zone: String, state: ZoneState, ttl_secs: u32) {
        let clamped = ttl_secs.clamp(MIN_ZONE_CACHE_TTL_SECS, MAX_ZONE_CACHE_TTL_SECS);
        self.zone_cache.insert(
            zone,
            ZoneCacheEntry {
                state,
                expires_at: Instant::now() + Duration::from_secs(u64::from(clamped)),
            },
        );
    }

    /// Validates an upstream DNS response and returns the (possibly stripped/AD-marked) wire bytes.
    pub async fn validate_and_process(
        &self,
        resp_bytes: &[u8],
        upstream: &UpstreamPool,
        client_wants_do: bool,
    ) -> Result<Vec<u8>> {
        let mut msg = Message::from_vec(resp_bytes)
            .map_err(|e| CoreError::Protocol(format!("invalid upstream DNS response: {e}")))?;

        let raw_unix_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        if raw_unix_secs < MIN_PLAUSIBLE_UNIX_SECS {
            if !self.unsynced_clock_warned.swap(true, Ordering::Relaxed) {
                tracing::warn!(
                    unix_secs = raw_unix_secs,
                    "system clock is before plausible epoch; bypassing DNSSEC time validation until NTP syncs"
                );
            }
            msg.metadata.authentic_data = false;
            if !client_wants_do {
                strip_dnssec_records(&mut msg);
            }
            return msg
                .to_vec()
                .map_err(|e| CoreError::Protocol(format!("failed to encode response: {e}")));
        }

        let now_secs = (raw_unix_secs & 0xFFFF_FFFF) as u32;
        let now_unix_i64 = i64::try_from(raw_unix_secs).unwrap_or(i64::MAX);
        let outcome = self
            .validate_message_at(&msg, upstream, now_secs, now_unix_i64)
            .await;

        match outcome {
            ValidationOutcome::Bogus => Err(CoreError::Protocol(
                "DNSSEC validation failed (bogus)".to_string(),
            )),
            ValidationOutcome::Secure => {
                msg.metadata.authentic_data = true;
                if !client_wants_do {
                    strip_dnssec_records(&mut msg);
                }
                msg.to_vec()
                    .map_err(|e| CoreError::Protocol(format!("failed to encode response: {e}")))
            }
            ValidationOutcome::Insecure => {
                msg.metadata.authentic_data = false;
                if !client_wants_do {
                    strip_dnssec_records(&mut msg);
                }
                msg.to_vec()
                    .map_err(|e| CoreError::Protocol(format!("failed to encode response: {e}")))
            }
        }
    }

    pub async fn validate_message(
        &self,
        msg: &Message,
        upstream: &UpstreamPool,
        now_secs: u32,
    ) -> ValidationOutcome {
        self.validate_message_at(msg, upstream, now_secs, i64::from(now_secs))
            .await
    }

    async fn validate_message_at(
        &self,
        msg: &Message,
        upstream: &UpstreamPool,
        now_secs: u32,
        now_unix_secs: i64,
    ) -> ValidationOutcome {
        if msg.response_code == ResponseCode::ServFail {
            return ValidationOutcome::Insecure;
        }

        // RFC 7646: bypass DNSSEC validation for zones covered by an active NTA.
        let ntas = self.ntas.load();
        if !ntas.is_empty()
            && let Some(q) = msg.queries.first()
            && ntas.is_covered(&q.name().to_ascii(), now_unix_secs)
        {
            return ValidationOutcome::Insecure;
        }

        let rrsigs = extract_rrsigs(&msg.answers);
        if rrsigs.is_empty() {
            return self.check_unsigned_response(msg, upstream, now_secs).await;
        }

        for (sig_record, rrsig) in rrsigs {
            let input = rrsig.input();
            let signer = normalize_zone(&input.signer_name.to_ascii());
            let Ok(keys) = self.resolve_zone_keys(&signer, upstream, now_secs).await else {
                return ValidationOutcome::Bogus;
            };
            let Some(keys) = keys else {
                return ValidationOutcome::Bogus;
            };
            let covered: Vec<&Record> = msg
                .answers
                .iter()
                .filter(|r| {
                    r.name == sig_record.name
                        && r.record_type() == input.type_covered
                        && r.dns_class == sig_record.dns_class
                })
                .collect();
            if covered.is_empty()
                || !verify_rrset_with_keys(
                    &sig_record.name,
                    sig_record.dns_class,
                    rrsig,
                    &covered,
                    &keys,
                    now_secs,
                )
            {
                return ValidationOutcome::Bogus;
            }
        }

        ValidationOutcome::Secure
    }

    async fn check_unsigned_response(
        &self,
        msg: &Message,
        upstream: &UpstreamPool,
        now_secs: u32,
    ) -> ValidationOutcome {
        let Some(q) = msg.queries.first() else {
            return ValidationOutcome::Insecure;
        };
        let target_zone = find_negative_zone_candidate(q.name(), &msg.authorities);
        match self
            .resolve_zone_keys(&target_zone, upstream, now_secs)
            .await
        {
            Ok(Some(keys)) => {
                if !msg.answers.is_empty() {
                    return ValidationOutcome::Bogus;
                }
                match crate::dnssec_nsec::validate_negative_response(
                    msg,
                    q.name(),
                    q.query_type(),
                    &keys,
                    now_secs,
                    verify_rrset_with_keys,
                ) {
                    crate::dnssec_nsec::NegativeOutcome::Secure => ValidationOutcome::Secure,
                    crate::dnssec_nsec::NegativeOutcome::Insecure => ValidationOutcome::Insecure,
                    crate::dnssec_nsec::NegativeOutcome::Bogus => ValidationOutcome::Bogus,
                }
            }
            Ok(None) => ValidationOutcome::Insecure,
            Err(_) => ValidationOutcome::Bogus,
        }
    }

    async fn resolve_zone_keys(
        &self,
        zone: &str,
        upstream: &UpstreamPool,
        now_secs: u32,
    ) -> Result<Option<Vec<DNSKEY>>> {
        if let Some(cached) = self.get_cached_zone(zone) {
            return Ok(match cached {
                ZoneState::Secure(keys) => Some(keys),
                ZoneState::Insecure => None,
            });
        }

        match self.zone_inflight.acquire(zone.to_string()) {
            FlightRole::Leader(guard) => {
                if let Some(cached) = self.get_cached_zone(zone) {
                    let res = match cached {
                        ZoneState::Secure(keys) => Some(keys),
                        ZoneState::Insecure => None,
                    };
                    guard.complete(Ok(res.clone()));
                    return Ok(res);
                }

                let res = self
                    .resolve_zone_keys_uncached(zone, upstream, now_secs)
                    .await;
                match &res {
                    Ok(val) => guard.complete(Ok(val.clone())),
                    Err(err) => guard.complete(Err(err.to_string())),
                }
                res
            }
            FlightRole::Follower(rx) => wait_follower(rx).await.map_err(CoreError::Protocol),
        }
    }

    async fn resolve_zone_keys_uncached(
        &self,
        zone: &str,
        upstream: &UpstreamPool,
        now_secs: u32,
    ) -> Result<Option<Vec<DNSKEY>>> {
        let chain = build_zone_chain(zone);
        let mut parent_keys = self.ensure_root_keys(upstream, now_secs).await?;

        for child in chain.into_iter().skip(1) {
            if let Some(cached) = self.get_cached_zone(&child) {
                match cached {
                    ZoneState::Secure(keys) => {
                        parent_keys = keys;
                        continue;
                    }
                    ZoneState::Insecure => {
                        self.put_cached_zone(
                            zone.to_string(),
                            ZoneState::Insecure,
                            MIN_ZONE_CACHE_TTL_SECS,
                        );
                        return Ok(None);
                    }
                }
            }

            let Some((child_keys, ttl)) = self
                .validate_child_zone(&child, &parent_keys, upstream, now_secs)
                .await?
            else {
                self.put_cached_zone(child, ZoneState::Insecure, MIN_ZONE_CACHE_TTL_SECS);
                self.put_cached_zone(
                    zone.to_string(),
                    ZoneState::Insecure,
                    MIN_ZONE_CACHE_TTL_SECS,
                );
                return Ok(None);
            };
            self.put_cached_zone(child, ZoneState::Secure(child_keys.clone()), ttl);
            parent_keys = child_keys;
        }

        Ok(Some(parent_keys))
    }

    async fn ensure_root_keys(
        &self,
        upstream: &UpstreamPool,
        now_secs: u32,
    ) -> Result<Vec<DNSKEY>> {
        if let Some(ZoneState::Secure(keys)) = self.get_cached_zone(".") {
            return Ok(keys);
        }
        let root_name = Name::root();
        let resp = query_upstream_dnssec(upstream, &root_name, RecordType::DNSKEY).await?;
        let keys = extract_dnskeys(&resp.answers, &root_name);
        if keys.is_empty() {
            return Err(CoreError::Protocol("missing root DNSKEY".to_string()));
        }

        let anchors = self.trust_anchors.load();
        let trusted_ksks: Vec<DNSKEY> = keys
            .iter()
            .filter(|k| anchors.contains(k.public_key()))
            .cloned()
            .collect();
        if trusted_ksks.is_empty() {
            return Err(CoreError::Protocol(
                "root DNSKEY does not match trust anchor".to_string(),
            ));
        }

        let key_records: Vec<&Record> = resp
            .answers
            .iter()
            .filter(|r| r.record_type() == RecordType::DNSKEY)
            .collect();
        if !verify_any_rrsig(
            &root_name,
            DNSClass::IN,
            &resp.answers,
            &key_records,
            &trusted_ksks,
            now_secs,
        ) {
            return Err(CoreError::Protocol(
                "root DNSKEY RRSIG verification failed".to_string(),
            ));
        }

        let ttl = key_records
            .iter()
            .map(|r| r.ttl)
            .min()
            .unwrap_or(MAX_ZONE_CACHE_TTL_SECS);
        self.put_cached_zone(".".to_string(), ZoneState::Secure(keys.clone()), ttl);
        Ok(keys)
    }

    async fn validate_child_zone(
        &self,
        child: &str,
        parent_keys: &[DNSKEY],
        upstream: &UpstreamPool,
        now_secs: u32,
    ) -> Result<Option<(Vec<DNSKEY>, u32)>> {
        let child_name = Name::from_ascii(child).map_err(|e| CoreError::Protocol(e.to_string()))?;
        let ds_resp = query_upstream_dnssec(upstream, &child_name, RecordType::DS).await?;
        let ds_list = extract_ds(&ds_resp.answers, &child_name);
        if ds_list.is_empty() {
            return Ok(None);
        }

        let ds_records: Vec<&Record> = ds_resp
            .answers
            .iter()
            .filter(|r| r.record_type() == RecordType::DS)
            .collect();
        if !verify_any_rrsig(
            &child_name,
            DNSClass::IN,
            &ds_resp.answers,
            &ds_records,
            parent_keys,
            now_secs,
        ) {
            return Err(CoreError::Protocol(format!(
                "DS RRSIG verification failed for {child}"
            )));
        }

        let key_resp = query_upstream_dnssec(upstream, &child_name, RecordType::DNSKEY).await?;
        let keys = extract_dnskeys(&key_resp.answers, &child_name);
        if keys.is_empty() {
            return Err(CoreError::Protocol(format!("missing DNSKEY for {child}")));
        }

        let ds_matched_keys: Vec<DNSKEY> = keys
            .iter()
            .filter(|k| {
                ds_list
                    .iter()
                    .any(|ds| ds.covers(&child_name, k).unwrap_or(false))
            })
            .cloned()
            .collect();
        if ds_matched_keys.is_empty() {
            return Err(CoreError::Protocol(format!(
                "no DNSKEY matches DS for {child}"
            )));
        }

        let key_records: Vec<&Record> = key_resp
            .answers
            .iter()
            .filter(|r| r.record_type() == RecordType::DNSKEY)
            .collect();
        if !verify_any_rrsig(
            &child_name,
            DNSClass::IN,
            &key_resp.answers,
            &key_records,
            &ds_matched_keys,
            now_secs,
        ) {
            return Err(CoreError::Protocol(format!(
                "DNSKEY RRSIG verification failed for {child}"
            )));
        }

        let ds_ttl = ds_records
            .iter()
            .map(|r| r.ttl)
            .min()
            .unwrap_or(MAX_ZONE_CACHE_TTL_SECS);
        let key_ttl = key_records
            .iter()
            .map(|r| r.ttl)
            .min()
            .unwrap_or(MAX_ZONE_CACHE_TTL_SECS);
        Ok(Some((keys, ds_ttl.min(key_ttl))))
    }
}

fn normalize_zone(raw: &str) -> String {
    let trimmed = raw.trim().to_ascii_lowercase();
    if trimmed.is_empty() || trimmed == "." {
        ".".to_string()
    } else if trimmed.ends_with('.') {
        trimmed
    } else {
        format!("{trimmed}.")
    }
}

fn build_zone_chain(zone: &str) -> Vec<String> {
    let norm = normalize_zone(zone);
    if norm == "." {
        return vec![".".to_string()];
    }
    let labels: Vec<&str> = norm.trim_end_matches('.').split('.').collect();
    let mut chain = Vec::with_capacity(labels.len() + 1);
    chain.push(".".to_string());
    for i in (0..labels.len()).rev() {
        let suffix = labels[i..].join(".");
        chain.push(format!("{suffix}."));
    }
    chain
}

async fn query_upstream_dnssec(
    upstream: &UpstreamPool,
    name: &Name,
    qtype: RecordType,
) -> Result<Message> {
    let tx_id = next_tx_id();
    let mut msg = Message::new(tx_id, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(name.clone(), qtype));
    crate::edns::set_dnssec_ok(&mut msg);
    let wire = msg
        .to_vec()
        .map_err(|e| CoreError::Protocol(e.to_string()))?;
    let (resp_bytes, _) = upstream.exchange(&wire).await?;
    let resp = Message::from_vec(&resp_bytes).map_err(|e| CoreError::Protocol(e.to_string()))?;
    if resp.id != tx_id {
        return Err(CoreError::Protocol(
            "DNSSEC auxiliary response transaction ID mismatch".to_string(),
        ));
    }
    Ok(resp)
}

fn find_negative_zone_candidate(qname: &Name, authorities: &[Record]) -> String {
    for (_, sig) in extract_rrsigs(authorities) {
        let signer = sig.input().signer_name.clone();
        if signer.zone_of(qname) {
            return normalize_zone(&signer.to_ascii());
        }
    }
    for rec in authorities {
        if rec.record_type() == RecordType::SOA && rec.name.zone_of(qname) {
            return normalize_zone(&rec.name.to_ascii());
        }
    }
    if !qname.is_root() {
        let parent = qname.base_name();
        return normalize_zone(&parent.to_ascii());
    }
    normalize_zone(&qname.to_ascii())
}

pub(crate) fn extract_rrsigs(records: &[Record]) -> Vec<(&Record, &RRSIG)> {
    records
        .iter()
        .filter_map(|r| match &r.data {
            RData::DNSSEC(DNSSECRData::RRSIG(sig)) => Some((r, sig)),
            _ => None,
        })
        .collect()
}

fn extract_dnskeys(records: &[Record], expected_name: &Name) -> Vec<DNSKEY> {
    records
        .iter()
        .filter(|r| &r.name == expected_name)
        .filter_map(|r| match &r.data {
            RData::DNSSEC(DNSSECRData::DNSKEY(k)) => Some(k.clone()),
            _ => None,
        })
        .collect()
}

fn extract_ds(records: &[Record], expected_name: &Name) -> Vec<DS> {
    records
        .iter()
        .filter(|r| &r.name == expected_name)
        .filter_map(|r| match &r.data {
            RData::DNSSEC(DNSSECRData::DS(ds)) => Some(ds.clone()),
            _ => None,
        })
        .collect()
}

fn verify_any_rrsig(
    name: &Name,
    dns_class: DNSClass,
    all_records: &[Record],
    covered_records: &[&Record],
    keys: &[DNSKEY],
    now_secs: u32,
) -> bool {
    if covered_records.is_empty() {
        return false;
    }
    let covered_type = covered_records[0].record_type();
    for (_, sig) in extract_rrsigs(all_records) {
        if sig.input().type_covered == covered_type
            && verify_rrset_with_keys(name, dns_class, sig, covered_records, keys, now_secs)
        {
            return true;
        }
    }
    false
}

pub(crate) fn verify_rrset_with_keys(
    name: &Name,
    dns_class: DNSClass,
    sig: &RRSIG,
    covered_records: &[&Record],
    keys: &[DNSKEY],
    now_secs: u32,
) -> bool {
    let input = sig.input();
    let inception = input.sig_inception.get();
    let expiration = input.sig_expiration.get();
    // RFC 4034 Section 3.1.5 / RFC 1982 serial number arithmetic (handles post-2038 wraparound).
    let after_inception = now_secs.wrapping_sub(inception).cast_signed() >= 0;
    let before_expiration = expiration.wrapping_sub(now_secs).cast_signed() >= 0;
    if !after_inception || !before_expiration {
        return false;
    }
    for key in keys {
        let Ok(tag) = key.calculate_key_tag() else {
            continue;
        };
        if tag != input.key_tag || key.algorithm() != input.algorithm {
            continue;
        }
        if key
            .verify_rrsig(name, dns_class, sig, covered_records.iter().copied())
            .is_ok()
        {
            return true;
        }
    }
    false
}

pub(crate) fn strip_dnssec_records(msg: &mut Message) {
    let keep = |r: &Record| {
        !matches!(
            r.record_type(),
            RecordType::RRSIG | RecordType::NSEC | RecordType::NSEC3
        )
    };
    msg.answers.retain(keep);
    msg.authorities.retain(keep);
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::dnssec::crypto::Ed25519SigningKey;
    use hickory_proto::dnssec::rdata::DNSKEY;
    use hickory_proto::dnssec::{Algorithm, SigningKey, TBS};
    use hickory_proto::rr::SerialNumber;
    use hickory_proto::rr::rdata::A;
    use std::net::Ipv4Addr;

    #[test]
    fn test_build_zone_chain() {
        assert_eq!(build_zone_chain("."), vec!["."]);
        assert_eq!(
            build_zone_chain("sub.example.com"),
            vec![".", "com.", "example.com.", "sub.example.com."]
        );
    }

    #[test]
    fn test_sign_and_verify_rrset_roundtrip() {
        use hickory_proto::dnssec::rdata::sig::SigInput;

        let pkcs8 = Ed25519SigningKey::generate_pkcs8().unwrap();
        let signing_key = Ed25519SigningKey::from_pkcs8(&pkcs8).unwrap();
        let pub_key = signing_key.to_public_key().unwrap();
        let dnskey = DNSKEY::new(true, true, false, pub_key);
        let key_tag = dnskey.calculate_key_tag().unwrap();

        let owner = Name::from_ascii("www.example.com.").unwrap();
        let signer_name = Name::from_ascii("example.com.").unwrap();
        let a_rec = Record::from_rdata(
            owner.clone(),
            300,
            RData::A(A(Ipv4Addr::new(93, 184, 216, 34))),
        );
        let records = [&a_rec];

        let sig_input = SigInput {
            type_covered: RecordType::A,
            algorithm: Algorithm::ED25519,
            num_labels: 3,
            original_ttl: 300,
            sig_expiration: SerialNumber::new(2_000_000_000),
            sig_inception: SerialNumber::new(1_000_000_000),
            key_tag,
            signer_name,
        };
        let tbs =
            TBS::from_input(&owner, DNSClass::IN, &sig_input, records.iter().copied()).unwrap();
        let sig_bytes = signing_key.sign(&tbs).unwrap();
        let rrsig = RRSIG::from_sig(sig_input, sig_bytes);

        // Valid within window
        assert!(verify_rrset_with_keys(
            &owner,
            DNSClass::IN,
            &rrsig,
            &records,
            std::slice::from_ref(&dnskey),
            1_500_000_000,
        ));

        // Expired
        assert!(!verify_rrset_with_keys(
            &owner,
            DNSClass::IN,
            &rrsig,
            &records,
            std::slice::from_ref(&dnskey),
            2_100_000_000,
        ));

        // Tampered record
        let tampered_rec =
            Record::from_rdata(owner.clone(), 300, RData::A(A(Ipv4Addr::new(1, 2, 3, 4))));
        assert!(!verify_rrset_with_keys(
            &owner,
            DNSClass::IN,
            &rrsig,
            &[&tampered_rec],
            &[dnskey],
            1_500_000_000,
        ));
    }

    #[tokio::test]
    async fn test_nta_bypasses_validation_until_expiry() {
        let validator = DnssecValidator::default();
        validator
            .reload_anchors(
                &[],
                &[DnssecNta {
                    domain: "broken.example".to_string(),
                    expires_at_unix_secs: Some(1_900_000_000),
                    reason: "signing outage".to_string(),
                }],
            )
            .expect("reload nta");

        let mut msg = Message::new(0x1234, MessageType::Response, OpCode::Query);
        let qname = Name::from_ascii("www.broken.example.").unwrap();
        msg.add_query(Query::query(qname.clone(), RecordType::A));
        msg.add_answer(Record::from_rdata(
            qname,
            60,
            RData::A(A(Ipv4Addr::new(93, 184, 216, 34))),
        ));

        // Dead upstream ensures validation would fail (Bogus) if NTA did not short-circuit.
        let dead_upstream = UpstreamPool::new(&["udp://127.0.0.1:1".to_string()], 50).unwrap();
        assert_eq!(
            validator
                .validate_message_at(&msg, &dead_upstream, 1_800_000_000, 1_800_000_000)
                .await,
            ValidationOutcome::Insecure
        );
        // Once expired, NTA no longer bypasses and dead upstream yields Bogus.
        assert_eq!(
            validator
                .validate_message_at(&msg, &dead_upstream, 1_950_000_000, 1_950_000_000)
                .await,
            ValidationOutcome::Bogus
        );
    }
}
