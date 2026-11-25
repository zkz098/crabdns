use std::path::Path;
use std::str::FromStr;

use hickory_proto::dnssec::TrustAnchors;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::error::{CoreError, Result};

/// RFC 7646 Negative Trust Anchor (NTA) entry that temporarily disables DNSSEC
/// validation for `domain` and all of its subdomains until `expires_at_unix_secs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct DnssecNta {
    pub domain: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(type = "number | null")]
    pub expires_at_unix_secs: Option<i64>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct NtaList {
    entries: Vec<CompiledNta>,
}

#[derive(Debug, Clone)]
struct CompiledNta {
    /// Lowercase FQDN with trailing dot (e.g. `broken.example.com.`).
    zone: String,
    expires_at_unix_secs: Option<i64>,
}

impl NtaList {
    pub(crate) fn compile(raw: &[DnssecNta]) -> Result<Self> {
        let mut entries = Vec::with_capacity(raw.len());
        for item in raw {
            let zone = normalize_nta_domain(&item.domain)?;
            entries.push(CompiledNta {
                zone,
                expires_at_unix_secs: item.expires_at_unix_secs,
            });
        }
        Ok(Self { entries })
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns true if `domain` (or any ancestor zone) is covered by a non-expired NTA.
    pub(crate) fn is_covered(&self, domain: &str, now_unix_secs: i64) -> bool {
        if self.entries.is_empty() {
            return false;
        }
        let norm = normalize_query_zone(domain);
        for entry in &self.entries {
            if let Some(exp) = entry.expires_at_unix_secs
                && now_unix_secs >= exp
            {
                continue;
            }
            if zone_covers(&entry.zone, &norm) {
                return true;
            }
        }
        false
    }
}

pub fn normalize_nta_entries(raw: &[DnssecNta]) -> Result<Vec<DnssecNta>> {
    let mut out = Vec::with_capacity(raw.len());
    for item in raw {
        let trimmed = item.domain.trim();
        if trimmed.is_empty() {
            continue;
        }
        let fqdn = normalize_nta_domain(trimmed)?;
        let clean = fqdn.trim_end_matches('.').to_string();
        out.push(DnssecNta {
            domain: clean,
            expires_at_unix_secs: item.expires_at_unix_secs,
            reason: item.reason.trim().to_string(),
        });
    }
    Ok(out)
}

fn normalize_nta_domain(raw: &str) -> Result<String> {
    let trimmed = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if trimmed.is_empty() {
        return Err(CoreError::Config(
            "DNSSEC NTA domain cannot be empty or root".to_string(),
        ));
    }
    if trimmed.len() > 253
        || trimmed.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
    {
        return Err(CoreError::Config(format!(
            "invalid DNSSEC NTA domain: '{raw}'"
        )));
    }
    Ok(format!("{trimmed}."))
}

fn normalize_query_zone(raw: &str) -> String {
    let trimmed = raw.trim().to_ascii_lowercase();
    if trimmed.is_empty() || trimmed == "." {
        ".".to_string()
    } else if trimmed.ends_with('.') {
        trimmed
    } else {
        format!("{trimmed}.")
    }
}

fn zone_covers(nta_zone: &str, query_zone: &str) -> bool {
    if nta_zone == "." {
        return true;
    }
    if query_zone == nta_zone {
        return true;
    }
    query_zone
        .strip_suffix(nta_zone)
        .is_some_and(|prefix| prefix.ends_with('.'))
}

/// Parses custom DNSSEC root trust anchor lines (standard BIND/IANA DNSKEY format).
/// When `lines` is empty, returns the built-in default IANA root trust anchors.
pub fn parse_trust_anchors(lines: &[String]) -> Result<TrustAnchors> {
    let joined: String = lines
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty() && !s.starts_with(';'))
        .collect::<Vec<_>>()
        .join("\n");
    if joined.is_empty() {
        return Ok(TrustAnchors::default());
    }
    let anchors = TrustAnchors::from_str(&joined)
        .map_err(|e| CoreError::Config(format!("invalid DNSSEC trust anchor: {e}")))?;
    if anchors.is_empty() {
        return Err(CoreError::Config(
            "custom dnssec_trust_anchors must contain at least one root DNSKEY".to_string(),
        ));
    }
    Ok(anchors)
}

/// Loads DNSSEC root trust anchors from a zone-format file (e.g. IANA `root.key`).
pub fn load_trust_anchors_from_file(path: &Path) -> Result<TrustAnchors> {
    let anchors = TrustAnchors::from_file(path).map_err(|e| {
        CoreError::Config(format!(
            "failed to load DNSSEC trust anchors from '{}': {e}",
            path.display()
        ))
    })?;
    if anchors.is_empty() {
        return Err(CoreError::Config(format!(
            "trust anchor file '{}' contains no root DNSKEY records",
            path.display()
        )));
    }
    Ok(anchors)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nta_matching_and_expiration() {
        let ntas = NtaList::compile(&[
            DnssecNta {
                domain: "Broken.Example.COM.".to_string(),
                expires_at_unix_secs: Some(2_000_000_000),
                reason: "upstream signing outage".to_string(),
            },
            DnssecNta {
                domain: "expired.test".to_string(),
                expires_at_unix_secs: Some(1_000_000_000),
                reason: String::new(),
            },
            DnssecNta {
                domain: "permanent.lan".to_string(),
                expires_at_unix_secs: None,
                reason: "split-horizon".to_string(),
            },
        ])
        .expect("compile ntas");

        assert!(ntas.is_covered("broken.example.com.", 1_800_000_000));
        assert!(ntas.is_covered("sub.broken.example.com.", 1_800_000_000));
        assert!(!ntas.is_covered("notbroken.example.com.", 1_800_000_000));
        assert!(!ntas.is_covered("broken.example.com.", 2_000_000_000));
        assert!(!ntas.is_covered("expired.test.", 1_800_000_000));
        assert!(ntas.is_covered("host.permanent.lan", 2_500_000_000));
    }

    #[test]
    fn test_nta_rejects_root_or_invalid() {
        assert!(
            NtaList::compile(&[DnssecNta {
                domain: ".".to_string(),
                expires_at_unix_secs: None,
                reason: String::new(),
            }])
            .is_err()
        );
        assert!(
            NtaList::compile(&[DnssecNta {
                domain: "bad domain!".to_string(),
                expires_at_unix_secs: None,
                reason: String::new(),
            }])
            .is_err()
        );
    }

    #[test]
    fn test_parse_trust_anchors_default_and_custom() {
        let def = parse_trust_anchors(&[]).expect("default anchors");
        assert!(!def.is_empty());

        // Real IANA Root KSK 20326 DNSKEY record format.
        let custom = parse_trust_anchors(&[
            ". 172800 IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=".to_string(),
        ])
        .expect("custom root anchor");
        assert_eq!(custom.len(), 1);

        assert!(parse_trust_anchors(&["not a valid dnskey".to_string()]).is_err());
    }
}
