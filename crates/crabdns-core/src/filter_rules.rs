use std::net::IpAddr;
use std::str::FromStr;

use hickory_proto::rr::RecordType;
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::acl::IpNet;
use crate::error::{CoreError, Result};

const MAX_REGEX_PATTERN_LEN: usize = 512;
const REGEX_SIZE_LIMIT: usize = 64 * 1024;
const REGEX_DFA_SIZE_LIMIT: usize = 128 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RewriteAction {
    Ip(IpAddr),
    Cname(String),
    Txt(String),
}

impl RewriteAction {
    pub(crate) fn matches_qtype(&self, qtype: RecordType) -> bool {
        matches!(
            (self, qtype),
            (Self::Ip(IpAddr::V4(_)), RecordType::A)
                | (Self::Ip(IpAddr::V6(_)), RecordType::AAAA)
                | (Self::Txt(_), RecordType::TXT)
                | (Self::Cname(_), _)
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum DnsRewriteKind {
    #[default]
    Auto,
    A,
    Aaaa,
    Cname,
    Txt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct DnsRewriteEntry {
    pub id: String,
    pub domain: String,
    #[serde(default)]
    pub kind: DnsRewriteKind,
    pub answer: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub comment: String,
}

const fn default_true() -> bool {
    true
}

impl DnsRewriteEntry {
    /// Converts an enabled rewrite entry into an AdGuard-compatible `$dnsrewrite=` filter rule.
    pub fn to_filter_rule(&self) -> String {
        let domain_clean = self.domain.trim().trim_end_matches('.');
        let pattern = if domain_clean.starts_with("||")
            || domain_clean.starts_with('|')
            || domain_clean.starts_with("*.")
        {
            domain_clean.to_string()
        } else {
            format!("|{domain_clean}^")
        };
        let ans = self.answer.trim();
        let rhs = match self.kind {
            DnsRewriteKind::Auto => ans.to_string(),
            DnsRewriteKind::A => format!("A;{ans}"),
            DnsRewriteKind::Aaaa => format!("AAAA;{ans}"),
            DnsRewriteKind::Cname => format!("CNAME;{}", ans.trim_end_matches('.')),
            DnsRewriteKind::Txt => format!("TXT;{ans}"),
        };
        format!("{pattern}$dnsrewrite={rhs}")
    }
}

/// Validates and normalizes `(domain, kind, answer)` for a dedicated DNS rewrite entry.
pub fn validate_dns_rewrite(
    domain: &str,
    kind: DnsRewriteKind,
    answer: &str,
) -> Result<(String, DnsRewriteKind, String)> {
    let raw_domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let check_domain = raw_domain
        .strip_prefix("||")
        .or_else(|| raw_domain.strip_prefix('|'))
        .unwrap_or(&raw_domain)
        .trim_end_matches('^')
        .trim_end_matches('.');
    let check_token = check_domain.strip_prefix("*.").unwrap_or(check_domain);
    if !is_valid_domain_token(check_token) {
        return Err(CoreError::Config(format!(
            "invalid rewrite domain '{domain}'"
        )));
    }
    let norm_domain = if let Some(rest) = raw_domain.strip_prefix("*.") {
        format!("*.{}", rest.trim_end_matches('.'))
    } else {
        check_domain.to_string()
    };

    let ans = answer.trim();
    if ans.is_empty() {
        return Err(CoreError::Config(
            "rewrite answer cannot be empty".to_string(),
        ));
    }

    let normalized_answer = match kind {
        DnsRewriteKind::A => {
            let ip: IpAddr = ans
                .parse()
                .map_err(|_| CoreError::Config(format!("invalid IPv4 answer '{ans}'")))?;
            if !ip.is_ipv4() {
                return Err(CoreError::Config(format!(
                    "expected IPv4 address for A rewrite, got '{ans}'"
                )));
            }
            ip.to_string()
        }
        DnsRewriteKind::Aaaa => {
            let ip: IpAddr = ans
                .parse()
                .map_err(|_| CoreError::Config(format!("invalid IPv6 answer '{ans}'")))?;
            if !ip.is_ipv6() {
                return Err(CoreError::Config(format!(
                    "expected IPv6 address for AAAA rewrite, got '{ans}'"
                )));
            }
            ip.to_string()
        }
        DnsRewriteKind::Cname => {
            let target = ans.trim_end_matches('.').to_ascii_lowercase();
            if !is_valid_domain_token(&target) {
                return Err(CoreError::Config(format!("invalid CNAME target '{ans}'")));
            }
            target
        }
        DnsRewriteKind::Txt => {
            if ans.len() > 255 {
                return Err(CoreError::Config(
                    "TXT rewrite answer must be <= 255 bytes".to_string(),
                ));
            }
            ans.to_string()
        }
        DnsRewriteKind::Auto => {
            if let Ok(ip) = ans.parse::<IpAddr>() {
                ip.to_string()
            } else {
                let target = ans.trim_end_matches('.').to_ascii_lowercase();
                if !is_valid_domain_token(&target) {
                    return Err(CoreError::Config(format!(
                        "invalid auto rewrite answer '{ans}' (expected IP or domain)"
                    )));
                }
                target
            }
        }
    };

    Ok((norm_domain, kind, normalized_answer))
}

#[derive(Debug, Clone, Copy, Default)]
pub struct FilterQueryContext<'a> {
    pub domain: &'a str,
    pub qtype: Option<RecordType>,
    pub client_ip: Option<IpAddr>,
    pub client_id: Option<&'a str>,
    pub client_name: Option<&'a str>,
    pub client_tags: &'a [String],
}

impl<'a> FilterQueryContext<'a> {
    pub fn from_domain(domain: &'a str) -> Self {
        Self {
            domain,
            qtype: None,
            client_ip: None,
            client_id: None,
            client_name: None,
            client_tags: &[],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ClientMatcher {
    Ip(IpAddr),
    Cidr(IpNet),
    Ident(String),
}

impl ClientMatcher {
    fn parse(raw: &str) -> Option<(bool, Self)> {
        let mut token = raw.trim();
        let negated = if let Some(rest) = token.strip_prefix('~') {
            token = rest.trim();
            true
        } else {
            false
        };
        token = strip_matching_quotes(token).trim();
        if token.is_empty() {
            return None;
        }
        if token.contains('/')
            && let Ok(net) = IpNet::parse(token)
        {
            return Some((negated, Self::Cidr(net)));
        }
        if let Ok(ip) = token.parse::<IpAddr>() {
            return Some((negated, Self::Ip(ip)));
        }
        Some((negated, Self::Ident(token.to_ascii_lowercase())))
    }

    fn matches(&self, ctx: &FilterQueryContext<'_>) -> bool {
        match self {
            Self::Ip(expected) => ctx.client_ip.is_some_and(|ip| ip == *expected),
            Self::Cidr(net) => ctx.client_ip.is_some_and(|ip| net.contains(ip)),
            Self::Ident(expected) => {
                ctx.client_id
                    .is_some_and(|id| id.trim().eq_ignore_ascii_case(expected))
                    || ctx
                        .client_name
                        .is_some_and(|name| name.trim().eq_ignore_ascii_case(expected))
                    || ctx
                        .client_tags
                        .iter()
                        .any(|tag| tag.trim().eq_ignore_ascii_case(expected))
            }
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RuleConditions {
    pub positive_dnstypes: Vec<RecordType>,
    pub negative_dnstypes: Vec<RecordType>,
    pub positive_clients: Vec<ClientMatcher>,
    pub negative_clients: Vec<ClientMatcher>,
    pub denyallow_domains: Vec<String>,
}

impl RuleConditions {
    pub(crate) fn matches(&self, ctx: &FilterQueryContext<'_>, clean_domain: &str) -> bool {
        if !self.positive_dnstypes.is_empty() {
            let Some(qt) = ctx.qtype else {
                return false;
            };
            if !self.positive_dnstypes.contains(&qt) {
                return false;
            }
        }
        if !self.negative_dnstypes.is_empty() {
            let Some(qt) = ctx.qtype else {
                return false;
            };
            if self.negative_dnstypes.contains(&qt) {
                return false;
            }
        }

        if !self.positive_clients.is_empty()
            && !self.positive_clients.iter().any(|m| m.matches(ctx))
        {
            return false;
        }
        if self.negative_clients.iter().any(|m| m.matches(ctx)) {
            return false;
        }

        if !self.denyallow_domains.is_empty()
            && self
                .denyallow_domains
                .iter()
                .any(|d| domain_matches_suffix(clean_domain, d))
        {
            return false;
        }

        true
    }
}

fn domain_matches_suffix(domain: &str, suffix: &str) -> bool {
    if domain.eq_ignore_ascii_case(suffix) {
        return true;
    }
    let diff = domain.len().checked_sub(suffix.len());
    match diff {
        Some(pos) if pos > 1 => {
            domain.as_bytes()[pos - 1] == b'.' && domain[pos..].eq_ignore_ascii_case(suffix)
        }
        _ => false,
    }
}

fn strip_matching_quotes(s: &str) -> &str {
    if s.len() >= 2
        && ((s.starts_with('\'') && s.ends_with('\'')) || (s.starts_with('"') && s.ends_with('"')))
    {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

fn parse_record_type_token(raw: &str) -> Option<RecordType> {
    let trimmed = raw.trim().to_ascii_uppercase();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(code) = trimmed.parse::<u16>() {
        return Some(RecordType::from(code));
    }
    RecordType::from_str(&trimmed).ok()
}

pub(crate) struct ParsedModifiers {
    pub is_important: bool,
    pub rewrite: Option<RewriteAction>,
    pub conditions: RuleConditions,
}

pub(crate) fn parse_modifiers(mods: Option<&str>) -> ParsedModifiers {
    let mut parsed = ParsedModifiers {
        is_important: false,
        rewrite: None,
        conditions: RuleConditions::default(),
    };
    let Some(raw_mods) = mods else {
        return parsed;
    };

    for part in raw_mods.split(',') {
        let trimmed = part.trim();
        if !trimmed.is_empty() {
            apply_single_modifier(&mut parsed, trimmed);
        }
    }
    parsed
}

fn apply_single_modifier(parsed: &mut ParsedModifiers, trimmed: &str) {
    if trimmed == "important" {
        parsed.is_important = true;
    } else if let Some(val) = trimmed.strip_prefix("dnsrewrite=") {
        parsed.rewrite = parse_dnsrewrite_value(val);
    } else if let Some(val) = trimmed.strip_prefix("dnstype=") {
        parse_dnstype_list(&mut parsed.conditions, val);
    } else if let Some(val) = trimmed.strip_prefix("client=") {
        parse_client_list(&mut parsed.conditions, val);
    } else if let Some(val) = trimmed.strip_prefix("denyallow=") {
        parse_denyallow_list(&mut parsed.conditions, val);
    }
}

fn parse_dnstype_list(conditions: &mut RuleConditions, val: &str) {
    for item in val.split('|').map(str::trim) {
        if let Some(neg) = item.strip_prefix('~') {
            if let Some(rt) = parse_record_type_token(neg) {
                conditions.negative_dnstypes.push(rt);
            }
        } else if let Some(rt) = parse_record_type_token(item) {
            conditions.positive_dnstypes.push(rt);
        }
    }
}

fn parse_client_list(conditions: &mut RuleConditions, val: &str) {
    for item in val.split('|') {
        if let Some((negated, matcher)) = ClientMatcher::parse(item) {
            if negated {
                conditions.negative_clients.push(matcher);
            } else {
                conditions.positive_clients.push(matcher);
            }
        }
    }
}

fn parse_denyallow_list(conditions: &mut RuleConditions, val: &str) {
    for item in val.split('|') {
        let clean = item.trim().trim_end_matches('.').to_ascii_lowercase();
        if is_valid_domain_token(&clean) {
            conditions.denyallow_domains.push(clean);
        }
    }
}

pub(crate) fn parse_dnsrewrite_value(raw: &str) -> Option<RewriteAction> {
    let val = raw.trim();
    if val.is_empty() {
        return None;
    }
    if let Ok(ip) = val.parse::<IpAddr>() {
        return Some(RewriteAction::Ip(ip));
    }
    if let Some((rr_type, target)) = val.split_once(';') {
        let kind = rr_type.trim().to_ascii_uppercase();
        let target = target.trim();
        if target.is_empty() {
            return None;
        }
        return match kind.as_str() {
            "A" | "AAAA" => target.parse::<IpAddr>().ok().map(RewriteAction::Ip),
            "CNAME" => {
                let clean = target.trim_end_matches('.');
                is_valid_domain_token(clean).then(|| RewriteAction::Cname(clean.to_string()))
            }
            "TXT" => Some(RewriteAction::Txt(target.to_string())),
            _ => None,
        };
    }
    let clean = val.trim_end_matches('.');
    is_valid_domain_token(clean).then(|| RewriteAction::Cname(clean.to_string()))
}

pub(crate) fn is_valid_domain_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= 253
        && !token.contains('*')
        && !token.contains('/')
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
}

pub(crate) struct ParsedRegexRule {
    pub pattern: String,
    pub is_allow: bool,
    pub is_important: bool,
    pub rewrite: Option<RewriteAction>,
    pub conditions: RuleConditions,
}

pub(crate) fn parse_regex_rule(line: &str) -> Option<ParsedRegexRule> {
    let (is_allow, rest) = if let Some(stripped) = line.strip_prefix("@@") {
        (true, stripped)
    } else {
        (false, line)
    };
    if !rest.starts_with('/') {
        return None;
    }
    let after_open = &rest[1..];
    let close_idx = find_closing_slash(after_open)?;
    let pattern = &after_open[..close_idx];
    if pattern.is_empty() || pattern.len() > MAX_REGEX_PATTERN_LEN {
        return None;
    }
    let tail = after_open[close_idx + 1..].trim();
    let mods = if tail.is_empty() {
        None
    } else {
        Some(tail.strip_prefix('$')?)
    };

    let parsed_mods = parse_modifiers(mods);
    Some(ParsedRegexRule {
        pattern: pattern.to_string(),
        is_allow,
        is_important: parsed_mods.is_important,
        rewrite: parsed_mods.rewrite,
        conditions: parsed_mods.conditions,
    })
}

fn find_closing_slash(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2;
            continue;
        }
        if bytes[i] == b'/' {
            return Some(i);
        }
        i += 1;
    }
    None
}

pub(crate) fn compile_safe_regex(pattern: &str) -> Option<Regex> {
    if pattern.is_empty() || pattern.len() > MAX_REGEX_PATTERN_LEN {
        return None;
    }
    RegexBuilder::new(pattern)
        .case_insensitive(true)
        .size_limit(REGEX_SIZE_LIMIT)
        .dfa_size_limit(REGEX_DFA_SIZE_LIMIT)
        .build()
        .ok()
}
