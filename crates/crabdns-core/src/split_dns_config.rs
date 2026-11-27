use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::error::{CoreError, Result};
use crate::pipeline_types::QueryProtocol;

const DEFAULT_ECS_IPV4_PREFIX: u8 = 24;
const DEFAULT_ECS_IPV6_PREFIX: u8 = 56;

const fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum UpstreamStrategy {
    #[default]
    Failover,
    Parallel,
    LeastLatency,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum SplitDnsMatchMode {
    #[default]
    SpecificityFirst,
    ConfigOrder,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct UpstreamPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_strategy: Option<UpstreamStrategy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(type = "number | null")]
    pub upstream_timeout_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dnssec_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ecs_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ecs_custom_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ecs_ipv4_prefix: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ecs_ipv6_prefix: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_rebinding_protection: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns64_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub svcb_strip_ech: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub svcb_strip_hints: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cf_cdn_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disable_ipv6: Option<bool>,
}

impl UpstreamPolicy {
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }

    #[must_use]
    pub fn normalized(&self) -> Self {
        let mut out = self.clone();
        out.ecs_custom_ip = out
            .ecs_custom_ip
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string);
        out
    }

    pub fn validate(&self) -> Result<()> {
        let _ = CompiledUpstreamPolicy::compile(self)?;
        Ok(())
    }

    #[must_use]
    pub fn merge_over(&self, base: &Self) -> Self {
        Self {
            upstream_strategy: self.upstream_strategy.or(base.upstream_strategy),
            upstream_timeout_ms: self.upstream_timeout_ms.or(base.upstream_timeout_ms),
            dnssec_enabled: self.dnssec_enabled.or(base.dnssec_enabled),
            ecs_enabled: self.ecs_enabled.or(base.ecs_enabled),
            ecs_custom_ip: self
                .ecs_custom_ip
                .clone()
                .or_else(|| base.ecs_custom_ip.clone()),
            ecs_ipv4_prefix: self.ecs_ipv4_prefix.or(base.ecs_ipv4_prefix),
            ecs_ipv6_prefix: self.ecs_ipv6_prefix.or(base.ecs_ipv6_prefix),
            dns_rebinding_protection: self
                .dns_rebinding_protection
                .or(base.dns_rebinding_protection),
            dns64_enabled: self.dns64_enabled.or(base.dns64_enabled),
            svcb_strip_ech: self.svcb_strip_ech.or(base.svcb_strip_ech),
            svcb_strip_hints: self.svcb_strip_hints.or(base.svcb_strip_hints),
            cf_cdn_enabled: self.cf_cdn_enabled.or(base.cf_cdn_enabled),
            disable_ipv6: self.disable_ipv6.or(base.disable_ipv6),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct CompiledUpstreamPolicy {
    pub upstream_strategy: Option<UpstreamStrategy>,
    pub upstream_timeout_ms: Option<u64>,
    pub dnssec_enabled: Option<bool>,
    pub ecs_enabled: Option<bool>,
    pub ecs_custom_subnet: Option<(IpAddr, u8)>,
    pub ecs_ipv4_prefix: Option<u8>,
    pub ecs_ipv6_prefix: Option<u8>,
    pub dns_rebinding_protection: Option<bool>,
    pub dns64_enabled: Option<bool>,
    pub svcb_strip_ech: Option<bool>,
    pub svcb_strip_hints: Option<bool>,
    pub cf_cdn_enabled: Option<bool>,
    pub disable_ipv6: Option<bool>,
}

impl CompiledUpstreamPolicy {
    pub fn compile(policy: &UpstreamPolicy) -> Result<Self> {
        if let Some(ms) = policy.upstream_timeout_ms
            && ms == 0
        {
            return Err(CoreError::Config(
                "upstream_timeout_ms override must be > 0".to_string(),
            ));
        }
        if let Some(v4) = policy.ecs_ipv4_prefix
            && v4 > 32
        {
            return Err(CoreError::Config(format!(
                "invalid ecs_ipv4_prefix override: {v4} (must be 0..=32)"
            )));
        }
        if let Some(v6) = policy.ecs_ipv6_prefix
            && v6 > 128
        {
            return Err(CoreError::Config(format!(
                "invalid ecs_ipv6_prefix override: {v6} (must be 0..=128)"
            )));
        }
        let ecs_custom_subnet = match policy
            .ecs_custom_ip
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(raw) => Some(crate::edns::parse_ecs_custom(
                raw,
                policy.ecs_ipv4_prefix.unwrap_or(DEFAULT_ECS_IPV4_PREFIX),
                policy.ecs_ipv6_prefix.unwrap_or(DEFAULT_ECS_IPV6_PREFIX),
            )?),
            None => None,
        };
        Ok(Self {
            upstream_strategy: policy.upstream_strategy,
            upstream_timeout_ms: policy.upstream_timeout_ms,
            dnssec_enabled: policy.dnssec_enabled,
            ecs_enabled: policy.ecs_enabled,
            ecs_custom_subnet,
            ecs_ipv4_prefix: policy.ecs_ipv4_prefix,
            ecs_ipv6_prefix: policy.ecs_ipv6_prefix,
            dns_rebinding_protection: policy.dns_rebinding_protection,
            dns64_enabled: policy.dns64_enabled,
            svcb_strip_ech: policy.svcb_strip_ech,
            svcb_strip_hints: policy.svcb_strip_hints,
            cf_cdn_enabled: policy.cf_cdn_enabled,
            disable_ipv6: policy.disable_ipv6,
        })
    }

    #[must_use]
    pub fn merge_over(&self, base: &Self) -> Self {
        Self {
            upstream_strategy: self.upstream_strategy.or(base.upstream_strategy),
            upstream_timeout_ms: self.upstream_timeout_ms.or(base.upstream_timeout_ms),
            dnssec_enabled: self.dnssec_enabled.or(base.dnssec_enabled),
            ecs_enabled: self.ecs_enabled.or(base.ecs_enabled),
            ecs_custom_subnet: self.ecs_custom_subnet.or(base.ecs_custom_subnet),
            ecs_ipv4_prefix: self.ecs_ipv4_prefix.or(base.ecs_ipv4_prefix),
            ecs_ipv6_prefix: self.ecs_ipv6_prefix.or(base.ecs_ipv6_prefix),
            dns_rebinding_protection: self
                .dns_rebinding_protection
                .or(base.dns_rebinding_protection),
            dns64_enabled: self.dns64_enabled.or(base.dns64_enabled),
            svcb_strip_ech: self.svcb_strip_ech.or(base.svcb_strip_ech),
            svcb_strip_hints: self.svcb_strip_hints.or(base.svcb_strip_hints),
            cf_cdn_enabled: self.cf_cdn_enabled.or(base.cf_cdn_enabled),
            disable_ipv6: self.disable_ipv6.or(base.disable_ipv6),
        }
    }

    pub fn resolve_ecs_config(&self, global: &crate::edns::EcsConfig) -> crate::edns::EcsConfig {
        crate::edns::EcsConfig {
            enabled: self.ecs_enabled.unwrap_or(global.enabled),
            custom_subnet: self.ecs_custom_subnet.or(global.custom_subnet),
            ipv4_prefix: self.ecs_ipv4_prefix.unwrap_or(global.ipv4_prefix),
            ipv6_prefix: self.ecs_ipv6_prefix.unwrap_or(global.ipv6_prefix),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct UpstreamGroup {
    pub name: String,
    #[serde(default)]
    pub upstreams: Vec<String>,
    #[serde(default)]
    pub fallback_groups: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_url: Option<String>,
    #[serde(default)]
    pub policy: UpstreamPolicy,
}

impl UpstreamGroup {
    #[must_use]
    pub fn normalized(self) -> Self {
        Self {
            name: self.name.trim().to_ascii_lowercase(),
            upstreams: clean_vec(self.upstreams),
            fallback_groups: self
                .fallback_groups
                .into_iter()
                .map(|s| s.trim().trim_start_matches('@').to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect(),
            proxy_url: clean_opt(self.proxy_url),
            policy: self.policy.normalized(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ResponseIpRule {
    #[serde(default)]
    pub expected_cidrs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_ip_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_ip_url: Option<String>,
    #[serde(default)]
    pub invert: bool,
    #[serde(default)]
    pub fallback_upstreams: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(type = "number | null")]
    pub fallback_delay_ms: Option<u64>,
    #[serde(default)]
    pub match_cname_domains: Vec<String>,
    #[serde(default)]
    pub fallback_on_empty: bool,
}

impl ResponseIpRule {
    pub fn is_active(&self) -> bool {
        !self.expected_cidrs.is_empty()
            || self
                .expected_ip_file
                .as_deref()
                .is_some_and(|s| !s.trim().is_empty())
            || self
                .expected_ip_url
                .as_deref()
                .is_some_and(|s| !s.trim().is_empty())
            || !self.match_cname_domains.is_empty()
            || self.fallback_on_empty
    }

    #[must_use]
    pub fn normalized(self) -> Self {
        Self {
            expected_cidrs: clean_vec(self.expected_cidrs),
            expected_ip_file: clean_opt(self.expected_ip_file),
            expected_ip_url: clean_opt(self.expected_ip_url),
            invert: self.invert,
            fallback_upstreams: clean_vec(self.fallback_upstreams),
            fallback_delay_ms: self.fallback_delay_ms.filter(|&ms| ms > 0),
            match_cname_domains: clean_vec(self.match_cname_domains),
            fallback_on_empty: self.fallback_on_empty,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SplitDnsRule {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub domains_file: Option<String>,
    #[serde(default)]
    pub domains_url: Option<String>,
    #[serde(default)]
    pub exclude_domains: Vec<String>,
    #[serde(default)]
    pub qtypes: Vec<String>,
    #[serde(default)]
    pub client_cidrs: Vec<String>,
    #[serde(default)]
    pub client_groups: Vec<String>,
    #[serde(default)]
    pub client_tags: Vec<String>,
    #[serde(default)]
    pub protocols: Vec<QueryProtocol>,
    #[serde(default)]
    pub upstreams: Vec<String>,
    #[serde(default)]
    pub fallback_upstreams: Vec<String>,
    #[serde(default = "default_true")]
    pub fallback_to_default: bool,
    #[serde(default)]
    pub fallback_on_nxdomain: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_local: Option<bool>,
    #[serde(default)]
    pub policy: UpstreamPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_ip: Option<ResponseIpRule>,
}

impl Default for SplitDnsRule {
    fn default() -> Self {
        Self {
            name: None,
            enabled: true,
            domain: String::new(),
            domains_file: None,
            domains_url: None,
            exclude_domains: Vec::new(),
            qtypes: Vec::new(),
            client_cidrs: Vec::new(),
            client_groups: Vec::new(),
            client_tags: Vec::new(),
            protocols: Vec::new(),
            upstreams: Vec::new(),
            fallback_upstreams: Vec::new(),
            fallback_to_default: true,
            fallback_on_nxdomain: false,
            is_local: None,
            policy: UpstreamPolicy::default(),
            response_ip: None,
        }
    }
}

impl SplitDnsRule {
    pub fn has_target(&self) -> bool {
        !self.domain.trim().is_empty()
            || self
                .domains_file
                .as_deref()
                .is_some_and(|s| !s.trim().is_empty())
            || self
                .domains_url
                .as_deref()
                .is_some_and(|s| !s.trim().is_empty())
    }

    #[must_use]
    pub fn normalized(self) -> Self {
        Self {
            name: clean_opt(self.name),
            enabled: self.enabled,
            domain: self.domain.trim().to_string(),
            domains_file: clean_opt(self.domains_file),
            domains_url: clean_opt(self.domains_url),
            exclude_domains: clean_vec(self.exclude_domains),
            qtypes: clean_vec(self.qtypes),
            client_cidrs: clean_vec(self.client_cidrs),
            client_groups: clean_vec(self.client_groups),
            client_tags: clean_vec(self.client_tags),
            protocols: self.protocols,
            upstreams: clean_vec(self.upstreams),
            fallback_upstreams: clean_vec(self.fallback_upstreams),
            fallback_to_default: self.fallback_to_default,
            fallback_on_nxdomain: self.fallback_on_nxdomain,
            is_local: self.is_local,
            policy: self.policy.normalized(),
            response_ip: self
                .response_ip
                .map(ResponseIpRule::normalized)
                .filter(ResponseIpRule::is_active),
        }
    }
}

fn clean_opt(raw: Option<String>) -> Option<String> {
    raw.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

fn clean_vec(items: Vec<String>) -> Vec<String> {
    items
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}
