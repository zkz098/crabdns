use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::cf_cdn::CfCdnConfig;
use crate::error::{CoreError, Result};
use crate::safesearch::SafeSearchConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum BlockMode {
    #[default]
    ZeroIp,
    NxDomain,
    NoData,
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
pub enum AcmeChallengeType {
    #[default]
    Http01,
    Dns01Local,
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
}

impl UpstreamPolicy {
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }

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
                policy
                    .ecs_ipv4_prefix
                    .unwrap_or_else(default_ecs_ipv4_prefix),
                policy
                    .ecs_ipv6_prefix
                    .unwrap_or_else(default_ecs_ipv6_prefix),
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
        })
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SplitDnsRule {
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub domains_file: Option<String>,
    #[serde(default)]
    pub domains_url: Option<String>,
    pub upstreams: Vec<String>,
    #[serde(default = "default_true")]
    pub fallback_to_default: bool,
    #[serde(default)]
    pub policy: UpstreamPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct Config {
    #[serde(default = "default_listen_dns")]
    pub listen_dns: SocketAddr,
    #[serde(default = "default_listen_web")]
    pub listen_web: SocketAddr,
    #[serde(default)]
    pub listen_web_tls: Option<SocketAddr>,
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    #[serde(default = "default_upstreams")]
    pub upstreams: Vec<String>,
    #[serde(default)]
    pub bootstrap_dns: Vec<String>,
    #[serde(default)]
    pub upstream_strategy: UpstreamStrategy,
    #[serde(default = "default_cache_size")]
    pub cache_size: u64,
    #[serde(default = "default_true")]
    pub optimistic_cache: bool,
    #[serde(default = "default_cache_min_ttl_secs")]
    pub cache_min_ttl_secs: u32,
    #[serde(default = "default_cache_max_ttl_secs")]
    pub cache_max_ttl_secs: u32,
    #[serde(default = "default_true")]
    pub cache_prefetch_enabled: bool,
    #[serde(default)]
    pub cache_persist_enabled: bool,
    #[serde(default = "default_upstream_timeout_ms")]
    pub upstream_timeout_ms: u64,
    #[serde(default)]
    pub custom_rules: Vec<String>,
    #[serde(default = "default_log_retention_hours")]
    pub log_retention_hours: u64,
    #[serde(default)]
    pub block_mode: BlockMode,
    #[serde(default)]
    pub allow_cidrs: Vec<String>,
    #[serde(default)]
    pub deny_cidrs: Vec<String>,
    #[serde(default)]
    pub rate_limit_qps: u32,
    #[serde(default)]
    pub web_auth_enabled: bool,
    #[serde(default = "default_web_username")]
    pub web_username: String,
    #[serde(default)]
    pub web_password_hash: String,
    #[serde(default = "default_true")]
    pub setup_completed: bool,
    #[serde(default)]
    pub split_dns: Vec<SplitDnsRule>,
    #[serde(default = "default_true")]
    pub cname_cloaking_blocking: bool,
    #[serde(default = "default_true")]
    pub doh_enabled: bool,
    #[serde(default)]
    pub listen_dot: Option<SocketAddr>,
    #[serde(default)]
    pub listen_doq: Option<SocketAddr>,
    #[serde(default)]
    pub listen_doh3: Option<SocketAddr>,
    #[serde(default)]
    pub sni_client_id_hostnames: Vec<String>,
    #[serde(default)]
    pub tls_cert_path: Option<PathBuf>,
    #[serde(default)]
    pub tls_key_path: Option<PathBuf>,
    #[serde(default = "default_tcp_max_connections")]
    pub tcp_max_connections: usize,
    #[serde(default = "default_tcp_idle_timeout_secs")]
    pub tcp_idle_timeout_secs: u64,
    #[serde(default)]
    pub allow_private_subscriptions: bool,
    #[serde(default)]
    pub ecs_enabled: bool,
    #[serde(default)]
    pub ecs_custom_ip: Option<String>,
    #[serde(default = "default_ecs_ipv4_prefix")]
    pub ecs_ipv4_prefix: u8,
    #[serde(default = "default_ecs_ipv6_prefix")]
    pub ecs_ipv6_prefix: u8,
    #[serde(default)]
    pub dnssec_enabled: bool,
    #[serde(default)]
    pub hosts_enabled: bool,
    #[serde(default)]
    pub hosts_path: Option<String>,
    #[serde(default)]
    pub dhcp_leases_enabled: bool,
    #[serde(default)]
    pub dhcp_leases_path: Option<String>,
    #[serde(default)]
    pub dhcp_leases_forward_enabled: bool,
    #[serde(default = "default_dhcp_leases_domain")]
    pub dhcp_leases_domain: String,
    #[serde(default)]
    pub mdns_enabled: bool,
    #[serde(default)]
    pub private_ptr_enabled: bool,
    #[serde(default)]
    pub private_ptr_upstreams: Vec<String>,
    #[serde(default)]
    pub block_local_domains: bool,
    #[serde(default)]
    pub suppress_local_domain_logs: bool,
    #[serde(default)]
    pub ddr_enabled: bool,
    #[serde(default)]
    pub ddr_hostname: Option<String>,
    #[serde(default)]
    pub dns_rebinding_protection: bool,
    #[serde(default)]
    pub block_any_queries: bool,
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    #[serde(default = "default_true")]
    pub rdns_enabled: bool,
    #[serde(default)]
    pub safesearch: SafeSearchConfig,
    #[serde(default)]
    pub dns64_enabled: bool,
    #[serde(default = "default_dns64_prefixes")]
    pub dns64_prefixes: Vec<String>,
    #[serde(default)]
    pub svcb_strip_ech: bool,
    #[serde(default)]
    pub svcb_strip_hints: bool,
    #[serde(default = "default_true")]
    pub ede_enabled: bool,
    #[serde(default)]
    pub dns_cookies_enabled: bool,
    #[serde(default)]
    pub dns_cookies_require_valid: bool,
    #[serde(default = "default_max_udp_payload_size")]
    pub max_udp_payload_size: u16,
    #[serde(default)]
    pub rrl_enabled: bool,
    #[serde(default = "default_rrl_responses_per_second")]
    pub rrl_responses_per_second: u32,
    #[serde(default = "default_rrl_slip")]
    pub rrl_slip: u32,
    #[serde(default = "default_rrl_window_secs")]
    pub rrl_window_secs: u64,
    #[serde(default)]
    pub acme_enabled: bool,
    #[serde(default)]
    pub acme_domains: Vec<String>,
    #[serde(default)]
    pub acme_email: Option<String>,
    #[serde(default = "default_acme_directory_url")]
    pub acme_directory_url: String,
    #[serde(default)]
    pub acme_challenge_type: AcmeChallengeType,
    #[serde(default)]
    pub acme_http_listen: Option<SocketAddr>,
    #[serde(default = "default_acme_renew_before_days")]
    pub acme_renew_before_days: u32,
    #[serde(default)]
    pub cf_cdn: CfCdnConfig,
}

fn default_listen_dns() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 5353)
}

fn default_listen_web() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3000)
}

fn default_data_dir() -> PathBuf {
    PathBuf::from("./data")
}

fn default_upstreams() -> Vec<String> {
    vec![
        "udp://1.1.1.1:53".to_string(),
        "udp://8.8.8.8:53".to_string(),
    ]
}

fn default_cache_size() -> u64 {
    65_536
}

fn default_cache_min_ttl_secs() -> u32 {
    10
}

fn default_cache_max_ttl_secs() -> u32 {
    86_400
}

fn default_true() -> bool {
    true
}

fn default_upstream_timeout_ms() -> u64 {
    3_000
}

fn default_log_retention_hours() -> u64 {
    24
}

fn default_web_username() -> String {
    "admin".to_string()
}

fn default_tcp_max_connections() -> usize {
    256
}

fn default_tcp_idle_timeout_secs() -> u64 {
    10
}

fn default_ecs_ipv4_prefix() -> u8 {
    24
}

fn default_ecs_ipv6_prefix() -> u8 {
    56
}

fn default_dns64_prefixes() -> Vec<String> {
    vec![crate::dns64::DEFAULT_DNS64_PREFIX.to_string()]
}

fn default_max_udp_payload_size() -> u16 {
    1232
}

fn default_rrl_responses_per_second() -> u32 {
    10
}

fn default_rrl_slip() -> u32 {
    2
}

fn default_rrl_window_secs() -> u64 {
    15
}

fn default_acme_directory_url() -> String {
    "https://acme-v02.api.letsencrypt.org/directory".to_string()
}

fn default_acme_renew_before_days() -> u32 {
    30
}

fn default_dhcp_leases_domain() -> String {
    "lan".to_string()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_dns: default_listen_dns(),
            listen_web: default_listen_web(),
            listen_web_tls: None,
            data_dir: default_data_dir(),
            upstreams: default_upstreams(),
            bootstrap_dns: Vec::new(),
            upstream_strategy: UpstreamStrategy::default(),
            cache_size: default_cache_size(),
            optimistic_cache: default_true(),
            cache_min_ttl_secs: default_cache_min_ttl_secs(),
            cache_max_ttl_secs: default_cache_max_ttl_secs(),
            cache_prefetch_enabled: true,
            cache_persist_enabled: false,
            upstream_timeout_ms: default_upstream_timeout_ms(),
            custom_rules: Vec::new(),
            log_retention_hours: default_log_retention_hours(),
            block_mode: BlockMode::default(),
            allow_cidrs: Vec::new(),
            deny_cidrs: Vec::new(),
            rate_limit_qps: 0,
            web_auth_enabled: false,
            web_username: default_web_username(),
            web_password_hash: String::new(),
            setup_completed: false,
            split_dns: Vec::new(),
            cname_cloaking_blocking: true,
            doh_enabled: true,
            listen_dot: None,
            listen_doq: None,
            listen_doh3: None,
            sni_client_id_hostnames: Vec::new(),
            tls_cert_path: None,
            tls_key_path: None,
            tcp_max_connections: default_tcp_max_connections(),
            tcp_idle_timeout_secs: default_tcp_idle_timeout_secs(),
            allow_private_subscriptions: false,
            ecs_enabled: false,
            ecs_custom_ip: None,
            ecs_ipv4_prefix: default_ecs_ipv4_prefix(),
            ecs_ipv6_prefix: default_ecs_ipv6_prefix(),
            dnssec_enabled: false,
            hosts_enabled: false,
            hosts_path: None,
            dhcp_leases_enabled: false,
            dhcp_leases_path: None,
            dhcp_leases_forward_enabled: false,
            dhcp_leases_domain: default_dhcp_leases_domain(),
            mdns_enabled: false,
            private_ptr_enabled: false,
            private_ptr_upstreams: Vec::new(),
            block_local_domains: false,
            suppress_local_domain_logs: false,
            ddr_enabled: false,
            ddr_hostname: None,
            dns_rebinding_protection: false,
            block_any_queries: false,
            trusted_proxies: Vec::new(),
            rdns_enabled: true,
            safesearch: SafeSearchConfig::default(),
            dns64_enabled: false,
            dns64_prefixes: default_dns64_prefixes(),
            svcb_strip_ech: false,
            svcb_strip_hints: false,
            ede_enabled: true,
            dns_cookies_enabled: false,
            dns_cookies_require_valid: false,
            max_udp_payload_size: default_max_udp_payload_size(),
            rrl_enabled: false,
            rrl_responses_per_second: default_rrl_responses_per_second(),
            rrl_slip: default_rrl_slip(),
            rrl_window_secs: default_rrl_window_secs(),
            acme_enabled: false,
            acme_domains: Vec::new(),
            acme_email: None,
            acme_directory_url: default_acme_directory_url(),
            acme_challenge_type: AcmeChallengeType::default(),
            acme_http_listen: None,
            acme_renew_before_days: default_acme_renew_before_days(),
            cf_cdn: CfCdnConfig::default(),
        }
    }
}

impl Config {
    pub fn from_toml_str(input: &str) -> Result<Self> {
        toml::from_str(input).map_err(|err| CoreError::Config(err.to_string()))
    }

    pub fn load_or_default(path: Option<&std::path::Path>) -> Result<Self> {
        match path {
            Some(p) if p.exists() => {
                let text = std::fs::read_to_string(p)?;
                Self::from_toml_str(&text)
            }
            Some(p) => Err(CoreError::Config(format!(
                "config file not found: {}",
                p.display()
            ))),
            None => Ok(Self::default()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_and_toml_config() {
        let def = Config::default();
        assert_eq!(def.listen_dns.port(), 5353);
        assert_eq!(def.listen_web.port(), 3000);
        assert!(def.optimistic_cache);

        let parsed = Config::from_toml_str(
            r#"
            listen_dns = "127.0.0.1:15353"
            bootstrap_dns = ["1.1.1.1", "tcp://8.8.8.8:53"]
            cache_size = 1024
            optimistic_cache = false
            custom_rules = ["||ads.test^"]
            "#,
        )
        .expect("valid toml");
        assert_eq!(parsed.listen_dns.port(), 15353);
        assert_eq!(parsed.bootstrap_dns, vec!["1.1.1.1", "tcp://8.8.8.8:53"]);
        assert_eq!(parsed.cache_size, 1024);
        assert!(!parsed.optimistic_cache);
        assert_eq!(parsed.custom_rules, vec!["||ads.test^"]);
    }

    #[test]
    fn test_load_or_default_paths() {
        assert!(Config::load_or_default(None).is_ok());

        let missing = PathBuf::from("/tmp/definitely_missing_crabdns_cfg.toml");
        assert!(Config::load_or_default(Some(&missing)).is_err());

        let dir = tempfile::tempdir().expect("tempdir");
        let cfg_path = dir.path().join("crabdns.toml");
        std::fs::write(&cfg_path, "cache_size = 2048\n").expect("write cfg");
        let loaded = Config::load_or_default(Some(&cfg_path)).expect("load cfg");
        assert_eq!(loaded.cache_size, 2048);
    }
}
