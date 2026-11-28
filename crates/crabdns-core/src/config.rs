use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::blocked_services::BlockedServicesConfig;
use crate::cf_cdn::CfCdnConfig;
use crate::dnssec_anchors::DnssecNta;
use crate::error::{CoreError, Result};
use crate::recursor::RecursiveConfig;
use crate::safesearch::SafeSearchConfig;

pub use crate::split_dns_config::{
    CompiledUpstreamPolicy, ResponseIpRule, SplitDnsMatchMode, SplitDnsRule, UpstreamGroup,
    UpstreamPolicy, UpstreamStrategy,
};

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
pub enum AcmeChallengeType {
    #[default]
    Http01,
    Dns01Local,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum StorageProfile {
    #[default]
    Auto,
    Embedded,
    Balanced,
    Performance,
}

/// Static startup, listener, and storage-path configuration loaded from CLI/TOML.
///
/// These fields are intentionally separated from [`RuntimeConfig`] so they are
/// never overwritten by persisted runtime settings on restart.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapConfig {
    #[serde(default = "default_listen_dns")]
    pub listen_dns: SocketAddr,
    #[serde(default = "default_listen_web")]
    pub listen_web: SocketAddr,
    #[serde(default)]
    pub listen_web_tls: Option<SocketAddr>,
    #[serde(default)]
    pub listen_dot: Option<SocketAddr>,
    #[serde(default)]
    pub listen_doq: Option<SocketAddr>,
    #[serde(default)]
    pub listen_doh3: Option<SocketAddr>,
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    #[serde(default = "default_tcp_max_connections")]
    pub tcp_max_connections: usize,
    #[serde(default = "default_tcp_idle_timeout_secs")]
    pub tcp_idle_timeout_secs: u64,
    #[serde(default)]
    pub custom_rules: Vec<String>,
}

/// Dynamic runtime configuration editable via the Web UI and persisted in storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct RuntimeConfig {
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
    #[serde(default = "default_log_retention_hours")]
    pub log_retention_hours: u64,
    #[serde(default = "default_log_max_disk_mb")]
    pub log_max_disk_mb: u64,
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
    #[serde(default)]
    pub upstream_groups: Vec<UpstreamGroup>,
    #[serde(default)]
    pub split_dns_match_mode: SplitDnsMatchMode,
    #[serde(default)]
    pub split_dns_before_client_upstreams: bool,
    #[serde(default = "default_split_dns_refresh_interval_secs")]
    pub split_dns_refresh_interval_secs: u64,
    #[serde(default = "default_true")]
    pub cname_cloaking_blocking: bool,
    #[serde(default = "default_true")]
    pub doh_enabled: bool,
    #[serde(default)]
    pub sni_client_id_hostnames: Vec<String>,
    #[serde(default)]
    pub tls_cert_path: Option<PathBuf>,
    #[serde(default)]
    pub tls_key_path: Option<PathBuf>,
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
    pub dnssec_trust_anchors: Vec<String>,
    #[serde(default)]
    pub dnssec_ntas: Vec<DnssecNta>,
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
    pub llmnr_enabled: bool,
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
    #[serde(default)]
    pub trusted_forwarders: Vec<String>,
    #[serde(default = "default_true")]
    pub rdns_enabled: bool,
    #[serde(default)]
    pub safesearch: SafeSearchConfig,
    #[serde(default)]
    pub blocked_services: BlockedServicesConfig,
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
    #[serde(default)]
    pub storage_profile: StorageProfile,
    #[serde(default = "default_disk_min_free_mb")]
    pub disk_min_free_mb: u64,
    #[serde(default = "default_true")]
    pub serve_stale_enabled: bool,
    #[serde(default)]
    pub dnssec_strict_clock: bool,
    #[serde(default)]
    pub dnssec_auto_rollover: bool,
    #[serde(default)]
    pub recursive: RecursiveConfig,
}

/// Top-level `CrabDNS` configuration combining [`BootstrapConfig`] and [`RuntimeConfig`].
///
/// Both sections are flattened for TOML/JSON compatibility with existing config files.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(flatten)]
    pub bootstrap: BootstrapConfig,
    #[serde(flatten)]
    pub runtime: RuntimeConfig,
}

impl std::ops::Deref for Config {
    type Target = RuntimeConfig;

    fn deref(&self) -> &Self::Target {
        &self.runtime
    }
}

impl std::ops::DerefMut for Config {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.runtime
    }
}

fn default_listen_dns() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 5354)
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

fn default_log_max_disk_mb() -> u64 {
    256
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

fn default_disk_min_free_mb() -> u64 {
    128
}

fn default_dhcp_leases_domain() -> String {
    "lan".to_string()
}

const fn default_split_dns_refresh_interval_secs() -> u64 {
    86_400
}

pub fn validate_split_dns_refresh_interval(secs: u64) -> Result<()> {
    if secs != 0 && secs < 60 {
        return Err(CoreError::Config(
            "split_dns_refresh_interval_secs must be 0 (disabled) or >= 60".to_string(),
        ));
    }
    Ok(())
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            listen_dns: default_listen_dns(),
            listen_web: default_listen_web(),
            listen_web_tls: None,
            listen_dot: None,
            listen_doq: None,
            listen_doh3: None,
            data_dir: default_data_dir(),
            tcp_max_connections: default_tcp_max_connections(),
            tcp_idle_timeout_secs: default_tcp_idle_timeout_secs(),
            custom_rules: Vec::new(),
        }
    }
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
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
            log_retention_hours: default_log_retention_hours(),
            log_max_disk_mb: default_log_max_disk_mb(),
            block_mode: BlockMode::default(),
            allow_cidrs: Vec::new(),
            deny_cidrs: Vec::new(),
            rate_limit_qps: 0,
            web_auth_enabled: false,
            web_username: default_web_username(),
            web_password_hash: String::new(),
            setup_completed: false,
            split_dns: Vec::new(),
            upstream_groups: Vec::new(),
            split_dns_match_mode: SplitDnsMatchMode::default(),
            split_dns_before_client_upstreams: false,
            split_dns_refresh_interval_secs: default_split_dns_refresh_interval_secs(),
            cname_cloaking_blocking: true,
            doh_enabled: true,
            sni_client_id_hostnames: Vec::new(),
            tls_cert_path: None,
            tls_key_path: None,
            allow_private_subscriptions: false,
            ecs_enabled: false,
            ecs_custom_ip: None,
            ecs_ipv4_prefix: default_ecs_ipv4_prefix(),
            ecs_ipv6_prefix: default_ecs_ipv6_prefix(),
            dnssec_enabled: false,
            dnssec_trust_anchors: Vec::new(),
            dnssec_ntas: Vec::new(),
            hosts_enabled: false,
            hosts_path: None,
            dhcp_leases_enabled: false,
            dhcp_leases_path: None,
            dhcp_leases_forward_enabled: false,
            dhcp_leases_domain: default_dhcp_leases_domain(),
            mdns_enabled: false,
            llmnr_enabled: false,
            private_ptr_enabled: false,
            private_ptr_upstreams: Vec::new(),
            block_local_domains: false,
            suppress_local_domain_logs: false,
            ddr_enabled: false,
            ddr_hostname: None,
            dns_rebinding_protection: false,
            block_any_queries: false,
            trusted_proxies: Vec::new(),
            trusted_forwarders: Vec::new(),
            rdns_enabled: true,
            safesearch: SafeSearchConfig::default(),
            blocked_services: BlockedServicesConfig::default(),
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
            storage_profile: StorageProfile::default(),
            disk_min_free_mb: default_disk_min_free_mb(),
            serve_stale_enabled: true,
            dnssec_strict_clock: false,
            dnssec_auto_rollover: false,
            recursive: RecursiveConfig::default(),
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
        assert_eq!(def.bootstrap.listen_dns.port(), 5354);
        assert_eq!(def.bootstrap.listen_web.port(), 3000);
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
        assert_eq!(parsed.bootstrap.listen_dns.port(), 15353);
        assert_eq!(parsed.bootstrap_dns, vec!["1.1.1.1", "tcp://8.8.8.8:53"]);
        assert_eq!(parsed.cache_size, 1024);
        assert!(!parsed.optimistic_cache);
        assert_eq!(parsed.bootstrap.custom_rules, vec!["||ads.test^"]);
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
