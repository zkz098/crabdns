use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::error::{CoreError, Result};

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SplitDnsRule {
    pub domain: String,
    pub upstreams: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct Config {
    #[serde(default = "default_listen_dns")]
    pub listen_dns: SocketAddr,
    #[serde(default = "default_listen_web")]
    pub listen_web: SocketAddr,
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
    #[serde(default)]
    pub split_dns: Vec<SplitDnsRule>,
    #[serde(default = "default_true")]
    pub cname_cloaking_blocking: bool,
    #[serde(default = "default_true")]
    pub doh_enabled: bool,
    #[serde(default)]
    pub listen_dot: Option<SocketAddr>,
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

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_dns: default_listen_dns(),
            listen_web: default_listen_web(),
            data_dir: default_data_dir(),
            upstreams: default_upstreams(),
            bootstrap_dns: Vec::new(),
            upstream_strategy: UpstreamStrategy::default(),
            cache_size: default_cache_size(),
            optimistic_cache: default_true(),
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
            split_dns: Vec::new(),
            cname_cloaking_blocking: true,
            doh_enabled: true,
            listen_dot: None,
            tls_cert_path: None,
            tls_key_path: None,
            tcp_max_connections: default_tcp_max_connections(),
            tcp_idle_timeout_secs: default_tcp_idle_timeout_secs(),
            allow_private_subscriptions: false,
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
