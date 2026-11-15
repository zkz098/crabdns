use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_listen_dns")]
    pub listen_dns: SocketAddr,
    #[serde(default = "default_listen_web")]
    pub listen_web: SocketAddr,
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    #[serde(default = "default_upstreams")]
    pub upstreams: Vec<String>,
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

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_dns: default_listen_dns(),
            listen_web: default_listen_web(),
            data_dir: default_data_dir(),
            upstreams: default_upstreams(),
            cache_size: default_cache_size(),
            optimistic_cache: default_true(),
            upstream_timeout_ms: default_upstream_timeout_ms(),
            custom_rules: Vec::new(),
            log_retention_hours: default_log_retention_hours(),
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
