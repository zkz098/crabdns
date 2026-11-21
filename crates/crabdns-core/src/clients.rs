use std::cmp::Reverse;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use foldhash::fast::RandomState;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use moka::sync::Cache;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use tokio::sync::Semaphore;

use crate::acl::IpNet;
use crate::config::{BlockMode, UpstreamStrategy};
use crate::error::{CoreError, Result};
use crate::filter::{FilterAction, FilterDecision, FilterEngine};
use crate::upstream::UpstreamPool;

const RDNS_CACHE_CAPACITY: u64 = 4096;
const RDNS_CACHE_TTL: Duration = Duration::from_mins(15);
const RDNS_QUERY_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_CLIENT_ID_LEN: usize = 64;
const MAX_INFLIGHT_RDNS: usize = 32;

const fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ClientGroup {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_true")]
    pub blocking_enabled: bool,
    #[serde(default = "default_true")]
    pub use_global_rules: bool,
    #[serde(default)]
    pub custom_rules: String,
    #[serde(default)]
    pub upstreams: Vec<String>,
    #[serde(default)]
    pub block_mode: Option<BlockMode>,
    #[serde(default)]
    pub cname_cloaking_blocking: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ClientProfile {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub identifiers: Vec<String>,
    #[serde(default)]
    pub group_id: Option<String>,
    #[serde(default)]
    pub blocking_enabled: Option<bool>,
    #[serde(default)]
    pub use_global_rules: Option<bool>,
    #[serde(default)]
    pub custom_rules: String,
    #[serde(default)]
    pub upstreams: Vec<String>,
    #[serde(default)]
    pub block_mode: Option<BlockMode>,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedClientIdentifier {
    Ip(IpAddr),
    Cidr(IpNet, u8),
    ClientId(String),
}

pub fn validate_client_id(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_CLIENT_ID_LEN {
        return Err(CoreError::Config(format!(
            "client ID '{trimmed}' must be 1..={MAX_CLIENT_ID_LEN} characters"
        )));
    }
    if !trimmed
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(CoreError::Config(format!(
            "client ID '{trimmed}' may only contain ASCII letters, digits, '-' or '_'"
        )));
    }
    Ok(trimmed.to_ascii_lowercase())
}

pub fn validate_client_identifier(raw: &str) -> Result<ParsedClientIdentifier> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(CoreError::Config(
            "client identifier cannot be empty".to_string(),
        ));
    }
    if let Some((_, prefix_str)) = trimmed.split_once('/') {
        let net = IpNet::parse(trimmed)?;
        let prefix: u8 = prefix_str
            .trim()
            .parse()
            .map_err(|_| CoreError::Config(format!("invalid CIDR prefix: {trimmed}")))?;
        return Ok(ParsedClientIdentifier::Cidr(net, prefix));
    }
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Ok(ParsedClientIdentifier::Ip(ip));
    }
    Ok(ParsedClientIdentifier::ClientId(validate_client_id(
        trimmed,
    )?))
}

pub struct ResolvedClientPolicy {
    pub profile_id: String,
    pub client_name: String,
    pub group_id: Option<String>,
    pub group_name: Option<String>,
    pub blocking_enabled: bool,
    pub use_global_rules: bool,
    pub block_mode: Option<BlockMode>,
    pub cname_cloaking_blocking: Option<bool>,
    pub client_filter: Option<Arc<FilterEngine>>,
    pub group_filter: Option<Arc<FilterEngine>>,
    pub upstream_pool: Option<(String, Arc<UpstreamPool>)>,
}

struct CompiledGroup<'a> {
    group: &'a ClientGroup,
    filter: Option<Arc<FilterEngine>>,
    upstream_pool: Option<(String, Arc<UpstreamPool>)>,
}

type FastMap<K, V> = HashMap<K, V, RandomState>;

#[derive(Default)]
pub struct ClientRegistry {
    client_id_map: FastMap<String, Arc<ResolvedClientPolicy>>,
    ip_map: FastMap<IpAddr, Arc<ResolvedClientPolicy>>,
    cidr_rules: Vec<(IpNet, u8, Arc<ResolvedClientPolicy>)>,
}

impl ClientRegistry {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn compile(
        clients: &[ClientProfile],
        groups: &[ClientGroup],
        timeout_ms: u64,
        strategy: UpstreamStrategy,
        bootstrap_dns: &[String],
    ) -> Result<Self> {
        let mut compiled_groups: FastMap<&str, CompiledGroup<'_>> =
            HashMap::with_hasher(RandomState::default());

        for group in groups {
            let filter = (!group.custom_rules.trim().is_empty()).then(|| {
                Arc::new(FilterEngine::from_named_text(
                    &format!("group:{}", group.name),
                    &group.custom_rules,
                ))
            });
            let upstream_pool = if group.upstreams.is_empty() {
                None
            } else {
                let pool = Arc::new(UpstreamPool::new_with_bootstrap(
                    &group.upstreams,
                    timeout_ms,
                    strategy,
                    bootstrap_dns,
                )?);
                Some((format!("group:{}", group.id), pool))
            };
            compiled_groups.insert(
                group.id.as_str(),
                CompiledGroup {
                    group,
                    filter,
                    upstream_pool,
                },
            );
        }

        let mut registry = Self::default();
        for client in clients {
            let compiled_group = match client.group_id.as_deref().filter(|s| !s.is_empty()) {
                Some(gid) => Some(compiled_groups.get(gid).ok_or_else(|| {
                    CoreError::Config(format!(
                        "client '{}' references unknown group '{gid}'",
                        client.name
                    ))
                })?),
                None => None,
            };

            let policy =
                build_resolved_policy(client, compiled_group, timeout_ms, strategy, bootstrap_dns)?;

            for raw_ident in &client.identifiers {
                match validate_client_identifier(raw_ident)? {
                    ParsedClientIdentifier::ClientId(cid) => {
                        registry.client_id_map.insert(cid, Arc::clone(&policy));
                    }
                    ParsedClientIdentifier::Ip(ip) => {
                        registry.ip_map.insert(ip, Arc::clone(&policy));
                    }
                    ParsedClientIdentifier::Cidr(net, prefix) => {
                        registry.cidr_rules.push((net, prefix, Arc::clone(&policy)));
                    }
                }
            }
        }

        registry
            .cidr_rules
            .sort_by_key(|(_, prefix, _)| Reverse(*prefix));
        Ok(registry)
    }

    pub fn match_client_id(&self, client_id: &str) -> Option<Arc<ResolvedClientPolicy>> {
        let norm = client_id.trim().to_ascii_lowercase();
        self.client_id_map.get(&norm).map(Arc::clone)
    }

    pub fn match_client(
        &self,
        ip: IpAddr,
        client_id: Option<&str>,
    ) -> Option<Arc<ResolvedClientPolicy>> {
        if let Some(cid) = client_id
            && let Some(policy) = self.match_client_id(cid)
        {
            return Some(policy);
        }
        if let Some(policy) = self.ip_map.get(&ip) {
            return Some(Arc::clone(policy));
        }
        for (net, _, policy) in &self.cidr_rules {
            if net.contains(ip) {
                return Some(Arc::clone(policy));
            }
        }
        None
    }

    pub fn evaluate_domain(
        policy: Option<&ResolvedClientPolicy>,
        global_filter: &FilterEngine,
        domain: &str,
    ) -> FilterDecision {
        if let Some(p) = policy {
            if let Some(cf) = &p.client_filter {
                let dec = cf.evaluate(domain);
                if dec.matched_rule.is_some() {
                    return dec;
                }
            }
            if let Some(gf) = &p.group_filter {
                let dec = gf.evaluate(domain);
                if dec.matched_rule.is_some() {
                    return dec;
                }
            }
            if !p.use_global_rules {
                return FilterDecision {
                    action: FilterAction::Allow,
                    matched_rule: None,
                    matched_list: None,
                };
            }
        }
        global_filter.evaluate(domain)
    }
}

fn build_resolved_policy(
    client: &ClientProfile,
    compiled_group: Option<&CompiledGroup<'_>>,
    timeout_ms: u64,
    strategy: UpstreamStrategy,
    bootstrap_dns: &[String],
) -> Result<Arc<ResolvedClientPolicy>> {
    let group_ref = compiled_group.map(|cg| cg.group);
    let blocking_enabled = client
        .blocking_enabled
        .unwrap_or_else(|| group_ref.is_none_or(|g| g.blocking_enabled));
    let use_global_rules = client
        .use_global_rules
        .unwrap_or_else(|| group_ref.is_none_or(|g| g.use_global_rules));
    let block_mode = client
        .block_mode
        .or_else(|| group_ref.and_then(|g| g.block_mode));
    let cname_cloaking_blocking = group_ref.and_then(|g| g.cname_cloaking_blocking);

    let client_filter = (!client.custom_rules.trim().is_empty()).then(|| {
        Arc::new(FilterEngine::from_named_text(
            &format!("client:{}", client.name),
            &client.custom_rules,
        ))
    });
    let group_filter = compiled_group.and_then(|cg| cg.filter.clone());

    let upstream_pool = if client.upstreams.is_empty() {
        compiled_group.and_then(|cg| cg.upstream_pool.clone())
    } else {
        let pool = Arc::new(UpstreamPool::new_with_bootstrap(
            &client.upstreams,
            timeout_ms,
            strategy,
            bootstrap_dns,
        )?);
        Some((format!("client:{}", client.id), pool))
    };

    Ok(Arc::new(ResolvedClientPolicy {
        profile_id: client.id.clone(),
        client_name: client.name.clone(),
        group_id: group_ref.map(|g| g.id.clone()),
        group_name: group_ref.map(|g| g.name.clone()),
        blocking_enabled,
        use_global_rules,
        block_mode,
        cname_cloaking_blocking,
        client_filter,
        group_filter,
        upstream_pool,
    }))
}

pub struct ClientNameResolver {
    rdns_cache: Cache<IpAddr, Option<String>, RandomState>,
    inflight: Arc<DashMap<IpAddr, (), RandomState>>,
    limiter: Arc<Semaphore>,
}

struct RdnsInflightGuard {
    inflight: Arc<DashMap<IpAddr, (), RandomState>>,
    ip: IpAddr,
}

impl Drop for RdnsInflightGuard {
    fn drop(&mut self) {
        self.inflight.remove(&self.ip);
    }
}

impl Default for ClientNameResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientNameResolver {
    pub fn new() -> Self {
        let rdns_cache = Cache::builder()
            .max_capacity(RDNS_CACHE_CAPACITY)
            .time_to_live(RDNS_CACHE_TTL)
            .build_with_hasher(RandomState::default());
        Self {
            rdns_cache,
            inflight: Arc::new(DashMap::with_hasher(RandomState::default())),
            limiter: Arc::new(Semaphore::new(MAX_INFLIGHT_RDNS)),
        }
    }

    pub fn inflight_count(&self) -> usize {
        self.inflight.len()
    }

    pub fn lookup_cached(&self, ip: IpAddr) -> Option<Option<String>> {
        self.rdns_cache.get(&ip)
    }

    pub fn spawn_rdns_if_needed(&self, ip: IpAddr, upstream: Arc<UpstreamPool>) {
        if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
            return;
        }
        if self.rdns_cache.contains_key(&ip) {
            return;
        }
        let Ok(permit) = Arc::clone(&self.limiter).try_acquire_owned() else {
            return;
        };
        let Entry::Vacant(vacant) = self.inflight.entry(ip) else {
            return;
        };
        vacant.insert(());

        let cache = self.rdns_cache.clone();
        let guard = RdnsInflightGuard {
            inflight: Arc::clone(&self.inflight),
            ip,
        };
        tokio::spawn(async move {
            let _permit = permit;
            let _guard = guard;
            let resolved = resolve_ptr_name(ip, &upstream).await;
            cache.insert(ip, resolved);
        });
    }
}

async fn resolve_ptr_name(ip: IpAddr, upstream: &UpstreamPool) -> Option<String> {
    let ptr_domain = format!("{}.", ip_to_ptr_domain(ip));
    let name = Name::from_ascii(&ptr_domain).ok()?;
    let tx_id = (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0x5244, |d| d.subsec_nanos())
        & 0xFFFF) as u16;
    let mut msg = Message::new(tx_id, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(name, RecordType::PTR));
    let wire = msg.to_vec().ok()?;

    let (resp_wire, _) = tokio::time::timeout(RDNS_QUERY_TIMEOUT, upstream.exchange(&wire))
        .await
        .ok()?
        .ok()?;
    let resp = Message::from_vec(&resp_wire).ok()?;
    if resp.response_code != ResponseCode::NoError {
        return None;
    }
    for answer in &resp.answers {
        if let RData::PTR(ptr) = &answer.data {
            let host = ptr.to_utf8();
            let clean = host.trim().trim_end_matches('.');
            if !clean.is_empty() {
                return Some(clean.to_string());
            }
        }
    }
    None
}

pub fn ip_to_ptr_domain(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, d] = v4.octets();
            format!("{d}.{c}.{b}.{a}.in-addr.arpa")
        }
        IpAddr::V6(v6) => {
            let bytes = v6.octets();
            let mut out = String::with_capacity(72);
            for byte in bytes.iter().rev() {
                use std::fmt::Write;
                let low = byte & 0x0F;
                let high = byte >> 4;
                let _ = write!(&mut out, "{low:x}.{high:x}.");
            }
            out.push_str("ip6.arpa");
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_identifier_validation_and_ptr_formatting() {
        assert_eq!(
            validate_client_identifier("192.168.1.10").unwrap(),
            ParsedClientIdentifier::Ip("192.168.1.10".parse().unwrap())
        );
        assert!(matches!(
            validate_client_identifier("192.168.1.0/24").unwrap(),
            ParsedClientIdentifier::Cidr(_, 24)
        ));
        assert_eq!(
            validate_client_identifier("Kid-Phone_1").unwrap(),
            ParsedClientIdentifier::ClientId("kid-phone_1".to_string())
        );
        assert!(validate_client_identifier("bad/cidr/extra").is_err());
        assert!(validate_client_identifier("bad id!").is_err());

        assert_eq!(
            ip_to_ptr_domain("192.168.1.50".parse().unwrap()),
            "50.1.168.192.in-addr.arpa"
        );
        assert_eq!(
            ip_to_ptr_domain("fd00::1".parse().unwrap()),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa"
        );
    }

    #[test]
    fn test_client_registry_precedence_and_layered_filters() {
        let groups = vec![ClientGroup {
            id: "kids".to_string(),
            name: "Kids".to_string(),
            description: "Restricted devices".to_string(),
            blocking_enabled: true,
            use_global_rules: true,
            custom_rules: "||tiktok.com^\n@@||ads.example.com^".to_string(),
            upstreams: vec!["udp://9.9.9.9:53".to_string()],
            block_mode: Some(BlockMode::NxDomain),
            cname_cloaking_blocking: Some(false),
        }];
        let clients = vec![
            ClientProfile {
                id: "subnet-kid".to_string(),
                name: "Kids Subnet".to_string(),
                identifiers: vec!["192.168.10.0/24".to_string()],
                group_id: Some("kids".to_string()),
                blocking_enabled: None,
                use_global_rules: None,
                custom_rules: String::new(),
                upstreams: Vec::new(),
                block_mode: None,
                tags: Vec::new(),
            },
            ClientProfile {
                id: "laptop".to_string(),
                name: "Work Laptop".to_string(),
                identifiers: vec!["192.168.10.50".to_string(), "work-laptop".to_string()],
                group_id: Some("kids".to_string()),
                blocking_enabled: Some(false),
                use_global_rules: Some(true),
                custom_rules: "@@||tiktok.com^\n||custom-block.test^".to_string(),
                upstreams: vec!["udp://1.1.1.1:53".to_string()],
                block_mode: Some(BlockMode::NoData),
                tags: vec!["work".to_string()],
            },
        ];

        let registry =
            ClientRegistry::compile(&clients, &groups, 1000, UpstreamStrategy::Failover, &[])
                .unwrap();

        // ClientID overrides IP / CIDR
        let by_cid = registry
            .match_client("10.0.0.99".parse().unwrap(), Some("WORK-LAPTOP"))
            .unwrap();
        assert_eq!(by_cid.profile_id, "laptop");
        assert!(!by_cid.blocking_enabled);
        assert_eq!(by_cid.block_mode, Some(BlockMode::NoData));
        assert_eq!(by_cid.upstream_pool.as_ref().unwrap().0, "client:laptop");

        // Exact IP overrides CIDR
        let by_ip = registry
            .match_client("192.168.10.50".parse().unwrap(), None)
            .unwrap();
        assert_eq!(by_ip.profile_id, "laptop");

        // CIDR matches other host in 192.168.10.0/24 and inherits group policy
        let by_cidr = registry
            .match_client("192.168.10.88".parse().unwrap(), None)
            .unwrap();
        assert_eq!(by_cidr.profile_id, "subnet-kid");
        assert!(by_cidr.blocking_enabled);
        assert_eq!(by_cidr.block_mode, Some(BlockMode::NxDomain));
        assert_eq!(by_cidr.upstream_pool.as_ref().unwrap().0, "group:kids");

        // Layered filter: client rule > group rule > global filter
        let global = FilterEngine::new(&["||ads.example.com^".to_string()]);
        let d1 = ClientRegistry::evaluate_domain(Some(&by_ip), &global, "tiktok.com");
        assert_eq!(d1.action, FilterAction::Allow);
        assert_eq!(d1.matched_list.as_deref(), Some("client:Work Laptop"));

        let d2 = ClientRegistry::evaluate_domain(Some(&by_cidr), &global, "tiktok.com");
        assert_eq!(d2.action, FilterAction::Block);
        assert_eq!(d2.matched_list.as_deref(), Some("group:Kids"));

        // Group allow overrides global block
        let d3 = ClientRegistry::evaluate_domain(Some(&by_cidr), &global, "ads.example.com");
        assert_eq!(d3.action, FilterAction::Allow);
        assert_eq!(d3.matched_list.as_deref(), Some("group:Kids"));
    }
}
