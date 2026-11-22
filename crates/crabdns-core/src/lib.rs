pub mod acl;
pub mod cache;
pub mod clients;
mod clock;
pub mod config;
pub mod cookies;
pub mod device_names;
pub mod dns64;
pub mod dnssec;
mod dnssec_nsec;
pub mod edns;
pub mod error;
pub mod filter;
pub mod filter_rules;
mod filter_trie;
pub mod lan;
pub mod pipeline;
mod pipeline_cache;
mod pipeline_exec;
mod pipeline_fast;
mod pipeline_post;
mod pipeline_types;
pub mod rrl;
pub mod safesearch;
pub mod security;
pub mod singleflight;
pub mod split_dns;
pub mod svcb;
pub mod upstream;
pub mod upstream_probe;
mod upstream_probe_wire;
mod upstream_transport;
mod wire;
mod wire_fast;

pub use acl::{AccessController, AclDecision, IpNet};
pub use cache::{CacheHit, CacheStats, DnsCache, PersistedCacheEntry};
pub use clients::{
    ClientGroup, ClientNameResolver, ClientProfile, ClientRegistry, ParsedClientIdentifier,
    ResolvedClientPolicy, ip_to_ptr_domain, validate_client_id, validate_client_identifier,
};
pub use config::{BlockMode, Config, SplitDnsRule, UpstreamStrategy};
pub use cookies::{CookieCheck, DnsCookieEngine};
pub use device_names::{
    DEFAULT_DHCP_LEASES_PATH, DhcpLeaseTable, MdnsNameResolver, OPENWRT_DHCP_LEASES_PATH,
    default_dhcp_leases_path, resolve_dhcp_leases_path,
};
pub use dns64::{DEFAULT_DNS64_PREFIX, Dns64Config, Dns64Prefix};
pub use dnssec::{DnssecValidator, ValidationOutcome};
pub use edns::{DEFAULT_MAX_UDP_PAYLOAD, EcsConfig};
pub use error::{CoreError, Result};
pub use filter::{FilterAction, FilterDecision, FilterEngine, FilterStats};
pub use filter_rules::{
    DnsRewriteEntry, DnsRewriteKind, FilterQueryContext, RewriteAction, validate_dns_rewrite,
};
pub use lan::{DdrConfig, HostsMatch, HostsTable, PrivatePtrRouter};
pub use pipeline::{
    DnsPipeline, LatencyHistogramSnapshot, PipelineRuntimeMetrics, QueryContext, QueryEvent,
    QueryOutcome, QueryProtocol,
};
pub use pipeline_fast::UdpFastOutcome;
pub use rrl::{ResponseRateLimiter, RrlCategory, RrlConfig, RrlDecision};
pub use safesearch::SafeSearchConfig;
pub use split_dns::SplitUpstreamRouter;
pub use svcb::SvcbSanitizeOptions;
pub use upstream::{UpstreamPool, UpstreamStatus};
pub use upstream_probe::{UpstreamCapabilities, UpstreamProtocol, probe_upstreams};
pub use wire::build_raw_formerr;
