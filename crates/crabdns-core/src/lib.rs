pub mod acl;
pub mod cache;
pub mod clients;
mod clock;
pub mod config;
pub mod device_names;
pub mod dnssec;
pub mod edns;
pub mod error;
pub mod filter;
pub mod filter_rules;
pub mod lan;
pub mod pipeline;
mod pipeline_cache;
mod pipeline_exec;
mod pipeline_types;
pub mod security;
pub mod singleflight;
pub mod split_dns;
pub mod upstream;
pub mod upstream_probe;
mod upstream_probe_wire;
mod upstream_transport;
mod wire;

pub use acl::{AccessController, AclDecision, IpNet};
pub use cache::{CacheHit, CacheStats, DnsCache, PersistedCacheEntry};
pub use clients::{
    ClientGroup, ClientNameResolver, ClientProfile, ClientRegistry, ParsedClientIdentifier,
    ResolvedClientPolicy, ip_to_ptr_domain, validate_client_id, validate_client_identifier,
};
pub use config::{BlockMode, Config, SplitDnsRule, UpstreamStrategy};
pub use device_names::{DhcpLeaseTable, MdnsNameResolver};
pub use dnssec::{DnssecValidator, ValidationOutcome};
pub use edns::EcsConfig;
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
pub use split_dns::SplitUpstreamRouter;
pub use upstream::{UpstreamPool, UpstreamStatus};
pub use upstream_probe::{UpstreamCapabilities, UpstreamProtocol, probe_upstreams};
pub use wire::build_raw_formerr;
