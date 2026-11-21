pub mod acl;
pub mod cache;
pub mod clients;
pub mod config;
pub mod dnssec;
pub mod edns;
pub mod error;
pub mod filter;
pub mod lan;
pub mod pipeline;
mod pipeline_exec;
pub mod security;
pub mod singleflight;
pub mod split_dns;
pub mod upstream;
pub mod upstream_probe;
mod upstream_transport;
mod wire;

pub use acl::{AccessController, AclDecision, IpNet};
pub use cache::{CacheHit, CacheStats, DnsCache, PersistedCacheEntry};
pub use clients::{
    ClientGroup, ClientNameResolver, ClientProfile, ClientRegistry, ParsedClientIdentifier,
    ResolvedClientPolicy, ip_to_ptr_domain, validate_client_id, validate_client_identifier,
};
pub use config::{BlockMode, Config, SplitDnsRule, UpstreamStrategy};
pub use dnssec::{DnssecValidator, ValidationOutcome};
pub use edns::EcsConfig;
pub use error::{CoreError, Result};
pub use filter::{FilterAction, FilterDecision, FilterEngine, FilterStats, RewriteAction};
pub use lan::{DdrConfig, HostsMatch, HostsTable, PrivatePtrRouter};
pub use pipeline::{DnsPipeline, QueryContext, QueryEvent, QueryOutcome, QueryProtocol};
pub use split_dns::SplitUpstreamRouter;
pub use upstream::{UpstreamPool, UpstreamStatus};
pub use upstream_probe::{UpstreamCapabilities, UpstreamProtocol, probe_upstreams};
