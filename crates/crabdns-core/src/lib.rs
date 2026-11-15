pub mod acl;
pub mod cache;
pub mod config;
pub mod error;
pub mod filter;
pub mod pipeline;
pub mod split_dns;
pub mod upstream;
mod wire;

pub use acl::{AccessController, AclDecision, IpNet};
pub use cache::{CacheHit, CacheStats, DnsCache};
pub use config::{BlockMode, Config, SplitDnsRule, UpstreamStrategy};
pub use error::{CoreError, Result};
pub use filter::{FilterAction, FilterDecision, FilterEngine, FilterStats, RewriteAction};
pub use pipeline::{DnsPipeline, QueryEvent, QueryOutcome};
pub use split_dns::SplitUpstreamRouter;
pub use upstream::{UpstreamPool, UpstreamStatus};
