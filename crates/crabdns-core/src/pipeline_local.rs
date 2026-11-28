use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::RecordType;
use tokio::sync::Notify;

use crate::blocked_services::{BlockedServicesConfig, BlockedServicesMatcher};
use crate::clients::{ResolvedClientPolicy, ip_to_ptr_domain};
use crate::edns::has_dnssec_ok;
use crate::error::Result;
use crate::lan::{HostsMatch, build_hosts_response, is_local_domain};
use crate::llmnr::LlmnrNameResolver;
use crate::pipeline::{DnsPipeline, QueryOutcome};
use crate::pipeline_exec::PolicyFlags;
use crate::pipeline_types::LogMeta;
use crate::recursor::{BuiltinRecursor, RecursiveConfig};
use crate::security::is_private_or_special_ip;
use crate::upstream::UpstreamPool;
use crate::wire::{build_error_response, extract_answer_summaries};

impl DnsPipeline {
    pub(crate) fn build_policy_flags(
        &self,
        request: &Message,
        policy: Option<&ResolvedClientPolicy>,
    ) -> PolicyFlags {
        PolicyFlags {
            blocking_disabled: self.is_blocking_paused()
                || policy.is_some_and(|p| !p.blocking_enabled),
            explicitly_allowed: false,
            cname_cloaking_on: policy
                .and_then(|p| p.cname_cloaking_blocking)
                .unwrap_or_else(|| self.cname_cloaking()),
            block_mode: policy
                .and_then(|p| p.block_mode)
                .unwrap_or_else(|| self.block_mode()),
            dnssec_on: self.dnssec_enabled.load(Ordering::Relaxed),
            client_wants_do: has_dnssec_ok(request),
            client_cd: request.checking_disabled,
            dns_rebinding_on: self.dns_rebinding_protection.load(Ordering::Relaxed),
            dns64_on: self.dns64_enabled(),
            svcb_strip_ech: self.svcb_strip_ech.load(Ordering::Relaxed),
            svcb_strip_hints: self.svcb_strip_hints.load(Ordering::Relaxed),
            cf_cdn_on: self.cf_cdn.is_enabled(),
            disable_ipv6: false,
        }
    }

    pub(crate) fn resolve_unconfigured_client_name(
        &self,
        ip: IpAddr,
    ) -> (Option<String>, &'static str) {
        if self.hosts_enabled.load(Ordering::Relaxed)
            && let Some(HostsMatch::Ptr(name)) = self
                .hosts_table
                .load()
                .lookup(&ip_to_ptr_domain(ip), RecordType::PTR)
        {
            return (Some(name), "hosts");
        }

        if self.dhcp_leases_enabled.load(Ordering::Relaxed)
            && let Some(name) = self.dhcp_leases.load().lookup(ip)
        {
            return (Some(name.to_string()), "dhcp");
        }

        if self.mdns_enabled.load(Ordering::Relaxed) {
            match self.mdns_resolver.lookup_cached(ip) {
                Some(Some(name)) => return (Some(name), "mdns"),
                Some(None) => {}
                None => {
                    if is_private_or_special_ip(ip) {
                        self.mdns_resolver.spawn_lookup_if_needed(ip);
                    }
                }
            }
        }

        if self.llmnr_enabled.load(Ordering::Relaxed) {
            match self.llmnr_resolver.lookup_cached(ip) {
                Some(Some(name)) => return (Some(name), "llmnr"),
                Some(None) => {}
                None => {
                    if is_private_or_special_ip(ip) {
                        self.llmnr_resolver.spawn_lookup_if_needed(ip);
                    }
                }
            }
        }

        match self.name_resolver.lookup_cached(ip) {
            Some(Some(name)) => return (Some(name), "rdns"),
            Some(None) => return (None, "unknown"),
            None => {}
        }

        if self.rdns_enabled.load(Ordering::Relaxed)
            && let Some(pool) = self.rdns_upstream_for(ip)
        {
            self.name_resolver.spawn_rdns_if_needed(ip, pool);
        }
        (None, "unknown")
    }

    fn rdns_upstream_for(&self, ip: IpAddr) -> Option<Arc<UpstreamPool>> {
        if !is_private_or_special_ip(ip)
            || ip.is_loopback()
            || ip.is_unspecified()
            || ip.is_multicast()
        {
            return None;
        }
        let ptr_router = self.private_ptr_router.load();
        if let Some(pool) = &ptr_router.pool {
            return Some(Arc::clone(pool));
        }
        if ptr_router.enabled {
            return None;
        }
        let upstream = self.upstream.load_full();
        upstream.has_private_endpoint().then_some(upstream)
    }

    pub fn set_blocked_services(&self, config: BlockedServicesConfig) {
        self.blocked_services
            .store(Arc::new(BlockedServicesMatcher::new(config)));
    }

    pub fn set_recursive(&self, config: &RecursiveConfig, timeout_ms: u64) -> Result<()> {
        if config.enabled {
            let built = BuiltinRecursor::new(config, timeout_ms)?;
            self.recursor.store(Some(Arc::new(built)));
        } else {
            self.recursor.store(None);
        }
        Ok(())
    }

    pub fn set_llmnr_enabled(&self, enabled: bool) {
        self.llmnr_enabled.store(enabled, Ordering::Relaxed);
        self.llmnr_notify.notify_waiters();
    }

    pub fn llmnr_notify(&self) -> Arc<Notify> {
        Arc::clone(&self.llmnr_notify)
    }

    pub fn llmnr_resolver(&self) -> Arc<LlmnrNameResolver> {
        Arc::clone(&self.llmnr_resolver)
    }

    pub(crate) fn check_policy_interceptors(
        &self,
        request: &Message,
        meta: &LogMeta,
        policy: Option<&ResolvedClientPolicy>,
        flags: PolicyFlags,
    ) -> Result<Option<Vec<u8>>> {
        if let Some(resp) = self.check_blocked_services_interceptor(
            request,
            meta,
            policy,
            flags.blocking_disabled,
            flags.block_mode,
        )? {
            return Ok(Some(resp));
        }
        self.check_safesearch_interceptor(request, meta, policy, flags.blocking_disabled)
    }

    pub(crate) async fn check_multicast_local_resolution(
        &self,
        request: &Message,
        meta: &LogMeta,
    ) -> Result<Option<Vec<u8>>> {
        if self.mdns_enabled.load(Ordering::Relaxed)
            && (is_local_domain(&meta.domain) || meta.qtype == RecordType::PTR)
            && let Some(matched) = self
                .mdns_resolver
                .resolve_forward(&meta.domain, meta.qtype)
                .await
        {
            let resp = build_hosts_response(request, &matched)?;
            self.emit_log(
                meta,
                QueryOutcome::Rewritten,
                Some("mdns:local".to_string()),
                Some("mdns".to_string()),
                None,
                "NOERROR",
                extract_answer_summaries(&resp),
            );
            return Ok(Some(resp));
        }

        if self.llmnr_enabled.load(Ordering::Relaxed)
            && (!meta.domain.contains('.') || meta.qtype == RecordType::PTR)
            && let Some(matched) = self
                .llmnr_resolver
                .resolve_forward(&meta.domain, meta.qtype)
                .await
        {
            let resp = build_hosts_response(request, &matched)?;
            self.emit_log(
                meta,
                QueryOutcome::Rewritten,
                Some("llmnr:local".to_string()),
                Some("llmnr".to_string()),
                None,
                "NOERROR",
                extract_answer_summaries(&resp),
            );
            return Ok(Some(resp));
        }

        Ok(None)
    }

    pub(crate) fn check_local_domain_block(
        &self,
        request: &Message,
        meta: &LogMeta,
    ) -> Result<Option<Vec<u8>>> {
        if self.block_local_domains.load(Ordering::Relaxed)
            && is_local_domain(&meta.domain)
            && self
                .split_router
                .load()
                .resolve_with_policy(&meta.domain)
                .is_none()
        {
            let resp = build_error_response(request, ResponseCode::NXDomain)?;
            if !self.suppress_local_domain_logs.load(Ordering::Relaxed) {
                self.emit_log(
                    meta,
                    QueryOutcome::Blocked,
                    Some("lan:local-mdns".to_string()),
                    Some("lan".to_string()),
                    None,
                    "NXDOMAIN",
                    Vec::new(),
                );
            }
            return Ok(Some(resp));
        }
        Ok(None)
    }
}
