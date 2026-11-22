use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use axum::serve::ListenerExt;
use crabdns_core::{
    Config, DdrConfig, DnsCache, DnsPipeline, FilterEngine, QueryEvent, UpstreamPool,
};
use crabdns_storage::{StorageEngine, spawn_log_sink};
use crabdns_web::acme_api::AcmeManager;
use crabdns_web::tls_api::TlsReloader;
use crabdns_web::update_api::UpdateManager;
use crabdns_web::{AppState, build_router_with_managers};
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, broadcast, mpsc, watch};
use tokio::task::{JoinHandle, JoinSet};

mod doh3;
mod doq;
mod dot;
mod listeners;
mod tasks;
mod tls;

pub(crate) use listeners::{
    ActiveConnGuard, IpConnGuard, IpConnLimiter, bind_udp_sockets, handle_dns_stream_with_context,
    run_tcp_server, run_udp_server,
};
pub use tasks::prune_logs_once;

const UDP_MAX_INFLIGHT: usize = 2048;
const WEB_MAX_CONNECTIONS: usize = 512;
pub(crate) const GRACEFUL_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
const SHUTDOWN_JOIN_TIMEOUT: Duration = Duration::from_secs(3);

pub struct RunningServer {
    pub dns_addr: SocketAddr,
    pub web_addr: SocketAddr,
    pub web_tls_addr: Option<SocketAddr>,
    pub dot_addr: Option<SocketAddr>,
    pub doq_addr: Option<SocketAddr>,
    pub doh3_addr: Option<SocketAddr>,
    pub pipeline: Arc<DnsPipeline>,
    pub storage: Arc<StorageEngine>,
    config: Arc<ArcSwap<Config>>,
    shutdown_tx: watch::Sender<bool>,
    udp_tasks: Vec<JoinHandle<()>>,
    tcp_task: JoinHandle<()>,
    dot_task: Option<JoinHandle<()>>,
    doq_task: Option<JoinHandle<()>>,
    doh3_task: Option<JoinHandle<()>>,
    web_task: JoinHandle<()>,
    web_tls_accept_task: Option<JoinHandle<()>>,
    web_tls_task: Option<JoinHandle<()>>,
    sub_refresh_task: JoinHandle<()>,
    hosts_watch_task: JoinHandle<()>,
    dhcp_watch_task: JoinHandle<()>,
    neighbor_watch_task: JoinHandle<()>,
    mdns_watch_task: JoinHandle<()>,
    cache_persist_task: JoinHandle<()>,
    log_prune_task: JoinHandle<()>,
    cf_cdn_task: JoinHandle<()>,
    tls_watch_task: Option<JoinHandle<()>>,
    acme_renew_task: JoinHandle<()>,
    acme_http_task: Option<JoinHandle<()>>,
    sighup_task: Option<JoinHandle<()>>,
    sink_handle: JoinHandle<()>,
}

impl RunningServer {
    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);

        for task in self.udp_tasks {
            join_with_timeout(task, SHUTDOWN_JOIN_TIMEOUT).await;
        }
        join_with_timeout(self.tcp_task, SHUTDOWN_JOIN_TIMEOUT).await;
        join_opt_with_timeout(self.dot_task, SHUTDOWN_JOIN_TIMEOUT).await;
        join_opt_with_timeout(self.doq_task, SHUTDOWN_JOIN_TIMEOUT).await;
        join_opt_with_timeout(self.doh3_task, SHUTDOWN_JOIN_TIMEOUT).await;
        join_with_timeout(self.web_task, SHUTDOWN_JOIN_TIMEOUT).await;
        join_opt_with_timeout(self.web_tls_accept_task, SHUTDOWN_JOIN_TIMEOUT).await;
        join_opt_with_timeout(self.web_tls_task, SHUTDOWN_JOIN_TIMEOUT).await;
        join_with_timeout(self.sub_refresh_task, GRACEFUL_DRAIN_TIMEOUT).await;
        join_with_timeout(self.hosts_watch_task, GRACEFUL_DRAIN_TIMEOUT).await;
        join_with_timeout(self.dhcp_watch_task, GRACEFUL_DRAIN_TIMEOUT).await;
        join_with_timeout(self.neighbor_watch_task, GRACEFUL_DRAIN_TIMEOUT).await;
        join_with_timeout(self.mdns_watch_task, GRACEFUL_DRAIN_TIMEOUT).await;
        join_with_timeout(self.cache_persist_task, GRACEFUL_DRAIN_TIMEOUT).await;
        join_with_timeout(self.log_prune_task, GRACEFUL_DRAIN_TIMEOUT).await;
        join_with_timeout(self.cf_cdn_task, GRACEFUL_DRAIN_TIMEOUT).await;
        join_opt_with_timeout(self.tls_watch_task, GRACEFUL_DRAIN_TIMEOUT).await;
        join_with_timeout(self.acme_renew_task, GRACEFUL_DRAIN_TIMEOUT).await;
        join_opt_with_timeout(self.acme_http_task, GRACEFUL_DRAIN_TIMEOUT).await;
        join_opt_with_timeout(self.sighup_task, GRACEFUL_DRAIN_TIMEOUT).await;

        if self.config.load().cache_persist_enabled {
            let now_secs = tasks::current_unix_secs();
            let cache = self.pipeline.cache();
            let storage = Arc::clone(&self.storage);
            match tokio::task::spawn_blocking(move || {
                let snapshot = cache.export_persisted(now_secs);
                storage.save_dns_cache(&snapshot)
            })
            .await
            {
                Ok(Ok(_)) => {}
                Ok(Err(err)) => {
                    tracing::warn!(error = %err, "failed to persist dns cache on shutdown");
                }
                Err(err) => {
                    tracing::warn!(error = %err, "dns cache shutdown persistence task panicked");
                }
            }
        }

        drop(self.pipeline);
        join_with_timeout(self.sink_handle, Duration::from_secs(5)).await;
        drop(self.storage);
    }
}

pub(crate) async fn drain_join_set(tasks: &mut JoinSet<()>, timeout: Duration) {
    let drain = async { while tasks.join_next().await.is_some() {} };
    if tokio::time::timeout(timeout, drain).await.is_err() {
        tasks.shutdown().await;
    }
}

async fn join_with_timeout(mut handle: JoinHandle<()>, timeout: Duration) {
    if tokio::time::timeout(timeout, &mut handle).await.is_err() {
        handle.abort();
        let _ = handle.await;
    }
}

async fn join_opt_with_timeout(handle: Option<JoinHandle<()>>, timeout: Duration) {
    if let Some(h) = handle {
        join_with_timeout(h, timeout).await;
    }
}

async fn shutdown_signal(mut shutdown_rx: watch::Receiver<bool>) {
    if *shutdown_rx.borrow() {
        return;
    }
    while shutdown_rx.changed().await.is_ok() {
        if *shutdown_rx.borrow() {
            break;
        }
    }
}

fn merge_saved_config(config: &mut Config, saved_cfg: Config) {
    config.upstreams = saved_cfg.upstreams;
    config.bootstrap_dns = saved_cfg.bootstrap_dns;
    config.upstream_strategy = saved_cfg.upstream_strategy;
    config.cache_size = saved_cfg.cache_size;
    config.optimistic_cache = saved_cfg.optimistic_cache;
    config.cache_min_ttl_secs = saved_cfg.cache_min_ttl_secs;
    config.cache_max_ttl_secs = saved_cfg.cache_max_ttl_secs;
    config.cache_prefetch_enabled = saved_cfg.cache_prefetch_enabled;
    config.cache_persist_enabled = saved_cfg.cache_persist_enabled;
    config.upstream_timeout_ms = saved_cfg.upstream_timeout_ms;
    config.log_retention_hours = saved_cfg.log_retention_hours;
    config.block_mode = saved_cfg.block_mode;
    config.allow_cidrs = saved_cfg.allow_cidrs;
    config.deny_cidrs = saved_cfg.deny_cidrs;
    config.rate_limit_qps = saved_cfg.rate_limit_qps;
    config.web_auth_enabled = saved_cfg.web_auth_enabled;
    config.web_username = saved_cfg.web_username;
    config.web_password_hash = saved_cfg.web_password_hash;
    config.setup_completed = saved_cfg.setup_completed;
    config.split_dns = saved_cfg.split_dns;
    config.cname_cloaking_blocking = saved_cfg.cname_cloaking_blocking;
    config.doh_enabled = saved_cfg.doh_enabled;
    config.allow_private_subscriptions = saved_cfg.allow_private_subscriptions;
    config.ecs_enabled = saved_cfg.ecs_enabled;
    config.ecs_custom_ip = saved_cfg.ecs_custom_ip;
    config.ecs_ipv4_prefix = saved_cfg.ecs_ipv4_prefix;
    config.ecs_ipv6_prefix = saved_cfg.ecs_ipv6_prefix;
    config.dnssec_enabled = saved_cfg.dnssec_enabled;
    config.hosts_enabled = saved_cfg.hosts_enabled;
    config.hosts_path = saved_cfg.hosts_path;
    config.dhcp_leases_enabled = saved_cfg.dhcp_leases_enabled;
    config.dhcp_leases_path = saved_cfg.dhcp_leases_path;
    config.dhcp_leases_forward_enabled = saved_cfg.dhcp_leases_forward_enabled;
    config.dhcp_leases_domain = saved_cfg.dhcp_leases_domain;
    config.mdns_enabled = saved_cfg.mdns_enabled;
    config.sni_client_id_hostnames = saved_cfg.sni_client_id_hostnames;
    config.private_ptr_enabled = saved_cfg.private_ptr_enabled;
    config.private_ptr_upstreams = saved_cfg.private_ptr_upstreams;
    config.ddr_enabled = saved_cfg.ddr_enabled;
    config.ddr_hostname = saved_cfg.ddr_hostname;
    config.dns_rebinding_protection = saved_cfg.dns_rebinding_protection;
    config.block_any_queries = saved_cfg.block_any_queries;
    config.trusted_proxies = saved_cfg.trusted_proxies;
    config.rdns_enabled = saved_cfg.rdns_enabled;
    config.safesearch = saved_cfg.safesearch;
    config.dns64_enabled = saved_cfg.dns64_enabled;
    config.dns64_prefixes = saved_cfg.dns64_prefixes;
    config.svcb_strip_ech = saved_cfg.svcb_strip_ech;
    config.svcb_strip_hints = saved_cfg.svcb_strip_hints;
    config.ede_enabled = saved_cfg.ede_enabled;
    config.dns_cookies_enabled = saved_cfg.dns_cookies_enabled;
    config.dns_cookies_require_valid = saved_cfg.dns_cookies_require_valid;
    config.max_udp_payload_size = saved_cfg.max_udp_payload_size;
    config.rrl_enabled = saved_cfg.rrl_enabled;
    config.rrl_responses_per_second = saved_cfg.rrl_responses_per_second;
    config.rrl_slip = saved_cfg.rrl_slip;
    config.rrl_window_secs = saved_cfg.rrl_window_secs;
    config.acme_enabled = saved_cfg.acme_enabled;
    config.acme_domains = saved_cfg.acme_domains;
    config.acme_email = saved_cfg.acme_email;
    config.acme_directory_url = saved_cfg.acme_directory_url;
    config.acme_challenge_type = saved_cfg.acme_challenge_type;
    config.acme_http_listen = saved_cfg.acme_http_listen;
    config.acme_renew_before_days = saved_cfg.acme_renew_before_days;
    if saved_cfg.tls_cert_path.is_some() {
        config.tls_cert_path = saved_cfg.tls_cert_path;
    }
    if saved_cfg.tls_key_path.is_some() {
        config.tls_key_path = saved_cfg.tls_key_path;
    }
}

fn init_pipeline(
    cfg: &Config,
    storage: &StorageEngine,
    log_tx: mpsc::Sender<QueryEvent>,
) -> anyhow::Result<Arc<DnsPipeline>> {
    let filter = Arc::new(FilterEngine::new(&cfg.custom_rules));
    let custom_rules_text = storage
        .load_custom_rules()?
        .unwrap_or_else(|| cfg.custom_rules.join("\n"));
    let custom_enabled = storage.load_custom_rules_enabled()?;
    let mut sub_contents = storage.load_enabled_named_subscription_contents()?;
    let rewrites = storage.list_dns_rewrites()?;
    let rewrite_lines: Vec<String> = rewrites
        .into_iter()
        .filter(|r| r.enabled)
        .map(|r| r.to_filter_rule())
        .collect();
    if !rewrite_lines.is_empty() {
        sub_contents.push(("rewrites".to_string(), rewrite_lines.join("\n")));
    }
    filter.reload_from_named_sources(&custom_rules_text, custom_enabled, &sub_contents);

    let cache = Arc::new(DnsCache::with_options(
        cfg.cache_size,
        cfg.optimistic_cache,
        cfg.cache_min_ttl_secs,
        cfg.cache_max_ttl_secs,
        cfg.cache_prefetch_enabled,
    ));
    if cfg.cache_persist_enabled {
        let now_secs = tasks::current_unix_secs();
        match storage.load_dns_cache(now_secs, cache.stale_grace_secs()) {
            Ok(entries) => {
                let restored = cache.import_persisted(entries, now_secs);
                if restored > 0 {
                    tracing::info!(restored, "restored persisted dns cache entries");
                }
            }
            Err(err) => {
                tracing::warn!(error = %err, "failed to load persisted dns cache");
            }
        }
    }

    let upstream = Arc::new(UpstreamPool::new_with_bootstrap(
        &cfg.upstreams,
        cfg.upstream_timeout_ms,
        cfg.upstream_strategy,
        &cfg.bootstrap_dns,
    )?);

    let pipeline = Arc::new(DnsPipeline::new(filter, cache, upstream, Some(log_tx)));
    configure_pipeline(&pipeline, cfg, storage)?;
    Ok(pipeline)
}

fn configure_pipeline(
    pipeline: &DnsPipeline,
    cfg: &Config,
    storage: &StorageEngine,
) -> anyhow::Result<()> {
    pipeline.set_block_mode(cfg.block_mode);
    pipeline.set_cname_cloaking(cfg.cname_cloaking_blocking);
    pipeline.set_rdns_enabled(cfg.rdns_enabled);
    pipeline.reload_acl(&cfg.allow_cidrs, &cfg.deny_cidrs, cfg.rate_limit_qps)?;
    pipeline.reload_split_dns_with_resolver(
        &cfg.split_dns,
        cfg.upstream_timeout_ms,
        cfg.upstream_strategy,
        &cfg.bootstrap_dns,
        |url| storage.load_split_dns_list(url).ok().flatten(),
    )?;
    pipeline.reload_ecs(
        cfg.ecs_enabled,
        cfg.ecs_custom_ip.as_deref(),
        cfg.ecs_ipv4_prefix,
        cfg.ecs_ipv6_prefix,
    )?;
    pipeline.set_dnssec_enabled(cfg.dnssec_enabled);
    pipeline.set_hosts_enabled(cfg.hosts_enabled);
    if cfg.hosts_enabled {
        let resolved_hosts = cfg.hosts_path.as_deref().unwrap_or("/etc/hosts");
        if let Err(err) = pipeline.reload_hosts_from_path(std::path::Path::new(resolved_hosts)) {
            tracing::warn!(path = %resolved_hosts, error = %err, "failed to load hosts file");
        }
    }
    pipeline.set_dhcp_leases_enabled(cfg.dhcp_leases_enabled);
    pipeline.set_dhcp_leases_forward(
        cfg.dhcp_leases_forward_enabled,
        cfg.dhcp_leases_domain.clone(),
    );
    if cfg.dhcp_leases_enabled {
        let resolved_dhcp = crabdns_core::resolve_dhcp_leases_path(cfg.dhcp_leases_path.as_deref());
        if let Err(err) = pipeline.reload_dhcp_leases_from_path(std::path::Path::new(resolved_dhcp))
        {
            tracing::warn!(path = %resolved_dhcp, error = %err, "failed to load DHCP leases file");
        }
    }
    pipeline.set_mdns_enabled(cfg.mdns_enabled);
    pipeline.reload_private_ptr(
        cfg.private_ptr_enabled,
        &cfg.private_ptr_upstreams,
        cfg.upstream_timeout_ms,
        cfg.upstream_strategy,
        &cfg.bootstrap_dns,
    )?;
    pipeline.set_dns_rebinding_protection(cfg.dns_rebinding_protection);
    pipeline.set_block_any_queries(cfg.block_any_queries);
    pipeline.set_safesearch(cfg.safesearch.clone());
    pipeline.reload_dns64(cfg.dns64_enabled, &cfg.dns64_prefixes)?;
    pipeline.set_svcb_sanitization(cfg.svcb_strip_ech, cfg.svcb_strip_hints);
    pipeline.reload_cf_cdn(cfg.cf_cdn.clone());
    pipeline.set_ede_enabled(cfg.ede_enabled);
    pipeline.set_dns_cookies(cfg.dns_cookies_enabled, cfg.dns_cookies_require_valid);
    pipeline.set_max_udp_payload_size(cfg.max_udp_payload_size);
    pipeline.set_rrl(crabdns_core::RrlConfig {
        enabled: cfg.rrl_enabled,
        responses_per_second: cfg.rrl_responses_per_second,
        slip: cfg.rrl_slip,
        window_secs: cfg.rrl_window_secs,
    });

    let clients = storage.list_clients()?;
    let groups = storage.list_client_groups()?;
    pipeline.reload_clients(
        &clients,
        &groups,
        cfg.upstream_timeout_ms,
        cfg.upstream_strategy,
        &cfg.bootstrap_dns,
    )?;
    Ok(())
}

struct WebAndTlsHandles {
    dot_addr: Option<SocketAddr>,
    dot_task: Option<JoinHandle<()>>,
    doq_addr: Option<SocketAddr>,
    doq_task: Option<JoinHandle<()>>,
    doh3_addr: Option<SocketAddr>,
    doh3_task: Option<JoinHandle<()>>,
    web_addr: SocketAddr,
    web_task: JoinHandle<()>,
    web_tls_addr: Option<SocketAddr>,
    web_tls_accept_task: Option<JoinHandle<()>>,
    web_tls_task: Option<JoinHandle<()>>,
}

async fn start_dot_listener(
    config: &Arc<ArcSwap<Config>>,
    pipeline: &Arc<DnsPipeline>,
    tls_manager: &Arc<tls::TlsManager>,
    max_connections: usize,
    idle_timeout: Duration,
    shutdown_rx: &watch::Receiver<bool>,
) -> anyhow::Result<(Option<SocketAddr>, Option<JoinHandle<()>>)> {
    let current_cfg = config.load_full();
    let (Some(addr), Some(acceptor)) = (current_cfg.listen_dot, tls_manager.dot_acceptor()) else {
        return Ok((None, None));
    };
    let dot_listener = dot::bind_dot_listener(addr).await?;
    let bound_dot = dot_listener.local_addr()?;
    let task = tokio::spawn(dot::run_dot_server(
        dot_listener,
        acceptor,
        Arc::clone(config),
        Arc::clone(pipeline),
        max_connections,
        idle_timeout,
        shutdown_rx.clone(),
    ));
    Ok((Some(bound_dot), Some(task)))
}

fn start_doq_listener(
    config: &Arc<ArcSwap<Config>>,
    pipeline: &Arc<DnsPipeline>,
    tls_manager: &Arc<tls::TlsManager>,
    max_connections: usize,
    idle_timeout: Duration,
    shutdown_rx: &watch::Receiver<bool>,
) -> anyhow::Result<(Option<SocketAddr>, Option<JoinHandle<()>>)> {
    let cfg = config.load_full();
    let (Some(addr), Some(cert_p), Some(key_p)) = (
        cfg.listen_doq,
        cfg.tls_cert_path.as_deref(),
        cfg.tls_key_path.as_deref(),
    ) else {
        return Ok((None, None));
    };
    let quic_cfg = doq::build_doq_server_config(cert_p, key_p, idle_timeout)?;
    let endpoint = doq::bind_doq_endpoint(addr, quic_cfg)?;
    let bound = endpoint.local_addr()?;
    tls_manager.set_doq_endpoint(Some(endpoint.clone()));
    let task = tokio::spawn(doq::run_doq_server(
        endpoint,
        Arc::clone(config),
        Arc::clone(pipeline),
        max_connections,
        idle_timeout,
        shutdown_rx.clone(),
    ));
    Ok((Some(bound), Some(task)))
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn start_web_and_tls(
    config: &Arc<ArcSwap<Config>>,
    pipeline: &Arc<DnsPipeline>,
    storage: &Arc<StorageEngine>,
    tls_manager: &Arc<tls::TlsManager>,
    acme_manager: &Arc<AcmeManager>,
    live_tx: broadcast::Sender<QueryEvent>,
    tcp_max_connections: usize,
    tcp_idle_timeout: Duration,
    shutdown_rx: &watch::Receiver<bool>,
) -> anyhow::Result<WebAndTlsHandles> {
    let current_cfg = config.load_full();

    let (dot_addr, dot_task) = start_dot_listener(
        config,
        pipeline,
        tls_manager,
        tcp_max_connections,
        tcp_idle_timeout,
        shutdown_rx,
    )
    .await?;

    let (quic_addr, quic_task) = start_doq_listener(
        config,
        pipeline,
        tls_manager,
        tcp_max_connections,
        tcp_idle_timeout,
        shutdown_rx,
    )?;

    let (doh3_addr, doh3_ep, doh3_task) = doh3::start_doh3_listener(
        config,
        pipeline,
        tcp_max_connections,
        tcp_idle_timeout,
        shutdown_rx,
    )?;
    if let Some(ep) = doh3_ep {
        tls_manager.set_doh3_endpoint(Some(ep));
    }

    let web_listener = TcpListener::bind(current_cfg.listen_web).await?;
    let web_addr = web_listener.local_addr()?;

    let web_tls_listener = match current_cfg.listen_web_tls {
        Some(addr) => Some(TcpListener::bind(addr).await?),
        None => None,
    };
    let bound_web_tls = web_tls_listener.as_ref().and_then(|l| l.local_addr().ok());
    tls_manager.update_bound_addrs(bound_web_tls, dot_addr, quic_addr, doh3_addr);

    pipeline.reload_ddr(DdrConfig {
        enabled: current_cfg.ddr_enabled,
        hostname: current_cfg.ddr_hostname.clone(),
        dot_port: dot_addr.map(|a| a.port()),
        doq_port: quic_addr.map(|a| a.port()),
        doh_enabled: current_cfg.doh_enabled,
        doh_port: bound_web_tls.map(|a| a.port()).or(Some(web_addr.port())),
    });

    let tls_reloader: Option<Arc<dyn TlsReloader>> = Some(Arc::clone(tls_manager) as _);
    let app = build_router_with_managers(
        AppState {
            config: Arc::clone(config),
            pipeline: Arc::clone(pipeline),
            storage: Arc::clone(storage),
            live_tx,
            tls_reloader,
        },
        Arc::new(UpdateManager::new()),
        Arc::clone(acme_manager),
    );

    let web_max_connections = tcp_max_connections.max(WEB_MAX_CONNECTIONS);
    let (web_tls_addr, web_tls_accept_task, web_tls_task) =
        match (web_tls_listener, tls_manager.https_acceptor()) {
            (Some(listener), Some(acceptor)) => {
                let (https_listener, addr, accept_task) = tls::HttpsTlsListener::from_tcp_listener(
                    listener,
                    acceptor,
                    shutdown_rx.clone(),
                )?;
                let tls_app = app.clone();
                let tls_shutdown = shutdown_rx.clone();
                let limited_https = tls::PermittedListener::new(
                    https_listener,
                    web_max_connections,
                    Arc::clone(pipeline),
                );
                let serve_task = tokio::spawn(async move {
                    if let Err(err) = axum::serve(
                        limited_https.tap_io(|_| {}),
                        tls_app.into_make_service_with_connect_info::<SocketAddr>(),
                    )
                    .with_graceful_shutdown(shutdown_signal(tls_shutdown))
                    .await
                    {
                        tracing::error!(error = %err, "HTTPS web server error");
                    }
                });
                (Some(addr), Some(accept_task), Some(serve_task))
            }
            _ => (None, None, None),
        };

    let web_shutdown = shutdown_rx.clone();
    let limited_web =
        tls::PermittedListener::new(web_listener, web_max_connections, Arc::clone(pipeline));
    let web_task = tokio::spawn(async move {
        if let Err(err) = axum::serve(
            limited_web.tap_io(|_| {}),
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown_signal(web_shutdown))
        .await
        {
            tracing::error!(error = %err, "web server error");
        }
    });

    Ok(WebAndTlsHandles {
        dot_addr,
        dot_task,
        doq_addr: quic_addr,
        doq_task: quic_task,
        doh3_addr,
        doh3_task,
        web_addr,
        web_task,
        web_tls_addr,
        web_tls_accept_task,
        web_tls_task,
    })
}

struct BackgroundTasks {
    sub_refresh: JoinHandle<()>,
    hosts_watch: JoinHandle<()>,
    dhcp_watch: JoinHandle<()>,
    neighbor_watch: JoinHandle<()>,
    mdns_watch: JoinHandle<()>,
    cache_persist: JoinHandle<()>,
    log_prune: JoinHandle<()>,
    cf_cdn_speedtest: JoinHandle<()>,
    tls_watch: Option<JoinHandle<()>>,
    sighup: Option<JoinHandle<()>>,
}

fn spawn_background_tasks(
    config: Arc<ArcSwap<Config>>,
    pipeline: Arc<DnsPipeline>,
    storage: Arc<StorageEngine>,
    tls_manager: &Arc<tls::TlsManager>,
    tls_active: bool,
    shutdown_rx: &watch::Receiver<bool>,
) -> BackgroundTasks {
    BackgroundTasks {
        tls_watch: tls_active
            .then(|| tasks::spawn_tls_watch_task(Arc::clone(tls_manager), shutdown_rx.clone())),
        sighup: tasks::spawn_sighup_task(
            Arc::clone(&config),
            Arc::clone(&pipeline),
            Arc::clone(tls_manager),
            shutdown_rx.clone(),
        ),
        sub_refresh: tasks::spawn_subscription_refresh_task(
            Arc::clone(&config),
            Arc::clone(&storage),
            Arc::clone(&pipeline),
            shutdown_rx.clone(),
        ),
        hosts_watch: tasks::spawn_hosts_watch_task(
            Arc::clone(&config),
            Arc::clone(&pipeline),
            shutdown_rx.clone(),
        ),
        dhcp_watch: tasks::spawn_dhcp_lease_refresh_task(
            Arc::clone(&config),
            Arc::clone(&pipeline),
            shutdown_rx.clone(),
        ),
        neighbor_watch: tasks::spawn_neighbor_watch_task(
            Arc::clone(&pipeline),
            shutdown_rx.clone(),
        ),
        mdns_watch: tasks::spawn_mdns_listener_task(
            Arc::clone(&config),
            Arc::clone(&pipeline),
            shutdown_rx.clone(),
        ),
        cf_cdn_speedtest: tasks::spawn_cf_cdn_speedtest_task(
            Arc::clone(&config),
            Arc::clone(&pipeline),
            shutdown_rx.clone(),
        ),
        cache_persist: tasks::spawn_cache_persist_task(
            Arc::clone(&config),
            pipeline,
            Arc::clone(&storage),
            shutdown_rx.clone(),
        ),
        log_prune: tasks::spawn_log_prune_task(config, storage, shutdown_rx.clone()),
    }
}

#[allow(clippy::too_many_lines)]
pub async fn spawn_server(mut config: Config) -> anyhow::Result<RunningServer> {
    let storage = Arc::new(StorageEngine::open(&config.data_dir)?);

    if let Some(saved_cfg) = storage.load_config()? {
        merge_saved_config(&mut config, saved_cfg);
    }

    if config.acme_enabled && (config.tls_cert_path.is_none() || config.tls_key_path.is_none()) {
        let (acme_cert, acme_key, _) = AcmeManager::acme_paths(&config.data_dir);
        if acme_cert.is_file() && acme_key.is_file() {
            config.tls_cert_path = Some(acme_cert);
            config.tls_key_path = Some(acme_key);
        }
    }

    let config = Arc::new(ArcSwap::from_pointee(config));
    let current_cfg = config.load_full();

    let (log_tx, log_rx) = mpsc::channel::<QueryEvent>(4096);
    let (live_tx, _) = broadcast::channel::<QueryEvent>(512);
    let sink_handle = spawn_log_sink(Arc::clone(&storage), log_rx, live_tx.clone());
    let pipeline = init_pipeline(&current_cfg, &storage, log_tx)?;

    let tcp_max_connections = current_cfg.tcp_max_connections.max(1);
    let tcp_idle_timeout = Duration::from_secs(current_cfg.tcp_idle_timeout_secs.max(1));
    let tls_manager = Arc::new(tls::TlsManager::new(
        current_cfg.listen_web_tls,
        current_cfg.listen_dot,
        current_cfg.listen_doq,
        current_cfg.listen_doh3,
        tcp_idle_timeout,
        current_cfg.tls_cert_path.as_deref(),
        current_cfg.tls_key_path.as_deref(),
    )?);

    let tcp_listener = TcpListener::bind(current_cfg.listen_dns).await?;
    let dns_addr = tcp_listener.local_addr()?;
    let udp_worker_count = std::thread::available_parallelism()
        .map_or(2, std::num::NonZeroUsize::get)
        .clamp(2, 16);
    let udp_sockets = bind_udp_sockets(dns_addr, udp_worker_count)?;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let acme_manager = Arc::new(AcmeManager::new());
    let web_tls = start_web_and_tls(
        &config,
        &pipeline,
        &storage,
        &tls_manager,
        &acme_manager,
        live_tx,
        tcp_max_connections,
        tcp_idle_timeout,
        &shutdown_rx,
    )
    .await?;
    let acme_http_task = tasks::start_acme_http_listener(
        current_cfg.acme_http_listen,
        acme_manager.http_challenges.clone(),
        shutdown_rx.clone(),
    )
    .await?;
    let acme_renew_task = tasks::spawn_acme_renew_task(
        Arc::clone(&config),
        Arc::clone(&pipeline),
        Arc::clone(&tls_manager),
        Arc::clone(&acme_manager),
        shutdown_rx.clone(),
    );

    tracing::info!(
        dns = %dns_addr,
        dot = ?web_tls.dot_addr,
        doq = ?web_tls.doq_addr,
        web = %web_tls.web_addr,
        web_tls = ?web_tls.web_tls_addr,
        "crabdns started"
    );

    let udp_limiter = Arc::new(Semaphore::new(UDP_MAX_INFLIGHT));
    let udp_tasks = udp_sockets
        .into_iter()
        .map(|sock| {
            let udp_pipeline = Arc::clone(&pipeline);
            let limiter = Arc::clone(&udp_limiter);
            let rx = shutdown_rx.clone();
            tokio::spawn(run_udp_server(sock, udp_pipeline, limiter, rx))
        })
        .collect();

    let tcp_task = tokio::spawn(run_tcp_server(
        tcp_listener,
        Arc::clone(&pipeline),
        tcp_max_connections,
        tcp_idle_timeout,
        shutdown_rx.clone(),
    ));

    let tls_active = web_tls.dot_addr.is_some()
        || web_tls.doq_addr.is_some()
        || web_tls.doh3_addr.is_some()
        || web_tls.web_tls_addr.is_some();
    let bg = spawn_background_tasks(
        Arc::clone(&config),
        Arc::clone(&pipeline),
        Arc::clone(&storage),
        &tls_manager,
        tls_active,
        &shutdown_rx,
    );

    Ok(RunningServer {
        dns_addr,
        web_addr: web_tls.web_addr,
        web_tls_addr: web_tls.web_tls_addr,
        dot_addr: web_tls.dot_addr,
        doq_addr: web_tls.doq_addr,
        doh3_addr: web_tls.doh3_addr,
        pipeline,
        storage,
        config,
        shutdown_tx,
        udp_tasks,
        tcp_task,
        dot_task: web_tls.dot_task,
        doq_task: web_tls.doq_task,
        doh3_task: web_tls.doh3_task,
        web_task: web_tls.web_task,
        web_tls_accept_task: web_tls.web_tls_accept_task,
        web_tls_task: web_tls.web_tls_task,
        sub_refresh_task: bg.sub_refresh,
        hosts_watch_task: bg.hosts_watch,
        dhcp_watch_task: bg.dhcp_watch,
        neighbor_watch_task: bg.neighbor_watch,
        mdns_watch_task: bg.mdns_watch,
        cache_persist_task: bg.cache_persist,
        log_prune_task: bg.log_prune,
        cf_cdn_task: bg.cf_cdn_speedtest,
        tls_watch_task: bg.tls_watch,
        acme_renew_task,
        acme_http_task,
        sighup_task: bg.sighup,
        sink_handle,
    })
}

#[cfg(test)]
#[path = "server_tests.rs"]
mod tests;
