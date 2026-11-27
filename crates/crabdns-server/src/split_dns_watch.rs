use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use arc_swap::ArcSwap;
use crabdns_core::{Config, DnsPipeline};
use crabdns_storage::StorageEngine;
use crabdns_web::split_dns_sync::{
    collect_split_dns_local_files, collect_split_dns_remote_urls,
    refresh_split_dns_subscriptions_job, reload_split_dns_from_storage,
};
use crabdns_web::subscriptions::build_subscription_http_client;
use tokio::sync::watch;
use tokio::task::JoinHandle;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    mtime: SystemTime,
    len: u64,
}

async fn read_file_stamp(path: &str) -> Option<FileStamp> {
    let meta = tokio::fs::metadata(path).await.ok()?;
    let mtime = meta.modified().ok()?;
    Some(FileStamp {
        mtime,
        len: meta.len(),
    })
}

async fn snapshot_initial_stamps(config: &Config) -> HashMap<String, FileStamp> {
    let mut out = HashMap::new();
    for path in collect_split_dns_local_files(config) {
        if let Some(stamp) = read_file_stamp(&path).await {
            out.insert(path, stamp);
        }
    }
    out
}

async fn sync_local_files_if_changed(
    cfg_now: &Config,
    storage: &Arc<StorageEngine>,
    pipeline: &Arc<DnsPipeline>,
    stamps: &mut HashMap<String, FileStamp>,
) {
    let files = collect_split_dns_local_files(cfg_now);
    let active: HashSet<&str> = files.iter().map(String::as_str).collect();
    stamps.retain(|k, _| active.contains(k.as_str()));

    let mut pending_updates: Vec<(String, FileStamp)> = Vec::new();
    for path in files {
        let Some(current) = read_file_stamp(&path).await else {
            continue;
        };
        match stamps.get(&path) {
            Some(&prev) if prev != current => {
                pending_updates.push((path, current));
            }
            Some(_) => {}
            None => {
                stamps.insert(path, current);
            }
        }
    }

    if pending_updates.is_empty() {
        return;
    }

    match reload_split_dns_from_storage(cfg_now, storage, pipeline).await {
        Ok(()) => {
            let changed_count = pending_updates.len();
            for (path, stamp) in pending_updates {
                stamps.insert(path, stamp);
            }
            tracing::info!(
                changed_files = changed_count,
                "hot-reloaded split-DNS after local list file change"
            );
        }
        Err(err) => {
            tracing::warn!(error = %err, "failed to hot-reload split-DNS local list files");
        }
    }
}

pub fn spawn_split_dns_sync_and_watch_task(
    config: Arc<ArcSwap<Config>>,
    storage: Arc<StorageEngine>,
    pipeline: Arc<DnsPipeline>,
    shutdown_rx: watch::Receiver<bool>,
) -> JoinHandle<()> {
    spawn_split_dns_watch_with_interval(
        config,
        storage,
        pipeline,
        shutdown_rx,
        Duration::from_secs(30),
    )
}

pub fn spawn_split_dns_watch_with_interval(
    config: Arc<ArcSwap<Config>>,
    storage: Arc<StorageEngine>,
    pipeline: Arc<DnsPipeline>,
    mut shutdown_rx: watch::Receiver<bool>,
    poll_interval: Duration,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let client_public = build_subscription_http_client(false);
        let client_private = build_subscription_http_client(true);

        let initial_cfg = config.load_full();
        let mut stamps = snapshot_initial_stamps(&initial_cfg).await;

        let missing_remote = collect_split_dns_remote_urls(&initial_cfg)
            .into_iter()
            .any(|u| storage.load_split_dns_list(&u).ok().flatten().is_none());
        if missing_remote {
            let client = if initial_cfg.allow_private_subscriptions {
                &client_private
            } else {
                &client_public
            };
            if let Err(err) = refresh_split_dns_subscriptions_job(
                client,
                &initial_cfg,
                &storage,
                &pipeline,
                initial_cfg.allow_private_subscriptions,
            )
            .await
            {
                tracing::warn!(error = %err, "initial split-DNS subscription fetch failed");
            }
        }

        let mut last_remote_sync = Instant::now();
        let mut interval = tokio::time::interval(poll_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        interval.tick().await;

        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
                _ = interval.tick() => {
                    let cfg_now = config.load_full();
                    sync_local_files_if_changed(&cfg_now, &storage, &pipeline, &mut stamps).await;

                    let interval_secs = cfg_now.split_dns_refresh_interval_secs;
                    if interval_secs > 0
                        && !collect_split_dns_remote_urls(&cfg_now).is_empty()
                        && last_remote_sync.elapsed() >= Duration::from_secs(interval_secs.max(60))
                    {
                        let client = if cfg_now.allow_private_subscriptions {
                            &client_private
                        } else {
                            &client_public
                        };
                        match refresh_split_dns_subscriptions_job(
                            client,
                            &cfg_now,
                            &storage,
                            &pipeline,
                            cfg_now.allow_private_subscriptions,
                        )
                        .await
                        {
                            Ok(summary) => {
                                tracing::debug!(
                                    updated = summary.updated,
                                    not_modified = summary.not_modified,
                                    failed = summary.failed,
                                    "scheduled split-DNS sync finished"
                                );
                            }
                            Err(err) => {
                                tracing::warn!(error = %err, "scheduled split-DNS refresh failed");
                            }
                        }
                        last_remote_sync = Instant::now();
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use crabdns_core::{
        DnsCache, FilterEngine, ResponseIpRule, SplitDnsRule, UpstreamPool, UpstreamStrategy,
    };

    use super::*;

    #[tokio::test]
    async fn test_split_dns_local_file_hot_reload_domains_and_response_ip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let domains_path = dir.path().join("split-domains.txt");
        let cidrs_path = dir.path().join("expected-cidrs.txt");
        std::fs::write(&domains_path, "first.local\n").expect("write initial domains");
        std::fs::write(&cidrs_path, "1.0.1.0/24\n").expect("write initial cidrs");

        let cfg = Config {
            split_dns_refresh_interval_secs: 0,
            split_dns: vec![SplitDnsRule {
                name: Some("hot-local".to_string()),
                domains_file: Some(domains_path.display().to_string()),
                upstreams: vec!["udp://10.0.0.1:53".to_string()],
                response_ip: Some(ResponseIpRule {
                    expected_ip_file: Some(cidrs_path.display().to_string()),
                    fallback_upstreams: vec!["udp://10.0.0.2:53".to_string()],
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Config::default()
        };

        let storage = Arc::new(StorageEngine::open(&dir.path().join("db")).expect("open db"));
        let filter = Arc::new(FilterEngine::new(&[]));
        let cache = Arc::new(DnsCache::with_options(64, false, 10, 600, false));
        let default_pool =
            Arc::new(UpstreamPool::new(&["udp://8.8.8.8:53".to_string()], 500).unwrap());
        let pipeline = Arc::new(DnsPipeline::new(filter, cache, default_pool, None));
        pipeline
            .reload_split_dns_full(
                &cfg.upstream_groups,
                &cfg.split_dns,
                cfg.split_dns_match_mode,
                cfg.upstream_timeout_ms,
                UpstreamStrategy::Failover,
                &cfg.bootstrap_dns,
                |_| None,
            )
            .unwrap();

        assert!(pipeline.split_router().resolve("a.first.local").is_some());
        assert!(pipeline.split_router().resolve("a.second.local").is_none());

        let shared_cfg = Arc::new(ArcSwap::from_pointee(cfg));
        let (tx, rx) = watch::channel(false);
        let handle = spawn_split_dns_watch_with_interval(
            shared_cfg,
            Arc::clone(&storage),
            Arc::clone(&pipeline),
            rx,
            Duration::from_millis(40),
        );

        tokio::time::sleep(Duration::from_millis(80)).await;
        std::fs::write(&domains_path, "first.local\nsecond.local\n").expect("update domains file");
        std::fs::write(&cidrs_path, "1.0.1.0/24\n223.5.5.0/24\n").expect("update cidrs file");

        let mut reloaded = false;
        for _ in 0..40 {
            if pipeline.split_router().resolve("a.second.local").is_some() {
                reloaded = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(40)).await;
        }
        assert!(
            reloaded,
            "expected local domains_file modification to hot-reload router"
        );

        let plan = pipeline
            .split_router()
            .resolve_plan(&crabdns_core::split_dns::SplitQueryContext::domain_only(
                "a.second.local",
            ))
            .expect("plan");
        let rip = plan.response_ip.expect("response_ip rule compiled");
        assert!(rip.ip_set.contains("223.5.5.5".parse().unwrap()));

        let _ = tx.send(true);
        let _ = handle.await;
    }
}
