use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Parser, Subcommand};
use crabdns_core::Config;
use crabdns_server::spawn_server;
use crabdns_web::update_api::{
    UpdateConfig, check_for_update_with_config, download_and_install_update,
};
use tracing_subscriber::EnvFilter;

#[cfg(all(feature = "prof-jemalloc", unix))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[cfg(all(feature = "prof-jemalloc", unix))]
use mimalloc as _;

#[cfg(not(all(feature = "prof-jemalloc", unix)))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(Debug, Parser)]
#[command(
    name = "crabdns",
    about = "High-performance Rust DNS ad-blocker",
    version
)]
struct Cli {
    #[arg(short, long)]
    config: Option<PathBuf>,

    #[arg(long)]
    dns_listen: Option<SocketAddr>,

    #[arg(long)]
    web_listen: Option<SocketAddr>,

    #[arg(long)]
    web_tls_listen: Option<SocketAddr>,

    #[arg(long)]
    dot_listen: Option<SocketAddr>,

    #[arg(long)]
    doq_listen: Option<SocketAddr>,

    /// Check for a newer signed `CrabDNS` release via sigilup and exit
    #[arg(long)]
    check_update: bool,

    /// Download, verify (Ed25519 + ML-DSA-65 + BLAKE3 + SHA-512), and self-replace binary via sigilup
    #[arg(long)]
    self_update: bool,

    /// Override the signed release manifest URL (latest.hsig.json)
    #[arg(long)]
    update_manifest_url: Option<String>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Check for or apply a post-quantum signed self-update via sigilup
    Update {
        /// Only check if a newer version is available without installing
        #[arg(long)]
        check: bool,

        /// Override the signed release manifest URL (latest.hsig.json)
        #[arg(long)]
        manifest_url: Option<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let mut config = Config::load_or_default(cli.config.as_deref())?;

    if let Some(Commands::Update {
        check,
        manifest_url,
    }) = cli.command
    {
        return run_cli_self_update(
            &config.data_dir,
            check,
            manifest_url.or(cli.update_manifest_url),
        )
        .await;
    }

    if cli.check_update || cli.self_update {
        let check_only = cli.check_update && !cli.self_update;
        return run_cli_self_update(&config.data_dir, check_only, cli.update_manifest_url).await;
    }

    if let Some(addr) = cli.dns_listen {
        config.listen_dns = addr;
    }
    if let Some(addr) = cli.web_listen {
        config.listen_web = addr;
    }
    if let Some(addr) = cli.web_tls_listen {
        config.listen_web_tls = Some(addr);
    }
    if let Some(addr) = cli.dot_listen {
        config.listen_dot = Some(addr);
    }
    if let Some(addr) = cli.doq_listen {
        config.listen_doq = Some(addr);
    }

    let server = spawn_server(config).await?;
    wait_for_shutdown_signal().await?;
    tracing::info!("shutting down crabdns");
    server.shutdown().await;
    Ok(())
}

async fn run_cli_self_update(
    data_dir: &Path,
    check_only: bool,
    manifest_url_override: Option<String>,
) -> anyhow::Result<()> {
    let mut update_cfg = UpdateConfig::default_production().map_err(anyhow::Error::msg)?;
    if let Some(custom_url) = manifest_url_override {
        update_cfg = update_cfg.with_custom_manifest_url(custom_url);
    }

    let client = reqwest::Client::builder()
        .user_agent(format!("crabdns/{}", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(300))
        .build()?;

    let Some(update) = check_for_update_with_config(&client, data_dir, &update_cfg)
        .await
        .map_err(anyhow::Error::msg)?
    else {
        tracing::info!(
            current_version = env!("CARGO_PKG_VERSION"),
            "crabdns is already up to date"
        );
        return Ok(());
    };

    tracing::info!(
        current_version = env!("CARGO_PKG_VERSION"),
        latest_version = %update.version,
        asset_size = update.asset_size,
        asset_url = %update.asset_url,
        "new signed crabdns release available"
    );
    if !update.notes.trim().is_empty() {
        tracing::info!(notes = %update.notes.trim(), "release notes");
    }

    if check_only {
        return Ok(());
    }

    let mut last_bucket = 0_u64;
    download_and_install_update(&client, data_dir, &update, &update_cfg, |done, total| {
        if let Some(total) = total.filter(|&t| t > 0) {
            let pct = (done.saturating_mul(100)) / total;
            let bucket = pct / 25;
            if bucket > last_bucket {
                last_bucket = bucket;
                tracing::info!(
                    progress_pct = pct,
                    downloaded_bytes = done,
                    total_bytes = total,
                    "downloading and verifying update artifact"
                );
            }
        }
    })
    .await
    .map_err(anyhow::Error::msg)?;

    tracing::info!(
        version = %update.version,
        "crabdns binary updated in place via sigilup; restart the service to apply"
    );
    Ok(())
}

async fn wait_for_shutdown_signal() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm = signal(SignalKind::terminate())?;
        tokio::select! {
            res = tokio::signal::ctrl_c() => res,
            _ = sigterm.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_parses_update_subcommand_and_flags() {
        let sub = Cli::try_parse_from([
            "crabdns",
            "update",
            "--check",
            "--manifest-url",
            "https://example.com/latest.hsig.json",
        ])
        .expect("parse update subcommand");
        match sub.command {
            Some(Commands::Update {
                check,
                manifest_url,
            }) => {
                assert!(check);
                assert_eq!(
                    manifest_url.as_deref(),
                    Some("https://example.com/latest.hsig.json")
                );
            }
            None => panic!("expected Update subcommand"),
        }

        let flags = Cli::try_parse_from(["crabdns", "--check-update", "--self-update"])
            .expect("parse update flags");
        assert!(flags.check_update);
        assert!(flags.self_update);
    }
}
