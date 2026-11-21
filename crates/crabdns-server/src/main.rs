use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use crabdns_core::Config;
use crabdns_server::spawn_server;
use mimalloc::MiMalloc;
use tracing_subscriber::EnvFilter;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[derive(Debug, Parser)]
#[command(name = "crabdns", about = "High-performance Rust DNS ad-blocker")]
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

    let server = spawn_server(config).await?;
    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down crabdns");
    server.shutdown().await;
    Ok(())
}
