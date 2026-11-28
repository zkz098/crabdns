use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use clap::{Parser, ValueEnum};
use crabdns_core::Config;
use crabdns_server::spawn_server;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use serde::Serialize;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ScenarioArg {
    CachedUdp,
    BlockedUdp,
    UpstreamUdp,
    CachedTcp,
    MixedUdp,
    All,
}

#[derive(Debug, Parser)]
#[command(
    name = "dns_loadtest",
    about = "CrabDNS end-to-end load and latency benchmark"
)]
struct Args {
    #[arg(long, value_enum, default_value_t = ScenarioArg::All)]
    scenario: ScenarioArg,
    #[arg(long, default_value_t = 32)]
    concurrency: usize,
    #[arg(long, default_value_t = 5)]
    duration_secs: u64,
    #[arg(long, default_value_t = 1)]
    warmup_secs: u64,
    #[arg(long, default_value_t = 10_000)]
    rules: usize,
    #[arg(long)]
    json: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scenario {
    CachedUdp,
    BlockedUdp,
    UpstreamUdp,
    CachedTcp,
    MixedUdp,
}

impl Scenario {
    fn as_str(self) -> &'static str {
        match self {
            Self::CachedUdp => "cached-udp",
            Self::BlockedUdp => "blocked-udp",
            Self::UpstreamUdp => "upstream-udp",
            Self::CachedTcp => "cached-tcp",
            Self::MixedUdp => "mixed-udp",
        }
    }
}

#[derive(Debug, Serialize)]
struct ScenarioReport {
    scenario: String,
    concurrency: usize,
    duration_secs: f64,
    total_requests: u64,
    errors: u64,
    error_rate_pct: f64,
    qps: f64,
    min_us: u64,
    p50_us: u64,
    p90_us: u64,
    p95_us: u64,
    p99_us: u64,
    p999_us: u64,
    max_us: u64,
    rss_mb: Option<f64>,
}

fn build_query(id: u16, domain: &str) -> Vec<u8> {
    let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    let name = Name::from_ascii(domain).expect("valid domain");
    msg.add_query(Query::query(name, RecordType::A));
    msg.to_vec().expect("encode query")
}

fn build_mock_upstream_response(raw_query: &[u8]) -> Option<Vec<u8>> {
    let req = Message::from_vec(raw_query).ok()?;
    let q = req.queries.first()?.clone();
    let qname = q.name().clone();

    let mut resp = Message::new(req.id, MessageType::Response, OpCode::Query);
    resp.metadata.recursion_desired = req.recursion_desired;
    resp.metadata.recursion_available = true;
    resp.metadata.response_code = ResponseCode::NoError;
    resp.add_query(q);
    resp.add_answer(Record::from_rdata(
        qname,
        300,
        RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
    ));
    resp.to_vec().ok()
}

async fn spawn_mock_udp_upstream() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind mock udp");
    let addr = socket.local_addr().expect("mock udp addr");

    tokio::spawn(async move {
        let mut buf = [0_u8; 4096];
        while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
            if let Some(resp) = build_mock_upstream_response(&buf[..len]) {
                let _ = socket.send_to(&resp, peer).await;
            }
        }
    });

    addr
}

fn generate_custom_rules(count: usize) -> Vec<String> {
    (0..count)
        .map(|i| format!("||ad-{i}.blocked.test^"))
        .collect()
}

fn read_rss_mb() -> Option<f64> {
    let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
    let pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
    #[allow(clippy::cast_precision_loss)]
    Some((pages * 4096) as f64 / (1024.0 * 1024.0))
}

fn percentile(sorted: &[u64], pct: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    let idx = ((sorted.len() - 1) as f64 * pct).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

async fn warmup_cache(dns_addr: SocketAddr, count: usize) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind warmup");
    sock.connect(dns_addr).await.expect("connect warmup");
    let mut buf = [0_u8; 4096];
    for i in 0..count {
        let pkt = build_query(i as u16 + 1, &format!("cached-{i}.example.test."));
        let _ = sock.send(&pkt).await;
        let _ = tokio::time::timeout(Duration::from_secs(1), sock.recv(&mut buf)).await;
    }
}

async fn run_udp_worker(
    dns_addr: SocketAddr,
    scenario: Scenario,
    worker_id: usize,
    stop: Arc<AtomicBool>,
    record: bool,
    rule_count: usize,
    errors: Arc<AtomicU64>,
) -> Vec<u64> {
    let sock = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind worker udp");
    sock.connect(dns_addr).await.expect("connect worker udp");

    let cached_pool: Vec<Vec<u8>> = (0_u16..100)
        .map(|i| build_query(i + 1, &format!("cached-{i}.example.test.")))
        .collect();
    let blocked_pool: Vec<Vec<u8>> = (0..100)
        .map(|i| {
            let rule_idx = (i * 97) % rule_count.max(1);
            build_query(i as u16 + 1, &format!("sub.ad-{rule_idx}.blocked.test."))
        })
        .collect();

    let mut latencies = if record {
        Vec::with_capacity(8_192)
    } else {
        Vec::new()
    };
    let mut buf = [0_u8; 4096];
    let mut seq: usize = 0;

    while !stop.load(Ordering::Relaxed) {
        let owned_pkt;
        let pkt: &[u8] = match scenario {
            Scenario::CachedUdp | Scenario::CachedTcp => &cached_pool[seq % cached_pool.len()],
            Scenario::BlockedUdp => &blocked_pool[seq % blocked_pool.len()],
            Scenario::UpstreamUdp => {
                owned_pkt = build_query(
                    (seq & 0xffff) as u16,
                    &format!("u-{worker_id}-{seq}.forward.test."),
                );
                &owned_pkt
            }
            Scenario::MixedUdp => match seq % 20 {
                0..=11 => &cached_pool[seq % cached_pool.len()],
                12..=16 => &blocked_pool[seq % blocked_pool.len()],
                _ => {
                    owned_pkt = build_query(
                        (seq & 0xffff) as u16,
                        &format!("m-{worker_id}-{seq}.forward.test."),
                    );
                    &owned_pkt
                }
            },
        };

        let start = Instant::now();
        if sock.send(pkt).await.is_err() {
            errors.fetch_add(1, Ordering::Relaxed);
            seq = seq.wrapping_add(1);
            continue;
        }
        match tokio::time::timeout(Duration::from_secs(2), sock.recv(&mut buf)).await {
            Ok(Ok(_)) => {
                if record {
                    latencies.push(start.elapsed().as_micros() as u64);
                }
            }
            _ => {
                errors.fetch_add(1, Ordering::Relaxed);
            }
        }
        seq = seq.wrapping_add(1);
    }

    latencies
}

async fn run_tcp_worker(
    dns_addr: SocketAddr,
    stop: Arc<AtomicBool>,
    record: bool,
    errors: Arc<AtomicU64>,
) -> Vec<u64> {
    let mut stream = TcpStream::connect(dns_addr)
        .await
        .expect("connect worker tcp");
    let _ = stream.set_nodelay(true);

    let cached_pool: Vec<Vec<u8>> = (0_u16..100)
        .map(|i| build_query(i + 1, &format!("cached-{i}.example.test.")))
        .collect();

    let mut latencies = if record {
        Vec::with_capacity(4_096)
    } else {
        Vec::new()
    };
    let mut buf = vec![0_u8; 4096];
    let mut seq: usize = 0;

    while !stop.load(Ordering::Relaxed) {
        let pkt = &cached_pool[seq % cached_pool.len()];
        let len_prefix = (pkt.len() as u16).to_be_bytes();

        let start = Instant::now();
        if stream.write_all(&len_prefix).await.is_err() || stream.write_all(pkt).await.is_err() {
            errors.fetch_add(1, Ordering::Relaxed);
            if let Ok(reconn) = TcpStream::connect(dns_addr).await {
                let _ = reconn.set_nodelay(true);
                stream = reconn;
            }
            seq = seq.wrapping_add(1);
            continue;
        }

        let mut resp_len_buf = [0_u8; 2];
        let read_res = tokio::time::timeout(Duration::from_secs(2), async {
            stream.read_exact(&mut resp_len_buf).await?;
            let resp_len = u16::from_be_bytes(resp_len_buf) as usize;
            if buf.len() < resp_len {
                buf.resize(resp_len, 0);
            }
            stream.read_exact(&mut buf[..resp_len]).await
        })
        .await;

        match read_res {
            Ok(Ok(_)) => {
                if record {
                    latencies.push(start.elapsed().as_micros() as u64);
                }
            }
            _ => {
                errors.fetch_add(1, Ordering::Relaxed);
            }
        }
        seq = seq.wrapping_add(1);
    }

    latencies
}

async fn run_scenario(dns_addr: SocketAddr, scenario: Scenario, args: &Args) -> ScenarioReport {
    if args.warmup_secs > 0 {
        let warmup_stop = Arc::new(AtomicBool::new(false));
        let warmup_errors = Arc::new(AtomicU64::new(0));
        let mut warmup_handles = Vec::with_capacity(args.concurrency);
        for w in 0..args.concurrency {
            let stop = Arc::clone(&warmup_stop);
            let errs = Arc::clone(&warmup_errors);
            let rules = args.rules;
            warmup_handles.push(tokio::spawn(async move {
                if scenario == Scenario::CachedTcp {
                    run_tcp_worker(dns_addr, stop, false, errs).await
                } else {
                    run_udp_worker(dns_addr, scenario, w, stop, false, rules, errs).await
                }
            }));
        }
        tokio::time::sleep(Duration::from_secs(args.warmup_secs)).await;
        warmup_stop.store(true, Ordering::Relaxed);
        for h in warmup_handles {
            let _ = h.await;
        }
    }

    let stop = Arc::new(AtomicBool::new(false));
    let errors = Arc::new(AtomicU64::new(0));
    let start = Instant::now();
    let mut handles = Vec::with_capacity(args.concurrency);

    for w in 0..args.concurrency {
        let stop_flag = Arc::clone(&stop);
        let errs = Arc::clone(&errors);
        let rules = args.rules;
        handles.push(tokio::spawn(async move {
            if scenario == Scenario::CachedTcp {
                run_tcp_worker(dns_addr, stop_flag, true, errs).await
            } else {
                run_udp_worker(dns_addr, scenario, w, stop_flag, true, rules, errs).await
            }
        }));
    }

    tokio::time::sleep(Duration::from_secs(args.duration_secs)).await;
    stop.store(true, Ordering::Relaxed);

    let mut all_latencies = Vec::new();
    for h in handles {
        if let Ok(mut part) = h.await {
            all_latencies.append(&mut part);
        }
    }
    let elapsed = start.elapsed().as_secs_f64();
    let err_count = errors.load(Ordering::Relaxed);
    let ok_count = all_latencies.len() as u64;
    let total_requests = ok_count + err_count;

    all_latencies.sort_unstable();

    #[allow(clippy::cast_precision_loss)]
    let qps = ok_count as f64 / elapsed.max(0.001);
    #[allow(clippy::cast_precision_loss)]
    let error_rate_pct = if total_requests == 0 {
        0.0
    } else {
        (err_count as f64 / total_requests as f64) * 100.0
    };

    ScenarioReport {
        scenario: scenario.as_str().to_string(),
        concurrency: args.concurrency,
        duration_secs: elapsed,
        total_requests,
        errors: err_count,
        error_rate_pct,
        qps,
        min_us: all_latencies.first().copied().unwrap_or(0),
        p50_us: percentile(&all_latencies, 0.50),
        p90_us: percentile(&all_latencies, 0.90),
        p95_us: percentile(&all_latencies, 0.95),
        p99_us: percentile(&all_latencies, 0.99),
        p999_us: percentile(&all_latencies, 0.999),
        max_us: all_latencies.last().copied().unwrap_or(0),
        rss_mb: read_rss_mb(),
    }
}

fn print_reports(reports: &[ScenarioReport]) {
    println!(
        "\n{:<14} {:>6} {:>10} {:>10} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8}",
        "Scenario",
        "Conc",
        "QPS",
        "Requests",
        "Err%",
        "P50(us)",
        "P95(us)",
        "P99(us)",
        "Max(us)",
        "RSS(MB)"
    );
    println!("{}", "-".repeat(98));
    for r in reports {
        let rss = r
            .rss_mb
            .map_or_else(|| "-".to_string(), |v| format!("{v:.1}"));
        println!(
            "{:<14} {:>6} {:>10.0} {:>10} {:>7.2}% {:>8} {:>8} {:>8} {:>8} {:>8}",
            r.scenario,
            r.concurrency,
            r.qps,
            r.total_requests,
            r.error_rate_pct,
            r.p50_us,
            r.p95_us,
            r.p99_us,
            r.max_us,
            rss
        );
    }
    println!();
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let upstream_addr = spawn_mock_udp_upstream().await;
    let temp_dir = TempDir::new()?;

    let mut config = Config::default();
    config.bootstrap.listen_dns = "127.0.0.1:0".parse()?;
    config.bootstrap.listen_web = "127.0.0.1:0".parse()?;
    config.bootstrap.data_dir = temp_dir.path().to_path_buf();
    config.bootstrap.custom_rules = generate_custom_rules(args.rules);
    config.upstreams = vec![upstream_addr.to_string()];
    config.cache_size = 100_000;
    config.optimistic_cache = true;

    let server = spawn_server(config).await?;
    warmup_cache(server.dns_addr, 100).await;

    let scenarios: Vec<Scenario> = match args.scenario {
        ScenarioArg::CachedUdp => vec![Scenario::CachedUdp],
        ScenarioArg::BlockedUdp => vec![Scenario::BlockedUdp],
        ScenarioArg::UpstreamUdp => vec![Scenario::UpstreamUdp],
        ScenarioArg::CachedTcp => vec![Scenario::CachedTcp],
        ScenarioArg::MixedUdp => vec![Scenario::MixedUdp],
        ScenarioArg::All => vec![
            Scenario::CachedUdp,
            Scenario::BlockedUdp,
            Scenario::UpstreamUdp,
            Scenario::CachedTcp,
            Scenario::MixedUdp,
        ],
    };

    let mut reports = Vec::with_capacity(scenarios.len());
    for sc in scenarios {
        let report = run_scenario(server.dns_addr, sc, &args).await;
        reports.push(report);
    }

    print_reports(&reports);

    let cache_stats = server.pipeline.cache().stats();
    println!(
        "Final Cache Stats: entries={}, hits={}, misses={}, hit_rate={:.2}%",
        cache_stats.entries,
        cache_stats.hits,
        cache_stats.misses,
        cache_stats.hit_rate * 100.0
    );

    if let Some(ref json_path) = args.json {
        let json_text = serde_json::to_string_pretty(&reports)?;
        std::fs::write(json_path, json_text)?;
        println!("JSON report written to {}", json_path.display());
    }

    server.shutdown().await;
    Ok(())
}
