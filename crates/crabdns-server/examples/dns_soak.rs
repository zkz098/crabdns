use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::State;
use axum::routing::get;
use clap::Parser;
use futures_util::StreamExt;
use hdrhistogram::Histogram;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_tungstenite::connect_async;

const MAX_TRACKED_US: u64 = 60_000_000;
const FAULT_NORMAL: u8 = 0;
const FAULT_SERVFAIL: u8 = 1;
const FAULT_TRUNCATED: u8 = 2;
const FAULT_DROP: u8 = 3;

#[derive(Debug, Parser)]
#[command(
    name = "dns_soak",
    about = "External multi-protocol soak load & chaos driver for CrabDNS"
)]
struct Args {
    #[arg(long)]
    dns_addr: SocketAddr,
    #[arg(long)]
    web_addr: String,
    #[arg(long)]
    mock_upstream_bind: SocketAddr,
    #[arg(long)]
    mock_sub_bind: SocketAddr,
    #[arg(long, default_value_t = 30)]
    duration_secs: u64,
    #[arg(long, default_value_t = 10)]
    warmup_secs: u64,
    #[arg(long, default_value_t = 8)]
    concurrency: usize,
    #[arg(long, default_value_t = 2)]
    tcp_concurrency: usize,
    #[arg(long, default_value_t = 2)]
    doh_concurrency: usize,
    #[arg(long, default_value_t = 5_000)]
    rule_count: usize,
    #[arg(long, default_value_t = 10)]
    control_interval_secs: u64,
    #[arg(long, default_value_t = 20)]
    jitter_interval_secs: u64,
    #[arg(long, default_value_t = 2)]
    jitter_duration_secs: u64,
    #[arg(long, default_value_t = 30)]
    health_timeout_secs: u64,
    #[arg(long)]
    warmup_done_file: Option<PathBuf>,
    #[arg(long)]
    hosts_file: Option<PathBuf>,
    #[arg(long)]
    json: Option<PathBuf>,
}

#[derive(Clone)]
struct WorkerCtx {
    dns_addr: SocketAddr,
    web_addr: String,
    rule_count: usize,
    sub_gen: Arc<AtomicU64>,
    window: (Instant, Instant),
    stop: Arc<AtomicBool>,
    counters: Arc<Counters>,
}

struct WorkerHistograms {
    first_half: Histogram<u64>,
    second_half: Histogram<u64>,
    errors: u64,
    total: u64,
}

impl WorkerHistograms {
    fn new() -> Self {
        Self {
            first_half: Histogram::new_with_bounds(1, MAX_TRACKED_US, 3).expect("hist"),
            second_half: Histogram::new_with_bounds(1, MAX_TRACKED_US, 3).expect("hist"),
            errors: 0,
            total: 0,
        }
    }

    fn record_outcome(
        &mut self,
        window: (Instant, Instant),
        started: Instant,
        ok: bool,
        ok_ctr: &AtomicU64,
        err_ctr: &AtomicU64,
    ) {
        self.total = self.total.saturating_add(1);
        if !ok {
            self.errors = self.errors.saturating_add(1);
            err_ctr.fetch_add(1, Ordering::Relaxed);
            return;
        }
        ok_ctr.fetch_add(1, Ordering::Relaxed);
        let now = Instant::now();
        if now >= window.0 {
            let clamped = (started.elapsed().as_micros() as u64).clamp(1, MAX_TRACKED_US);
            let hist = if now < window.1 {
                &mut self.first_half
            } else {
                &mut self.second_half
            };
            let _ = hist.record(clamped);
        }
    }

    fn merge(&mut self, other: &Self) {
        let _ = self.first_half.add(&other.first_half);
        let _ = self.second_half.add(&other.second_half);
        self.errors = self.errors.saturating_add(other.errors);
        self.total = self.total.saturating_add(other.total);
    }
}

#[derive(Debug, Default)]
struct Counters {
    udp_ok: AtomicU64,
    udp_err: AtomicU64,
    tcp_ok: AtomicU64,
    tcp_err: AtomicU64,
    doh_ok: AtomicU64,
    doh_err: AtomicU64,
    control_cycles: AtomicU64,
    control_err: AtomicU64,
    ws_sessions: AtomicU64,
    sub_refreshes: AtomicU64,
    config_reloads: AtomicU64,
}

#[derive(Debug, Serialize)]
struct LatencyStats {
    count: u64,
    p50_us: u64,
    p95_us: u64,
    p99_us: u64,
    p999_us: u64,
    max_us: u64,
}

impl LatencyStats {
    fn from_hist(h: &Histogram<u64>) -> Self {
        Self {
            count: h.len(),
            p50_us: h.value_at_quantile(0.50),
            p95_us: h.value_at_quantile(0.95),
            p99_us: h.value_at_quantile(0.99),
            p999_us: h.value_at_quantile(0.999),
            max_us: h.max(),
        }
    }
}

#[derive(Debug, Serialize)]
struct SoakReport {
    duration_secs: f64,
    total_requests: u64,
    total_errors: u64,
    error_rate_pct: f64,
    qps: f64,
    udp_requests: u64,
    tcp_requests: u64,
    doh_requests: u64,
    ws_sessions: u64,
    control_cycles: u64,
    control_errors: u64,
    sub_refreshes: u64,
    config_reloads: u64,
    steady_overall: LatencyStats,
    steady_first_half: LatencyStats,
    steady_second_half: LatencyStats,
    p99_drift_ratio: f64,
}

fn build_query(id: u16, domain: &str, qtype: RecordType) -> Vec<u8> {
    let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    let name = Name::from_ascii(domain).expect("valid domain");
    msg.add_query(Query::query(name, qtype));
    msg.to_vec().expect("encode query")
}

fn encode_mock_response(raw_query: &[u8], fault_mode: u8) -> Option<Vec<u8>> {
    if fault_mode == FAULT_DROP {
        return None;
    }
    let req = Message::from_vec(raw_query).ok()?;
    let q = req.queries.first()?.clone();
    let qname = q.name().clone();

    let mut resp = Message::new(req.id, MessageType::Response, OpCode::Query);
    resp.metadata.recursion_desired = req.recursion_desired;
    resp.metadata.recursion_available = true;
    resp.metadata.truncation = fault_mode == FAULT_TRUNCATED;
    resp.metadata.response_code = if fault_mode == FAULT_SERVFAIL {
        ResponseCode::ServFail
    } else {
        ResponseCode::NoError
    };
    resp.add_query(q.clone());
    if fault_mode == FAULT_NORMAL && q.query_type == RecordType::A {
        resp.add_answer(Record::from_rdata(
            qname,
            60,
            RData::A(A(Ipv4Addr::new(10, 20, 30, 40))),
        ));
    }
    resp.to_vec().ok()
}

async fn spawn_mock_upstream(
    bind_addr: SocketAddr,
    fault_mode: Arc<AtomicU8>,
    stop: Arc<AtomicBool>,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let socket = UdpSocket::bind(bind_addr).await?;
    Ok(tokio::spawn(async move {
        let mut buf = [0_u8; 4096];
        while !stop.load(Ordering::Relaxed) {
            let recv =
                tokio::time::timeout(Duration::from_millis(250), socket.recv_from(&mut buf)).await;
            let Ok(Ok((len, peer))) = recv else {
                continue;
            };
            let mode = fault_mode.load(Ordering::Relaxed);
            if let Some(resp) = encode_mock_response(&buf[..len], mode) {
                let _ = socket.send_to(&resp, peer).await;
            }
        }
    }))
}

#[derive(Clone)]
struct MockSubState {
    generation: Arc<AtomicU64>,
    rule_count: usize,
}

async fn serve_mock_subscription(State(st): State<MockSubState>) -> String {
    use std::fmt::Write as _;

    let epoch = st.generation.load(Ordering::Relaxed);
    let mut out = String::with_capacity(st.rule_count * 36);
    for i in 0..st.rule_count {
        let _ = writeln!(out, "||sub-{epoch}-{i}.blocked.example.test^");
    }
    out
}

async fn spawn_mock_sub_server(
    bind_addr: SocketAddr,
    generation: Arc<AtomicU64>,
    rule_count: usize,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    let app = Router::new()
        .route("/rules.txt", get(serve_mock_subscription))
        .with_state(MockSubState {
            generation,
            rule_count,
        });
    Ok(tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    }))
}

async fn wait_for_crabdns_health(
    client: &reqwest::Client,
    web_addr: &str,
    timeout_secs: u64,
) -> anyhow::Result<()> {
    let url = format!("{}/api/health", web_addr.trim_end_matches('/'));
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        if let Ok(resp) = client.get(&url).send().await
            && resp.status().is_success()
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for crabdns health endpoint at {url}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn register_mock_subscription(
    client: &reqwest::Client,
    web_addr: &str,
    sub_addr: SocketAddr,
) -> anyhow::Result<()> {
    let base = web_addr.trim_end_matches('/');
    let url = format!("http://{sub_addr}/rules.txt");
    let body = serde_json::to_vec(&serde_json::json!({
        "name": "soak-evolving-list",
        "url": url,
        "enabled": true,
    }))?;
    let resp = client
        .post(format!("{base}/api/subscriptions"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("failed to create soak subscription: {status} {text}");
    }
    Ok(())
}

fn build_mixed_query(
    worker_id: usize,
    seq: u64,
    rule_count: usize,
    sub_gen: u64,
    hot_pool: &[Vec<u8>],
) -> Vec<u8> {
    let slot = seq % 20;
    if slot < 10 {
        return hot_pool[((seq / 20) as usize + worker_id * 7) % hot_pool.len()].clone();
    }
    let id = (seq & 0xffff) as u16;
    if slot < 14 {
        build_query(
            id,
            &format!("longtail-{worker_id}-{seq}.entropy.example.test."),
            RecordType::A,
        )
    } else if slot < 17 {
        let r = (seq as usize * 131 + worker_id) % rule_count.max(1);
        build_query(
            id,
            &format!("ad.sub-{sub_gen}-{r}.blocked.example.test."),
            RecordType::A,
        )
    } else if slot < 19 {
        build_query(
            id,
            &format!("{}.1.168.192.in-addr.arpa.", (seq % 250) + 1),
            RecordType::PTR,
        )
    } else {
        build_query(
            id,
            &format!("ipv6-{worker_id}-{}.example.test.", seq % 64),
            RecordType::AAAA,
        )
    }
}

fn build_hot_pool() -> Vec<Vec<u8>> {
    (0_u16..200)
        .map(|i| build_query(i + 1, &format!("hot-{i}.example.test."), RecordType::A))
        .collect()
}

async fn run_udp_worker(worker_id: usize, ctx: WorkerCtx) -> WorkerHistograms {
    let Ok(sock) = UdpSocket::bind("127.0.0.1:0").await else {
        return WorkerHistograms::new();
    };
    if sock.connect(ctx.dns_addr).await.is_err() {
        return WorkerHistograms::new();
    }

    let hot_pool = build_hot_pool();
    let mut stats = WorkerHistograms::new();
    let mut buf = [0_u8; 4096];
    let mut seq = 0_u64;

    while !ctx.stop.load(Ordering::Relaxed) {
        let epoch = ctx.sub_gen.load(Ordering::Relaxed);
        let pkt = build_mixed_query(worker_id, seq, ctx.rule_count, epoch, &hot_pool);
        seq = seq.wrapping_add(1);

        let started = Instant::now();
        let ok = sock.send(&pkt).await.is_ok()
            && matches!(
                tokio::time::timeout(Duration::from_secs(2), sock.recv(&mut buf)).await,
                Ok(Ok(_))
            );
        stats.record_outcome(
            ctx.window,
            started,
            ok,
            &ctx.counters.udp_ok,
            &ctx.counters.udp_err,
        );
    }
    stats
}

async fn send_tcp_query(
    stream: &mut TcpStream,
    pkt: &[u8],
    buf: &mut Vec<u8>,
) -> std::io::Result<()> {
    let prefix = (pkt.len() as u16).to_be_bytes();
    stream.write_all(&prefix).await?;
    stream.write_all(pkt).await?;
    let mut rlen = [0_u8; 2];
    tokio::time::timeout(Duration::from_secs(2), async {
        stream.read_exact(&mut rlen).await?;
        let n = u16::from_be_bytes(rlen) as usize;
        if buf.len() < n {
            buf.resize(n, 0);
        }
        stream.read_exact(&mut buf[..n]).await?;
        Ok::<(), std::io::Error>(())
    })
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "tcp read timeout"))??;
    Ok(())
}

async fn run_tcp_worker(worker_id: usize, ctx: WorkerCtx) -> WorkerHistograms {
    let hot_pool = build_hot_pool();
    let mut stats = WorkerHistograms::new();
    let mut buf = vec![0_u8; 4096];
    let mut stream: Option<TcpStream> = None;
    let mut seq = 0_u64;

    while !ctx.stop.load(Ordering::Relaxed) {
        if stream.is_none() || seq.is_multiple_of(32) {
            stream = match TcpStream::connect(ctx.dns_addr).await {
                Ok(s) => {
                    let _ = s.set_nodelay(true);
                    Some(s)
                }
                Err(_) => None,
            };
        }
        let Some(ref mut conn) = stream else {
            stats.record_outcome(
                ctx.window,
                Instant::now(),
                false,
                &ctx.counters.tcp_ok,
                &ctx.counters.tcp_err,
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
            seq = seq.wrapping_add(1);
            continue;
        };

        let epoch = ctx.sub_gen.load(Ordering::Relaxed);
        let pkt = build_mixed_query(worker_id + 100, seq, ctx.rule_count, epoch, &hot_pool);
        seq = seq.wrapping_add(1);

        let started = Instant::now();
        let ok = send_tcp_query(conn, &pkt, &mut buf).await.is_ok();
        if !ok {
            stream = None;
        }
        stats.record_outcome(
            ctx.window,
            started,
            ok,
            &ctx.counters.tcp_ok,
            &ctx.counters.tcp_err,
        );
    }
    stats
}

fn local_http_client(timeout_secs: u64) -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(timeout_secs))
        .build()
        .expect("http client")
}

async fn run_doh_worker(worker_id: usize, ctx: WorkerCtx) -> WorkerHistograms {
    let client = local_http_client(3);
    let endpoint = format!("{}/dns-query", ctx.web_addr.trim_end_matches('/'));
    let hot_pool = build_hot_pool();
    let mut stats = WorkerHistograms::new();
    let mut seq = 0_u64;

    while !ctx.stop.load(Ordering::Relaxed) {
        let epoch = ctx.sub_gen.load(Ordering::Relaxed);
        let pkt = build_mixed_query(worker_id + 200, seq, ctx.rule_count, epoch, &hot_pool);
        let client_ip = format!(
            "10.{}.{}.{}",
            (seq >> 16) & 0xff,
            (seq >> 8) & 0xff,
            (seq & 0xfe) + 1
        );
        seq = seq.wrapping_add(1);

        let started = Instant::now();
        let res = client
            .post(&endpoint)
            .header("content-type", "application/dns-message")
            .header("x-forwarded-for", client_ip)
            .body(pkt)
            .send()
            .await;
        let ok = if let Ok(resp) = res
            && resp.status().is_success()
        {
            let _ = resp.bytes().await;
            true
        } else {
            false
        };
        stats.record_outcome(
            ctx.window,
            started,
            ok,
            &ctx.counters.doh_ok,
            &ctx.counters.doh_err,
        );
    }
    stats
}

async fn exercise_ws_client(ws_url: &str, counters: &Counters) {
    let Ok((mut ws, _)) = connect_async(ws_url).await else {
        counters.control_err.fetch_add(1, Ordering::Relaxed);
        return;
    };
    counters.ws_sessions.fetch_add(1, Ordering::Relaxed);
    let _ = tokio::time::timeout(Duration::from_millis(250), ws.next()).await;
    // Deliberately drop half the connections abruptly without Close frame.
    if counters
        .ws_sessions
        .load(Ordering::Relaxed)
        .is_multiple_of(2)
    {
        let _ = ws.close(None).await;
    }
}

async fn sleep_with_stop(stop: &AtomicBool, secs: u64) {
    for _ in 0..secs.max(1) {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn post_control(req: reqwest::RequestBuilder, ok_ctr: &AtomicU64, err_ctr: &AtomicU64) {
    if req.send().await.is_ok_and(|r| r.status().is_success()) {
        ok_ctr.fetch_add(1, Ordering::Relaxed);
    } else {
        err_ctr.fetch_add(1, Ordering::Relaxed);
    }
}

async fn exercise_control_cycle(
    client: &reqwest::Client,
    base_url: &str,
    ws_url: &str,
    ctx: &WorkerCtx,
    hosts_file: Option<&Path>,
    toggle: bool,
) {
    ctx.sub_gen.fetch_add(1, Ordering::Relaxed);
    let refresh_req = client.post(format!("{base_url}/api/subscriptions/refresh"));
    post_control(
        refresh_req,
        &ctx.counters.sub_refreshes,
        &ctx.counters.control_err,
    )
    .await;

    let timeout_ms = if toggle { 2200 } else { 2000 };
    if let Ok(resp) = client.get(format!("{base_url}/api/config")).send().await
        && let Ok(bytes) = resp.bytes().await
        && let Ok(mut cfg) = serde_json::from_slice::<serde_json::Value>(&bytes)
    {
        cfg["upstream_timeout_ms"] = serde_json::json!(timeout_ms);
        let cfg_req = client
            .put(format!("{base_url}/api/config"))
            .header("content-type", "application/json")
            .body(cfg.to_string());
        post_control(
            cfg_req,
            &ctx.counters.config_reloads,
            &ctx.counters.control_err,
        )
        .await;
    } else {
        ctx.counters.control_err.fetch_add(1, Ordering::Relaxed);
    }

    for path in ["/metrics", "/api/stats", "/api/logs?limit=20&search=hot"] {
        if !client
            .get(format!("{base_url}{path}"))
            .send()
            .await
            .is_ok_and(|r| r.status().is_success())
        {
            ctx.counters.control_err.fetch_add(1, Ordering::Relaxed);
        }
    }
    if let Some(path) = hosts_file {
        let epoch = ctx.sub_gen.load(Ordering::Relaxed);
        let _ = std::fs::write(path, format!("192.168.50.10 router-soak-{epoch}.lan\n"));
    }
    exercise_ws_client(ws_url, &ctx.counters).await;
    ctx.counters.control_cycles.fetch_add(1, Ordering::Relaxed);
}

async fn run_control_worker(ctx: WorkerCtx, interval_secs: u64, hosts_file: Option<PathBuf>) {
    let client = local_http_client(10);
    let base_url = ctx.web_addr.trim_end_matches('/').to_string();
    let ws_base = base_url
        .replacen("https://", "wss://", 1)
        .replacen("http://", "ws://", 1);
    let ws_url = format!("{ws_base}/api/logs/ws");

    let mut toggle = false;
    while !ctx.stop.load(Ordering::Relaxed) {
        exercise_control_cycle(
            &client,
            &base_url,
            &ws_url,
            &ctx,
            hosts_file.as_deref(),
            toggle,
        )
        .await;
        toggle = !toggle;
        sleep_with_stop(&ctx.stop, interval_secs).await;
    }
}

async fn run_fault_injector(
    fault_mode: Arc<AtomicU8>,
    interval_secs: u64,
    duration_secs: u64,
    stop: Arc<AtomicBool>,
) {
    let mut kind = 0_u8;
    while !stop.load(Ordering::Relaxed) {
        sleep_with_stop(&stop, interval_secs).await;
        if stop.load(Ordering::Relaxed) {
            break;
        }
        kind = (kind % 3) + 1;
        fault_mode.store(kind, Ordering::Relaxed);
        sleep_with_stop(&stop, duration_secs).await;
        fault_mode.store(FAULT_NORMAL, Ordering::Relaxed);
    }
}

fn spawn_all_workers(
    args: &Args,
    ctx: &WorkerCtx,
) -> Vec<tokio::task::JoinHandle<WorkerHistograms>> {
    let mut workers =
        Vec::with_capacity(args.concurrency + args.tcp_concurrency + args.doh_concurrency);
    for id in 0..args.concurrency {
        workers.push(tokio::spawn(run_udp_worker(id, ctx.clone())));
    }
    for id in 0..args.tcp_concurrency {
        workers.push(tokio::spawn(run_tcp_worker(id, ctx.clone())));
    }
    for id in 0..args.doh_concurrency {
        workers.push(tokio::spawn(run_doh_worker(id, ctx.clone())));
    }
    workers
}

fn build_report(elapsed: f64, merged: &WorkerHistograms, counters: &Counters) -> SoakReport {
    let mut overall = Histogram::new_with_bounds(1, MAX_TRACKED_US, 3).expect("hist");
    let _ = overall.add(&merged.first_half);
    let _ = overall.add(&merged.second_half);

    let first = LatencyStats::from_hist(&merged.first_half);
    let second = LatencyStats::from_hist(&merged.second_half);
    #[allow(clippy::cast_precision_loss)]
    let (p99_drift_ratio, error_rate_pct, qps) = (
        (second.p99_us as f64) / (first.p99_us.max(1) as f64),
        if merged.total == 0 {
            0.0
        } else {
            (merged.errors as f64 / merged.total as f64) * 100.0
        },
        merged.total as f64 / elapsed.max(0.001),
    );
    let sum = |a: &AtomicU64, b: &AtomicU64| a.load(Ordering::Relaxed) + b.load(Ordering::Relaxed);

    SoakReport {
        duration_secs: elapsed,
        total_requests: merged.total,
        total_errors: merged.errors,
        error_rate_pct,
        qps,
        udp_requests: sum(&counters.udp_ok, &counters.udp_err),
        tcp_requests: sum(&counters.tcp_ok, &counters.tcp_err),
        doh_requests: sum(&counters.doh_ok, &counters.doh_err),
        ws_sessions: counters.ws_sessions.load(Ordering::Relaxed),
        control_cycles: counters.control_cycles.load(Ordering::Relaxed),
        control_errors: counters.control_err.load(Ordering::Relaxed),
        sub_refreshes: counters.sub_refreshes.load(Ordering::Relaxed),
        config_reloads: counters.config_reloads.load(Ordering::Relaxed),
        steady_overall: LatencyStats::from_hist(&overall),
        steady_first_half: first,
        steady_second_half: second,
        p99_drift_ratio,
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let fault_mode = Arc::new(AtomicU8::new(FAULT_NORMAL));
    let sub_gen = Arc::new(AtomicU64::new(1));
    let stop = Arc::new(AtomicBool::new(false));
    let counters = Arc::new(Counters::default());

    let _upstream_task = spawn_mock_upstream(
        args.mock_upstream_bind,
        Arc::clone(&fault_mode),
        Arc::clone(&stop),
    )
    .await?;
    let _sub_task =
        spawn_mock_sub_server(args.mock_sub_bind, Arc::clone(&sub_gen), args.rule_count).await?;

    let http = local_http_client(5);
    wait_for_crabdns_health(&http, &args.web_addr, args.health_timeout_secs).await?;
    register_mock_subscription(&http, &args.web_addr, args.mock_sub_bind).await?;

    let steady_start = Instant::now() + Duration::from_secs(args.warmup_secs);
    let half_point = steady_start + Duration::from_secs(args.duration_secs / 2);

    let ctx = WorkerCtx {
        dns_addr: args.dns_addr,
        web_addr: args.web_addr.clone(),
        rule_count: args.rule_count,
        sub_gen: Arc::clone(&sub_gen),
        window: (steady_start, half_point),
        stop: Arc::clone(&stop),
        counters: Arc::clone(&counters),
    };
    let workers = spawn_all_workers(&args, &ctx);
    let ctrl = tokio::spawn(run_control_worker(
        ctx.clone(),
        args.control_interval_secs,
        args.hosts_file.clone(),
    ));
    let jitter = tokio::spawn(run_fault_injector(
        Arc::clone(&fault_mode),
        args.jitter_interval_secs,
        args.jitter_duration_secs,
        Arc::clone(&stop),
    ));

    if args.warmup_secs > 0 {
        tokio::time::sleep(Duration::from_secs(args.warmup_secs)).await;
    }
    if let Some(ref ready) = args.warmup_done_file {
        std::fs::write(ready, b"warmup-complete\n")?;
    }

    let steady_begin = Instant::now();
    tokio::time::sleep(Duration::from_secs(args.duration_secs)).await;
    stop.store(true, Ordering::Relaxed);

    let mut merged = WorkerHistograms::new();
    for handle in workers {
        if let Ok(part) = handle.await {
            merged.merge(&part);
        }
    }
    let _ = ctrl.await;
    let _ = jitter.await;

    let report = build_report(steady_begin.elapsed().as_secs_f64(), &merged, &counters);
    println!("{}", serde_json::to_string_pretty(&report)?);
    if let Some(ref json_path) = args.json {
        std::fs::write(json_path, serde_json::to_string_pretty(&report)?)?;
    }
    Ok(())
}
