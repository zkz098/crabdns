# CrabDNS Performance Testing System

CrabDNS employs a two-tier performance testing architecture:

1. **Component Microbenchmarks (`criterion`)**: Deterministic, statistics-driven benchmarks for every hot-path module in `crabdns-core` and `crabdns-storage`, with HTML reports (`target/criterion/report/index.html`) and regression baseline comparison.
2. **End-to-End Load & Latency Harness (`dns_loadtest`)**: A self-contained release-mode load generator (`crates/crabdns-server/examples/dns_loadtest.rs`) that launches a real `crabdns-server` instance (with `mimalloc`) against a local mock UDP upstream, measuring QPS, tail latency (`P50` / `P90` / `P95` / `P99` / `P99.9` / `Max`), error rate, and RSS memory.

---

## 1. Benchmark Suite Inventory

### `crabdns-core` Microbenchmarks
- **`filter_bench`** ([filter_bench.rs](file:///home/zkz098/projects/crabdns/crates/crabdns-core/benches/filter_bench.rs))
  - `filter_compile`: `FilterEngine::reload_from_sources` across 1k, 10k, and 50k mixed rules (AdGuard domain, allowlist, wildcard, hosts, `$important`, `$dnsrewrite`).
  - `filter_evaluate_50k`: `FilterEngine::evaluate` across exact block, 4-level subdomain block, allowlist override, wildcard hit, rewrite hit, and clean miss.
- **`cache_bench`** ([cache_bench.rs](file:///home/zkz098/projects/crabdns/crates/crabdns-core/benches/cache_bench.rs))
  - `dns_cache`: `get_hit`, `get_miss`, and `insert_overwrite` on a 10k-capacity `DnsCache` (`moka` + `foldhash`).
- **`routing_bench`** ([routing_bench.rs](file:///home/zkz098/projects/crabdns/crates/crabdns-core/benches/routing_bench.rs))
  - `acl_check`: `AccessController::check` for IPv4/IPv6 CIDR allow/deny lists with and without rate limiting.
  - `split_dns_resolve`: `SplitUpstreamRouter::resolve` across 100 split-DNS rules.
- **`pipeline_bench`** ([pipeline_bench.rs](file:///home/zkz098/projects/crabdns/crates/crabdns-core/benches/pipeline_bench.rs))
  - `pipeline_handle_packet`: Full async `DnsPipeline::handle_packet` (wire decode -> ACL -> filter -> cache -> wire encode) for `blocked_zero_ip`, `cache_hit_a`, and `rewrite_a`.

### `crabdns-storage` Microbenchmarks
- **`storage_bench`** ([storage_bench.rs](file:///home/zkz098/projects/crabdns/crates/crabdns-storage/benches/storage_bench.rs))
  - `storage_record_batch`: `StorageEngine::record_batch` into `fjall` (batch sizes 64 and 512).
  - `storage_reads_5k`: `query_logs` (100 unfiltered / filtered) and `stats_snapshot` over 5,000 events.

### `crabdns-server` End-to-End Load Test
- **`dns_loadtest`** ([dns_loadtest.rs](file:///home/zkz098/projects/crabdns/crates/crabdns-server/examples/dns_loadtest.rs))
  - Scenarios: `cached-udp`, `blocked-udp`, `upstream-udp`, `cached-tcp`, `mixed-udp` (60% cached / 25% blocked / 15% upstream).
  - Supports `--concurrency`, `--duration-secs`, `--warmup-secs`, `--rules`, and `--json <path>`.

---

## 2. Running Benchmarks

Use the unified script [perf.sh](file:///home/zkz098/projects/crabdns/scripts/perf.sh):

```bash
# Run everything (fast microbenchmarks + all E2E scenarios)
./scripts/perf.sh all

# Run full Criterion microbenchmarks
./scripts/perf.sh micro

# Run a specific Criterion benchmark
cargo bench -p crabdns-core --bench filter_bench

# Run E2E load test with custom parameters and JSON output
./scripts/perf.sh e2e --scenario all --concurrency 32 --duration-secs 5 --json /tmp/e2e.json
```

---

## 3. Baseline & Regression Tracking

Before making a performance-sensitive change, save a baseline:

```bash
./scripts/perf.sh baseline-save main
```

After your optimization, compare against the saved baseline:

```bash
./scripts/perf.sh baseline-cmp main
```

Criterion reports statistical significance (`p < 0.05`) and percentage delta for every benchmark.
HTML reports are generated under `target/criterion/report/index.html`.
