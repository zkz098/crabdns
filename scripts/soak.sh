#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

MODE="quick"
WARMUP_SECS=""
DURATION_SECS=""
COOLDOWN_SECS=""
SAMPLE_INTERVAL=""
MEMORY_MAX="128M"
CPU_QUOTA="100%"
FD_LIMIT="1024"
CGROUP_MODE="auto"
USE_PROF=1
SKIP_BUILD=0
CONCURRENCY=8
RULE_COUNT=5000
CONTROL_INTERVAL=10
JITTER_INTERVAL=20
OUT_DIR=""

usage() {
  cat <<'EOF'
CrabDNS Independent-Process Soak & Heap Diff Harness

Usage:
  ./scripts/soak.sh [options]

Options:
  --mode <quick|ci|weekend|24h>   Preset durations (default: quick)
  --warmup-secs <n>               Override warmup duration
  --duration-secs <n>             Override steady-state duration
  --cooldown-secs <n>             Override post-traffic cooldown duration
  --sample-interval <n>           Sampling period in seconds
  --memory-max <size>             cgroup v2 MemoryMax & SLO reference (default: 128M)
  --fd-limit <n>                  Open FD soft limit via ulimit -n (default: 1024)
  --cgroup <auto|on|off>          Use systemd-run cgroup v2 sandbox (default: auto)
  --no-prof                       Build release without prof-jemalloc
  --skip-build                    Reuse existing binaries
  --concurrency <n>               UDP soak worker count (default: 8)
  --rule-count <n>                Mock subscription rule count (default: 5000)
  --control-interval <n>          Control-plane churn period in seconds (default: 10)
  --jitter-interval <n>           Mock upstream fault interval in seconds (default: 20)
  --out-dir <path>                Artifact output directory
  -h, --help                      Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="$2"; shift 2 ;;
    --warmup-secs) WARMUP_SECS="$2"; shift 2 ;;
    --duration-secs) DURATION_SECS="$2"; shift 2 ;;
    --cooldown-secs) COOLDOWN_SECS="$2"; shift 2 ;;
    --sample-interval) SAMPLE_INTERVAL="$2"; shift 2 ;;
    --memory-max) MEMORY_MAX="$2"; shift 2 ;;
    --fd-limit) FD_LIMIT="$2"; shift 2 ;;
    --cgroup) CGROUP_MODE="$2"; shift 2 ;;
    --no-prof) USE_PROF=0; shift ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    --concurrency) CONCURRENCY="$2"; shift 2 ;;
    --rule-count) RULE_COUNT="$2"; shift 2 ;;
    --control-interval) CONTROL_INTERVAL="$2"; shift 2 ;;
    --jitter-interval) JITTER_INTERVAL="$2"; shift 2 ;;
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

case "$MODE" in
  quick)
    WARMUP_SECS="${WARMUP_SECS:-5}"
    DURATION_SECS="${DURATION_SECS:-20}"
    COOLDOWN_SECS="${COOLDOWN_SECS:-4}"
    SAMPLE_INTERVAL="${SAMPLE_INTERVAL:-2}"
    ;;
  ci)
    WARMUP_SECS="${WARMUP_SECS:-30}"
    DURATION_SECS="${DURATION_SECS:-120}"
    COOLDOWN_SECS="${COOLDOWN_SECS:-10}"
    SAMPLE_INTERVAL="${SAMPLE_INTERVAL:-5}"
    ;;
  weekend)
    WARMUP_SECS="${WARMUP_SECS:-120}"
    DURATION_SECS="${DURATION_SECS:-1500}"
    COOLDOWN_SECS="${COOLDOWN_SECS:-30}"
    SAMPLE_INTERVAL="${SAMPLE_INTERVAL:-15}"
    ;;
  24h)
    WARMUP_SECS="${WARMUP_SECS:-3600}"
    DURATION_SECS="${DURATION_SECS:-79200}"
    COOLDOWN_SECS="${COOLDOWN_SECS:-900}"
    SAMPLE_INTERVAL="${SAMPLE_INTERVAL:-30}"
    ;;
  *)
    echo "Invalid mode: $MODE" >&2
    exit 1
    ;;
esac

if [[ -z "$OUT_DIR" ]]; then
  OUT_DIR="$ROOT_DIR/soak-results/$(date -u +%Y%m%dT%H%M%SZ)"
fi
mkdir -p "$OUT_DIR/data"

if [[ "$USE_PROF" -eq 1 ]]; then
  PROFILE_NAME="profiling"
  PROFILE_FLAG="--profile profiling"
  FEATURE_FLAG="--features prof-jemalloc"
else
  PROFILE_NAME="release"
  PROFILE_FLAG="--release"
  FEATURE_FLAG=""
fi

SERVER_BIN="$ROOT_DIR/target/$PROFILE_NAME/crabdns"
SOAK_BIN="$ROOT_DIR/target/$PROFILE_NAME/examples/dns_soak"

if [[ "$SKIP_BUILD" -eq 0 ]]; then
  echo "[soak] building crabdns ($PROFILE_NAME ${FEATURE_FLAG:-default}) and dns_soak..."
  # shellcheck disable=SC2086
  cargo build $PROFILE_FLAG -p crabdns-server --bin crabdns $FEATURE_FLAG
  # shellcheck disable=SC2086
  cargo build $PROFILE_FLAG -p crabdns-server --example dns_soak
fi

PORTS_RAW="$(python3 -c '
import socket
socks = []
for _ in range(4):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    socks.append(s)
print(" ".join(str(s.getsockname()[1]) for s in socks))
for s in socks:
    s.close()
')"
read -r DNS_PORT WEB_PORT UPSTREAM_PORT SUB_PORT <<<"$PORTS_RAW"

HOSTS_FILE="$OUT_DIR/soak_hosts"
CONFIG_FILE="$OUT_DIR/soak_config.toml"
WARMUP_DONE="$OUT_DIR/warmup.done"
SOAK_REPORT="$OUT_DIR/soak_report.json"
METRICS_CSV="$OUT_DIR/metrics.csv"
SLO_JSON="$OUT_DIR/slo_summary.json"
SERVER_LOG="$OUT_DIR/crabdns.log"
SOAK_LOG="$OUT_DIR/dns_soak.log"

cat >"$HOSTS_FILE" <<EOF
192.168.50.10 router-soak-0.lan
EOF

cat >"$CONFIG_FILE" <<EOF
listen_dns = "127.0.0.1:${DNS_PORT}"
listen_web = "127.0.0.1:${WEB_PORT}"
data_dir = "${OUT_DIR}/data"
upstreams = ["127.0.0.1:${UPSTREAM_PORT}"]
cache_size = 4096
optimistic_cache = true
cache_prefetch_enabled = true
cache_persist_enabled = true
allow_private_subscriptions = true
hosts_enabled = true
hosts_path = "${HOSTS_FILE}"
trusted_proxies = ["127.0.0.1"]
log_retention_hours = 1
upstream_timeout_ms = 2000
rate_limit_qps = 0
EOF

SERVER_PID=""
SOAK_PID=""
SCOPE_UNIT="crabdns-soak-$$"
CGROUP_PATH=""

cleanup() {
  if [[ -n "$SOAK_PID" ]] && kill -0 "$SOAK_PID" 2>/dev/null; then
    kill -TERM "$SOAK_PID" 2>/dev/null || true
    wait "$SOAK_PID" 2>/dev/null || true
  fi
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill -TERM "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

USE_CGROUP=0
if [[ "$CGROUP_MODE" != "off" ]] && command -v systemd-run >/dev/null 2>&1; then
  if systemd-run --user --scope -p MemoryMax="$MEMORY_MAX" -p MemorySwapMax=0 true >/dev/null 2>&1; then
    USE_CGROUP=1
  elif [[ "$CGROUP_MODE" == "on" ]]; then
    echo "[soak] --cgroup on requested, but systemd-run --user --scope is unavailable" >&2
    exit 1
  else
    echo "[soak] systemd-run --user --scope unavailable; running without cgroup scope"
  fi
fi

# Isolate loopback soak traffic from ambient HTTP_PROXY/NO_PROXY globs (e.g. 127.*).
unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy

# Start dns_soak first so mock UDP upstream and HTTP subscription server bind before crabdns probes.
"$SOAK_BIN" \
  --dns-addr "127.0.0.1:${DNS_PORT}" \
  --web-addr "http://127.0.0.1:${WEB_PORT}" \
  --mock-upstream-bind "127.0.0.1:${UPSTREAM_PORT}" \
  --mock-sub-bind "127.0.0.1:${SUB_PORT}" \
  --warmup-secs "$WARMUP_SECS" \
  --duration-secs "$DURATION_SECS" \
  --concurrency "$CONCURRENCY" \
  --rule-count "$RULE_COUNT" \
  --control-interval-secs "$CONTROL_INTERVAL" \
  --jitter-interval-secs "$JITTER_INTERVAL" \
  --health-timeout-secs 30 \
  --warmup-done-file "$WARMUP_DONE" \
  --hosts-file "$HOSTS_FILE" \
  --json "$SOAK_REPORT" >"$SOAK_LOG" 2>&1 &
SOAK_PID=$!

launch_crabdns() {
  ulimit -n "$FD_LIMIT"
  if [[ "$USE_PROF" -eq 1 ]]; then
    export _RJEM_MALLOC_CONF="prof:true,prof_active:true,lg_prof_sample:18,dirty_decay_ms:1000,muzzy_decay_ms:1000"
  fi
  if [[ "$USE_CGROUP" -eq 1 ]]; then
    exec systemd-run --user --scope --unit="$SCOPE_UNIT" \
      -p "MemoryMax=$MEMORY_MAX" \
      -p MemorySwapMax=0 \
      -p "CPUQuota=$CPU_QUOTA" \
      "$SERVER_BIN" --config "$CONFIG_FILE"
  else
    exec "$SERVER_BIN" --config "$CONFIG_FILE"
  fi
}

launch_crabdns >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!

if [[ "$USE_CGROUP" -eq 1 ]]; then
  for _ in $(seq 1 20); do
    cg_rel="$(awk -F: '$1 == "0" {print $3; exit}' "/proc/$SERVER_PID/cgroup" 2>/dev/null || true)"
    if [[ -n "$cg_rel" ]] && [[ -d "/sys/fs/cgroup${cg_rel}" ]]; then
      CGROUP_PATH="/sys/fs/cgroup${cg_rel}"
      break
    fi
    sleep 0.1
  done
fi

echo "elapsed_s,phase,private_dirty_bytes,pss_bytes,rss_anon_bytes,jemalloc_allocated_bytes,jemalloc_active_bytes,jemalloc_resident_bytes,cgroup_current_bytes,cgroup_peak_bytes,open_fds,threads,close_wait_sockets,fjall_bytes,proc_write_bytes,cache_entries,filter_rules,auth_sessions,auth_attempts,acl_tracked_clients,singleflight_inflight,rdns_inflight,bg_refresh_inflight,log_channel_dropped_total" >"$METRICS_CSV"

collect_sample() {
  local phase="$1"
  local elapsed_s="$2"
  local metrics_txt
  metrics_txt="$(curl -sf --max-time 2 "http://127.0.0.1:${WEB_PORT}/metrics" 2>/dev/null || true)"
  python3 - "$SERVER_PID" "$phase" "$elapsed_s" "$OUT_DIR/data" "$CGROUP_PATH" "$metrics_txt" >>"$METRICS_CSV" <<'PY'
import os, re, subprocess, sys

pid, phase, elapsed_s, data_dir, cg_path, metrics_txt = sys.argv[1:7]
metrics = {}
for line in metrics_txt.splitlines():
    if not line or line.startswith("#"):
        continue
    parts = line.split()
    if len(parts) >= 2:
        metrics[parts[0]] = parts[-1]

def read_int(path):
    try:
        with open(path, encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return "na"

smaps = {}
try:
    with open(f"/proc/{pid}/smaps_rollup", encoding="utf-8") as f:
        for line in f:
            m = re.match(r"^(\w+):\s+(\d+)\s+kB", line)
            if m:
                smaps[m.group(1)] = str(int(m.group(2)) * 1024)
except OSError:
    pass

status_fields = {}
try:
    with open(f"/proc/{pid}/status", encoding="utf-8") as f:
        for line in f:
            if line.startswith("RssAnon:"):
                status_fields["RssAnon"] = str(int(line.split()[1]) * 1024)
            elif line.startswith("Threads:"):
                status_fields["Threads"] = line.split()[1]
except OSError:
    pass

proc_write = "na"
try:
    with open(f"/proc/{pid}/io", encoding="utf-8") as f:
        for line in f:
            if line.startswith("write_bytes:"):
                proc_write = line.split()[1]
except OSError:
    pass

try:
    open_fds = str(len(os.listdir(f"/proc/{pid}/fd")))
except OSError:
    open_fds = metrics.get("crabdns_process_open_fds", "na")

close_wait = "0"
try:
    out = subprocess.check_output(["ss", "-Htan", "state", "close-wait"], text=True, stderr=subprocess.DEVNULL)
    # Count only sockets matching our crabdns ports if ss runs system-wide.
    close_wait = str(sum(1 for ln in out.splitlines() if f":{os.environ.get('DNS_PORT_ENV', '')}" in ln or f":{os.environ.get('WEB_PORT_ENV', '')}" in ln))
except Exception:
    close_wait = "0"

fjall_bytes = 0
fjall_dir = os.path.join(data_dir, "fjall")
if os.path.isdir(fjall_dir):
    for root, _, files in os.walk(fjall_dir):
        for fn in files:
            try:
                fjall_bytes += os.path.getsize(os.path.join(root, fn))
            except OSError:
                pass

cg_cur = read_int(os.path.join(cg_path, "memory.current")) if cg_path else "na"
cg_peak = read_int(os.path.join(cg_path, "memory.peak")) if cg_path else "na"

row = [
    elapsed_s,
    phase,
    smaps.get("Private_Dirty", "na"),
    smaps.get("Pss", "na"),
    status_fields.get("RssAnon", metrics.get("crabdns_process_rss_anon_bytes", "na")),
    metrics.get("crabdns_jemalloc_allocated_bytes", "na"),
    metrics.get("crabdns_jemalloc_active_bytes", "na"),
    metrics.get("crabdns_jemalloc_resident_bytes", "na"),
    cg_cur,
    cg_peak,
    open_fds,
    status_fields.get("Threads", metrics.get("crabdns_process_threads", "na")),
    close_wait,
    str(fjall_bytes),
    proc_write,
    metrics.get("crabdns_cache_entries", "na"),
    metrics.get('crabdns_filter_rules{kind="total"}', "na"),
    metrics.get("crabdns_auth_sessions", "na"),
    metrics.get("crabdns_auth_login_attempts", "na"),
    metrics.get("crabdns_acl_tracked_clients", "na"),
    metrics.get("crabdns_singleflight_inflight", "na"),
    metrics.get("crabdns_rdns_inflight", "na"),
    metrics.get("crabdns_bg_refresh_inflight", "na"),
    metrics.get("crabdns_log_channel_dropped_total", "na"),
]
print(",".join(row))
PY
}

export DNS_PORT_ENV="$DNS_PORT"
export WEB_PORT_ENV="$WEB_PORT"

START_EPOCH="$(date +%s)"
echo "[soak] running warmup (${WARMUP_SECS}s)..."
while [[ ! -f "$WARMUP_DONE" ]]; do
  if ! kill -0 "$SOAK_PID" 2>/dev/null; then
    echo "[soak] dns_soak exited prematurely during warmup; log:" >&2
    cat "$SOAK_LOG" >&2 || true
    cat "$SERVER_LOG" >&2 || true
    exit 1
  fi
  now="$(date +%s)"
  collect_sample "warmup" "$((now - START_EPOCH))"
  sleep "$SAMPLE_INTERVAL"
done

if [[ "$USE_PROF" -eq 1 ]]; then
  curl -sf --max-time 5 "http://127.0.0.1:${WEB_PORT}/debug/pprof/heap" -o "$OUT_DIR/heap_warmup.pb" || true
fi

echo "[soak] running steady-state soak (${DURATION_SECS}s)..."
while kill -0 "$SOAK_PID" 2>/dev/null; do
  now="$(date +%s)"
  collect_sample "steady" "$((now - START_EPOCH))"
  sleep "$SAMPLE_INTERVAL"
done

set +e
wait "$SOAK_PID"
SOAK_EXIT=$?
set -e
SOAK_PID=""
if [[ "$SOAK_EXIT" -ne 0 ]]; then
  echo "[soak] dns_soak failed with exit code $SOAK_EXIT" >&2
  cat "$SOAK_LOG" >&2 || true
  exit "$SOAK_EXIT"
fi

if [[ "$USE_PROF" -eq 1 ]]; then
  curl -sf --max-time 5 "http://127.0.0.1:${WEB_PORT}/debug/pprof/heap" -o "$OUT_DIR/heap_end.pb" || true
fi

echo "[soak] running post-traffic cooldown (${COOLDOWN_SECS}s)..."
COOLDOWN_END=$(($(date +%s) + COOLDOWN_SECS))
while [[ "$(date +%s)" -lt "$COOLDOWN_END" ]]; do
  now="$(date +%s)"
  collect_sample "cooldown" "$((now - START_EPOCH))"
  sleep "$SAMPLE_INTERVAL"
done
now="$(date +%s)"
collect_sample "cooldown" "$((now - START_EPOCH))"

echo "[soak] stopping crabdns with SIGTERM..."
kill -TERM "$SERVER_PID"
set +e
wait "$SERVER_PID"
SERVER_EXIT=$?
set -e
SERVER_PID=""

if [[ "$USE_PROF" -eq 1 ]] && [[ -s "$OUT_DIR/heap_warmup.pb" ]] && [[ -s "$OUT_DIR/heap_end.pb" ]]; then
  if command -v go >/dev/null 2>&1; then
    go tool pprof -top -base "$OUT_DIR/heap_warmup.pb" "$OUT_DIR/heap_end.pb" >"$OUT_DIR/pprof_diff.txt" 2>&1 || true
    echo "[soak] top differential pprof allocations written to $OUT_DIR/pprof_diff.txt"
    head -n 25 "$OUT_DIR/pprof_diff.txt" || true
  else
    echo "[soak] go tool pprof not installed; saved heap_warmup.pb & heap_end.pb for offline diffing"
  fi
fi

ANALYZE_FLAGS=()
if [[ "$USE_CGROUP" -eq 1 ]]; then
  ANALYZE_FLAGS+=(--enforce-mem-peak)
fi

python3 "$ROOT_DIR/scripts/soak_analyze.py" \
  --csv "$METRICS_CSV" \
  --report "$SOAK_REPORT" \
  --out "$SLO_JSON" \
  --server-exit-code "$SERVER_EXIT" \
  --memory-max "$MEMORY_MAX" \
  "${ANALYZE_FLAGS[@]}"
