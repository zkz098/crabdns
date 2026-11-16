#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'EOF'
CrabDNS Performance Testing Harness

Usage:
  ./scripts/perf.sh <command> [args...]

Commands:
  micro                  Run full Criterion microbenchmarks across workspace
  micro-quick            Run fast Criterion microbenchmarks (short warmup/sample)
  e2e [args...]          Run release E2E DNS load test (passes extra args to dns_loadtest)
  baseline-save <name>   Save Criterion microbenchmark baseline
  baseline-cmp <name>    Compare current microbenchmarks against saved baseline
  all                    Run micro-quick + E2E DNS load test
EOF
}

cmd="${1:-help}"
shift || true

case "$cmd" in
  micro)
    cargo bench -p crabdns-core -p crabdns-storage --benches "$@"
    ;;
  micro-quick)
    cargo bench -p crabdns-core -p crabdns-storage --benches -- --warm-up-time 1 --measurement-time 2 --sample-size 20 "$@"
    ;;
  e2e)
    cargo run --release -p crabdns-server --example dns_loadtest -- "$@"
    ;;
  baseline-save)
    name="${1:?baseline name required}"
    cargo bench -p crabdns-core -p crabdns-storage --benches -- --save-baseline "$name"
    ;;
  baseline-cmp)
    name="${1:?baseline name required}"
    cargo bench -p crabdns-core -p crabdns-storage --benches -- --baseline "$name"
    ;;
  all)
    "$0" micro-quick
    "$0" e2e --scenario all
    ;;
  help|-h|--help)
    usage
    ;;
  *)
    echo "Unknown command: $cmd" >&2
    usage
    exit 1
    ;;
esac
