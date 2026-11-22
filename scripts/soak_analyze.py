#!/usr/bin/env python3
"""Analyze CrabDNS soak metrics, compute OLS memory slopes, and evaluate SLOs."""

import argparse
import csv
import json
import math
import os
import sys
from typing import Dict, List, Optional, Tuple


def ols_slope_per_x(xs: List[float], ys: List[float]) -> Optional[float]:
    n = len(xs)
    if n < 2:
        return None
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n
    denom = sum((x - mean_x) ** 2 for x in xs)
    if denom <= 0.0:
        return 0.0
    numer = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys))
    return numer / denom


def parse_float(val: str) -> Optional[float]:
    if val is None or val == "" or val.lower() == "na":
        return None
    try:
        parsed = float(val)
        return parsed if math.isfinite(parsed) else None
    except ValueError:
        return None


def parse_size_bytes(spec: str) -> int:
    s = spec.strip().upper()
    units = {"B": 1, "K": 1024, "KB": 1024, "M": 1024**2, "MB": 1024**2, "G": 1024**3, "GB": 1024**3}
    for suffix in sorted(units, key=len, reverse=True):
        if s.endswith(suffix):
            num = float(s[: -len(suffix)].strip())
            return int(num * units[suffix])
    return int(s)


def series_stats(
    rows: List[Dict[str, str]],
    col: str,
    total_requests: int,
) -> Dict[str, Optional[float]]:
    points: List[Tuple[float, float]] = []
    for r in rows:
        t = parse_float(r.get("elapsed_s", ""))
        v = parse_float(r.get(col, ""))
        if t is not None and v is not None:
            points.append((t, v))
    if not points:
        return {
            "samples": 0,
            "start": None,
            "end": None,
            "peak": None,
            "span_secs": 0.0,
            "slope_kb_per_hour": None,
            "net_ols_growth_kb": None,
            "mb_per_1m_req": None,
        }

    xs_sec = [p[0] - points[0][0] for p in points]
    ys_bytes = [p[1] for p in points]
    span_secs = xs_sec[-1]
    slope_b_per_s = ols_slope_per_x(xs_sec, ys_bytes) or 0.0
    slope_kb_per_hour = (slope_b_per_s * 3600.0) / 1024.0
    net_ols_growth_kb = (slope_b_per_s * span_secs) / 1024.0
    mb_per_1m_req = None
    if total_requests > 0:
        mb_per_1m_req = ((slope_b_per_s * span_secs) / (1024.0 * 1024.0)) * (1_000_000.0 / total_requests)

    return {
        "samples": len(points),
        "start": ys_bytes[0],
        "end": ys_bytes[-1],
        "peak": max(ys_bytes),
        "span_secs": span_secs,
        "slope_kb_per_hour": slope_kb_per_hour,
        "net_ols_growth_kb": net_ols_growth_kb,
        "mb_per_1m_req": mb_per_1m_req,
    }


def evaluate_slos(args: argparse.Namespace) -> Tuple[bool, Dict]:
    with open(args.csv, newline="", encoding="utf-8") as f:
        all_rows = list(csv.DictReader(f))
    steady_rows = [r for r in all_rows if r.get("phase") == "steady"]
    warmup_rows = [r for r in all_rows if r.get("phase") == "warmup"]
    cooldown_rows = [r for r in all_rows if r.get("phase") == "cooldown"]

    with open(args.report, encoding="utf-8") as f:
        soak_report = json.load(f)

    total_reqs = int(soak_report.get("total_requests", 0))
    priv_dirty = series_stats(steady_rows, "private_dirty_bytes", total_reqs)
    jemalloc_alloc = series_stats(steady_rows, "jemalloc_allocated_bytes", total_reqs)
    fjall_disk = series_stats(steady_rows, "fjall_bytes", total_reqs)

    # Peak memory check across all phases.
    all_peaks = [
        v
        for r in all_rows
        for k in ("cgroup_peak_bytes", "rss_anon_bytes", "private_dirty_bytes")
        if (v := parse_float(r.get(k, ""))) is not None
    ]
    peak_mem_bytes = max(all_peaks) if all_peaks else 0.0
    mem_max_bytes = parse_size_bytes(args.memory_max)

    baseline_fds = parse_float(steady_rows[0].get("open_fds", "")) if steady_rows else None
    cooldown_end = cooldown_rows[-1] if cooldown_rows else (steady_rows[-1] if steady_rows else {})
    cooldown_fds = parse_float(cooldown_end.get("open_fds", ""))
    fd_drift = (cooldown_fds - baseline_fds) if (cooldown_fds is not None and baseline_fds is not None) else 0.0

    close_wait = int(parse_float(cooldown_end.get("close_wait_sockets", "0")) or 0)
    sf_inflight = int(parse_float(cooldown_end.get("singleflight_inflight", "0")) or 0)
    bg_inflight = int(parse_float(cooldown_end.get("bg_refresh_inflight", "0")) or 0)
    rdns_inflight = int(parse_float(cooldown_end.get("rdns_inflight", "0")) or 0)
    ctrl_errors = int(soak_report.get("control_errors", 0))
    err_rate = float(soak_report.get("error_rate_pct", 0.0))
    p99_drift = float(soak_report.get("p99_drift_ratio", 1.0))

    failures: List[str] = []

    if not steady_rows or priv_dirty["samples"] < 2:
        failures.append(f"insufficient steady-state samples ({priv_dirty['samples']})")
    if args.server_exit_code != 0:
        failures.append(f"crabdns exited non-zero on shutdown: {args.server_exit_code}")

    def check_mem_slope(name: str, stats: Dict[str, Optional[float]]) -> None:
        if stats["samples"] < 2:
            return
        span = stats["span_secs"] or 0.0
        slope = stats["slope_kb_per_hour"] or 0.0
        net_kb = stats["net_ols_growth_kb"] or 0.0
        per_1m = stats["mb_per_1m_req"] or 0.0
        if span >= 300.0 and slope > args.max_slope_kb_per_hour:
            failures.append(f"{name} slope {slope:.2f} KB/h > {args.max_slope_kb_per_hour:.2f} KB/h")
        if net_kb > args.max_net_growth_kb:
            failures.append(f"{name} linear net growth {net_kb:.2f} KB > {args.max_net_growth_kb:.2f} KB")
        if total_reqs >= 50_000 and span >= 300.0 and per_1m > args.max_mb_per_1m_req:
            failures.append(f"{name} growth {per_1m:.3f} MB/1M req > {args.max_mb_per_1m_req:.3f}")

    check_mem_slope("private_dirty", priv_dirty)
    if jemalloc_alloc["samples"] >= 2:
        check_mem_slope("jemalloc_allocated", jemalloc_alloc)

    if args.enforce_mem_peak and mem_max_bytes > 0 and peak_mem_bytes > mem_max_bytes * 0.90:
        failures.append(
            f"peak memory {peak_mem_bytes / (1024*1024):.2f} MiB > 90% of {mem_max_bytes / (1024*1024):.2f} MiB"
        )
    if close_wait > 0:
        failures.append(f"cooldown CLOSE_WAIT sockets = {close_wait} (> 0)")
    if sf_inflight != 0 or bg_inflight != 0 or rdns_inflight != 0:
        failures.append(
            f"inflight did not return to 0 after cooldown: singleflight={sf_inflight}, bg_refresh={bg_inflight}, rdns={rdns_inflight}"
        )
    if fd_drift > args.max_fd_drift:
        failures.append(f"open FD drift {fd_drift:.0f} > {args.max_fd_drift:.0f}")
    if ctrl_errors > 0:
        failures.append(f"control-plane errors = {ctrl_errors} (> 0)")
    if err_rate > args.max_error_rate_pct:
        failures.append(f"DNS error rate {err_rate:.2f}% > {args.max_error_rate_pct:.2f}%")
    if p99_drift > args.max_p99_drift_ratio and soak_report.get("steady_first_half", {}).get("count", 0) >= 1000:
        failures.append(f"P99 latency drift ratio {p99_drift:.2f}x > {args.max_p99_drift_ratio:.2f}x")

    summary = {
        "passed": len(failures) == 0,
        "failures": failures,
        "counts": {
            "warmup_samples": len(warmup_rows),
            "steady_samples": len(steady_rows),
            "cooldown_samples": len(cooldown_rows),
            "total_requests": total_reqs,
        },
        "memory": {
            "private_dirty": priv_dirty,
            "jemalloc_allocated": jemalloc_alloc,
            "peak_observed_bytes": peak_mem_bytes,
            "memory_max_bytes": mem_max_bytes,
        },
        "disk": {"fjall_bytes": fjall_disk},
        "cooldown": {
            "fd_drift": fd_drift,
            "close_wait_sockets": close_wait,
            "singleflight_inflight": sf_inflight,
            "bg_refresh_inflight": bg_inflight,
            "rdns_inflight": rdns_inflight,
        },
        "traffic": {
            "qps": soak_report.get("qps"),
            "error_rate_pct": err_rate,
            "control_errors": ctrl_errors,
            "p99_drift_ratio": p99_drift,
            "first_half_p99_us": soak_report.get("steady_first_half", {}).get("p99_us"),
            "second_half_p99_us": soak_report.get("steady_second_half", {}).get("p99_us"),
        },
    }
    return summary["passed"], summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze CrabDNS soak results and enforce SLOs")
    parser.add_argument("--csv", required=True)
    parser.add_argument("--report", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--server-exit-code", type=int, required=True)
    parser.add_argument("--memory-max", default="64M")
    parser.add_argument("--enforce-mem-peak", action="store_true")
    parser.add_argument("--max-slope-kb-per-hour", type=float, default=50.0)
    parser.add_argument("--max-net-growth-kb", type=float, default=8192.0)
    parser.add_argument("--max-mb-per-1m-req", type=float, default=2.0)
    parser.add_argument("--max-fd-drift", type=float, default=8.0)
    parser.add_argument("--max-error-rate-pct", type=float, default=15.0)
    parser.add_argument("--max-p99-drift-ratio", type=float, default=2.0)
    args = parser.parse_args()

    passed, summary = evaluate_slos(args)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print("\n=== CrabDNS Soak SLO Summary ===")
    print(json.dumps(summary, indent=2))
    if not passed:
        print("\nSOAK SLO FAILED:", "; ".join(summary["failures"]), file=sys.stderr)
        return 1
    print("\nSOAK SLO PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
