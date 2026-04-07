#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""
FlexStack Benchmark — Statistical Analysis

Reads CSV output from the benchmark orchestrator and produces:
  1. Summary table (mean ± std, 95% CI) per cell
  2. LaTeX-formatted tables for the paper
  3. Comparison ratios (Rust vs CPython, PyPy vs CPython)

Usage:
  python3 analyze_results.py --input ../results/results.csv
  python3 analyze_results.py --input ../results/results.csv --latex
"""

import argparse
import sys

import numpy as np
import pandas as pd
from scipy import stats


def load_results(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    # Normalize numeric columns
    for col in [
        "duration_s",
        "total_cams",
        "throughput_cams_s",
        "latency_mean_us",
        "latency_std_us",
        "latency_p50_us",
        "latency_p95_us",
        "latency_p99_us",
        "latency_min_us",
        "latency_max_us",
        "sign_latency_mean_us",
    ]:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")
    return df


def summarize(df: pd.DataFrame) -> pd.DataFrame:
    """Compute summary statistics per (implementation, platform, security, benchmark) cell."""
    group_cols = ["implementation", "platform", "security", "benchmark"]
    rows = []

    for keys, group in df.groupby(group_cols):
        impl_, plat, sec, bench = keys
        n = len(group)

        tp = group["throughput_cams_s"]
        tp_mean = tp.mean()
        tp_std = tp.std(ddof=1) if n > 1 else 0.0
        tp_se = tp_std / np.sqrt(n) if n > 0 else 0.0
        t_crit = stats.t.ppf(0.975, df=max(n - 1, 1))
        tp_ci_low = tp_mean - t_crit * tp_se
        tp_ci_high = tp_mean + t_crit * tp_se

        lat_mean = group["latency_mean_us"].mean()
        lat_std = group["latency_std_us"].mean()
        lat_p50 = group["latency_p50_us"].mean()
        lat_p95 = group["latency_p95_us"].mean()
        lat_p99 = group["latency_p99_us"].mean()
        lat_min = group["latency_min_us"].min()
        lat_max = group["latency_max_us"].max()

        cv = (tp_std / tp_mean * 100) if tp_mean > 0 else 0.0

        rows.append(
            {
                "implementation": impl_,
                "platform": plat,
                "security": sec,
                "benchmark": bench,
                "n": n,
                "throughput_mean": tp_mean,
                "throughput_std": tp_std,
                "throughput_ci95_low": tp_ci_low,
                "throughput_ci95_high": tp_ci_high,
                "cv_pct": cv,
                "latency_mean_us": lat_mean,
                "latency_std_us": lat_std,
                "latency_p50_us": lat_p50,
                "latency_p95_us": lat_p95,
                "latency_p99_us": lat_p99,
                "latency_min_us": lat_min,
                "latency_max_us": lat_max,
            }
        )

    return pd.DataFrame(rows)


def print_summary(summary: pd.DataFrame):
    """Print a human-readable summary table."""
    print()
    print("=" * 120)
    print(f"{'Implementation':>15s} | {'Platform':>8s} | {'Sec':>3s} | {'Benchmark':>13s} | "
          f"{'N':>3s} | {'Throughput (CAMs/s)':>25s} | {'95% CI':>25s} | {'CV%':>5s} | "
          f"{'Lat p50 (μs)':>12s} | {'Lat p99 (μs)':>12s}")
    print("-" * 120)

    for _, row in summary.iterrows():
        tp_str = f"{row['throughput_mean']:.0f} ± {row['throughput_std']:.0f}"
        ci_str = f"[{row['throughput_ci95_low']:.0f}, {row['throughput_ci95_high']:.0f}]"
        print(
            f"{row['implementation']:>15s} | {row['platform']:>8s} | {row['security']:>3s} | "
            f"{row['benchmark']:>13s} | {row['n']:>3.0f} | {tp_str:>25s} | {ci_str:>25s} | "
            f"{row['cv_pct']:>5.1f} | {row['latency_p50_us']:>12.1f} | {row['latency_p99_us']:>12.1f}"
        )

    print("=" * 120)


def compute_speedup(summary: pd.DataFrame):
    """Compute speedup ratios (Rust vs CPython, PyPy vs CPython)."""
    print("\n── Speedup Ratios ──")
    print(f"{'Comparison':>30s} | {'Platform':>8s} | {'Sec':>3s} | {'Benchmark':>13s} | {'Speedup':>10s}")
    print("-" * 80)

    for (plat, sec, bench), group in summary.groupby(["platform", "security", "benchmark"]):
        # Find CPython baseline
        cpython_rows = group[group["implementation"].str.contains("cpython", case=False)]
        if cpython_rows.empty:
            continue
        baseline = cpython_rows.iloc[0]["throughput_mean"]
        if baseline <= 0:
            continue

        for _, row in group.iterrows():
            if "cpython" in row["implementation"].lower():
                continue
            speedup = row["throughput_mean"] / baseline
            label = f"{row['implementation']} vs CPython"
            print(
                f"{label:>30s} | {plat:>8s} | {sec:>3s} | {bench:>13s} | {speedup:>10.1f}×"
            )


def generate_latex(summary: pd.DataFrame):
    """Generate LaTeX table for the paper."""
    print("\n── LaTeX Table (B1: TX Throughput) ──\n")
    print(r"\begin{table}[htbp]")
    print(r"\centering")
    print(r"\caption{Full-stack TX throughput (B1) across implementations and platforms.}")
    print(r"\label{tab:tx-throughput}")
    print(r"\begin{tabular}{llcrrr}")
    print(r"\toprule")
    print(r"Implementation & Platform & Security & Throughput (CAMs/s) & Latency $\tilde{x}$ (\si{\micro\second}) & Speedup \\")
    print(r"\midrule")

    tx = summary[summary["benchmark"] == "tx"].copy()
    if tx.empty:
        tx = summary.copy()

    # Get CPython baselines for speedup
    for (plat, sec), group in tx.groupby(["platform", "security"]):
        cpython = group[group["implementation"].str.contains("cpython", case=False)]
        baseline = cpython.iloc[0]["throughput_mean"] if not cpython.empty else 1.0

        for _, row in group.iterrows():
            speedup = row["throughput_mean"] / baseline if baseline > 0 else 0
            speedup_str = f"{speedup:.1f}$\\times$" if "cpython" not in row["implementation"].lower() else "1.0$\\times$"
            print(
                f"  {row['implementation']} & {plat} & {sec} & "
                f"${row['throughput_mean']:.0f} \\pm {row['throughput_std']:.0f}$ & "
                f"${row['latency_p50_us']:.1f}$ & {speedup_str} \\\\"
            )
        print(r"\midrule")

    print(r"\bottomrule")
    print(r"\end{tabular}")
    print(r"\end{table}")


def main():
    parser = argparse.ArgumentParser(description="FlexStack Benchmark Analysis")
    parser.add_argument("--input", "-i", required=True, help="CSV results file")
    parser.add_argument("--latex", action="store_true", help="Generate LaTeX tables")
    parser.add_argument(
        "--output-summary",
        type=str,
        default=None,
        help="Save summary CSV to this path",
    )
    args = parser.parse_args()

    df = load_results(args.input)
    print(f"Loaded {len(df)} result rows from {args.input}")

    summary = summarize(df)
    print_summary(summary)
    compute_speedup(summary)

    if args.latex:
        generate_latex(summary)

    if args.output_summary:
        summary.to_csv(args.output_summary, index=False)
        print(f"\nSummary saved to {args.output_summary}")

    # Flag high-variability cells
    high_cv = summary[summary["cv_pct"] > 5.0]
    if not high_cv.empty:
        print("\n⚠ High variability cells (CV > 5%):")
        for _, row in high_cv.iterrows():
            print(
                f"  {row['implementation']} | {row['platform']} | {row['security']} | "
                f"{row['benchmark']} — CV = {row['cv_pct']:.1f}%"
            )


if __name__ == "__main__":
    main()
