#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""
FlexStack Benchmark — Visualization

Generates publication-quality plots from benchmark CSV results:
  1. Box plots comparing implementations per benchmark × platform
  2. Grouped bars: unsecured vs. secured side by side
  3. JIT warm-up curve (if time-series data available)

Usage:
  python3 generate_plots.py --input ../results/results.csv --output-dir ../results/plots/
"""

import argparse
import os

import matplotlib
matplotlib.use("Agg")  # Non-interactive backend
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import numpy as np
import pandas as pd


# Publication style
plt.rcParams.update({
    "font.size": 10,
    "font.family": "serif",
    "figure.figsize": (8, 5),
    "figure.dpi": 150,
    "savefig.dpi": 300,
    "savefig.bbox": "tight",
    "axes.grid": True,
    "grid.alpha": 0.3,
})

IMPL_COLORS = {
    "rust": "#E07020",
    "cpython": "#306998",
    "pypy": "#4B8BBE",
}

IMPL_ORDER = ["cpython", "pypy", "rust"]


def load_results(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    for col in ["throughput_cams_s", "latency_p50_us", "latency_p95_us", "latency_p99_us"]:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")
    return df


def normalize_impl(impl_str: str) -> str:
    """Normalize implementation name for consistent ordering."""
    s = impl_str.lower()
    if "cpython" in s:
        return "cpython"
    elif "pypy" in s:
        return "pypy"
    elif "rust" in s:
        return "rust"
    return s


def plot_throughput_boxplots(df: pd.DataFrame, output_dir: str):
    """
    Box plots of throughput per (implementation, platform, security, benchmark).
    One figure per (benchmark, platform) combination.
    """
    df = df.copy()
    df["impl_norm"] = df["implementation"].apply(normalize_impl)

    for (bench, plat), group in df.groupby(["benchmark", "platform"]):
        fig, ax = plt.subplots(figsize=(8, 5))

        sec_modes = sorted(group["security"].unique())
        impls = [i for i in IMPL_ORDER if i in group["impl_norm"].unique()]
        n_impl = len(impls)
        n_sec = len(sec_modes)

        positions = []
        labels = []
        box_data = []
        colors = []

        for i, impl in enumerate(impls):
            for j, sec in enumerate(sec_modes):
                mask = (group["impl_norm"] == impl) & (group["security"] == sec)
                data = group.loc[mask, "throughput_cams_s"].dropna().values
                if len(data) == 0:
                    continue
                pos = i * (n_sec + 1) + j
                positions.append(pos)
                labels.append(f"{impl}\n({sec})")
                box_data.append(data)
                alpha = 1.0 if sec == "off" else 0.6
                colors.append(IMPL_COLORS.get(impl, "#999999"))

        if not box_data:
            plt.close(fig)
            continue

        bp = ax.boxplot(
            box_data,
            positions=positions,
            widths=0.6,
            patch_artist=True,
            showfliers=True,
            flierprops=dict(marker="o", markersize=3, alpha=0.5),
        )

        for patch, color in zip(bp["boxes"], colors):
            patch.set_facecolor(color)
            patch.set_alpha(0.7)

        ax.set_xticks(positions)
        ax.set_xticklabels(labels, fontsize=8)
        ax.set_ylabel("Throughput (CAMs/s)")
        ax.set_title(f"{bench.upper()} — {plat}")
        ax.yaxis.set_major_formatter(ticker.StrMethodFormatter("{x:,.0f}"))

        fname = f"boxplot_{bench}_{plat}.pdf"
        fig.savefig(os.path.join(output_dir, fname))
        plt.close(fig)
        print(f"  Saved {fname}")


def plot_security_comparison(df: pd.DataFrame, output_dir: str):
    """
    Grouped bar chart: unsecured vs. secured throughput per implementation.
    One figure per (benchmark, platform).
    """
    df = df.copy()
    df["impl_norm"] = df["implementation"].apply(normalize_impl)

    for (bench, plat), group in df.groupby(["benchmark", "platform"]):
        impls = [i for i in IMPL_ORDER if i in group["impl_norm"].unique()]
        sec_modes = sorted(group["security"].unique())

        if len(sec_modes) < 2:
            continue

        fig, ax = plt.subplots(figsize=(8, 5))
        x = np.arange(len(impls))
        width = 0.35

        for j, sec in enumerate(sec_modes):
            means = []
            stds = []
            for impl in impls:
                mask = (group["impl_norm"] == impl) & (group["security"] == sec)
                data = group.loc[mask, "throughput_cams_s"].dropna()
                means.append(data.mean() if len(data) > 0 else 0)
                stds.append(data.std() if len(data) > 1 else 0)

            offset = (j - 0.5) * width
            color = "#4A90D9" if sec == "off" else "#D94A4A"
            hatch = "" if sec == "off" else "///"
            ax.bar(
                x + offset,
                means,
                width,
                yerr=stds,
                label=f"Security {sec}",
                color=color,
                alpha=0.7,
                hatch=hatch,
                edgecolor="black",
                linewidth=0.5,
                capsize=3,
            )

        ax.set_xticks(x)
        ax.set_xticklabels([i.upper() for i in impls])
        ax.set_ylabel("Throughput (CAMs/s)")
        ax.set_title(f"{bench.upper()} — {plat}: Security Overhead")
        ax.legend()
        ax.yaxis.set_major_formatter(ticker.StrMethodFormatter("{x:,.0f}"))

        fname = f"security_{bench}_{plat}.pdf"
        fig.savefig(os.path.join(output_dir, fname))
        plt.close(fig)
        print(f"  Saved {fname}")


def plot_latency_cdf(df: pd.DataFrame, output_dir: str):
    """
    CDF of per-run mean latency per (benchmark, platform).
    """
    df = df.copy()
    df["impl_norm"] = df["implementation"].apply(normalize_impl)

    for (bench, plat), group in df.groupby(["benchmark", "platform"]):
        fig, ax = plt.subplots(figsize=(8, 5))

        impls = [i for i in IMPL_ORDER if i in group["impl_norm"].unique()]
        for impl in impls:
            mask = group["impl_norm"] == impl
            data = group.loc[mask, "latency_p50_us"].dropna().sort_values()
            if len(data) == 0:
                continue
            cdf = np.arange(1, len(data) + 1) / len(data)
            ax.plot(data, cdf, label=impl.upper(), color=IMPL_COLORS.get(impl, "#999"))

        ax.set_xlabel("Median Latency per Run (μs)")
        ax.set_ylabel("CDF")
        ax.set_title(f"{bench.upper()} — {plat}: Latency Distribution")
        ax.legend()

        fname = f"latency_cdf_{bench}_{plat}.pdf"
        fig.savefig(os.path.join(output_dir, fname))
        plt.close(fig)
        print(f"  Saved {fname}")


def main():
    parser = argparse.ArgumentParser(description="FlexStack Benchmark Plots")
    parser.add_argument("--input", "-i", required=True, help="CSV results file")
    parser.add_argument(
        "--output-dir",
        "-o",
        default="../results/plots/",
        help="Output directory for plots",
    )
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    df = load_results(args.input)
    print(f"Loaded {len(df)} rows from {args.input}")
    print()

    print("Generating box plots...")
    plot_throughput_boxplots(df, args.output_dir)

    print("Generating security comparison plots...")
    plot_security_comparison(df, args.output_dir)

    print("Generating latency CDF plots...")
    plot_latency_cdf(df, args.output_dir)

    print(f"\nAll plots saved to {args.output_dir}")


if __name__ == "__main__":
    main()
