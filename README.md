# FlexStack Benchmarking Suite

Rigorous benchmarking harness for [V2X FlexStack](https://flexstack.eu/) performance evaluation across Python (CPython, PyPy) and Rust implementations.

Designed for a Q1 journal paper with reproducible results, statistical rigor (30 runs per cell, 95% CI), and publication-quality output.

## Project Structure

```
FlexStackBenchmarking/
├── python/
│   ├── benchmark.py            # Python benchmark (CPython + PyPy)
│   ├── generate_certs.py       # ECDSA certificate chain generator
│   └── requirements.txt
├── rust/
│   ├── Cargo.toml              # Rust benchmark project
│   └── src/
│       └── main.rs             # Rust benchmark binary
├── scripts/
│   ├── prepare_system.sh       # System preparation (CPU governor, etc.)
│   └── run_benchmarks.sh       # Full orchestrator (all combinations)
├── analysis/
│   ├── analyze_results.py      # Statistical analysis + LaTeX tables
│   ├── generate_plots.py       # Box plots, security comparison, CDF
│   └── requirements.txt
├── certs/                      # Generated certificates (auto-created)
├── results/                    # Benchmark CSV output (auto-created)
├── next_steps2.md              # Detailed requirements specification
└── README.md                   # This file
```

## Benchmark Matrix

| ID | Benchmark | Security | Platforms | Implementations |
|----|-----------|----------|-----------|-----------------|
| B1 | Full-stack TX throughput | Off + On | Laptop, RPi3, RPi5 | CPython, PyPy, Rust |
| B2 | Full-stack RX throughput | Off + On | Laptop, RPi3, RPi5 | CPython, PyPy, Rust |
| B3 | Concurrent TX/RX throughput | Off + On | Laptop, RPi3, RPi5 | CPython, PyPy, Rust |
| B4 | ASN.1 Codec (encode + decode) | N/A | Laptop, RPi3, RPi5 | CPython, PyPy, Rust |

Each cell: **30 independent runs × 60s measurement** with warm-up discard (5s CPython/Rust, 15s PyPy).

## Quick Start

### 1. Prerequisites

```bash
# Python (CPython 3.13)
pip install v2xflexstack==0.11.0 numpy

# PyPy (optional)
pypy3 -m pip install v2xflexstack==0.11.0 numpy

# Rust
cd rust && cargo build --release
```

### 2. Generate Certificates (for secured benchmarks)

```bash
cd python
python3 generate_certs.py
```

This creates an ECDSA-P256 certificate chain under `certs/` (Root CA → AA → AT1, AT2) used by both Python and Rust benchmarks.

### 3. Run Individual Benchmarks

```bash
# Python TX benchmark (unsecured, loopback)
sudo python3 python/benchmark.py --mode tx --security off --duration 60

# Python TX benchmark (secured)
sudo python3 python/benchmark.py --mode tx --security on --duration 60 --warmup 5

# PyPy TX benchmark (15s JIT warm-up)
sudo pypy3 python/benchmark.py --mode tx --security off --duration 60 --warmup 15

# Rust TX benchmark
sudo rust/target/release/flexstack-bench --mode tx --security off --duration 60

# Codec benchmarks (no sudo needed)
python3 python/benchmark.py --mode codec-encode --duration 60
rust/target/release/flexstack-bench --mode codec-decode --duration 60
```

### 4. Run Full Benchmark Suite

```bash
# Prepare system (disable turbo boost, lock CPU freq, etc.)
sudo scripts/prepare_system.sh laptop

# Run all benchmarks (3 impl × 2 security × 4 modes × 30 runs)
sudo scripts/run_benchmarks.sh laptop 30 60
```

### 5. Analyze Results

```bash
cd analysis
pip install -r requirements.txt

# Summary table + speedup ratios
python3 analyze_results.py --input ../results/results_laptop_*.csv

# With LaTeX table output
python3 analyze_results.py --input ../results/results.csv --latex

# Generate plots
python3 generate_plots.py --input ../results/results.csv
```

## Benchmark Modes

### `--mode tx` (B1: Full-Stack TX Throughput)

Measures CAM generation rate through the complete stack: CA Service → BTP → GeoNetworking → loopback interface. Bypasses the ETSI 100ms rate limiter to measure maximum software processing throughput.

### `--mode rx` (B2: Full-Stack RX Throughput)

A dedicated TX stack sends encoded CAMs via BTP at maximum rate on loopback, while a separate RX stack receives and decodes them with a direct BTP callback. Measures per-packet RX decode latency and throughput.

### `--mode concurrent` (B3: Concurrent TX/RX)

Simultaneous TX and RX. TX generates CAMs at maximum rate while RX decodes incoming loopback packets. Simulates a real ITS station processing both directions.

### `--mode codec-encode` / `--mode codec-decode` (B4: ASN.1 Codec)

In-memory UPER encode/decode of CAM messages. No networking involved. Measures pure ASN.1 processing throughput.

## CLI Interface

Both Python and Rust benchmarks share the same CLI:

```
flexstack-bench / benchmark.py [OPTIONS]

OPTIONS:
  --mode <tx|rx|concurrent|codec-encode|codec-decode>  Benchmark mode
  --security <off|on>                                  ECDSA-P256 security
  --duration <seconds>                                 Measurement time [60]
  --warmup <seconds>                                   Warm-up discard [5]
  --output <csv_path>                                  CSV output file
  --run-id <integer>                                   Run identifier
  --platform <laptop|rpi3|rpi5>                        Platform tag
  --interface <iface>                                  Network interface [lo]
```

## CSV Output Format

Each run appends one row:

```
run_id, implementation, platform, security, benchmark, duration_s, total_cams,
throughput_cams_s, latency_mean_us, latency_std_us, latency_p50_us, latency_p95_us,
latency_p99_us, latency_min_us, latency_max_us, sign_latency_mean_us
```

## Statistical Methodology

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Runs per cell | 30 | CLT-based CI estimation |
| Duration | 60s | Amortize startup transients |
| Cool-down | 10s | Prevent thermal throttling carryover |
| PyPy warm-up | 15s | Conservative JIT compilation margin |
| CPython/Rust warm-up | 5s | OS scheduler settling |

**Reported statistics per cell:**
- Mean ± std deviation
- 95% CI (Student-t: $\bar{x} \pm t_{0.025,29} \cdot s/\sqrt{n}$, where $t_{0.025,29} = 2.045$)
- Percentiles: p50, p95, p99
- Coefficient of variation (flagged if CV > 5%)

## System Preparation

Applied before every benchmark session (documented in paper):

| Setting | Laptop | RPi3/RPi5 |
|---------|--------|-----------|
| CPU governor | `performance` | `performance` |
| Turbo Boost | Disabled | N/A |
| Process pinning | `taskset -c 2,3` | `taskset -c 2,3` |
| RT priority | `chrt -f 50` | `chrt -f 50` |
| Swap | Disabled | Disabled |
| Background services | Stopped | Stopped |

## Cross-Compilation (RPi3/RPi5)

```bash
# Rust cross-compilation for aarch64
cd rust
rustup target add aarch64-unknown-linux-gnu
cargo build --release --target aarch64-unknown-linux-gnu
# Binary at: target/aarch64-unknown-linux-gnu/release/flexstack-bench
```

## Software Versions

| Component | Version |
|-----------|---------|
| Python FlexStack | v2xflexstack 0.11.0 |
| Rust FlexStack | rustflexstack 0.2.1 |
| CPython | 3.13 |
| PyPy | 3.11 |
| Rust | stable (1.75+), `--release`, LTO |

## License

AGPL-3.0 — See individual source files for copyright notices.

## Citation

If you use this benchmarking suite, please cite:
- Python FlexStack: https://github.com/Fundacio-i2CAT/FlexStack
- Rust FlexStack: https://github.com/Fundacio-i2CAT/RustFlexstack
