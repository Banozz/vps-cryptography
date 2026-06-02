#!/usr/bin/env python3
"""
analysis.py — Analisis Statistik Hasil Benchmark PQC TLS 1.3

[W6] Menambahkan Wilcoxon rank-sum test (Mann-Whitney U) untuk mengonfirmasi
     perbedaan antar skenario bukan noise statistik.

Output:
  - analysis_report.json  : Statistik deskriptif + hasil uji Wilcoxon
  - feasibility_report.txt: Penilaian layak/tidak berdasarkan kriteria Subbab 3.5
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

try:
    import numpy as np
    import pandas as pd
    from scipy import stats
except ImportError:
    print("ERROR: Pastikan pandas, numpy, scipy sudah terinstall.")
    print("       pip3 install pandas numpy scipy")
    sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# Kriteria evaluasi kelayakan (Subbab 3.5)
# ─────────────────────────────────────────────────────────────────────────────
THRESHOLD_LATENCY_OVERHEAD_PCT = 30.0  # Overhead TTLB/Handshake C vs A ≤ 30%
THRESHOLD_CPU_PEAK_PCT = 80.0  # CPU peak Skenario C ≤ 80%

METRICS_LABELS = {
    "handshake_time_s": "Handshake Time (s)",
    "ttfb_s": "TTFB (s)",
    "ttlb_s": "TTLB (s)",
    "cpu_peak_pct": "CPU Peak (%)",
    "cpu_mean_pct": "CPU Mean (%)",
    "ram_peak_bytes": "RAM Peak (bytes)",
}


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
def load_results(results_file: Path) -> pd.DataFrame:
    df = pd.read_csv(results_file)
    # Pastikan hanya baris data (bukan warmup) yang diproses
    if "is_warmup" in df.columns:
        df = df[df["is_warmup"] == False].copy()
    return df


def descriptive_stats(series: pd.Series) -> dict:
    """Statistik deskriptif sesuai Subbab 3.5: median, P95, std."""
    s = series.dropna()
    if len(s) == 0:
        return {"n": 0}
    return {
        "n": len(s),
        "median": float(s.median()),
        "mean": float(s.mean()),
        "std": float(s.std()),
        "p05": float(s.quantile(0.05)),
        "p95": float(s.quantile(0.95)),
        "min": float(s.min()),
        "max": float(s.max()),
    }


def wilcoxon_ranksum(a: pd.Series, b: pd.Series) -> dict:
    """
    [W6] Wilcoxon rank-sum test (Mann-Whitney U, two-sided).

    H₀: Distribusi a dan b identik (tidak ada perbedaan signifikan).
    H₁: Ada perbedaan signifikan (p < 0.05 → tolak H₀).

    Juga menghitung:
      - Overhead relatif: (median_b - median_a) / median_a x 100%
      - Effect size: rank-biserial correlation (r = 1 - 2U/(n_a x n_b))
    """
    a_clean = a.dropna()
    b_clean = b.dropna()

    if len(a_clean) == 0 or len(b_clean) == 0:
        return {"error": "Tidak cukup data untuk uji statistik"}

    u_stat, p_value = stats.mannwhitneyu(a_clean, b_clean, alternative="two-sided")
    n_a, n_b = len(a_clean), len(b_clean)

    # Rank-biserial correlation sebagai effect size
    r = 1 - (2 * u_stat) / (n_a * n_b)

    # Overhead relatif median
    median_a = a_clean.median()
    median_b = b_clean.median()
    overhead_pct = (
        ((median_b - median_a) / median_a * 100) if median_a != 0 else float("nan")
    )

    return {
        "u_stat": float(u_stat),
        "p_value": float(p_value),
        "significant": bool(p_value < 0.05),
        "effect_size_r": float(r),
        "median_a": float(median_a),
        "median_b": float(median_b),
        "overhead_pct": float(overhead_pct),
        "interpretation": (
            f"Overhead {overhead_pct:+.1f}% — "
            + ("signifikan" if p_value < 0.05 else "TIDAK signifikan")
            + f" (p={p_value:.4f})"
        ),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Analisis per-metrik per-jaringan
# ─────────────────────────────────────────────────────────────────────────────
def analyze_metric(df: pd.DataFrame, metric: str, network: str) -> dict:
    result = {}

    for sc in ["A", "B", "C"]:
        subset = df[(df["scenario"] == sc) & (df["network"] == network)][metric]
        result[f"scenario_{sc}"] = descriptive_stats(subset)

    # [W6] Wilcoxon: A vs B dan A vs C
    baseline = df[(df["scenario"] == "A") & (df["network"] == network)][metric]
    for sc in ["B", "C"]:
        comparison = df[(df["scenario"] == sc) & (df["network"] == network)][metric]
        result[f"wilcoxon_A_vs_{sc}"] = wilcoxon_ranksum(baseline, comparison)

    # [W6] Wilcoxon: B vs C (Pure PQC vs Hybrid)
    b_data = df[(df["scenario"] == "B") & (df["network"] == network)][metric]
    c_data = df[(df["scenario"] == "C") & (df["network"] == network)][metric]
    result["wilcoxon_B_vs_C"] = wilcoxon_ranksum(b_data, c_data)

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Penilaian kelayakan (Subbab 3.5)
# ─────────────────────────────────────────────────────────────────────────────
def assess_feasibility(df: pd.DataFrame) -> dict:
    """
    Kriteria dari Subbab 3.5:
    1. Overhead TTLB/Handshake Skenario C vs A pada jaringan ideal ≤ 30%
    2. CPU peak Skenario C ≤ 80% dari kapasitas single-core
    """

    def get(sc, net, col):
        return df[(df["scenario"] == sc) & (df["network"] == net)][col].dropna()

    # ── Latency overhead (jaringan ideal) ────────────────────────────────
    hs_a = get("A", "ideal", "handshake_time_s").median()
    hs_c = get("C", "ideal", "handshake_time_s").median()
    hs_ovh = (hs_c - hs_a) / hs_a * 100 if hs_a else float("nan")

    ttlb_a = get("A", "ideal", "ttlb_s").median()
    ttlb_c = get("C", "ideal", "ttlb_s").median()
    ttlb_ovh = (ttlb_c - ttlb_a) / ttlb_a * 100 if ttlb_a else float("nan")

    # ── CPU overhead ─────────────────────────────────────────────────────
    cpu_c_p95 = get("C", "ideal", "cpu_peak_pct").quantile(0.95)
    cpu_c_max = get("C", "ideal", "cpu_peak_pct").max()

    feas_hs = hs_ovh <= THRESHOLD_LATENCY_OVERHEAD_PCT
    feas_ttlb = ttlb_ovh <= THRESHOLD_LATENCY_OVERHEAD_PCT
    feas_cpu = cpu_c_p95 <= THRESHOLD_CPU_PEAK_PCT

    return {
        "handshake_overhead_pct": float(hs_ovh),
        "ttlb_overhead_pct": float(ttlb_ovh),
        "cpu_peak_p95_pct": float(cpu_c_p95),
        "cpu_peak_max_pct": float(cpu_c_max),
        "threshold_latency_pct": THRESHOLD_LATENCY_OVERHEAD_PCT,
        "threshold_cpu_pct": THRESHOLD_CPU_PEAK_PCT,
        "criterion_handshake_passed": bool(feas_hs),
        "criterion_ttlb_passed": bool(feas_ttlb),
        "criterion_cpu_passed": bool(feas_cpu),
        "overall_feasible": bool(feas_hs and feas_ttlb and feas_cpu),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Cetak ringkasan ke terminal
# ─────────────────────────────────────────────────────────────────────────────
def print_summary(report: dict):
    sep = "═" * 64

    print(f"\n{sep}")
    print(f"  RINGKASAN ANALISIS STATISTIK — PQC TLS 1.3 BENCHMARK")
    print(sep)

    for network in ["ideal", "edge"]:
        if network not in report["metrics"]:
            continue
        net_label = NETWORK_CONDITIONS_LABEL.get(network, network)
        print(f"\n  ▶ Jaringan: {net_label}")
        print(
            f"  {'Metrik':<25} {'A median':>12} {'B median':>12} {'C median':>12} "
            f"{'C vs A overhead':>16} {'Signifikan?':>12}"
        )
        print(f"  {'─' * 25} {'─' * 12} {'─' * 12} {'─' * 12} {'─' * 16} {'─' * 12}")

        for metric in [
            "handshake_time_s",
            "ttfb_s",
            "ttlb_s",
            "cpu_peak_pct",
            "ram_peak_bytes",
        ]:
            if metric not in report["metrics"].get(network, {}):
                continue
            m = report["metrics"][network][metric]
            sc_a = m.get("scenario_A", {})
            sc_c = m.get("scenario_C", {})
            wc = m.get("wilcoxon_A_vs_C", {})

            # Format nilai sesuai unit
            def fmt(v, col):
                if v is None or (isinstance(v, float) and np.isnan(v)):
                    return "   N/A"
                if col == "ram_peak_bytes":
                    return f"{v / 1024:10.1f}KB"
                elif col.endswith("_s"):
                    return f"{v * 1000:11.2f}ms"
                else:
                    return f"{v:11.1f}%"

            a_med = sc_a.get("median")
            c_med = sc_c.get("median")
            b_med = m.get("scenario_B", {}).get("median")
            ovh = wc.get("overhead_pct", float("nan"))
            sig = "✓ Ya" if wc.get("significant") else "✗ Tidak"

            print(
                f"  {METRICS_SHORT.get(metric, metric):<25}"
                f"{fmt(a_med, metric):>12}"
                f"{fmt(b_med, metric):>12}"
                f"{fmt(c_med, metric):>12}"
                f"{ovh:+15.1f}%"
                f"{sig:>13}"
            )

    # Kelayakan
    feas = report.get("feasibility", {})
    print(f"\n{sep}")
    print(f"  PENILAIAN KELAYAKAN (Subbab 3.5)")
    print(sep)
    print(
        f"  Overhead Handshake C vs A (ideal): "
        f"{feas.get('handshake_overhead_pct', float('nan')):+.1f}% "
        f"(threshold ≤{THRESHOLD_LATENCY_OVERHEAD_PCT}%) → "
        + ("LULUS" if feas.get("criterion_handshake_passed") else "GAGAL")
    )
    print(
        f"  Overhead TTLB       C vs A (ideal): "
        f"{feas.get('ttlb_overhead_pct', float('nan')):+.1f}% "
        f"(threshold ≤{THRESHOLD_LATENCY_OVERHEAD_PCT}%) → "
        + ("LULUS" if feas.get("criterion_ttlb_passed") else "GAGAL")
    )
    print(
        f"  CPU Peak P95       Skenario C:       "
        f"{feas.get('cpu_peak_p95_pct', float('nan')):.1f}% "
        f"(threshold ≤{THRESHOLD_CPU_PEAK_PCT}%) → "
        + ("LULUS" if feas.get("criterion_cpu_passed") else "GAGAL")
    )
    verdict = feas.get("overall_feasible")
    print(f"\n  Verdict: {'LULUS' if verdict else 'GAGAL'}")
    print(sep + "\n")


METRICS_SHORT = {
    "handshake_time_s": "Handshake Time",
    "ttfb_s": "TTFB",
    "ttlb_s": "TTLB",
    "cpu_peak_pct": "CPU Peak",
    "cpu_mean_pct": "CPU Mean",
    "ram_peak_bytes": "RAM Peak",
}

NETWORK_CONDITIONS_LABEL = {
    "ideal": "Ideal (<1ms, 0% loss)",
    "edge": "Edge (100ms, 1% loss)",
}


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Analisis statistik hasil benchmark PQC TLS 1.3 [W6]"
    )
    parser.add_argument(
        "--results-file",
        type=Path,
        required=True,
        help="Path ke file CSV hasil benchmark (results_combined_*.csv)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("/results"),
        help="Direktori output laporan",
    )
    args = parser.parse_args()

    if not args.results_file.exists():
        print(f"ERROR: File tidak ditemukan: {args.results_file}")
        sys.exit(1)

    args.output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Memuat data dari: {args.results_file}")
    df = load_results(args.results_file)
    print(
        f"Total baris: {len(df)} | Skenario: {sorted(df['scenario'].unique())} | "
        f"Jaringan: {sorted(df['network'].unique())}"
    )

    report = {
        "source_file": str(args.results_file),
        "total_rows": len(df),
        "metrics": {},
        "feasibility": {},
    }

    networks = df["network"].unique().tolist()
    metrics = [m for m in METRICS_LABELS if m in df.columns]

    for network in networks:
        report["metrics"][network] = {}
        for metric in metrics:
            report["metrics"][network][metric] = analyze_metric(df, metric, network)

    report["feasibility"] = assess_feasibility(df)

    # Simpan JSON
    report_path = args.output_dir / "analysis_report.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"Laporan JSON tersimpan: {report_path}")

    # Cetak ringkasan
    print_summary(report)


if __name__ == "__main__":
    main()
