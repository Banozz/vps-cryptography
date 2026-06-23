#!/usr/bin/env python3
"""
analysis.py — Analisis Statistik Hasil Benchmark PQC TLS 1.3

DISESUAIKAN dengan skema output benchmark.py terbaru (metrik waktu dari PCAP
terdekripsi via keylog, resource dari /usr/bin/time -v).

Perubahan skema kolom CSV vs versi lama:
  - handshake_time_s (s)  -> handshake_ms (ms; bisa kosong bila PCAP tak didekripsi)
  - ttfb_s / ttlb_s (s)   -> ttfb_ms / ttlb_ms (ms)
  - cpu_peak_pct (num)    -> cpu_pct_time (string "57%") + cpu_usr_s + cpu_sys_s
                             (CATATAN: cpu_pct_time = RATA-RATA CPU proses, bukan
                             peak instan; P95-nya dipakai sebagai PROKSI peak)
  - ram_peak_bytes        -> max_rss_kb (KB)

[W6] Wilcoxon rank-sum (Mann-Whitney U) untuk konfirmasi perbedaan antar skenario.
[W7] Correlation check Pearson Handshake<->TTFB (sanity-check isolasi variabel).

Output:
  - analysis/analysis_report.json : Statistik deskriptif + Wilcoxon + korelasi
  - plots/*.png                   : Grafik perbandingan antar skenario
  - (ringkasan dicetak ke terminal)
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path

try:
    import numpy as np
    import pandas as pd
    from scipy import stats
except ImportError:
    print("ERROR: Pastikan pandas, numpy, scipy sudah terinstall.")
    print("       pip3 install pandas numpy scipy")
    sys.exit(1)

# Matplotlib dipakai untuk output grafik. Wajib tersedia di Docker image,
# tetapi tetap dibuat defensif agar script tidak crash di environment lain.
try:
    import matplotlib
    matplotlib.use("Agg")  # headless / Docker-friendly
    import matplotlib.pyplot as plt
except Exception as _mpl_e:  # pragma: no cover
    plt = None
    _MPL_ERR = str(_mpl_e)
else:
    _MPL_ERR = ""

# Analisis konvergensi warm-up (modul terpisah; pandas+numpy+matplotlib).
# Dibungkus opsional agar analysis.py tetap jalan bila modul tak tersedia.
try:
    from warmup_convergence import warmup_convergence_analysis
    _WARMUP_OK = True
    _WARMUP_ERR = ""
except Exception as _wu_e:  # pragma: no cover
    _WARMUP_OK = False
    _WARMUP_ERR = str(_wu_e)


# ─────────────────────────────────────────────────────────
# Kriteria evaluasi kelayakan (Subbab 3.5)
# ─────────────────────────────────────────────────────────
THRESHOLD_LATENCY_OVERHEAD_PCT = 30.0  # Overhead TTLB/Handshake C vs A ≤ 30%
THRESHOLD_CPU_PEAK_PCT = 80.0          # CPU (proksi peak) Skenario C ≤ 80%

# metric_column -> (label, short, unit)
METRICS_CONFIG = {
    "handshake_ms": ("Handshake Time (ms)", "Handshake Time", "ms"),
    "ttfb_ms":      ("TTFB (ms)",           "TTFB",           "ms"),
    "ttlb_ms":      ("TTLB (ms)",           "TTLB",           "ms"),
    "cpu_ms":       ("CPU Time (ms)",       "CPU Time",       "ms"),
    "cpu_pct":      ("CPU Util (%)",        "CPU Util",       "pct"),
    "max_rss_kb":   ("RAM Peak (KB)",       "RAM Peak",       "kb"),
}

NETWORK_LABEL = {
    "ideal": "Ideal (<1ms, 0% loss)",
    "edge":  "Edge (100ms, 1% loss)",
}

SCENARIO_ORDER = ["A", "B", "C"]


# ─────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────
def _parse_cpu_pct(val) -> float:
    """Konversi string '57%' dari /usr/bin/time -v menjadi float 57.0."""
    if pd.isna(val):
        return np.nan
    m = re.search(r"([\d.]+)", str(val))
    return float(m.group(1)) if m else np.nan


def load_results(results_file: Path, keep_warmup: bool = False) -> pd.DataFrame:
    df = pd.read_csv(results_file)

    # Buang baris warmup untuk analisis steady-state. benchmark.py terbaru
    # mencatat SEMUA iterasi, jadi pembuangan dilakukan di sini. Set
    # keep_warmup=True untuk analisis konvergensi warm-up (butuh baris warm-up).
    if not keep_warmup and "is_warmup" in df.columns:
        is_wu = df["is_warmup"].astype(str).str.strip().str.lower()
        df = df[~is_wu.isin(["true", "1"])].copy()

    # Derivasi kolom numerik cpu_pct dari string cpu_pct_time ("57%").
    if "cpu_pct_time" in df.columns:
        df["cpu_pct"] = df["cpu_pct_time"].apply(_parse_cpu_pct)

    # Total CPU seconds (user + sys).
    if "cpu_usr_s" in df.columns and "cpu_sys_s" in df.columns:
        df["cpu_total_s"] = (
            pd.to_numeric(df["cpu_usr_s"], errors="coerce").fillna(0)
            + pd.to_numeric(df["cpu_sys_s"], errors="coerce").fillna(0)
        )

    # cpu_ms = metrik biaya komputasi PRIMER (absolut, invarian thd delay jaringan).
    # Utamakan kolom cpu_ms dari CSV benchmark.py terbaru (getrusage, presisi us).
    # Bila tidak ada (CSV lama), turunkan dari cpu_usr_s+cpu_sys_s.
    if "cpu_ms" not in df.columns and "cpu_total_s" in df.columns:
        df["cpu_ms"] = df["cpu_total_s"] * 1000.0
    if "cpu_ms" in df.columns:
        df["cpu_ms"] = pd.to_numeric(df["cpu_ms"], errors="coerce")

    # Pastikan kolom metrik waktu numerik (handshake_ms bisa kosong -> NaN).
    for col in ("handshake_ms", "ttfb_ms", "ttlb_ms", "max_rss_kb"):
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")

    return df


def descriptive_stats(series: pd.Series) -> dict:
    """Statistik deskriptif sesuai Subbab 3.5: median, P95, std."""
    s = series.dropna()
    if len(s) == 0:
        return {"n": 0}
    return {
        "n": int(len(s)),
        "median": float(s.median()),
        "mean": float(s.mean()),
        "std": float(s.std()),
        "p05": float(s.quantile(0.05)),
        "p95": float(s.quantile(0.95)),
        "min": float(s.min()),
        "max": float(s.max()),
    }


def wilcoxon_ranksum(a: pd.Series, b: pd.Series) -> dict:
    """[W6] Mann-Whitney U (two-sided) + overhead median + effect size."""
    a_clean = a.dropna()
    b_clean = b.dropna()
    if len(a_clean) == 0 or len(b_clean) == 0:
        return {"error": "Tidak cukup data untuk uji statistik"}

    u_stat, p_value = stats.mannwhitneyu(a_clean, b_clean, alternative="two-sided")
    n_a, n_b = len(a_clean), len(b_clean)
    r = 1 - (2 * u_stat) / (n_a * n_b)  # rank-biserial correlation

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


def _network_sorted_unique(df: pd.DataFrame) -> list[str]:
    order = [n for n in ["ideal", "edge"] if n in set(df["network"].dropna().astype(str))]
    extras = [n for n in sorted(df["network"].dropna().astype(str).unique()) if n not in order]
    return order + extras


# ─────────────────────────────────────────────────────────
# Analisis per-metrik per-jaringan
# ─────────────────────────────────────────────────────────
def analyze_metric(df: pd.DataFrame, metric: str, network: str) -> dict:
    result = {}
    for sc in SCENARIO_ORDER:
        subset = df[(df["scenario"] == sc) & (df["network"] == network)][metric]
        result[f"scenario_{sc}"] = descriptive_stats(subset)

    baseline = df[(df["scenario"] == "A") & (df["network"] == network)][metric]
    for sc in ["B", "C"]:
        comparison = df[(df["scenario"] == sc) & (df["network"] == network)][metric]
        result[f"wilcoxon_A_vs_{sc}"] = wilcoxon_ranksum(baseline, comparison)

    b_data = df[(df["scenario"] == "B") & (df["network"] == network)][metric]
    c_data = df[(df["scenario"] == "C") & (df["network"] == network)][metric]
    result["wilcoxon_B_vs_C"] = wilcoxon_ranksum(b_data, c_data)
    return result


# ─────────────────────────────────────────────────────────
# [W7] Correlation check Handshake <-> TTFB (sanity-check isolasi variabel)
# ─────────────────────────────────────────────────────────
def correlation_analysis(df: pd.DataFrame, network: str) -> dict:
    """
    Pearson r antara Handshake Time dan TTFB per skenario. r tinggi (mis. >0.95)
    = bukti empiris bahwa 'leg aplikasi' ~konstan (TTFB bergerak seiring
    Handshake), bukan sekadar asumsi desain. Juga korelasi (TTFB-Handshake)
    vs CPU untuk deteksi confounder resource-contention.
    """
    out = {}
    if "handshake_ms" not in df.columns or "ttfb_ms" not in df.columns:
        return {"error": "Kolom handshake_ms/ttfb_ms tidak tersedia"}

    for sc in SCENARIO_ORDER:
        sub = df[(df["scenario"] == sc) & (df["network"] == network)]
        pair = sub[["handshake_ms", "ttfb_ms"]].dropna()
        entry = {"n": int(len(pair))}
        if len(pair) >= 3 and pair["handshake_ms"].std() > 0 and pair["ttfb_ms"].std() > 0:
            r, p = stats.pearsonr(pair["handshake_ms"], pair["ttfb_ms"])
            entry["pearson_hs_ttfb_r"] = float(r)
            entry["pearson_hs_ttfb_p"] = float(p)
            entry["isolasi_terkonfirmasi"] = bool(r > 0.95)
        else:
            entry["pearson_hs_ttfb_r"] = None
            entry["pearson_hs_ttfb_p"] = None
            entry["isolasi_terkonfirmasi"] = None

        # (TTFB - Handshake) vs CPU
        if "cpu_pct" in sub.columns:
            tmp = sub[["handshake_ms", "ttfb_ms", "cpu_pct"]].dropna()
            if len(tmp) >= 3:
                proc = tmp["ttfb_ms"] - tmp["handshake_ms"]
                if proc.std() > 0 and tmp["cpu_pct"].std() > 0:
                    rc, pc = stats.pearsonr(proc, tmp["cpu_pct"])
                    entry["pearson_procleg_cpu_r"] = float(rc)
                    entry["pearson_procleg_cpu_p"] = float(pc)
        out[f"scenario_{sc}"] = entry
    return out


# ─────────────────────────────────────────────────────────
# Penilaian kelayakan (Subbab 3.5)
# ─────────────────────────────────────────────────────────
def _safe_overhead(med_a, med_c):
    if pd.notna(med_a) and med_a != 0 and pd.notna(med_c):
        return (med_c - med_a) / med_a * 100
    return float("nan")


def assess_feasibility(df: pd.DataFrame) -> dict:
    def get(sc, net, col):
        if col not in df.columns:
            return pd.Series(dtype=float)
        return df[(df["scenario"] == sc) & (df["network"] == net)][col].dropna()

    hs_a = get("A", "ideal", "handshake_ms").median()
    hs_c = get("C", "ideal", "handshake_ms").median()
    hs_ovh = _safe_overhead(hs_a, hs_c)
    handshake_available = pd.notna(hs_a) and pd.notna(hs_c)

    ttlb_a = get("A", "ideal", "ttlb_ms").median()
    ttlb_c = get("C", "ideal", "ttlb_ms").median()
    ttlb_ovh = _safe_overhead(ttlb_a, ttlb_c)

    # cpu_pct HANYA dibandingkan pada kondisi ideal; di edge terdilusi waktu tunggu I/O.
    cpu_series = get("C", "ideal", "cpu_pct")
    cpu_c_p95 = float(cpu_series.quantile(0.95)) if len(cpu_series) else float("nan")
    cpu_c_max = float(cpu_series.max()) if len(cpu_series) else float("nan")

    # Biaya komputasi absolut (cpu_ms) C vs A pada ideal -- metrik primer.
    cpu_ms_a = get("A", "ideal", "cpu_ms").median()
    cpu_ms_c = get("C", "ideal", "cpu_ms").median()
    cpu_ms_ovh = _safe_overhead(cpu_ms_a, cpu_ms_c)

    feas_hs = bool(hs_ovh <= THRESHOLD_LATENCY_OVERHEAD_PCT) if pd.notna(hs_ovh) else None
    feas_ttlb = bool(ttlb_ovh <= THRESHOLD_LATENCY_OVERHEAD_PCT) if pd.notna(ttlb_ovh) else None
    feas_cpu = bool(cpu_c_p95 <= THRESHOLD_CPU_PEAK_PCT) if pd.notna(cpu_c_p95) else None

    criteria = [feas_hs, feas_ttlb, feas_cpu]
    overall = all(c is True for c in criteria) if all(c is not None for c in criteria) else None

    return {
        "handshake_available": bool(handshake_available),
        "handshake_overhead_pct": float(hs_ovh),
        "ttlb_overhead_pct": float(ttlb_ovh),
        "cpu_p95_pct": float(cpu_c_p95),
        "cpu_max_pct": float(cpu_c_max),
        "cpu_ms_median_A_ideal": float(cpu_ms_a) if pd.notna(cpu_ms_a) else None,
        "cpu_ms_median_C_ideal": float(cpu_ms_c) if pd.notna(cpu_ms_c) else None,
        "cpu_ms_overhead_pct_ideal": float(cpu_ms_ovh),
        "cpu_note": (
            "Metrik CPU primer = cpu_ms (waktu CPU absolut via getrusage, "
            "invarian thd jaringan). cpu_pct (utilisasi %) hanya valid pada "
            "kondisi ideal; P95-nya dipakai sebagai proksi peak utk kriteria 3.5."
        ),
        "threshold_latency_pct": THRESHOLD_LATENCY_OVERHEAD_PCT,
        "threshold_cpu_pct": THRESHOLD_CPU_PEAK_PCT,
        "criterion_handshake_passed": feas_hs,
        "criterion_ttlb_passed": feas_ttlb,
        "criterion_cpu_passed": feas_cpu,
        "overall_feasible": overall,
    }


# ─────────────────────────────────────────────────────────
# Visualisasi
# ─────────────────────────────────────────────────────────
def _require_matplotlib() -> None:
    if plt is None:
        raise RuntimeError(f"Matplotlib tidak tersedia: {_MPL_ERR}")


def _format_units(metric: str, value: float) -> str:
    if value is None or (isinstance(value, float) and np.isnan(value)):
        return "N/A"
    _, _, unit = METRICS_CONFIG[metric]
    if unit == "ms":
        return f"{value:.2f} ms"
    if unit == "kb":
        return f"{value:.1f} KB"
    if unit == "pct":
        return f"{value:.1f}%"
    return str(value)


def _boxplot_with_labels(ax, data, labels):
    try:
        return ax.boxplot(data, tick_labels=labels, showfliers=False)
    except TypeError:
        return ax.boxplot(data, labels=labels, showfliers=False)


def plot_metric_boxplots(df: pd.DataFrame, metric: str, outpath: Path) -> str:
    """
    Boxplot per metrik dengan 2 panel:
      - kiri: ideal
      - kanan: edge
    Setiap panel berisi skenario A/B/C.
    """
    _require_matplotlib()

    title, short, unit = METRICS_CONFIG[metric]
    fig, axes = plt.subplots(1, 2, figsize=(13, 5), sharey=True)

    for ax, network in zip(axes, ["ideal", "edge"]):
        data = []
        labels = []
        for sc in SCENARIO_ORDER:
            vals = df[(df["network"] == network) & (df["scenario"] == sc)][metric].dropna()
            data.append(vals.tolist() if len(vals) else [np.nan])
            labels.append(sc)

        _boxplot_with_labels(ax, data, labels)
        ax.set_title(NETWORK_LABEL.get(network, network))
        ax.set_xlabel("Skenario")
        ax.set_ylabel(title)
        ax.grid(True, alpha=0.25)

    fig.suptitle(f"{title} per Skenario dan Jaringan")
    fig.tight_layout()
    fig.savefig(outpath, dpi=300, bbox_inches="tight")
    plt.close(fig)
    return str(outpath)


def plot_cpu_pct_ideal(df: pd.DataFrame, outpath: Path) -> str:
    """CPU utilitas hanya relevan pada jaringan ideal sesuai Bab III."""
    _require_matplotlib()

    metric = "cpu_pct"
    fig, ax = plt.subplots(figsize=(7, 5))

    data = []
    labels = []
    for sc in SCENARIO_ORDER:
        vals = df[(df["network"] == "ideal") & (df["scenario"] == sc)][metric].dropna()
        if len(vals) == 0:
            vals = pd.Series(dtype=float)
        data.append(vals)
        labels.append(sc)

    _boxplot_with_labels(ax, data, labels)
    ax.set_title("CPU Utilization (%) — Jaringan Ideal")
    ax.set_xlabel("Skenario")
    ax.set_ylabel("CPU Util (%)")
    ax.grid(True, alpha=0.25)

    fig.tight_layout()
    fig.savefig(outpath, dpi=300, bbox_inches="tight")
    plt.close(fig)
    return str(outpath)


def plot_overhead_c_vs_a(report: dict, outpath: Path) -> str:
    """Bar chart overhead median C vs A pada jaringan ideal."""
    _require_matplotlib()

    metrics = ["handshake_ms", "ttfb_ms", "ttlb_ms", "cpu_ms", "max_rss_kb"]
    labels = [METRICS_CONFIG[m][1] for m in metrics]

    values = []
    for metric in metrics:
        block = report.get("metrics", {}).get("ideal", {}).get(metric, {})
        wc = block.get("wilcoxon_A_vs_C", {})
        values.append(wc.get("overhead_pct", float("nan")))

    fig, ax = plt.subplots(figsize=(10, 5))
    x = np.arange(len(labels))
    bars = ax.bar(x, values)
    ax.axhline(0, linewidth=1)
    ax.axhline(THRESHOLD_LATENCY_OVERHEAD_PCT, linestyle="--", linewidth=1)
    ax.set_title("Overhead Median Skenario C terhadap A — Jaringan Ideal")
    ax.set_ylabel("Overhead (%)")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=20, ha="right")
    ax.grid(True, axis="y", alpha=0.25)

    for bar, val in zip(bars, values):
        if val == val:  # NaN check
            ax.annotate(
                f"{val:+.1f}%",
                (bar.get_x() + bar.get_width() / 2, bar.get_height()),
                textcoords="offset points",
                xytext=(0, 4),
                ha="center",
                fontsize=9,
            )

    fig.tight_layout()
    fig.savefig(outpath, dpi=300, bbox_inches="tight")
    plt.close(fig)
    return str(outpath)


def plot_handshake_ttfb_scatter(df: pd.DataFrame, network: str, outpath: Path) -> str:
    """Scatter handshake vs TTFB per skenario untuk sanity check visual."""
    _require_matplotlib()

    fig, ax = plt.subplots(figsize=(7, 5))
    for sc in SCENARIO_ORDER:
        sub = df[(df["network"] == network) & (df["scenario"] == sc)][["handshake_ms", "ttfb_ms"]].dropna()
        if len(sub) == 0:
            continue
        ax.scatter(sub["handshake_ms"], sub["ttfb_ms"], s=18, alpha=0.7, label=f"Skenario {sc}")

    ax.set_title(f"Handshake vs TTFB — {NETWORK_LABEL.get(network, network)}")
    ax.set_xlabel("Handshake Time (ms)")
    ax.set_ylabel("TTFB (ms)")
    ax.grid(True, alpha=0.25)
    ax.legend()
    fig.tight_layout()
    fig.savefig(outpath, dpi=300, bbox_inches="tight")
    plt.close(fig)
    return str(outpath)


def generate_plots(df: pd.DataFrame, report: dict, plots_dir: Path) -> list[str]:
    if plt is None:
        print(f"Analisis grafik dilewati (matplotlib tak tersedia: {_MPL_ERR})")
        return []

    plots_dir.mkdir(parents=True, exist_ok=True)
    generated: list[str] = []

    # Grafik utama per metrik
    for metric in ["handshake_ms", "ttfb_ms", "ttlb_ms", "cpu_ms", "max_rss_kb"]:
        if metric in df.columns:
            title, _, _ = METRICS_CONFIG[metric]
            outpath = plots_dir / f"{metric}_boxplot.png"
            generated.append(plot_metric_boxplots(df, metric, outpath))

    # CPU utilitas hanya untuk jaringan ideal
    if "cpu_pct" in df.columns:
        generated.append(plot_cpu_pct_ideal(df, plots_dir / "cpu_pct_ideal_boxplot.png"))

    # Ringkasan overhead utama
    generated.append(plot_overhead_c_vs_a(report, plots_dir / "overhead_c_vs_a_ideal.png"))

    # Scatter sanity-check hubungan handshake/ttfb
    if "handshake_ms" in df.columns and "ttfb_ms" in df.columns:
        for network in _network_sorted_unique(df):
            generated.append(
                plot_handshake_ttfb_scatter(
                    df, network, plots_dir / f"handshake_ttfb_scatter_{network}.png"
                )
            )

    return generated


# ─────────────────────────────────────────────────────────
# Cetak ringkasan ke terminal
# ─────────────────────────────────────────────────────────
def _fmt(v, unit):
    if v is None or (isinstance(v, float) and np.isnan(v)):
        return "      N/A"
    if unit == "ms":
        return f"{v:9.2f}ms"
    if unit == "kb":
        return f"{v:8.1f}KB"
    if unit == "pct":
        return f"{v:9.1f}%"
    return f"{v}"


def _pass_str(v):
    if v is None:
        return "N/A (tdk diukur)"
    return "LULUS" if v else "GAGAL"


def print_summary(report: dict):
    sep = "═" * 78
    print(f"\n{sep}")
    print("  RINGKASAN ANALISIS STATISTIK — PQC TLS 1.3 BENCHMARK")
    print(sep)

    for network in ["ideal", "edge"]:
        if network not in report["metrics"]:
            continue
        print(f"\n  ▶ Jaringan: {NETWORK_LABEL.get(network, network)}")
        print(
            f"  {'Metrik':<18}{'A median':>12}{'B median':>12}{'C median':>12}"
            f"{'C vs A':>12}{'Signif?':>10}"
        )
        print(f"  {'-' * 18}{'-' * 12}{'-' * 12}{'-' * 12}{'-' * 12}{'-' * 10}")
        for metric, (label, short, unit) in METRICS_CONFIG.items():
            block = report["metrics"].get(network, {})
            if metric not in block:
                continue
            m = block[metric]
            a_med = m.get("scenario_A", {}).get("median")
            b_med = m.get("scenario_B", {}).get("median")
            c_med = m.get("scenario_C", {}).get("median")
            wc = m.get("wilcoxon_A_vs_C", {})
            ovh = wc.get("overhead_pct", float("nan"))
            sig = "✓ Ya" if wc.get("significant") else "✗ Tidak"
            ovh_str = f"{ovh:+.1f}%" if ovh == ovh else "N/A"  # NaN check
            print(
                f"  {short:<18}{_fmt(a_med, unit):>12}{_fmt(b_med, unit):>12}"
                f"{_fmt(c_med, unit):>12}{ovh_str:>12}{sig:>10}"
            )

        # Korelasi Handshake <-> TTFB
        corr = report.get("correlation", {}).get(network, {})
        if corr and "error" not in corr:
            print("\n    Correlation check Handshake<->TTFB (Pearson r):")
            for sc in ["A", "B", "C"]:
                e = corr.get(f"scenario_{sc}", {})
                r = e.get("pearson_hs_ttfb_r")
                rstr = f"{r:.4f}" if isinstance(r, float) else "N/A"
                flag = ""
                if e.get("isolasi_terkonfirmasi") is True:
                    flag = " (isolasi terkonfirmasi, r>0.95)"
                print(f"      Skenario {sc}: r={rstr} (n={e.get('n', 0)}){flag}")

    feas = report.get("feasibility", {})
    print(f"\n{sep}")
    print("  PENILAIAN KELAYAKAN (Subbab 3.5)")
    print(sep)
    if not feas.get("handshake_available", False):
        print("  ⚠ Handshake Time tidak tersedia di CSV (PCAP tidak didekripsi?)")
    print(
        f"  Overhead Handshake C vs A (ideal): "
        f"{feas.get('handshake_overhead_pct', float('nan')):+.1f}% "
        f"(≤{THRESHOLD_LATENCY_OVERHEAD_PCT}%) → {_pass_str(feas.get('criterion_handshake_passed'))}"
    )
    print(
        f"  Overhead TTLB      C vs A (ideal): "
        f"{feas.get('ttlb_overhead_pct', float('nan')):+.1f}% "
        f"(≤{THRESHOLD_LATENCY_OVERHEAD_PCT}%) → {_pass_str(feas.get('criterion_ttlb_passed'))}"
    )
    print(
        f"  CPU P95 (proksi peak) Skenario C:  "
        f"{feas.get('cpu_p95_pct', float('nan')):.1f}% "
        f"(≤{THRESHOLD_CPU_PEAK_PCT}%) → {_pass_str(feas.get('criterion_cpu_passed'))}"
    )
    _cpu_ms_ovh = feas.get("cpu_ms_overhead_pct_ideal", float("nan"))
    _ms_str = ("%+.1f%%" % _cpu_ms_ovh) if _cpu_ms_ovh == _cpu_ms_ovh else "N/A"
    _a = feas.get("cpu_ms_median_A_ideal")
    _c = feas.get("cpu_ms_median_C_ideal")
    _a = float("nan") if _a is None else _a
    _c = float("nan") if _c is None else _c
    print(
        f"  CPU Time (cpu_ms) C vs A (ideal):  "
        f"A={_a:.3f}ms C={_c:.3f}ms (overhead {_ms_str}) [metrik primer]"
    )
    print(f"\n  Verdict: {_pass_str(feas.get('overall_feasible'))}")
    print(sep + "\n")


# ─────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Analisis statistik hasil benchmark PQC TLS 1.3 [W6/W7]"
    )
    parser.add_argument(
        "--results-file",
        type=Path,
        required=True,
        help="Path ke CSV hasil benchmark (results_combined_*.csv)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("/measurement/results/analysis"),
        help="Direktori output laporan JSON (default: /measurement/results/analysis)",
    )
    parser.add_argument(
        "--plots-dir",
        type=Path,
        default=None,
        help="Direktori output grafik. Default: sibling folder 'plots' di bawah results",
    )
    args = parser.parse_args()

    if not args.results_file.exists():
        print(f"ERROR: File tidak ditemukan: {args.results_file}")
        sys.exit(1)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    plots_dir = args.plots_dir or Path(
        os.getenv(
            "PLOTS_DIR",
            str(args.output_dir.parent / "plots"),
        )
    )
    plots_dir.mkdir(parents=True, exist_ok=True)

    print(f"Memuat data dari: {args.results_file}")
    df = load_results(args.results_file)
    print(
        f"Total baris: {len(df)} | Skenario: {sorted(df['scenario'].unique())} | "
        f"Jaringan: {sorted(df['network'].unique())}"
    )

    report = {
        "source_file": str(args.results_file),
        "total_rows": int(len(df)),
        "metrics": {},
        "correlation": {},
        "feasibility": {},
        "plots": [],
    }

    networks = _network_sorted_unique(df)
    metrics = [m for m in METRICS_CONFIG if m in df.columns]

    for network in networks:
        report["metrics"][network] = {}
        for metric in metrics:
            report["metrics"][network][metric] = analyze_metric(df, metric, network)
        report["correlation"][network] = correlation_analysis(df, network)

    report["feasibility"] = assess_feasibility(df)

    # ── Analisis grafik ──
    try:
        report["plots"] = generate_plots(df, report, plots_dir)
        if report["plots"]:
            print(f"Grafik tersimpan di: {plots_dir}")
            for p in report["plots"]:
                print(f"  plot: {p}")
    except Exception as _plot_e:
        print(f"Analisis grafik dilewati ({_plot_e}).")

    # ── Analisis konvergensi warm-up (opsional; butuh baris warm-up di CSV) ──
    if _WARMUP_OK:
        try:
            df_full = load_results(args.results_file, keep_warmup=True)
            has_wu = (
                "is_warmup" in df_full.columns
                and df_full["is_warmup"].astype(str).str.strip().str.lower()
                .isin(["true", "1"]).any()
            )
            if has_wu:
                _wu_report, _wu_path = warmup_convergence_analysis(
                    df_full, args.output_dir
                )
                report["warmup_convergence_json"] = _wu_path
                report["warmup_convergence_plots"] = _wu_report.get("plots", [])
                print(f"Analisis konvergensi warm-up tersimpan: {_wu_path}")
                for _p in _wu_report.get("plots", []):
                    print(f"  plot: {_p}")
            else:
                print(
                    "Lewati analisis konvergensi warm-up: CSV tidak memuat baris "
                    "warm-up (jalankan benchmark.py terbaru yg mencatat semua iterasi)."
                )
        except Exception as _e:
            print(f"Analisis konvergensi warm-up dilewati ({_e}).")
    else:
        print(f"Analisis konvergensi warm-up dilewati (modul tak tersedia: {_WARMUP_ERR}).")

    report_path = args.output_dir / "analysis_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"Laporan JSON tersimpan: {report_path}")

    print_summary(report)


if __name__ == "__main__":
    main()
