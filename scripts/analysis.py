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
    # cert_transfer_ms (CTT) = DEKOMPOSISI dari Handshake Time, BUKAN metrik
    # sejajar. Sengaja TIDAK ditampilkan di tabel ringkasan utama; disajikan di
    # blok "Dekomposisi Handshake" + plot terpisah. Didaftarkan di sini hanya
    # agar helper statistik/label/plot bisa memakainya secara seragam.
    "cert_transfer_ms": ("Certificate Transfer Time (ms)", "Cert Transfer", "ms"),
    "ttfb_ms":      ("TTFB (ms)",           "TTFB",           "ms"),
    "ttlb_ms":      ("TTLB (ms)",           "TTLB",           "ms"),
    "cpu_ms":       ("CPU Time (ms)",       "CPU Time",       "ms"),
    "cpu_pct":      ("CPU Util (%)",        "CPU Util",       "pct"),
    "max_rss_kb":   ("RAM Peak (KB)",       "RAM Peak",       "kb"),
}

NETWORK_LABEL = {
    "ideal":      "Ideal (<1ms, 0% loss)",
    "edge_loss0": "Edge (100ms, 0% loss)",
    "edge":       "Edge (100ms, 1% loss)",
    "edge_loss3": "Edge (100ms, 3% loss)",
}

SCENARIO_ORDER = ["A", "B", "C"]

# Urutan tampil jaringan: 'ideal' lalu sweep loss Edge (Tier 1.A) terurut by loss.
NETWORK_ORDER = ["ideal", "edge_loss0", "edge", "edge_loss3"]

# Peta loss% per blok Edge untuk tren Tier 1.A. 'edge' = titik 1% kanonik.
EDGE_LOSS_PCT = {"edge_loss0": 0.0, "edge": 1.0, "edge_loss3": 3.0}


# ─────────────────────────────────────────────────────────
# [Tier 1.B / 1.C] Model congestion-window awal & round-trip (ANALITIS)
#
# Ini BUKAN eksperimen baru: hanya lensa analitis di atas data yang sudah ada.
# Tujuannya mengubah hasil dari sekadar "angka overhead" menjadi "mekanisme":
# apakah selisih antar tipe sertifikat berasal dari (a) round-trip tambahan
# karena flight handshake server melebihi initcwnd, atau (b) murni biaya
# transfer byte + komputasi verifikasi (tanpa RTT tambahan).
# ─────────────────────────────────────────────────────────
INITCWND_SEGMENTS = 10                       # initcwnd default Linux (RFC 6928)
MSS_BYTES = 1460                             # MSS Ethernet umum
INITCWND_BYTES = INITCWND_SEGMENTS * MSS_BYTES  # ~14.600 byte (ambang Kampanakis)

# Estimasi byte "server authentication flight" (Certificate chain + CertVerify)
# per skenario, yakni bagian flight-1 server yang ukurannya bergantung algoritma.
#
# >>> PENTING: DEFAULT di bawah = ESTIMASI LITERATUR (Sikeridis NDSS 2020 Tabel
# III + ukuran Dilithium2). GANTI dengan ukuran AKTUAL sertifikat Anda agar
# prediksi valid. Cara mengukur: jumlahkan byte record `Certificate` +
# `CertificateVerify` dari PCAP (tshark), atau ukuran DER chain (leaf + ICA). <<<
SERVER_AUTH_BYTES = {
    "A": 1600,    # ECDSA-P256 : chain ~1,5 KB + CertVerify ~72 B
    "B": 10200,   # Dilithium2 : chain ~7,8 KB + CertVerify ~2,4 KB
    "C": 11800,   # p256_dilithium2 (hybrid): chain ~9 KB + CertVerify ~2,5 KB
}
# Overhead tetap flight-1 server (ServerHello + EncryptedExtensions + Finished +
# header record TLS), kira-kira konstan antar skenario.
SERVER_FIXED_OVERHEAD_BYTES = 300
# "estimasi_literatur" -> ganti ke "diukur" setelah SERVER_AUTH_BYTES diisi nilai
# aktual; nilai ini hanya menandai sumber angka pada laporan/peringatan.
CERT_BYTES_SOURCE = "estimasi_literatur"


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
    # cert_transfer_ms (CTT) ikut dikonversi -- dipakai utk dekomposisi handshake.
    for col in ("handshake_ms", "cert_transfer_ms", "ttfb_ms", "ttlb_ms", "max_rss_kb"):
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
    present = set(df["network"].dropna().astype(str))
    order = [n for n in NETWORK_ORDER if n in present]
    extras = [n for n in sorted(present) if n not in order]
    return order + extras


def _ordered_report_networks(report: dict) -> list[str]:
    """Urutkan kunci jaringan pada report sesuai NETWORK_ORDER (extras di akhir)."""
    present = list(report.get("metrics", {}).keys())
    order = [n for n in NETWORK_ORDER if n in present]
    extras = [n for n in present if n not in order]
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
# [Tier 1.A] Tren gap C vs A pada Edge seiring kenaikan packet loss
# ─────────────────────────────────────────────────────────
def tier1a_loss_trend(report: dict) -> dict:
    """
    Rangkum bagaimana gap Skenario C vs A pada Edge MELEBAR saat loss naik.

    Hanya membaca blok 'edge*' yang ada di report['metrics'] (0/1/3%); tidak
    menyentuh kondisi 'ideal'. Konsisten dengan guardrail: loss = blok Edge
    terpisah, tiap titik tetap dianalisis per tipe sertifikat (A/B/C).
    """
    metrics_block = report.get("metrics", {})
    loss_nets = [(n, EDGE_LOSS_PCT[n]) for n in EDGE_LOSS_PCT if n in metrics_block]
    loss_nets.sort(key=lambda x: x[1])
    if len(loss_nets) < 2:
        return {"available": False, "reason": "Butuh >=2 titik loss Edge (mis. edge_loss0 + edge)."}

    trend = {
        "available": True,
        "loss_points_pct": [p for _, p in loss_nets],
        "networks": [n for n, _ in loss_nets],
        "metrics": {},
    }
    for metric in ("handshake_ms", "ttfb_ms", "ttlb_ms", "cpu_ms"):
        series = []
        for net, loss in loss_nets:
            block = metrics_block.get(net, {}).get(metric, {})
            wc = block.get("wilcoxon_A_vs_C", {})
            series.append({
                "network": net,
                "loss_pct": loss,
                "median_A": block.get("scenario_A", {}).get("median"),
                "median_C": block.get("scenario_C", {}).get("median"),
                "overhead_C_vs_A_pct": wc.get("overhead_pct"),
                "significant": wc.get("significant"),
            })
        trend["metrics"][metric] = series
    return trend


# ─────────────────────────────────────────────────────────
# [Tier 1.B] Flight-1 server vs initcwnd (model congestion-window awal)
# ─────────────────────────────────────────────────────────
def _slowstart_rtts(total_bytes: float, initcwnd_bytes: int = INITCWND_BYTES) -> int:
    """Jumlah round-trip untuk mengirim total_bytes di bawah TCP slow-start.

    Window awal = initcwnd_bytes, lalu berlipat ganda tiap RTT (cwnd*=2).
    Return 1 = muat dalam jendela awal (tanpa RTT tambahan), 2 = butuh 1 RTT
    tambahan, dst. Model konservatif (mengabaikan ACK delay / pacing), cukup
    untuk argumen 'muat / tidak muat' ala Kampanakis.
    """
    if total_bytes is None or total_bytes <= 0:
        return 0
    sent, cwnd, rtts = 0, initcwnd_bytes, 0
    while sent < total_bytes:
        sent += cwnd
        cwnd *= 2
        rtts += 1
    return rtts


def tier1b_initcwnd_analysis() -> dict:
    """Prediksi apakah flight-1 handshake server tiap skenario MUAT di initcwnd.

    Murni analitis (berbasis ukuran artefak + initcwnd), tidak menyentuh CSV.
    Hasil dipakai Tier 1.C sebagai prediksi jumlah RTT handshake.
    """
    out = {
        "available": True,
        "cert_bytes_source": CERT_BYTES_SOURCE,
        "initcwnd_segments": INITCWND_SEGMENTS,
        "mss_bytes": MSS_BYTES,
        "initcwnd_bytes": INITCWND_BYTES,
        "server_fixed_overhead_bytes": SERVER_FIXED_OVERHEAD_BYTES,
        "scenarios": {},
    }
    for sc in SCENARIO_ORDER:
        auth = SERVER_AUTH_BYTES.get(sc)
        if auth is None:
            out["scenarios"][sc] = {"available": False,
                                    "reason": "SERVER_AUTH_BYTES[sc] belum diisi"}
            continue
        flight = SERVER_FIXED_OVERHEAD_BYTES + float(auth)
        windows = _slowstart_rtts(flight)
        out["scenarios"][sc] = {
            "server_auth_bytes": float(auth),
            "server_flight1_bytes": float(flight),
            "fits_in_initcwnd": bool(flight <= INITCWND_BYTES),
            "windows_needed": int(windows),
            "predicted_handshake_rtt": int(max(1, windows)),
            "extra_rtt_vs_first_window": int(max(0, windows - 1)),
        }
    return out


# ─────────────────────────────────────────────────────────
# [Tier 1.C] Prediksi jumlah RTT handshake vs Handshake/TTLB terukur
# ─────────────────────────────────────────────────────────
def tier1c_rtt_model(df: pd.DataFrame, report: dict) -> dict:
    """Hubungkan prediksi RTT (Tier 1.B) dengan latensi terukur.

    Ide inti: prediksi 'RTT tambahan C/B vs A' (akibat flight server melewati
    initcwnd) lalu cek apakah SELISIH Handshake terukur konsisten dgn prediksi
    itu — dinyatakan dalam SATUAN RTT. 1 RTT jaringan diestimasi EMPIRIS dari
    skenario A (kenaikan Handshake A dari ideal ke tiap blok Edge / jumlah RTT A),
    sehingga tidak bergantung pada asumsi semantik netem.
    """
    b1 = report.get("tier1b_initcwnd", {})
    scen_b = b1.get("scenarios", {})
    pred_rtt = {
        sc: int(scen_b.get(sc, {}).get("predicted_handshake_rtt", 1))
        for sc in SCENARIO_ORDER
    }

    def med_hs(sc: str, net: str) -> float:
        if "handshake_ms" not in df.columns:
            return float("nan")
        s = df[(df["scenario"] == sc) & (df["network"] == net)]["handshake_ms"].dropna()
        return float(s.median()) if len(s) else float("nan")

    hs_a_ideal = med_hs("A", "ideal")
    out = {
        "available": "handshake_ms" in df.columns,
        "cert_bytes_source": CERT_BYTES_SOURCE,
        "predicted_handshake_rtt": pred_rtt,
        "predicted_extra_rtt_C_vs_A": int(pred_rtt.get("C", 1) - pred_rtt.get("A", 1)),
        "rtt_est_basis": "empiris dari skenario A (Handshake net - Handshake ideal)/RTT_A",
        "networks": {},
    }
    if not out["available"]:
        out["reason"] = "Kolom handshake_ms tidak tersedia di CSV"
        return out

    for net in _network_sorted_unique(df):
        hs_a_net = med_hs("A", net)
        # 1 RTT jaringan ~ kenaikan Handshake A (ideal->net) dibagi jumlah RTT A.
        if net == "ideal" or not (np.isfinite(hs_a_net) and np.isfinite(hs_a_ideal)):
            rtt_net = float("nan")
        else:
            denom = max(1, pred_rtt.get("A", 1))
            rtt_net = (hs_a_net - hs_a_ideal) / denom
        entry = {"rtt_net_ms_est": (float(rtt_net) if np.isfinite(rtt_net) else None),
                 "scenarios": {}}
        for sc in SCENARIO_ORDER:
            hs_sc = med_hs(sc, net)
            gap_ms = (hs_sc - hs_a_net) if (np.isfinite(hs_sc) and np.isfinite(hs_a_net)) else float("nan")
            if np.isfinite(gap_ms) and np.isfinite(rtt_net) and rtt_net > 0:
                gap_rtts = gap_ms / rtt_net
            else:
                gap_rtts = float("nan")
            pred_extra = pred_rtt.get(sc, 1) - pred_rtt.get("A", 1)
            consistent = (abs(gap_rtts - pred_extra) < 0.5) if np.isfinite(gap_rtts) else None
            entry["scenarios"][sc] = {
                "predicted_extra_rtt_vs_A": int(pred_extra),
                "measured_handshake_median_ms": (float(hs_sc) if np.isfinite(hs_sc) else None),
                "measured_gap_vs_A_ms": (float(gap_ms) if np.isfinite(gap_ms) else None),
                "measured_gap_in_rtt_units": (float(gap_rtts) if np.isfinite(gap_rtts) else None),
                "mechanism_consistent": consistent,
            }
        out["networks"][net] = entry
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


def plot_metric_boxplot_by_network(
    df: pd.DataFrame,
    metric: str,
    network: str,
    outpath: Path,
) -> str:
    """Boxplot satu metrik untuk satu kondisi jaringan agar skala Y tetap terbaca."""
    _require_matplotlib()

    title, _, _ = METRICS_CONFIG[metric]
    fig, ax = plt.subplots(figsize=(7, 5))

    data = []
    labels = []
    for sc in SCENARIO_ORDER:
        vals = df[(df["network"] == network) & (df["scenario"] == sc)][metric].dropna()
        data.append(vals.tolist() if len(vals) else [np.nan])
        labels.append(sc)

    _boxplot_with_labels(ax, data, labels)
    ax.set_title(f"{title} per Skenario - {NETWORK_LABEL.get(network, network)}")
    ax.set_xlabel("Skenario")
    ax.set_ylabel(title)
    ax.grid(True, alpha=0.25)

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


def plot_tier1a_overhead_vs_loss(report: dict, outpath: Path):
    """[Tier 1.A] Plot overhead median C vs A pada Edge sebagai fungsi packet loss.

    Mengembalikan path PNG, atau None bila titik loss < 2 (plot dilewati).
    """
    _require_matplotlib()
    trend = report.get("tier1a_loss_trend", {})
    if not trend.get("available"):
        return None

    fig, ax = plt.subplots(figsize=(8, 5))
    plotted = False
    for metric in ("handshake_ms", "ttlb_ms", "ttfb_ms"):
        series = trend.get("metrics", {}).get(metric, [])
        xs, ys = [], []
        for pt in series:
            ov = pt.get("overhead_C_vs_A_pct")
            if isinstance(ov, (int, float)) and ov == ov:  # bukan None / NaN
                xs.append(pt["loss_pct"])
                ys.append(ov)
        if len(xs) >= 2:
            ax.plot(xs, ys, marker="o", label=METRICS_CONFIG[metric][1])
            plotted = True

    if not plotted:
        plt.close(fig)
        return None

    ax.axhline(THRESHOLD_LATENCY_OVERHEAD_PCT, linestyle="--", linewidth=1,
               label=f"Ambang {THRESHOLD_LATENCY_OVERHEAD_PCT:.0f}%")
    ax.set_title("Tier 1.A — Overhead Median C vs A pada Edge vs Packet Loss")
    ax.set_xlabel("Packet loss Edge (%)")
    ax.set_ylabel("Overhead C vs A (%)")
    ax.grid(True, alpha=0.25)
    ax.legend()
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

    # Bersihkan plot lama agar hasil analisis terbaru tidak tercampur
    # dengan format/nama file dari run sebelumnya.
    for old_plot in plots_dir.glob("*.png"):
        old_plot.unlink()

    # Grafik utama per metrik
    for metric in ["handshake_ms", "ttfb_ms", "ttlb_ms", "cpu_ms", "max_rss_kb"]:
        if metric in df.columns:
            for network in _network_sorted_unique(df):
                outpath = plots_dir / f"{metric}_boxplot_{network}.png"
                generated.append(plot_metric_boxplot_by_network(df, metric, network, outpath))

    # Dekomposisi handshake: CTT disajikan TERPISAH (bukan co-equal di grafik
    # overhead utama) untuk menegaskan posisinya sebagai komponen handshake.
    if "cert_transfer_ms" in df.columns:
        for network in _network_sorted_unique(df):
            outpath = plots_dir / f"cert_transfer_ms_boxplot_{network}.png"
            generated.append(
                plot_metric_boxplot_by_network(df, "cert_transfer_ms", network, outpath)
            )

    # CPU utilitas hanya untuk jaringan ideal
    if "cpu_pct" in df.columns:
        generated.append(plot_cpu_pct_ideal(df, plots_dir / "cpu_pct_ideal_boxplot.png"))

    # Ringkasan overhead utama
    generated.append(plot_overhead_c_vs_a(report, plots_dir / "overhead_c_vs_a_ideal.png"))

    # [Tier 1.A] Kurva overhead C vs A pada Edge terhadap packet loss
    tier1a_plot = plot_tier1a_overhead_vs_loss(
        report, plots_dir / "tier1a_overhead_vs_loss.png"
    )
    if tier1a_plot:
        generated.append(tier1a_plot)

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

    for network in _ordered_report_networks(report):
        if network not in report["metrics"]:
            continue
        print(f"\n  ▶ Jaringan: {NETWORK_LABEL.get(network, network)}")
        print(
            f"  {'Metrik':<18}{'A median':>12}{'B median':>12}{'C median':>12}"
            f"{'C vs A':>12}{'Signif?':>10}"
        )
        print(f"  {'-' * 18}{'-' * 12}{'-' * 12}{'-' * 12}{'-' * 12}{'-' * 10}")
        for metric, (label, short, unit) in METRICS_CONFIG.items():
            # CTT bukan metrik sejajar -> dilewati di tabel utama; disajikan di
            # blok "Dekomposisi Handshake" di bawah.
            if metric == "cert_transfer_ms":
                continue
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

        # Dekomposisi Handshake -> Certificate Transfer Time (CTT)
        mblock = report["metrics"].get(network, {})
        ctt = mblock.get("cert_transfer_ms")
        hsb = mblock.get("handshake_ms")
        if ctt:
            print("\n    Dekomposisi Handshake → Certificate Transfer Time (CTT):")
            print("      (CTT = segmen transfer sertifikat DI DALAM handshake, bukan metrik sejajar)")
            for sc in SCENARIO_ORDER:
                c_med = ctt.get(f"scenario_{sc}", {}).get("median")
                h_med = (hsb or {}).get(f"scenario_{sc}", {}).get("median")
                share = (
                    c_med / h_med * 100
                    if isinstance(c_med, (int, float)) and isinstance(h_med, (int, float)) and h_med
                    else None
                )
                c_str = f"{c_med:.2f}ms" if isinstance(c_med, (int, float)) else "N/A"
                sh_str = f"~{share:.0f}% dari Handshake" if isinstance(share, (int, float)) else "N/A"
                print(f"      Skenario {sc}: CTT median={c_str:>9}  ({sh_str})")
            wc = ctt.get("wilcoxon_A_vs_C", {})
            ov = wc.get("overhead_pct")
            if isinstance(ov, (int, float)) and ov == ov:
                sig = "signifikan" if wc.get("significant") else "tdk signifikan"
                print(f"      Isolasi efek sertifikat (CTT C vs A): {ov:+.1f}% ({sig})")

    # ── [Tier 1.A] Tren gap C vs A pada Edge seiring loss ──
    trend = report.get("tier1a_loss_trend", {})
    if trend.get("available"):
        print(f"\n{sep}")
        print("  TIER 1.A — TREN GAP C vs A PADA EDGE SEIRING PACKET LOSS")
        print(sep)
        for metric in ("handshake_ms", "ttlb_ms"):
            series = trend.get("metrics", {}).get(metric, [])
            if not series:
                continue
            label = METRICS_CONFIG.get(metric, (metric,))[0]
            print(f"\n    {label} — overhead median C vs A per titik loss:")
            for pt in series:
                ov = pt.get("overhead_C_vs_A_pct")
                ov_str = f"{ov:+.1f}%" if isinstance(ov, (int, float)) and ov == ov else "N/A"
                sig = "signifikan" if pt.get("significant") else "tdk signifikan"
                print(f"      loss {pt['loss_pct']:>4.1f}%: {ov_str:>9}  ({sig})")

    # ── [Tier 1.B] Flight-1 server vs initcwnd ──
    b1 = report.get("tier1b_initcwnd", {})
    if b1.get("available"):
        print(f"\n{sep}")
        print("  TIER 1.B — FLIGHT-1 HANDSHAKE SERVER vs initcwnd")
        print(sep)
        print(
            f"    initcwnd = {b1.get('initcwnd_segments')} seg x {b1.get('mss_bytes')} B "
            f"= {b1.get('initcwnd_bytes')} B"
        )
        if b1.get("cert_bytes_source") != "diukur":
            print("    ⚠ Ukuran sertifikat = ESTIMASI LITERATUR. Ganti SERVER_AUTH_BYTES")
            print("      dgn byte Certificate+CertificateVerify aktual agar prediksi valid.")
        print(f"    {'Skn':<5}{'flight-1 (B)':>14}{'muat initcwnd?':>16}{'pred. RTT HS':>14}")
        print(f"    {'-' * 5}{'-' * 14}{'-' * 16}{'-' * 14}")
        for sc in SCENARIO_ORDER:
            s = b1.get("scenarios", {}).get(sc, {})
            if not s or s.get("available") is False:
                print(f"    {sc:<5}{'N/A (isi SERVER_AUTH_BYTES)':>44}")
                continue
            fit = "ya" if s.get("fits_in_initcwnd") else "TIDAK"
            print(
                f"    {sc:<5}{s.get('server_flight1_bytes', float('nan')):>14.0f}"
                f"{fit:>16}{s.get('predicted_handshake_rtt', 0):>14}"
            )

    # ── [Tier 1.C] Prediksi RTT handshake vs selisih terukur ──
    c1 = report.get("tier1c_rtt_model", {})
    if c1.get("available"):
        print(f"\n{sep}")
        print("  TIER 1.C — PREDIKSI RTT HANDSHAKE vs SELISIH TERUKUR (dalam satuan RTT)")
        print(sep)
        pe = c1.get("predicted_extra_rtt_C_vs_A")
        if isinstance(pe, int):
            print(f"    Prediksi RTT tambahan C vs A (flight server & initcwnd): {pe:+d} RTT")
        nets_c = [n for n in NETWORK_ORDER if n in c1.get("networks", {})]
        nets_c += [n for n in c1.get("networks", {}) if n not in NETWORK_ORDER]
        for net in nets_c:
            e = c1["networks"][net]
            rtt = e.get("rtt_net_ms_est")
            rtt_str = f"{rtt:.1f}ms" if isinstance(rtt, (int, float)) else "N/A (ideal / tak terukur)"
            print(f"\n    {NETWORK_LABEL.get(net, net)} — 1 RTT jaringan ≈ {rtt_str}")
            for sc in ["B", "C"]:
                s = e.get("scenarios", {}).get(sc, {})
                gm = s.get("measured_gap_vs_A_ms")
                gr = s.get("measured_gap_in_rtt_units")
                pe2 = s.get("predicted_extra_rtt_vs_A")
                gm_str = f"{gm:+.2f}ms" if isinstance(gm, (int, float)) else "N/A"
                gr_str = f"{gr:.2f}" if isinstance(gr, (int, float)) else "N/A"
                cons = s.get("mechanism_consistent")
                cons_str = "konsisten" if cons is True else ("TIDAK konsisten" if cons is False else "—")
                print(
                    f"      {sc} vs A: prediksi +{pe2} RTT | terukur {gm_str} ≈ {gr_str} RTT  ({cons_str})"
                )

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


# ─────────��───────────────────────────────────────────────
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
    report["tier1a_loss_trend"] = tier1a_loss_trend(report)
    # Tier 1.B (analitis, berbasis ukuran artefak) lalu Tier 1.C (memakai 1.B + data).
    report["tier1b_initcwnd"] = tier1b_initcwnd_analysis()
    report["tier1c_rtt_model"] = tier1c_rtt_model(df, report)

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
