#!/usr/bin/env python3
"""
benchmark.py — PQC TLS 1.3 Performance Benchmark
Thesis: Evaluasi Performa Hybrid Signature Pasca-Kuantum pada TLS 1.3 di Edge Computing

Perubahan yang diakomodasi dari peringatan reviewer:
  [W1] Process spawn overhead diukur secara terpisah sebagai baseline
  [W2] CPU governor/Turbo Boost: dikontrol di HOST via scripts/host-setup.sh
       (tidak bisa dikontrol dari dalam container)
  [W3] Warmup ditingkatkan: 5 → 20 iterasi
  [W4] Payload size: ditetapkan eksplisit 10KB
  [W5] Session resumption: dinonaktifkan via -no_ticket di client dan server
  [W6] Wilcoxon rank-sum test: tersedia di analysis.py (dipanggil otomatis)
"""

import argparse
import csv
import json
import logging
import os
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Optional

import psutil

# ─────────────────────────────────────────────────────────────────────────────
# Konfigurasi global
# ─────────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

# Baca konfigurasi dari environment variables (sinkronisasi dengan run_experiments.sh)
WARMUP_ITERATIONS = int(os.environ.get("WARMUP_ITERS", "20"))
MEASUREMENT_ITERATIONS = int(os.environ.get("MEASURE_ITERS", "100"))
# [W1] Jumlah iterasi untuk mengukur process spawn overhead Baseline
SPAWN_OVERHEAD_ITERATIONS = 50

# [W4] Payload size ditetapkan eksplisit
PAYLOAD_SIZE_KB = int(os.environ.get("PAYLOAD_SIZE_KB", "10"))
PAYLOAD_FILENAME = f"payload_{PAYLOAD_SIZE_KB}kb.bin"

# Server host dan port (per skenario)
SERVER_HOST = os.environ.get("SERVER_HOST", "pqc-server")
PORT_SCENARIO = {
    "A": int(os.environ.get("SERVER_PORT_A", "4433")),
    "B": int(os.environ.get("SERVER_PORT_B", "4434")),
    "C": int(os.environ.get("SERVER_PORT_C", "4435")),
}

# Interface jaringan untuk tshark dan tc (penting untuk network_mode: host)
CAPTURE_INTERFACE = os.environ.get("CAPTURE_IFACE", "eth0")

# Direktori sertifikat
CERTS_DIR = Path(os.environ.get("CERTS_DIR", "/measurement/certs"))

CPU_POLL_INTERVAL_S = 0.010  # 10ms

# KEM groups — konstan di semua skenario agar hanya tanda tangan yang bervariasi
KEM_GROUPS = "kyber768:P-256:X25519"

# ─────────────────────────────────────────────────────────────────────────────
# Definisi Skenario
# ─────────────────────────────────────────────────────────────────────────────
SCENARIOS = {
    "A": {
        "name": "Baseline ECDSA-P256",
        "ca_cert": str(CERTS_DIR / "ca_A.crt"),
        "sigalgs": "ecdsa_secp256r1_sha256",
    },
    "B": {
        "name": "Pure PQC Dilithium2",
        "ca_cert": str(CERTS_DIR / "ca_B.crt"),
        "sigalgs": "dilithium2",
    },
    "C": {
        "name": "OQS Hybrid p256_dilithium2",
        "ca_cert": str(CERTS_DIR / "ca_C.crt"),
        "sigalgs": "p256_dilithium2",
    },
}

NETWORK_CONDITIONS = {
    "ideal": {
        "description": "Ideal (<1ms, 0% loss)",
        "delay_ms": 0,
        "loss_pct": 0.0,
    },
    "edge": {
        "description": "Edge (100ms, 1% loss)",
        "delay_ms": 100,
        "loss_pct": 1.0,
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# [W1] Network & Spawn Baseline
# ─────────────────────────────────────────────────────────────────────────────
def measure_spawn_overhead() -> dict:
    """
    Mengukur waktu yang dibutuhkan sistem untuk melakukan fork/execve
    terhadap proses openssl s_client. Ini adalah baseline [W1].
    """
    logger.info(
        f"[W1] Mengukur process spawn overhead ({SPAWN_OVERHEAD_ITERATIONS} iterasi)..."
    )
    samples = []

    # Perintah minimal yang cepat keluar untuk mengukur overhead spawn
    cmd = ["openssl", "version"]

    for _ in range(SPAWN_OVERHEAD_ITERATIONS):
        t_start = time.perf_counter()
        subprocess.run(cmd, capture_output=True)
        t_end = time.perf_counter()
        samples.append((t_end - t_start) * 1000)  # ms

    median = sorted(samples)[len(samples) // 2]
    p95 = sorted(samples)[int(len(samples) * 0.95)]

    logger.info(f"[W1] Spawn overhead — median: {median:.3f}ms  P95: {p95:.3f}ms")
    return {"median_ms": median, "p95_ms": p95, "samples_ms": samples}


# ─────────────────────────────────────────────────────────────────────────────
# [W2] Network Emulation via tc netem
# ─────────────────────────────────────────────────────────────────────────────
def configure_netem(condition: str, interface: str = CAPTURE_INTERFACE):
    """
    Menerapkan tc netem pada interface jaringan di dalam container klien.
    Membutuhkan CAP_NET_ADMIN (sudah ditambahkan di docker-compose.yml).
    """
    tc_path = shutil.which("tc")
    if not tc_path:
        if condition != "ideal":
            logger.warning(
                f"[netem] 'tc' tidak ditemukan! Melewati konfigurasi '{condition}'."
            )
        return

    params = NETWORK_CONDITIONS[condition]

    # Hapus qdisc lama jika ada
    subprocess.run(
        [tc_path, "qdisc", "del", "dev", interface, "root"],
        capture_output=True,
    )

    if condition == "ideal":
        logger.info(f"[netem] Kondisi ideal — tidak ada delay/loss diterapkan")
        return

    cmd = [
        tc_path,
        "qdisc",
        "add",
        "dev",
        interface,
        "root",
        "netem",
        "delay",
        f"{params['delay_ms']}ms",
        "loss",
        f"{params['loss_pct']}%",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        logger.error(f"tc netem gagal: {result.stderr.strip()}")
        if "No such file or directory" in result.stderr:
            logger.warning(
                f"Interface '{interface}' mungkin salah atau 'tc' tidak berfungsi."
            )
    else:
        logger.info(
            f"[netem] Diterapkan: delay={params['delay_ms']}ms "
            f"loss={params['loss_pct']}% pada {interface}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# CPU & RAM Monitor
# ─────────────────────────────────────────────────────────────────────────────
class ResourceMonitor:
    """
    Monitor penggunaan CPU dan RAM dari satu proses via psutil.
    Berjalan di thread terpisah (threading.Thread) untuk meminimalkan
    interferensi terhadap proses yang diukur (sesuai Subbab 3.2.3).
    """

    def __init__(self, pid: int, interval: float = CPU_POLL_INTERVAL_S):
        self.pid = pid
        self.interval = interval
        self.cpu_pct: list[float] = []
        self.rss_bytes: list[int] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=3)

    def _run(self):
        try:
            proc = psutil.Process(self.pid)
            proc.cpu_percent(interval=None)  # Panggilan pertama selalu 0.0 — buang
            while not self._stop.is_set():
                try:
                    self.cpu_pct.append(proc.cpu_percent(interval=None))
                    self.rss_bytes.append(proc.memory_info().rss)
                except psutil.NoSuchProcess:
                    break
                time.sleep(self.interval)
        except Exception as exc:
            logger.debug(f"ResourceMonitor error: {exc}")

    @property
    def cpu_peak(self) -> float:
        return max(self.cpu_pct, default=0.0)

    @property
    def cpu_mean(self) -> float:
        return (sum(self.cpu_pct) / len(self.cpu_pct)) if self.cpu_pct else 0.0

    @property
    def ram_peak_bytes(self) -> int:
        return max(self.rss_bytes, default=0)


# ─────────────────────────────────────────────────────────────────────────────
# tshark untuk pengukuran TTLB dari PCAP
# ─────────────────────────────────────────────────────────────────────────────
def start_tshark(port: int, pcap_path: str) -> subprocess.Popen:
    """Mulai tshark di background untuk merekam traffic di port tertentu."""
    cmd = [
        "tshark",
        "-i",
        CAPTURE_INTERFACE,
        "-f",
        f"tcp port {port}",
        "-w",
        pcap_path,
        "-q",
    ]
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(0.3)  # Beri waktu tshark memulai capture
    return proc


def stop_tshark(proc: subprocess.Popen):
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def parse_ttlb_from_pcap(pcap_path: str, server_port: int) -> Optional[float]:
    """
    Hitung TTLB dari file PCAP:
      t_start = timestamp paket ClientHello pertama
      t_end   = timestamp paket TLS Application Data TERAKHIR dari server
                (sebelum FIN atau close_notify)

    Ini sesuai dengan definisi TTLB pada Subbab 3.2.3.
    """
    try:
        # Timestamp ClientHello (tipe 1 = ClientHello dalam TLS handshake)
        ch_result = subprocess.run(
            [
                "tshark",
                "-r",
                pcap_path,
                "-Y",
                f"ssl.handshake.type == 1 and tcp.dstport == {server_port}",
                "-T",
                "fields",
                "-e",
                "frame.time_epoch",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )

        # Timestamp paket Application Data dari server ke client
        # content_type == 23 adalah TLS Application Data record
        app_result = subprocess.run(
            [
                "tshark",
                "-r",
                pcap_path,
                "-Y",
                (f"tls.record.content_type == 23 and tcp.srcport == {server_port}"),
                "-T",
                "fields",
                "-e",
                "frame.time_epoch",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )

        ch_times = [float(t) for t in ch_result.stdout.strip().split() if t]
        app_times = [float(t) for t in app_result.stdout.strip().split() if t]

        if not ch_times or not app_times:
            logger.debug("PCAP: Tidak ditemukan ClientHello atau AppData")
            return None

        # t=0 diselaraskan ke timestamp ClientHello (sesuai Subbab 3.2.3)
        t_start = ch_times[0]
        t_end = max(app_times)
        return t_end - t_start

    except subprocess.TimeoutExpired:
        logger.warning("tshark parse timeout")
        return None
    except Exception as exc:
        logger.warning(f"PCAP parse error: {exc}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Satu iterasi handshake
# ─────────────────────────────────────────────────────────────────────────────
def run_single_handshake(
    scenario_id: str,
    server_host: str,
    server_port: int,
) -> dict:
    """
    Menjalankan satu iterasi openssl s_client dan mengukur metrik.
    """
    sc = SCENARIOS[scenario_id]

    # HTTP/1.0 GET request — di-pipe ke stdin setelah handshake selesai
    get_request = (
        f"GET /{PAYLOAD_FILENAME} HTTP/1.0\r\n"
        f"Host: {server_host}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()

    cmd = [
        "openssl",
        "s_client",
        "-connect",
        f"{server_host}:{server_port}",
        "-CAfile",
        sc["ca_cert"],
        # [W5] Nonaktifkan TLS session tickets untuk mencegah session resumption
        "-no_ticket",
        # KEM groups — konstan di semua skenario
        "-groups",
        KEM_GROUPS,
        # Gagal jika verifikasi sertifikat tidak berhasil
        "-verify_return_error",
        # Jangan tutup koneksi saat stdin EOF sebelum server merespons
        "-ign_eof",
    ]

    handshake_time: Optional[float] = None
    ttfb: Optional[float] = None
    handshake_done = threading.Event()
    stderr_lines: list[str] = []

    t_start = time.perf_counter()

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    monitor = ResourceMonitor(proc.pid)
    monitor.start()

    # Thread membaca stderr dan mendeteksi akhir handshake
    def _read_stderr():
        nonlocal handshake_time
        try:
            for raw_line in proc.stderr:
                line = raw_line.decode("utf-8", errors="replace").rstrip()
                stderr_lines.append(line)
                # "Verify return code:" adalah baris terakhir sebelum OpenSSL
                # menunggu input — menandai akhir proses handshake TLS
                if "Verify return code:" in line and handshake_time is None:
                    handshake_time = time.perf_counter() - t_start
                    handshake_done.set()
        except Exception:
            pass

    stderr_thread = threading.Thread(target=_read_stderr, daemon=True)
    stderr_thread.start()

    # Tunggu handshake selesai
    if not handshake_done.wait(timeout=60):
        proc.kill()
        monitor.stop()
        raise TimeoutError(
            f"Handshake timeout setelah 60 detik (Skenario {scenario_id}, port {server_port})"
        )

    # Kirim GET request melalui koneksi TLS yang sudah terbangun
    try:
        proc.stdin.write(get_request)
        proc.stdin.flush()
        proc.stdin.close()
    except BrokenPipeError as exc:
        monitor.stop()
        raise ConnectionError(f"Broken pipe saat mengirim GET request: {exc}")

    # Baca byte pertama dari application data (TTFB)
    first_byte = proc.stdout.read(1)
    if first_byte:
        ttfb = time.perf_counter() - t_start

    # Drain sisa response
    proc.stdout.read()

    try:
        proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()

    monitor.stop()
    stderr_thread.join(timeout=1)

    return {
        "handshake_time_s": handshake_time,
        "ttfb_s": ttfb,
        "cpu_peak_pct": monitor.cpu_peak,
        "cpu_mean_pct": monitor.cpu_mean,
        "ram_peak_bytes": monitor.ram_peak_bytes,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Eksekusi satu skenario + kondisi jaringan
# ─────────────────────────────────────────────────────────────────────────────
def run_scenario(
    scenario_id: str,
    network_condition: str,
    output_dir: Path,
) -> list[dict]:
    """
    Menjalankan warmup + iterasi pengukuran.
    """
    scenario = SCENARIOS[scenario_id]
    port = PORT_SCENARIO[scenario_id]
    net_params = NETWORK_CONDITIONS[network_condition]

    sep = "─" * 62
    logger.info(f"\n{sep}")
    logger.info(f"  Skenario {scenario_id}: {scenario['name']}")
    logger.info(f"  Jaringan : {net_params['description']}")
    logger.info(
        f"  Port     : {port}  |  Warmup: {WARMUP_ITERATIONS}  |  Iterasi: {MEASUREMENT_ITERATIONS}"
    )
    logger.info(sep)

    # Konfigurasi netem
    configure_netem(network_condition)
    time.sleep(0.5)

    pcap_dir = output_dir / "pcap" / f"sc{scenario_id}" / network_condition
    pcap_dir.mkdir(parents=True, exist_ok=True)

    results: list[dict] = []
    total = WARMUP_ITERATIONS + MEASUREMENT_ITERATIONS
    failures = 0
    MAX_FAILURES = 20

    for idx in range(total):
        is_warmup = idx < WARMUP_ITERATIONS
        label = (
            f"warmup-{idx + 1:02d}"
            if is_warmup
            else f"data-{idx - WARMUP_ITERATIONS + 1:03d}"
        )

        pcap_path = str(pcap_dir / f"{label}.pcap")
        tshark_proc = start_tshark(port, pcap_path)

        try:
            metrics = run_single_handshake(scenario_id, SERVER_HOST, port)

            # Hentikan tshark dan parse TTLB dari PCAP
            stop_tshark(tshark_proc)
            time.sleep(0.15)
            ttlb = parse_ttlb_from_pcap(pcap_path, port)

            metrics["ttlb_s"] = ttlb
            metrics["scenario"] = scenario_id
            metrics["network"] = network_condition
            metrics["is_warmup"] = is_warmup
            metrics["iteration"] = label
            metrics["timestamp"] = datetime.now(UTC).isoformat()

            if not is_warmup:
                results.append(metrics)

                hs_ms = (metrics["handshake_time_s"] or 0) * 1000
                ttfb_ms = (metrics["ttfb_s"] or 0) * 1000
                ttlb_ms = (ttlb or 0) * 1000
                logger.info(
                    f"[{label}] "
                    f"HS={hs_ms:7.2f}ms  "
                    f"TTFB={ttfb_ms:7.2f}ms  "
                    f"TTLB={ttlb_ms:7.2f}ms  "
                    f"CPU_peak={metrics['cpu_peak_pct']:5.1f}%  "
                    f"RAM={metrics['ram_peak_bytes'] // 1024}KB"
                )
        except Exception as exc:
            failures += 1
            logger.error(f"[{label}] Gagal: {exc}")
            stop_tshark(tshark_proc)
            if failures > MAX_FAILURES:
                raise RuntimeError(
                    f"Terlalu banyak kegagalan di skenario {scenario_id}"
                )

    return results


def save_csv(data: list[dict], path: Path):
    if not data:
        return
    keys = data[0].keys()
    with open(path, "w", newline="") as f:
        dict_writer = csv.DictWriter(f, fieldnames=keys)
        dict_writer.writeheader()
        dict_writer.writerows(data)


def main():
    parser = argparse.ArgumentParser(
        description="PQC TLS 1.3 Benchmark — Thesis Edge Computing"
    )
    parser.add_argument(
        "--scenarios", nargs="+", choices=["A", "B", "C"], default=["A", "B", "C"]
    )
    parser.add_argument(
        "--networks", nargs="+", choices=["ideal", "edge"], default=["ideal", "edge"]
    )
    parser.add_argument("--output-dir", type=Path, default=Path("/measurement/results"))
    parser.add_argument("--skip-spawn-overhead", action="store_true")
    parser.add_argument("--run-analysis", action="store_true")
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)

    run_id = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    logger.info(f"{'=' * 62}")
    logger.info(f"  PQC TLS 1.3 Benchmark  |  Run ID: {run_id}")
    logger.info(f"  Skenario : {args.scenarios}")
    logger.info(f"  Jaringan : {args.networks}")
    logger.info(f"  Output   : {args.output_dir}")
    logger.info(f"  Warmup   : {WARMUP_ITERATIONS} iterasi")
    logger.info(f"  Payload  : {PAYLOAD_SIZE_KB}KB")
    logger.info(f"{'=' * 62}\n")

    if not args.skip_spawn_overhead:
        spawn_data = measure_spawn_overhead()
        with open(args.output_dir / "spawn_overhead.json", "w") as f:
            json.dump(
                {k: v for k, v in spawn_data.items() if k != "samples_ms"}, f, indent=2
            )

    all_results: list[dict] = []
    for sc_id in args.scenarios:
        for net_cond in args.networks:
            try:
                rows = run_scenario(sc_id, net_cond, args.output_dir)
                all_results.extend(rows)
                save_csv(
                    rows, args.output_dir / f"results_sc{sc_id}_{net_cond}_{run_id}.csv"
                )
            except Exception as exc:
                logger.error(f"Skenario {sc_id}/{net_cond} dibatalkan: {exc}")

    combined_path = args.output_dir / f"results_combined_{run_id}.csv"
    save_csv(all_results, combined_path)

    latest = args.output_dir / "results_combined_latest.csv"
    try:
        latest.unlink(missing_ok=True)
        latest.symlink_to(combined_path.name)
    except OSError:
        pass

    if args.run_analysis:
        subprocess.run(
            [
                "python3",
                "/measurement/scripts/analysis.py",
                "--results-file",
                str(combined_path),
                "--output-dir",
                str(args.output_dir),
            ]
        )


if __name__ == "__main__":
    main()
