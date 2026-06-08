#!/usr/bin/env python3
"""
benchmark.py — PQC TLS 1.3 Performance Benchmark
Thesis: Evaluasi Performa Hybrid Signature Pasca-Kuantum pada TLS 1.3 di Edge Computing
"""

import argparse
import csv
import json
import logging
import os
import shutil
import signal
import subprocess
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

WARMUP_ITERATIONS = int(os.environ.get("WARMUP_ITERS", "20"))
MEASUREMENT_ITERATIONS = int(os.environ.get("MEASURE_ITERS", "100"))
SPAWN_OVERHEAD_ITERATIONS = 50

PAYLOAD_SIZE_KB = int(os.environ.get("PAYLOAD_SIZE_KB", "10"))
# PAYLOAD_FILENAME = f"payload_{PAYLOAD_SIZE_KB}kb.bin"
PAYLOAD_FILENAME = "payload.bin"

SERVER_HOST = os.environ.get("SERVER_HOST", "pqc-server")
PORT_SCENARIO = {
    "A": int(os.environ.get("SERVER_PORT_A", "4433")),
    "B": int(os.environ.get("SERVER_PORT_B", "4434")),
    "C": int(os.environ.get("SERVER_PORT_C", "4435")),
}

CAPTURE_INTERFACE = os.environ.get("CAPTURE_IFACE", "eth0")
CERTS_DIR = Path(os.environ.get("CERTS_DIR", "/measurement/certs"))
CPU_POLL_INTERVAL_S = 0.010
KEM_GROUPS = "kyber768:P-256:X25519"

# ─────────────────────────────────────────────────────────────────────────────
# Definisi Skenario
# ─────────────────────────────────────────────────────────────────────────────
SCENARIOS = {
    "A": {
        "name": "Baseline ECDSA-P256",
        "ca_cert": str(CERTS_DIR / "ca_A.crt"),
    },
    "B": {
        "name": "Pure PQC Dilithium2",
        "ca_cert": str(CERTS_DIR / "ca_B.crt"),
    },
    "C": {
        "name": "OQS Hybrid p256_dilithium2",
        "ca_cert": str(CERTS_DIR / "ca_C.crt"),
    },
}

NETWORK_CONDITIONS = {
    "ideal": {"description": "Ideal (<1ms, 0% loss)", "delay_ms": 0, "loss_pct": 0.0},
    "edge": {"description": "Edge (100ms, 1% loss)", "delay_ms": 100, "loss_pct": 1.0},
}


# ─────────────────────────────────────────────────────────────────────────────
# [W1] Network & Spawn Baseline
# ─────────────────────────────────────────────────────────────────────────────
def measure_spawn_overhead() -> dict:
    logger.info(
        f"[W1] Mengukur process spawn overhead ({SPAWN_OVERHEAD_ITERATIONS} iterasi)..."
    )
    samples = []
    cmd = ["openssl", "version"]
    for _ in range(SPAWN_OVERHEAD_ITERATIONS):
        t_start = time.perf_counter()
        subprocess.run(cmd, capture_output=True)
        samples.append((time.perf_counter() - t_start) * 1000)
    median = sorted(samples)[len(samples) // 2]
    p95 = sorted(samples)[int(len(samples) * 0.95)]
    logger.info(f"[W1] Spawn overhead — median: {median:.3f}ms  P95: {p95:.3f}ms")
    return {"median_ms": median, "p95_ms": p95, "samples_ms": samples}


# ─────────────────────────────────────────────────────────────────────────────
# [W2] Network Emulation via tc netem
# ─────────────────────────────────────────────────────────────────────────────
def configure_netem(condition: str, interface: str = CAPTURE_INTERFACE):
    tc_path = shutil.which("tc")
    if not tc_path:
        if condition != "ideal":
            logger.warning(
                f"[netem] 'tc' tidak ditemukan! Melewati konfigurasi '{condition}'."
            )
        return
    params = NETWORK_CONDITIONS[condition]
    subprocess.run(
        [tc_path, "qdisc", "del", "dev", interface, "root"], capture_output=True
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
    else:
        logger.info(
            f"[netem] Diterapkan: delay={params['delay_ms']}ms loss={params['loss_pct']}% pada {interface}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# CPU & RAM Monitor
# ─────────────────────────────────────────────────────────────────────────────
class ResourceMonitor:
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
            proc.cpu_percent(interval=None)
            while not self._stop.is_set():
                try:
                    self.cpu_pct.append(proc.cpu_percent(interval=None))
                    self.rss_bytes.append(proc.memory_info().rss)
                except psutil.NoSuchProcess:
                    break
                time.sleep(self.interval)
        except Exception:
            pass

    @property
    def cpu_peak(self) -> float:
        return max(self.cpu_pct, default=0.0)

    @property
    def cpu_mean(self) -> float:
        return sum(self.cpu_pct) / len(self.cpu_pct) if self.cpu_pct else 0.0

    @property
    def ram_peak_bytes(self) -> int:
        return max(self.rss_bytes, default=0)


# ─────────────────────────────────────────────────────────────────────────────
# tshark
# ─────────────────────────────────────────────────────────────────────────────
def start_tshark(port: int, pcap_path: str) -> subprocess.Popen:
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
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.0)
    return proc


def stop_tshark(proc: subprocess.Popen):
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


# ─────────────────────────────────────────────────────────────────────────────
# tshark Parser (DIREVISI UNTUK WIRESHARK 4.x)
# ─────────────────────────────────────────────────────────────────────────────
def parse_ttlb_from_pcap(pcap_path: str, server_port: int) -> Optional[float]:
    try:
        # Periksa ukuran pcap
        pcap_size = os.path.getsize(pcap_path)
        if pcap_size < 1000:
            logger.warning(
                f"PCAP {pcap_path} sangat kecil ({pcap_size} bytes), mungkin gagal rekam."
            )

        # PENCARIAN CLIENT HELLO (Gunakan tls.handshake.type)
        ch_res = subprocess.run(
            [
                "tshark",
                "-r",
                pcap_path,
                "-Y",
                f"tls.handshake.type == 1 and tcp.dstport == {server_port}",
                "-T",
                "fields",
                "-e",
                "frame.time_epoch",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        # PENCARIAN APPLICATION DATA
        app_res = subprocess.run(
            [
                "tshark",
                "-r",
                pcap_path,
                "-Y",
                f"tls.record.content_type == 23 and tcp.srcport == {server_port}",
                "-T",
                "fields",
                "-e",
                "frame.time_epoch",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        ch_t = [float(t) for t in ch_res.stdout.strip().split() if t]
        app_t = [float(t) for t in app_res.stdout.strip().split() if t]

        if not ch_t:
            logger.warning(
                f"PCAP parse: ClientHello tidak ditemukan. stdout: '{ch_res.stdout}' stderr: '{ch_res.stderr}'"
            )
            return None

        if not app_t:
            logger.warning(
                f"PCAP parse: Application Data tidak ditemukan. stdout: '{app_res.stdout}' stderr: '{app_res.stderr}'"
            )
            return None

        return max(app_t) - ch_t[0]
    except Exception as e:
        logger.error(f"PCAP exception: {e}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Satu iterasi handshake (DIREVISI TOTAL UNTUK I/O PIPELINE & ERROR LOGGING)
# ─────────────────────────────────────────────────────────────────────────────
def run_single_handshake(scenario_id: str, server_host: str, server_port: int) -> dict:
    sc = SCENARIOS[scenario_id]
    get_request = f"GET /{PAYLOAD_FILENAME} HTTP/1.0\r\nHost: {server_host}\r\nConnection: close\r\n\r\n".encode()

    cmd = [
        "openssl",
        "s_client",
        "-provider",
        "oqsprovider",
        "-provider",
        "default",
        "-connect",
        f"{server_host}:{server_port}",
        "-CAfile",
        sc["ca_cert"],
        "-tls1_3",
        "-no_ticket",
        "-groups",
        KEM_GROUPS,
        "-verify_return_error",
        "-ign_eof",
        "-brief",
    ]

    proc = subprocess.Popen(
        cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )

    monitor = ResourceMonitor(proc.pid)
    monitor.start()

    stdout_data = b""
    try:
        # Tulis input secara aman (Cegah ValueError: flush of closed file)
        if proc.poll() is None:
            proc.stdin.write(get_request)
            proc.stdin.flush()
        proc.stdin.close()

        stdout_data = proc.stdout.read()
        proc.wait(timeout=30)
    except (BrokenPipeError, ValueError):
        # Jika OpenSSL mati seketika, tutup pipe dan baca errornya
        proc.stdin.close()
        stdout_data = proc.stdout.read()
        proc.wait()
    except subprocess.TimeoutExpired:
        monitor.stop()
        proc.kill()
        raise TimeoutError(f"OpenSSL timeout (Port {server_port})")
    except Exception as e:
        monitor.stop()
        proc.kill()
        raise e
    finally:
        monitor.stop()

    # Tangkap dan log output asli dari OpenSSL jika terjadi error
    if proc.returncode != 0:
        error_msg = stdout_data.decode(errors="ignore").strip()
        logger.error(f"OpenSSL Error (Code {proc.returncode}): {error_msg[:300]}")
        raise RuntimeError(f"Handshake dibatalkan oleh OpenSSL")

    return {
        "handshake_time_s": None,
        "ttfb_s": None,
        "cpu_peak_pct": monitor.cpu_peak,
        "cpu_mean_pct": monitor.cpu_mean,
        "ram_peak_bytes": monitor.ram_peak_bytes,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Eksekusi
# ─────────────────────────────────────────────────────────────────────────────
def run_scenario(
    scenario_id: str, network_condition: str, output_dir: Path
) -> list[dict]:
    port = PORT_SCENARIO[scenario_id]
    configure_netem(network_condition)
    time.sleep(0.5)

    pcap_dir = output_dir / "pcap" / f"sc{scenario_id}" / network_condition
    pcap_dir.mkdir(parents=True, exist_ok=True)

    results: list[dict] = []
    total = WARMUP_ITERATIONS + MEASUREMENT_ITERATIONS

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
            stop_tshark(tshark_proc)
            time.sleep(0.5)

            ttlb = parse_ttlb_from_pcap(pcap_path, port)
            if not ttlb:
                raise ValueError("Gagal menghitung TTLB dari PCAP")

            metrics["ttlb_s"] = ttlb
            metrics["scenario"] = scenario_id
            metrics["network"] = network_condition
            metrics["is_warmup"] = is_warmup
            metrics["iteration"] = label
            metrics["timestamp"] = datetime.now(UTC).isoformat()

            if not is_warmup:
                results.append(metrics)
                logger.info(
                    f"[{label}] TTLB={ttlb * 1000:7.2f}ms CPU={metrics['cpu_peak_pct']:5.1f}% RAM={metrics['ram_peak_bytes'] // 1024}KB"
                )
        except Exception as exc:
            import traceback

            logger.error(f"[{label}] Gagal: {exc}")
            logger.error(traceback.format_exc())
            stop_tshark(tshark_proc)
    return results


def save_csv(data: list[dict], path: Path):
    if not data:
        return
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenarios", nargs="+", default=["A", "B", "C"])
    parser.add_argument("--networks", nargs="+", default=["ideal", "edge"])
    parser.add_argument("--output-dir", type=Path, default=Path("/measurement/results"))
    parser.add_argument("--skip-spawn-overhead", action="store_true")
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    run_id = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    logger.info(f"Mulai Benchmark: Run {run_id}")

    if not args.skip_spawn_overhead:
        spawn_data = measure_spawn_overhead()
        with open(args.output_dir / "spawn_overhead.json", "w") as f:
            json.dump({k: v for k, v in spawn_data.items() if k != "samples_ms"}, f)

    all_results = []
    for sc_id in args.scenarios:
        for net_cond in args.networks:
            try:
                rows = run_scenario(sc_id, net_cond, args.output_dir)
                all_results.extend(rows)
            except Exception as e:
                logger.error(e)

    save_csv(all_results, args.output_dir / f"results_combined_{run_id}.csv")
    logger.info("Selesai")


if __name__ == "__main__":
    main()
