#!/usr/bin/env python3
"""
benchmark.py — PQC TLS 1.3 Performance Benchmark
Thesis: Evaluasi Performa Hybrid Signature Pasca-Kuantum pada TLS 1.3 di Edge Computing

Metrik yang diukur:
  Waktu (semua dari PCAP, referensi t=0 = ClientHello pertama):
    - TTFB  : ClientHello[0] → Application Data pertama dari server
    - TTLB  : ClientHello[0] → Application Data terakhir dari server
              (close_notify dikecualikan via CLOSE_NOTIFY_MAX_FRAME_LEN)

  Resource:
    - cpu_usr_s    : CPU user time (detik) via resource.getrusage (presisi mikrodetik)
    - cpu_sys_s    : CPU system time (detik) via resource.getrusage (presisi mikrodetik)
    - cpu_ms       : total waktu CPU (user+sys) dalam ms — metrik biaya komputasi
                     PRIMER, invarian terhadap delay jaringan
    - cpu_pct_time : Persentase CPU dari /usr/bin/time -v (string, mis. "52%"); hanya
                     valid untuk perbandingan DALAM kondisi jaringan yang sama karena
                     terdilusi oleh waktu tunggu I/O
    - max_rss_kb   : Peak RAM usage (KB) dari /usr/bin/time -v (fallback: ru_maxrss)

  Catatan: psutil dihapus karena cpu_percent(interval=None) selalu mengembalikan
  0.0 di environment container ini (kernel tidak mengupdate /proc/<pid>/stat
  untuk child processes secara real-time).

  Waktu CPU absolut diambil dari resource.getrusage(RUSAGE_CHILDREN) (ru_utime/
  ru_stime, presisi mikrodetik), BUKAN dari teks /usr/bin/time -v. Sebab field
  "User/System time (seconds)" pada /usr/bin/time hanya 2 desimal (resolusi 10ms),
  sehingga kerja kripto ~3-5ms membulat ke 0.00s. getrusage merekamnya sebagai
  ~0.004s. /usr/bin/time tetap dipakai untuk cpu_pct_time dan max_rss_kb.
"""

import argparse
import csv
import json
import logging
import os
import re
import resource
import shutil
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# Konfigurasi global
# ─────────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

WARMUP_ITERATIONS        = int(os.environ.get("WARMUP_ITERS", "20"))
MEASUREMENT_ITERATIONS   = int(os.environ.get("MEASURE_ITERS", "100"))
SPAWN_OVERHEAD_ITERATIONS = 50

PAYLOAD_SIZE_KB  = int(os.environ.get("PAYLOAD_SIZE_KB", "10"))
PAYLOAD_FILENAME = "payload.bin"

SERVER_HOST  = os.environ.get("SERVER_HOST", "pqc-server")
PORT_SCENARIO = {
    "A": int(os.environ.get("SERVER_PORT_A", "4433")),
    "B": int(os.environ.get("SERVER_PORT_B", "4434")),
    "C": int(os.environ.get("SERVER_PORT_C", "4435")),
}

CAPTURE_INTERFACE = os.environ.get("CAPTURE_IFACE", "eth0")
CERTS_DIR         = Path(os.environ.get("CERTS_DIR", "/measurement/certs"))
KEM_GROUPS        = "kyber768:P-256:X25519"

# Ukuran minimum PCAP yang dianggap valid (bytes)
# 384 = PCAP global header kosong di environment ini
PCAP_MIN_VALID_BYTES = 1000

# Ukuran maksimum TLS close_notify / alert record (bytes).
# Packet Application Data dari server dengan frame.len <= nilai ini
# kemungkinan besar adalah close_notify, bukan payload, dan akan dikecualikan
# dari perhitungan TTLB.
CLOSE_NOTIFY_MAX_FRAME_LEN = 100

# Batas waktu (detik) untuk SATU iterasi openssl s_client. Mencegah proses
# menggantung tak terbatas ketika FIN/close_notify dari server hilang akibat
# packet loss (kondisi edge) — apalagi dengan flag -ign_eof yang membuat
# s_client menunggu server menutup koneksi.
HANDSHAKE_TIMEOUT_S = int(os.environ.get("HANDSHAKE_TIMEOUT_S", "15"))

# ─────────────────────────────────────────────────────────────────────────────
# Definisi Skenario
# ─────────────────────────────────────────────────────────────────────────────
SCENARIOS = {
    "A": {"name": "Baseline ECDSA-P256",         "ca_cert": str(CERTS_DIR / "ca_A.crt")},
    "B": {"name": "Pure PQC Dilithium2",          "ca_cert": str(CERTS_DIR / "ca_B.crt")},
    "C": {"name": "OQS Hybrid p256_dilithium2",   "ca_cert": str(CERTS_DIR / "ca_C.crt")},
}

NETWORK_CONDITIONS = {
    "ideal": {"description": "Ideal (<1ms, 0% loss)", "delay_ms": 0,   "loss_pct": 0.0},
    "edge":  {"description": "Edge (100ms, 1% loss)", "delay_ms": 100, "loss_pct": 1.0},
}


# ─────────────────────────────────────────────────────────────────────────────
# [W1] Spawn Overhead
# ─────────────────────────────────────────────────────────────────────────────
def measure_spawn_overhead() -> dict:
    logger.info(f"[W1] Mengukur process spawn overhead ({SPAWN_OVERHEAD_ITERATIONS} iterasi)...")
    samples = []
    cmd = ["openssl", "version"]
    for _ in range(SPAWN_OVERHEAD_ITERATIONS):
        t0 = time.perf_counter()
        subprocess.run(cmd, capture_output=True)
        samples.append((time.perf_counter() - t0) * 1000)
    samples.sort()
    median = samples[len(samples) // 2]
    p95    = samples[int(len(samples) * 0.95)]
    logger.info(f"[W1] Spawn overhead — median: {median:.3f}ms  P95: {p95:.3f}ms")
    return {"median_ms": median, "p95_ms": p95}


# ─────────────────────────────────────────────────────────────────────────────
# [W2] Network Emulation via tc netem
# ─────────────────────────────────────────────────────────────────────────────
def configure_netem(condition: str, interface: str = CAPTURE_INTERFACE):
    tc_path = shutil.which("tc")
    if not tc_path:
        if condition != "ideal":
            logger.warning(f"[netem] 'tc' tidak ditemukan. Melewati konfigurasi '{condition}'.")
        return
    params = NETWORK_CONDITIONS[condition]
    subprocess.run([tc_path, "qdisc", "del", "dev", interface, "root"], capture_output=True)
    if condition == "ideal":
        logger.info("[netem] Kondisi ideal — tidak ada delay/loss diterapkan")
        return
    cmd = [
        tc_path, "qdisc", "add", "dev", interface, "root", "netem",
        "delay", f"{params['delay_ms']}ms",
        "loss",  f"{params['loss_pct']}%",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        logger.error(f"tc netem gagal: {result.stderr.strip()}")
    else:
        logger.info(
            f"[netem] Diterapkan: delay={params['delay_ms']}ms "
            f"loss={params['loss_pct']}% pada {interface}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# tshark: start / stop
# ─────────────────────────────────────────────────────────────────────────────
def start_tshark(port: int, pcap_path: str) -> subprocess.Popen:
    """
    Mulai tshark pada CAPTURE_INTERFACE dengan BPF filter tcp port <port>.
    Menunggu 1 detik setelah Popen agar tshark selesai membuka interface
    sebelum handshake dimulai.

    stderr dialihkan ke PIPE (bukan DEVNULL) agar error tshark bisa
    dideteksi oleh stop_tshark() dan di-log untuk debugging.
    """
    cmd = [
        "tshark",
        "-i", CAPTURE_INTERFACE,
        "-f", f"tcp port {port}",
        "-w", pcap_path,
        "-q",
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    time.sleep(1.0)

    # Deteksi dini: kalau tshark langsung exit (mis. interface tidak valid),
    # tangkap errornya sekarang sebelum handshake dimulai.
    if proc.poll() is not None:
        stderr_out = proc.stderr.read().decode(errors="ignore").strip()
        raise RuntimeError(f"tshark exit prematur (code {proc.returncode}): {stderr_out}")

    return proc


def stop_tshark(proc: subprocess.Popen):
    proc.terminate()
    try:
        _, stderr_data = proc.communicate(timeout=5)
        # Log stderr tshark kalau ada isi selain pesan "running as root" yang normal
        if stderr_data:
            msg = stderr_data.decode(errors="ignore").strip()
            # Filter pesan warning standar yang tidak actionable
            non_trivial = [
                line for line in msg.splitlines()
                if "Running as user" not in line
                and "This could be dangerous" not in line
                and line.strip()
            ]
            if non_trivial:
                logger.debug(f"tshark stderr: {chr(10).join(non_trivial)}")
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


# ─────────────────────────────────────────────────────────────────────────────
# PCAP Parser: Handshake Time, TTFB, TTLB
# ─────────────────────────────────────────────────────────────────────────────
def _tshark_query(pcap_path: str, display_filter: str, fields: list[str],
                  keylog_path: Optional[str] = None) -> list[list[str]]:
    """
    Helper: jalankan tshark -r dengan display filter dan field list tertentu.
    Jika keylog_path diberikan dan ada, tshark mendekripsi TLS 1.3 memakai
    session keys di file tsb (-o tls.keylog_file:...), sehingga record
    handshake terenkripsi (mis. Finished = type 20) dan Application Data
    sejati bisa DIBEDAKAN. Tanpa keylog, semua record terenkripsi (termasuk
    Certificate/CertificateVerify/Finished server) tampak sebagai
    Application Data (content_type 23).
    Kembalikan list of rows (setiap row adalah list of field values).
    """
    cmd = ["tshark", "-r", pcap_path]
    if keylog_path and os.path.exists(keylog_path):
        cmd += ["-o", f"tls.keylog_file:{keylog_path}"]
    cmd += ["-Y", display_filter, "-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    rows = []
    for line in result.stdout.strip().splitlines():
        parts = line.strip().split("\t")
        rows.append(parts)
    return rows


def parse_metrics_from_pcap(
    pcap_path: str,
    server_port: int,
    keylog_path: Optional[str] = None,
) -> Optional[dict]:
    """
    Parsing dua metrik waktu dari PCAP menggunakan referensi waktu yang seragam.

    Referensi t=0: frame.time_epoch dari ClientHello PERTAMA (min dari semua
    ClientHello yang ditemukan di port tujuan). Menggunakan min() menangani
    Hello Retry Request dengan benar — HRR menyebabkan dua ClientHello,
    dan kita ingin mengukur dari inisiasi koneksi pertama.

    TTFB (Time-To-First-Byte):
        t=0 → timestamp Application Data PERTAMA dari server.
        Filter: tls.app_data + tcp.srcport == server_port.
        Dikecualikan paket dengan frame.len <= CLOSE_NOTIFY_MAX_FRAME_LEN.

    TTLB (Time-To-Last-Byte):
        t=0 → timestamp Application Data TERAKHIR dari server sebelum close_notify.
        Filter sama dengan TTFB, diambil nilai max dari timestamps yang tersaring.

    Return dict dengan kunci ttfb_s dan ttlb_s, atau None jika gagal.
    """
    try:
        pcap_size = os.path.getsize(pcap_path)
        if pcap_size < PCAP_MIN_VALID_BYTES:
            logger.warning(
                f"PCAP {pcap_path} terlalu kecil ({pcap_size} bytes), kemungkinan kosong."
            )
            return None

        # ── ClientHello ──────────────────────────────────────────────────────
        ch_rows = _tshark_query(
            pcap_path,
            f"tls.handshake.type == 1 and tcp.dstport == {server_port}",
            ["frame.time_epoch"],
            keylog_path,
        )
        ch_times = [float(r[0]) for r in ch_rows if r and r[0].strip()]
        if not ch_times:
            logger.warning("PCAP parse: ClientHello tidak ditemukan.")
            return None
        t_ref = min(ch_times)   # t=0, pakai ClientHello pertama (handle HRR)

        # ── Handshake Time: ClientHello[0] → server Finished (type 20) ───────
        # CATATAN PENTING: tls.handshake.type == 20 HANYA terekspos jika PCAP
        # didekripsi (keylog tersedia). Tanpa keylog, Finished server ikut
        # terbungkus sebagai Application Data (content_type 23) sehingga tidak
        # bisa difilter → handshake_s = None.
        handshake_s = None
        t_finished_abs = None
        fin_frame_number = None
        fin_rows = _tshark_query(
            pcap_path,
            f"tls.handshake.type == 20 and tcp.srcport == {server_port}",
            ["frame.time_epoch", "frame.number"],
            keylog_path,
        )
        fin_parsed = [
            (float(r[0]), int(r[1]))
            for r in fin_rows
            if len(r) >= 2 and r[0].strip() and r[1].strip()
        ]
        if fin_parsed:
            fin_parsed.sort(key=lambda x: x[0])
            t_finished_abs, fin_frame_number = fin_parsed[0]
            handshake_s = t_finished_abs - t_ref

        # ── Application Data dari server (TTFB & TTLB) ───────────────────────
        # tls.app_data = filter tshark untuk Application Data record (konten terenkripsi)
        # Kita tambahkan frame.len agar bisa menyaring close_notify (frame kecil)
        app_rows = _tshark_query(
            pcap_path,
            f"tls.app_data and tcp.srcport == {server_port}",
            ["frame.time_epoch", "frame.len"],
            keylog_path,
        )

        # Saring close_notify: buang paket dengan frame.len <= CLOSE_NOTIFY_MAX_FRAME_LEN
        app_payload_times = []
        for row in app_rows:
            if len(row) < 2:
                continue
            try:
                ts      = float(row[0])
                flen    = int(row[1])
                if flen > CLOSE_NOTIFY_MAX_FRAME_LEN:
                    app_payload_times.append(ts)
            except (ValueError, IndexError):
                continue

        if not app_payload_times:
            logger.warning("PCAP parse: Application Data payload tidak ditemukan.")
            return None

        # ── TTLB: Time-To-Last-Byte ─────────────────────────────────────
        # Pada PCAP terdekripsi, tls.app_data hanya cocok dengan Application Data
        # SEJATI (record handshake jadi tls.handshake, close_notify jadi tls.alert).
        # Field tls.app_data hanya muncul di frame tempat TCP reassembly record
        # TLS SELESAI → timestamp-nya = byte TERAKHIR record tiba. max() = byte
        # terakhir seluruh respons. Inilah TTLB.
        ttlb_s = max(app_payload_times) - t_ref

        # ── TTFB: Time-To-First-Byte ─────────────────────────────────
        # KENAPA TIDAK pakai tls.app_data: jika server mengirim seluruh payload
        # sebagai SATU record TLS, hanya ADA SATU frame tls.app_data (di titik
        # TCP reassembly selesai) → min()==max() → TTFB==TTLB. Itu keliru.
        # Yang benar: byte pertama = TCP segment pertama BERMUATAN (tcp.len > 0)
        # dari server yang tiba SETELAH server Finished. Disaring via frame.number
        # > nomor frame Finished agar flight handshake (yang juga tcp.len>0) dan
        # frame Finished itu sendiri tidak ikut terhitung. (Perbandingan epoch
        # ber-:.9f rawan membatalkan filter > pada batas, jadi pakai frame.number.) Segment ini boleh jadi masih "TCP segment of a
        # reassembled PDU" (belum lengkap sebagai record TLS), tapi timestamp-nya
        # tetap sah sebagai "byte pertama respons tiba".
        ttfb_s = None
        if fin_frame_number is not None:
            seg_rows = _tshark_query(
                pcap_path,
                (f"tcp.srcport == {server_port} and tcp.len > 0 "
                 f"and frame.number > {fin_frame_number}"),
                ["frame.time_epoch"],
                keylog_path,
            )
            seg_times = [float(r[0]) for r in seg_rows if r and r[0].strip()]
            if seg_times:
                ttfb_s = min(seg_times) - t_ref
        if ttfb_s is None:
            # Fallback (mis. tanpa keylog → t_finished tak diketahui): pakai frame
            # tls.app_data paling awal. CATATAN: bisa salah ukur (proxy handshake
            # atau identik dengan TTLB). Hanya agar pipeline tidak gagal.
            logger.warning("TTFB fallback ke min(tls.app_data) — hasil mungkin tidak akurat.")
            ttfb_s = min(app_payload_times) - t_ref

        return {
            "handshake_s": handshake_s,   # None bila PCAP tidak didekripsi (tanpa keylog)
            "ttfb_s": ttfb_s,
            "ttlb_s": ttlb_s,
        }

    except subprocess.TimeoutExpired:
        logger.error("PCAP parse: tshark timeout.")
        return None
    except Exception as e:
        logger.error(f"PCAP parse exception: {e}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# /usr/bin/time -v parser (untuk validasi CPU)
# ────────────────────────────────────��────────────────────────────────────────
def _parse_usr_time_output(stderr_text: str) -> dict:
    """
    Parse output /usr/bin/time -v.
    Mengembalikan dict dengan kunci:
      cpu_usr_s    : User time (seconds)
      cpu_sys_s    : System time (seconds)
      cpu_pct_time : Percent of CPU this job got (string dari time, misal "45%")
      max_rss_kb   : Maximum resident set size (KB)
    """
    result = {}
    patterns = {
        "cpu_usr_s":    r"User time \(seconds\):\s+([\d.]+)",
        "cpu_sys_s":    r"System time \(seconds\):\s+([\d.]+)",
        "cpu_pct_time": r"Percent of CPU this job got:\s+(\S+)",
        "max_rss_kb":   r"Maximum resident set size \(kbytes\):\s+(\d+)",
    }
    for key, pattern in patterns.items():
        m = re.search(pattern, stderr_text)
        if m:
            val = m.group(1)
            if key in ("cpu_usr_s", "cpu_sys_s"):
                result[key] = float(val)
            elif key == "max_rss_kb":
                result[key] = int(val)
            else:
                result[key] = val
    return result

# ─────────────────────────────────────────────────────────────────────────────
# Satu iterasi handshake
# ─────────────────────────────────────────────────────────────────────────────
def run_single_handshake(scenario_id: str, server_host: str, server_port: int,
                         keylog_path: Optional[str] = None) -> dict:
    """
    Menjalankan satu iterasi openssl s_client dan mengumpulkan resource metrics
    via /usr/bin/time -v.

    Metrik waktu (ttfb_s, ttlb_s) TIDAK dihitung di sini — semuanya dihitung
    dari PCAP oleh parse_metrics_from_pcap() untuk memastikan referensi waktu
    yang seragam.
    """
    sc          = SCENARIOS[scenario_id]
    get_request = (
        f"GET /{PAYLOAD_FILENAME} HTTP/1.0\r\n"
        f"Host: {server_host}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()

    openssl_cmd = [
        "openssl", "s_client",
        "-provider", "oqsprovider",
        "-provider", "default",
        "-connect", f"{server_host}:{server_port}",
        "-CAfile",  sc["ca_cert"],
        "-tls1_3",
        "-no_ticket",
        "-groups",  KEM_GROUPS,
        "-verify_return_error",
        "-ign_eof",
        "-brief",
    ]
    # Tulis TLS 1.3 session keys ke file agar PCAP bisa didekripsi tshark.
    # Diverifikasi: OpenSSL 3.2.2 s_client mendukung opsi -keylogfile.
    if keylog_path:
        openssl_cmd += ["-keylogfile", keylog_path]

    # Cek ketersediaan /usr/bin/time -v (dilakukan sekali, di-cache bisa
    # ditambahkan nanti jika performa menjadi concern)
    time_bin = "/usr/bin/time"
    has_usr_time = False
    try:
        probe = subprocess.run(
            [time_bin, "-v", "true"],
            capture_output=True, text=True
        )
        has_usr_time = "Maximum resident set size" in probe.stderr
    except Exception:
        pass

    if has_usr_time:
        full_cmd = [time_bin, "-v"] + openssl_cmd
    else:
        full_cmd = openssl_cmd
        logger.warning("/usr/bin/time -v tidak tersedia — resource metrics tidak akan tersedia.")

    # Snapshot CPU child sebelum menjalankan handshake (presisi mikrodetik).
    # Handshake berjalan SERIAL & tiap child di-wait, sehingga delta before/after
    # mengisolasi CPU iterasi ini. tshark di-reap di luar jendela ini (di run_scenario),
    # jadi tidak ikut terhitung.
    rusage_before = resource.getrusage(resource.RUSAGE_CHILDREN)
    proc = subprocess.Popen(
        full_cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # communicate() menulis stdin lalu membaca stdout+stderr SECARA BERSAMAAN
    # (mencegah deadlock pipe) DAN menerapkan timeout wall-clock. Tanpa timeout,
    # 'proc.stdout.read()' menggantung selamanya bila openssl s_client tidak
    # pernah keluar — terjadi saat FIN/close_notify server hilang akibat packet
    # loss (kondisi edge), apalagi dengan flag -ign_eof yang membuat s_client
    # menunggu server menutup koneksi.
    try:
        stdout_data, stderr_data = proc.communicate(
            input=get_request, timeout=HANDSHAKE_TIMEOUT_S
        )
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout_data, stderr_data = proc.communicate()
        raise TimeoutError(
            f"OpenSSL timeout >{HANDSHAKE_TIMEOUT_S}s "
            f"(skenario {scenario_id}, port {server_port}) — "
            f"kemungkinan FIN/close_notify server hilang akibat packet loss"
        )
    except Exception as e:
        proc.kill()
        proc.communicate()
        raise e

    rusage_after = resource.getrusage(resource.RUSAGE_CHILDREN)
    cpu_usr_s = rusage_after.ru_utime - rusage_before.ru_utime
    cpu_sys_s = rusage_after.ru_stime - rusage_before.ru_stime

    if proc.returncode != 0:
        combined = (stdout_data + stderr_data).decode(errors="ignore").strip()
        logger.error(f"OpenSSL Error (Code {proc.returncode}): {combined[:400]}")
        raise RuntimeError("Handshake dibatalkan oleh OpenSSL")

    usr_time_data = {}
    if has_usr_time:
        usr_time_data = _parse_usr_time_output(stderr_data.decode(errors="ignore"))
        if not usr_time_data:
            logger.warning("/usr/bin/time output tidak dapat diparsing dari stderr.")

    # Waktu CPU absolut dari getrusage (presisi mikrodetik), bukan dari teks
    # /usr/bin/time yang hanya 2 desimal (membulat ke 0.00 untuk kerja sub-10ms).
    cpu_ms = (cpu_usr_s + cpu_sys_s) * 1000.0

    # max_rss: utamakan /usr/bin/time; fallback ke ru_maxrss (KB di Linux).
    max_rss_kb = usr_time_data.get("max_rss_kb")
    if max_rss_kb is None:
        max_rss_kb = int(rusage_after.ru_maxrss)

    return {
        "cpu_usr_s":    cpu_usr_s,
        "cpu_sys_s":    cpu_sys_s,
        "cpu_ms":       cpu_ms,
        "cpu_pct_time": usr_time_data.get("cpu_pct_time"),
        "max_rss_kb":   max_rss_kb,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Eksekusi satu skenario
# ─────────────────────────────────────────────────────────────────────────────
def run_scenario(scenario_id: str, network_condition: str, output_dir: Path) -> list[dict]:
    port = PORT_SCENARIO[scenario_id]
    sc   = SCENARIOS[scenario_id]
    logger.info(
        f"━━━━━ Skenario {scenario_id} — {sc['name']} | "
        f"jaringan={network_condition} | port={port} | CA={sc['ca_cert']} ━━━━━"
    )
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
        keylog_path = str(pcap_dir / f"{label}.keylog")

        logger.info(
            f"[sc{scenario_id}|{network_condition}|{label}] "
            f"▶ memulai handshake (cert: {SCENARIOS[scenario_id]['name']})..."
        )
        tshark_proc = start_tshark(port, pcap_path)
        try:
            resource_metrics = run_single_handshake(scenario_id, SERVER_HOST, port, keylog_path)

            # Tunggu sebentar agar paket terakhir sempat ditulis tshark ke disk
            time.sleep(1.0)
            stop_tshark(tshark_proc)
            time.sleep(0.5)

            time_metrics = parse_metrics_from_pcap(pcap_path, port, keylog_path)
            if time_metrics is None:
                raise ValueError("Gagal mem-parsing metrik waktu dari PCAP")

            # Gabungkan semua metrik
            row = {
                "scenario":         scenario_id,
                "network":          network_condition,
                "iteration":        label,
                "is_warmup":        is_warmup,
                "timestamp":        datetime.now(UTC).isoformat(),
                # ── Metrik waktu (dari PCAP didekripsi, t=0 = ClientHello pertama)
                "handshake_ms":     (time_metrics["handshake_s"] * 1000
                                     if time_metrics["handshake_s"] is not None else None),
                "ttfb_ms":          time_metrics["ttfb_s"] * 1000,
                "ttlb_ms":          time_metrics["ttlb_s"] * 1000,
                # ── Resource (CPU absolut via getrusage µs; pct & RAM via /usr/bin/time)
                "cpu_usr_s":        resource_metrics["cpu_usr_s"],
                "cpu_sys_s":        resource_metrics["cpu_sys_s"],
                "cpu_ms":           resource_metrics["cpu_ms"],
                "cpu_pct_time":     resource_metrics["cpu_pct_time"],
                "max_rss_kb":       resource_metrics["max_rss_kb"],
            }

            # Catat SEMUA iterasi (warm-up + data) ke CSV. Ambang warm-up
            # ditentukan POST-HOC lewat kolom is_warmup (lihat
            # warmup_convergence.py / analysis.py), tanpa perlu run ulang.
            results.append(row)
            hs_str = (f"{row['handshake_ms']:7.2f}ms"
                      if row['handshake_ms'] is not None else "   n/a   ")
            tag = "warmup" if is_warmup else " data "
            logger.info(
                f"[sc{scenario_id}|{network_condition}|{label}] ({tag}) "
                f"HS={hs_str}  "
                f"TTFB={row['ttfb_ms']:7.2f}ms  "
                f"TTLB={row['ttlb_ms']:7.2f}ms  "
                f"CPU={row['cpu_pct_time']}  "
                f"CPUms={row['cpu_ms']:6.3f}ms  "
                f"RAM={row['max_rss_kb']}KB"
            )

        except Exception as exc:
            import traceback
            logger.error(f"[sc{scenario_id}|{network_condition}|{label}] Gagal: {exc}")
            logger.error(traceback.format_exc())
            stop_tshark(tshark_proc)

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Simpan CSV
# ─────────────────────────────────────────────────────────────────────────────
def save_csv(data: list[dict], path: Path):
    if not data:
        logger.warning("Tidak ada data untuk disimpan.")
        return
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)
    logger.info(f"CSV disimpan: {path} ({len(data)} baris)")


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="PQC TLS 1.3 Benchmark — Hybrid Signature Thesis"
    )
    parser.add_argument("--scenarios",           nargs="+", default=["A", "B", "C"])
    parser.add_argument("--networks",            nargs="+", default=["ideal", "edge"])
    parser.add_argument("--output-dir",          type=Path, default=Path("/measurement/results"))
    parser.add_argument("--skip-spawn-overhead", action="store_true")
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    run_id = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    logger.info(f"Mulai Benchmark: Run {run_id}")

    if not args.skip_spawn_overhead:
        spawn_data = measure_spawn_overhead()
        with open(args.output_dir / "spawn_overhead.json", "w") as f:
            json.dump(spawn_data, f, indent=2)

    all_results = []
    for sc_id in args.scenarios:
        for net_cond in args.networks:
            try:
                rows = run_scenario(sc_id, net_cond, args.output_dir)
                all_results.extend(rows)
            except Exception as e:
                logger.error(f"Skenario {sc_id}/{net_cond} gagal: {e}")

    if all_results:
        out_path = args.output_dir / f"results_combined_{run_id}.csv"
        save_csv(all_results, out_path)
        # Symlink ke file terbaru untuk kemudahan analisis
        latest = args.output_dir / "results_combined_latest.csv"
        if latest.exists() or latest.is_symlink():
            latest.unlink()
        latest.symlink_to(out_path.name)

    logger.info("Selesai")


if __name__ == "__main__":
    main()