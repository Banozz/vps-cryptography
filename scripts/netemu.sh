#!/usr/bin/env bash
# =============================================================================
# netemu.sh — Kontrol manual tc/NetEm pada interface jaringan
#
# CATATAN: benchmark.py sudah mengelola NetEm secara internal via
# configure_netem(). Script ini disediakan untuk:
#   - Debugging manual kondisi jaringan
#   - Reset NetEm bila benchmark.py terhenti paksa (Ctrl+C) tanpa cleanup
#   - Verifikasi bahwa tc/NetEm berfungsi sebelum eksperimen
#
# Cara pakai:
#   bash netemu.sh check    <iface>               ← cek apakah tc berfungsi
#   bash netemu.sh setup    <iface> <latency_ms> <loss_pct> [jitter_ms]
#   bash netemu.sh teardown <iface>               ← hapus semua NetEm rules
#   bash netemu.sh status   <iface>               ← lihat config aktif
#
# Contoh:
#   bash netemu.sh check    wlan0
#   bash netemu.sh setup    wlan0 100 1 5     ← 100ms ±5ms, 1% loss
#   bash netemu.sh teardown wlan0
# =============================================================================
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'
CYAN='\033[0;36m'; NC='\033[0m'

ok()   { echo -e "${GREEN}[NETEM]${NC} $*"; }
warn() { echo -e "${YELLOW}[NETEM]${NC} $*"; }
err()  { echo -e "${RED}[NETEM]${NC} $*" >&2; }
info() { echo -e "${CYAN}[NETEM]${NC} $*"; }

ACTION="${1:?Gunakan: check | setup | teardown | status}"
IFACE="${2:?Argumen kedua: nama interface (misal: wlan0, eth0)}"

# ── Validasi interface ────────────────────────────────────────────────────────
if ! ip link show "$IFACE" &>/dev/null; then
  err "Interface '$IFACE' tidak ditemukan."
  echo ""
  echo "  Interface yang tersedia:"
  ip -o link show | awk -F': ' '{printf "    %s\n", $2}'
  exit 1
fi

# ── Cek tc tersedia dan berfungsi ─────────────────────────────────────────────
tc_works() {
  command -v tc &>/dev/null && tc qdisc show dev "$IFACE" &>/dev/null
}

clear_qdisc() {
  tc qdisc del dev "$IFACE" root 2>/dev/null || true
}

# ── Actions ───────────────────────────────────────────────────────────────────
case "$ACTION" in

  # Cek apakah tc/netem berfungsi — jalankan ini sebelum eksperimen
  check)
    if tc_works; then
      ok "tc/netem tersedia dan berfungsi pada '$IFACE'"
      info "Konfigurasi saat ini:"
      tc qdisc show dev "$IFACE"
      exit 0
    else
      warn "tc/netem TIDAK berfungsi pada '$IFACE'"
      warn "Kondisi 'edge' mungkin tidak dapat disimulasikan."
      exit 1
    fi
    ;;

  # Terapkan NetEm dengan parameter tertentu
  setup)
    LATENCY_MS="${3:?Argumen ketiga: latency dalam ms (0 = ideal)}"
    LOSS_PCT="${4:-0}"
    JITTER_MS="${5:-5}"

    if ! tc_works; then
      warn "tc tidak berfungsi — skip setup (tidak ada emulasi diterapkan)"
      exit 0
    fi

    clear_qdisc

    if [[ "$LATENCY_MS" -eq 0 && "$LOSS_PCT" == "0" ]]; then
      ok "Kondisi ideal — tidak ada emulasi jaringan pada '$IFACE'"
    else
      tc qdisc add dev "$IFACE" root netem \
        delay "${LATENCY_MS}ms" "${JITTER_MS}ms" distribution normal \
        loss "${LOSS_PCT}%"
      ok "NetEm aktif pada '$IFACE':"
      info "  Latency    : ${LATENCY_MS}ms ± ${JITTER_MS}ms (distribusi normal)"
      info "  Packet loss: ${LOSS_PCT}%"
    fi

    echo ""
    info "Konfigurasi tc aktif:"
    tc qdisc show dev "$IFACE"
    ;;

  # Hapus semua NetEm rules — gunakan ini setelah benchmark terhenti paksa
  teardown)
    if ! tc_works; then
      warn "tc tidak berfungsi — tidak ada yang perlu dihapus"
      exit 0
    fi
    clear_qdisc
    ok "Semua NetEm rules dihapus dari '$IFACE'"
    ;;

  # Lihat konfigurasi NetEm yang aktif
  status)
    info "Konfigurasi tc pada '$IFACE':"
    tc qdisc show dev "$IFACE"
    ;;

  *)
    err "Action tidak dikenal: '$ACTION'"
    echo "Gunakan: check | setup | teardown | status"
    exit 1
    ;;
esac