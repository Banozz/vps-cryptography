#!/usr/bin/env bash
# =============================================================================
# host_setup.sh — Jalankan di HOST FISIK (bukan di dalam container)
# Menyiapkan kondisi hardware agar pengukuran konsisten dan dapat direproduksi.
#
# Apa yang dilakukan skrip ini:
#   1. Nonaktifkan Intel Turbo Boost (mencegah variasi frekuensi CPU)
#   2. Set CPU governor ke "performance" (frekuensi tetap di max)
#   3. Nonaktifkan CPU frequency scaling
#   4. Nonaktifkan IRQ balancing (menghindari interupsi acak antar-core)
#
# Cara pakai:
#   sudo bash host_setup.sh setup    → sebelum eksperimen
#   sudo bash host_setup.sh teardown → setelah eksperimen (kembalikan ke normal)
# =============================================================================
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "[ERROR] Skrip ini harus dijalankan sebagai root: sudo bash $0 <setup|teardown>"
  exit 1
fi

print_info()  { echo -e "\e[34m[INFO]\e[0m  $*"; }
print_ok()    { echo -e "\e[32m[ OK ]\e[0m  $*"; }
print_warn()  { echo -e "\e[33m[WARN]\e[0m  $*"; }

# ── Deteksi jumlah core ───────────────────────────────────────────────────────
NUM_CPUS=$(nproc)
print_info "Terdeteksi $NUM_CPUS logical CPU cores"

# ── Nonaktifkan Turbo Boost (Intel) ──────────────────────────────────────────
disable_turbo() {
  local TURBO_FILE="/sys/devices/system/cpu/intel_pstate/no_turbo"
  if [[ -f "$TURBO_FILE" ]]; then
    echo 1 > "$TURBO_FILE"
    print_ok "Turbo Boost dinonaktifkan (intel_pstate)"
  else
    # Fallback: via MSR (perlu msr module)
    if modprobe msr 2>/dev/null; then
      for cpu in $(seq 0 $((NUM_CPUS - 1))); do
        rdmsr -p "$cpu" 0x1a0 2>/dev/null | \
          awk '{printf "0x%x\n", or(strtonum("0x"$1), 0x4000000000)}' | \
          xargs -I{} wrmsr -p "$cpu" 0x1a0 {} 2>/dev/null || true
      done
      print_ok "Turbo Boost dinonaktifkan (MSR)"
    else
      print_warn "Tidak dapat menonaktifkan Turbo Boost — file $TURBO_FILE tidak ada"
    fi
  fi
}

enable_turbo() {
  local TURBO_FILE="/sys/devices/system/cpu/intel_pstate/no_turbo"
  if [[ -f "$TURBO_FILE" ]]; then
    echo 0 > "$TURBO_FILE"
    print_ok "Turbo Boost diaktifkan kembali"
  fi
}

# ── Set CPU governor ──────────────────────────────────────────────────────────
set_governor() {
  local GOV="$1"
  if command -v cpupower &>/dev/null; then
    cpupower frequency-set -g "$GOV" > /dev/null
    print_ok "CPU governor diset ke '$GOV' (via cpupower)"
  else
    for cpu in $(seq 0 $((NUM_CPUS - 1))); do
      local GOV_FILE="/sys/devices/system/cpu/cpu${cpu}/cpufreq/scaling_governor"
      if [[ -f "$GOV_FILE" ]]; then
        echo "$GOV" > "$GOV_FILE"
      fi
    done
    print_ok "CPU governor diset ke '$GOV' (via sysfs)"
  fi
}

# ── IRQ balancing ─────────────────────────────────────────────────────────────
stop_irqbalance()  { systemctl stop irqbalance  2>/dev/null && print_ok "irqbalance dihentikan"  || print_warn "irqbalance tidak berjalan"; }
start_irqbalance() { systemctl start irqbalance 2>/dev/null && print_ok "irqbalance dijalankan kembali" || true; }

# ── Catat frekuensi CPU saat ini (untuk verifikasi) ───────────────────────────
print_cpu_info() {
  echo ""
  echo "── Kondisi CPU saat ini ─────────────────────────────────────────────"
  for cpu in $(seq 0 $((NUM_CPUS - 1))); do
    local FREQ_FILE="/sys/devices/system/cpu/cpu${cpu}/cpufreq/scaling_cur_freq"
    local GOV_FILE="/sys/devices/system/cpu/cpu${cpu}/cpufreq/scaling_governor"
    if [[ -f "$FREQ_FILE" ]]; then
      local FREQ=$(( $(cat "$FREQ_FILE") / 1000 ))
      local GOV=$(cat "$GOV_FILE" 2>/dev/null || echo "unknown")
      printf "  CPU%d: %4d MHz | governor: %s\n" "$cpu" "$FREQ" "$GOV"
    fi
  done
  local TURBO_FILE="/sys/devices/system/cpu/intel_pstate/no_turbo"
  if [[ -f "$TURBO_FILE" ]]; then
    local TURBO=$(cat "$TURBO_FILE")
    printf "  Turbo Boost: %s\n" "$([ "$TURBO" = "1" ] && echo 'OFF' || echo 'ON')"
  fi
  echo "─────────────────────────────────────────────────────────────────────"
  echo ""
}

# ── Main ─────────────────────────────────────────────────────────────────────
ACTION="${1:-}"
case "$ACTION" in
  setup)
    echo ""
    echo "════════════════════════════════════════════════════════════════════"
    echo "  HOST SETUP — Menyiapkan kondisi hardware untuk eksperimen"
    echo "════════════════════════════════════════════════════════════════════"
    disable_turbo
    set_governor "performance"
    stop_irqbalance
    print_cpu_info
    echo "[INFO] Jalankan 'sudo bash host_setup.sh teardown' setelah eksperimen selesai."
    ;;
  teardown)
    echo ""
    echo "════════════════════════════════════════════════════════════════════"
    echo "  HOST TEARDOWN — Mengembalikan pengaturan hardware ke normal"
    echo "════════════════════════════════════════════════════════════════════"
    enable_turbo
    set_governor "powersave"
    start_irqbalance
    print_cpu_info
    ;;
  status)
    print_cpu_info
    ;;
  *)
    echo "Usage: sudo bash $0 <setup|teardown|status>"
    exit 1
    ;;
esac