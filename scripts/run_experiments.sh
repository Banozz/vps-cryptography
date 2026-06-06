#!/usr/bin/env bash
# =============================================================================
# run_experiment.sh — Pre-flight validation + orchestrator eksperimen
#
# Dijalankan DI DALAM container client (dipanggil oleh docker-compose client-run).
# Melakukan validasi lingkungan sebelum benchmark.py dijalankan:
#
#   [1] SERVER_HOST terset dan server dapat dijangkau
#   [2] CA certificates tersedia untuk semua skenario
#   [3] tshark dapat menangkap di CAPTURE_IFACE
#   [4] tc/netem tersedia (bila tidak, kondisi 'edge' di-skip otomatis)
#
# Setelah semua validasi lulus, benchmark.py dieksekusi.
# =============================================================================
set -euo pipefail

# ── Warna output ──────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

ok()    { echo -e "${GREEN}[ OK ]${NC}  $*"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
step()  { echo -e "\n${BOLD}${CYAN}▶ $*${NC}"; }

# ── Baca environment variables ────────────────────────────────────────────────
SERVER_HOST="${SERVER_HOST:-}"
CAPTURE_IFACE="${CAPTURE_IFACE:-wlp2s0}"
CERTS_DIR="${CERTS_DIR:-/measurement/certs}"
RESULTS_DIR="${RESULTS_DIR:-/measurement/results}"
SCENARIOS="${SCENARIOS:-A,B,C}"
NETWORKS="${NETWORKS:-ideal,edge}"
PAYLOAD_SIZE_KB="${PAYLOAD_SIZE_KB:-10}"
WARMUP_ITERS="${WARMUP_ITERS:-20}"
MEASURE_ITERS="${MEASURE_ITERS:-100}"

ERRORS=0

# =============================================================================
# [1] Validasi SERVER_HOST
# =============================================================================
step "Validasi [1/4]: Koneksi ke server"

if [[ -z "$SERVER_HOST" ]]; then
  fail "SERVER_HOST tidak di-set."
  info "  Jalankan: export SERVER_HOST=<IP_SERVER>"
  (( ERRORS++ ))
else
  info "  Target server: $SERVER_HOST"

  # Cek setiap port sesuai skenario yang akan dijalankan
  declare -A SCENARIO_PORTS=( ["A"]="4433" ["B"]="4434" ["C"]="4435" )
  UNREACHABLE_PORTS=()

  for SC in $(echo "$SCENARIOS" | tr ',' ' '); do
    PORT="${SCENARIO_PORTS[$SC]:-}"
    if [[ -z "$PORT" ]]; then continue; fi

    if timeout 3 bash -c "echo > /dev/tcp/$SERVER_HOST/$PORT" 2>/dev/null; then
      ok "  Port $PORT (Skenario $SC) dapat dijangkau"
    else
      fail "  Port $PORT (Skenario $SC) TIDAK dapat dijangkau"
      UNREACHABLE_PORTS+=("$PORT")
      (( ERRORS++ ))
    fi
  done

  if [[ ${#UNREACHABLE_PORTS[@]} -gt 0 ]]; then
    info "  Pastikan server sudah berjalan:"
    info "    docker compose -f server/docker-compose.yml up -d tls-server"
  fi
fi

# =============================================================================
# [2] Validasi CA Certificates
# =============================================================================
step "Validasi [2/4]: CA Certificates"

MISSING_CERTS=()
for SC in $(echo "$SCENARIOS" | tr ',' ' '); do
  CA_FILE="$CERTS_DIR/ca_${SC}.crt"
  if [[ -f "$CA_FILE" ]]; then
    SIZE=$(wc -c < "$CA_FILE")
    ok "  ca_${SC}.crt ditemukan ($SIZE bytes)"
  else
    fail "  ca_${SC}.crt TIDAK ditemukan di $CERTS_DIR"
    MISSING_CERTS+=("ca_${SC}.crt")
    (( ERRORS++ ))
  fi
done

if [[ ${#MISSING_CERTS[@]} -gt 0 ]]; then
  info "  Generate sertifikat di server lalu salin ke client:"
  info "    scp <USER>@<IP_SERVER>:~/thesis-research/server/certs/ca_*.crt \\"
  info "        ~/thesis-research/certs/"
fi

# =============================================================================
# [3] Validasi tshark
# =============================================================================
step "Validasi [3/4]: tshark capture"

if ! command -v tshark &>/dev/null; then
  fail "tshark tidak ditemukan. Rebuild container."
  (( ERRORS++ ))
else
  TSHARK_VERSION=$(tshark --version 2>/dev/null | head -1)
  ok "  tshark tersedia: $TSHARK_VERSION"

  # Cek apakah interface ada
  if ip link show "$CAPTURE_IFACE" &>/dev/null; then
    ok "  Interface '$CAPTURE_IFACE' tersedia"
  else
    fail "  Interface '$CAPTURE_IFACE' TIDAK ditemukan"
    info "  Interface yang tersedia:"
    ip -o link show | awk -F': ' '{printf "    %s\n", $2}'
    info "  Set env: export CAPTURE_IFACE=<nama_interface>"
    (( ERRORS++ ))
  fi
fi

# =============================================================================
# [4] Validasi tc/NetEm (non-fatal: hanya skip kondisi edge jika gagal)
# =============================================================================
step "Validasi [4/4]: tc/NetEm (kondisi edge)"

NETEM_OK=false
if ! command -v tc &>/dev/null; then
  warn "tc tidak ditemukan — kondisi 'edge' akan di-skip"
elif ! tc qdisc show dev "$CAPTURE_IFACE" &>/dev/null; then
  warn "tc tidak dapat mengakses '$CAPTURE_IFACE' — kondisi 'edge' akan di-skip"
else
  ok "  tc/netem tersedia pada '$CAPTURE_IFACE'"
  NETEM_OK=true
fi

# Jika netem tidak tersedia dan NETWORKS mengandung 'edge', hapus 'edge'
if ! $NETEM_OK && echo "$NETWORKS" | grep -q "edge"; then
  warn "Menghapus 'edge' dari daftar kondisi jaringan (tc tidak tersedia)"
  NETWORKS=$(echo "$NETWORKS" | tr ',' '\n' | grep -v "^edge$" | tr '\n' ',' | sed 's/,$//')
  if [[ -z "$NETWORKS" ]]; then
    fail "Tidak ada kondisi jaringan yang valid tersisa."
    (( ERRORS++ ))
  else
    info "  Kondisi jaringan yang akan dijalankan: $NETWORKS"
  fi
fi

# =============================================================================
# Evaluasi hasil validasi
# =============================================================================
echo ""
echo "════════════════════════════════════════════════════════════════════"

if [[ $ERRORS -gt 0 ]]; then
  fail "Pre-flight GAGAL: $ERRORS masalah ditemukan. Eksperimen dihentikan."
  echo "════════════════════════════════════════════════════════════════════"
  exit 1
fi

ok "Semua validasi lulus. Memulai eksperimen."
echo ""
echo "  Server      : $SERVER_HOST"
echo "  Interface   : $CAPTURE_IFACE"
echo "  Skenario    : $SCENARIOS"
echo "  Jaringan    : $NETWORKS"
echo "  Payload     : ${PAYLOAD_SIZE_KB}KB"
echo "  Iterasi     : ${WARMUP_ITERS} warmup + ${MEASURE_ITERS} valid"
echo "  Output      : $RESULTS_DIR"
echo "════════════════════════════════════════════════════════════════════"
echo ""

# Buat direktori output bila belum ada
mkdir -p "$RESULTS_DIR"

# =============================================================================
# Jalankan benchmark.py
# =============================================================================

# Konversi SCENARIOS dan NETWORKS dari comma-separated ke space-separated
# karena benchmark.py menerima argumen dengan nargs="+"
SCENARIOS_ARGS=$(echo "$SCENARIOS" | tr ',' ' ')
NETWORKS_ARGS=$(echo "$NETWORKS" | tr ',' ' ')

exec python3 /measurement/scripts/benchmark.py \
  --scenarios $SCENARIOS_ARGS \
  --networks  $NETWORKS_ARGS \
  --output-dir "$RESULTS_DIR"
