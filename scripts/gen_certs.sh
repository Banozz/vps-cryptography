#!/usr/bin/env bash
# =============================================================================
# gen_certs.sh — Generate PKI (CA + server certs) untuk 3 skenario penelitian
# Jalankan di dalam container SEKALI SAJA sebelum memulai eksperimen.
#
# Output di /measurement/certs/:
#   Skenario A (ECDSA)    : ca_A.crt, server_A.crt, server_A.key
#   Skenario B (Dilithium): ca_B.crt, server_B.crt, server_B.key
#   Skenario C (Hybrid)   : ca_C.crt, server_C.crt, server_C.key
#
# File server_*.crt dan server_*.key perlu disalin ke mesin SERVER.
# File ca_*.crt hanya dibutuhkan di sisi CLIENT (sebagai trusted anchor).
# =============================================================================
set -euo pipefail

CERTS_DIR="${CERTS_DIR:-/measurement/certs}"
OQS_CNF="${OPENSSL_CONF:-/etc/ssl/openssl-oqs.cnf}"
DAYS=365

print_step() { echo -e "\n\e[36m▶ $*\e[0m"; }
print_ok()   { echo -e "\e[32m  ✓ $*\e[0m"; }
print_err()  { echo -e "\e[31m  ✗ $*\e[0m"; }

# ── Validasi lingkungan ───────────────────────────────────────────────────────
print_step "Validasi oqs-provider..."
if ! openssl list -providers 2>/dev/null | grep -q "oqsprovider"; then
  print_err "oqs-provider tidak ditemukan! Pastikan container dibangun dengan benar."
  exit 1
fi
print_ok "oqs-provider tersedia"

if ! openssl list -signature-algorithms -provider oqs -provider default 2>/dev/null \
     | grep -q "p256_dilithium2"; then
  print_err "Algoritma p256_dilithium2 tidak ditemukan di oqs-provider!"
  exit 1
fi
print_ok "p256_dilithium2 tersedia"

mkdir -p "$CERTS_DIR"
cd "$CERTS_DIR"

# ──────────────────────────────────────────────────────────────────────────────
# SKENARIO A — ECDSA-P256 (Baseline Klasik)
# ──────────────────────────────────────────────────────────────────────────────
print_step "Skenario A: Membuat PKI ECDSA-P256..."

# Root CA
openssl genpkey \
  -algorithm EC \
  -pkeyopt ec_paramgen_curve:P-256 \
  -out ca_A.key 2>/dev/null
print_ok "ca_A.key dibuat"

openssl req -new -x509 \
  -key ca_A.key \
  -out ca_A.crt \
  -days $DAYS \
  -subj "/C=ID/O=TLS-Hybrid-Research/CN=Root-CA-ECDSA-P256" \
  2>/dev/null
print_ok "ca_A.crt dibuat"

# Server cert
openssl genpkey \
  -algorithm EC \
  -pkeyopt ec_paramgen_curve:P-256 \
  -out server_A.key 2>/dev/null
print_ok "server_A.key dibuat"

openssl req -new \
  -key server_A.key \
  -out server_A.csr \
  -subj "/C=ID/O=TLS-Hybrid-Research/CN=TLS-Server-A" \
  2>/dev/null

openssl x509 -req \
  -in server_A.csr \
  -CA ca_A.crt \
  -CAkey ca_A.key \
  -CAcreateserial \
  -out server_A.crt \
  -days $DAYS \
  -extensions v3_server \
  -extfile "$OQS_CNF" \
  2>/dev/null
rm -f server_A.csr
print_ok "server_A.crt dibuat"

# Verifikasi
openssl verify -CAfile ca_A.crt server_A.crt > /dev/null \
  && print_ok "Verifikasi rantai sertifikat A: OK" \
  || { print_err "Verifikasi rantai sertifikat A GAGAL"; exit 1; }

# ──────────────────────────────────────────────────────────────────────────────
# SKENARIO B — CRYSTALS-Dilithium2 (Pure PQC)
# ──────────────────────────────────────────────────────────────────────────────
print_step "Skenario B: Membuat PKI CRYSTALS-Dilithium2..."

# Root CA
openssl genpkey \
  -provider oqs -provider default \
  -algorithm dilithium2 \
  -out ca_B.key 2>/dev/null
print_ok "ca_B.key dibuat"

openssl req -new -x509 \
  -provider oqs -provider default \
  -key ca_B.key \
  -out ca_B.crt \
  -days $DAYS \
  -subj "/C=ID/O=TLS-Hybrid-Research/CN=Root-CA-Dilithium2" \
  2>/dev/null
print_ok "ca_B.crt dibuat"

# Server cert
openssl genpkey \
  -provider oqs -provider default \
  -algorithm dilithium2 \
  -out server_B.key 2>/dev/null
print_ok "server_B.key dibuat"

openssl req -new \
  -provider oqs -provider default \
  -key server_B.key \
  -out server_B.csr \
  -subj "/C=ID/O=TLS-Hybrid-Research/CN=TLS-Server-B" \
  2>/dev/null

openssl x509 -req \
  -provider oqs -provider default \
  -in server_B.csr \
  -CA ca_B.crt \
  -CAkey ca_B.key \
  -CAcreateserial \
  -out server_B.crt \
  -days $DAYS \
  2>/dev/null
rm -f server_B.csr
print_ok "server_B.crt dibuat"

openssl verify \
  -provider oqs -provider default \
  -CAfile ca_B.crt server_B.crt > /dev/null \
  && print_ok "Verifikasi rantai sertifikat B: OK" \
  || { print_err "Verifikasi rantai sertifikat B GAGAL"; exit 1; }

# ──────────────────────────────────────────────────────────────────────────────
# SKENARIO C — p256_dilithium2 (OQS Hybrid)
# ──────────────────────────────────────────────────────────────────────────────
print_step "Skenario C: Membuat PKI OQS Hybrid p256_dilithium2..."

# Root CA
openssl genpkey \
  -provider oqs -provider default \
  -algorithm p256_dilithium2 \
  -out ca_C.key 2>/dev/null
print_ok "ca_C.key dibuat"

openssl req -new -x509 \
  -provider oqs -provider default \
  -key ca_C.key \
  -out ca_C.crt \
  -days $DAYS \
  -subj "/C=ID/O=TLS-Hybrid-Research/CN=Root-CA-Hybrid-p256-Dilithium2" \
  2>/dev/null
print_ok "ca_C.crt dibuat"

# Server cert
openssl genpkey \
  -provider oqs -provider default \
  -algorithm p256_dilithium2 \
  -out server_C.key 2>/dev/null
print_ok "server_C.key dibuat"

openssl req -new \
  -provider oqs -provider default \
  -key server_C.key \
  -out server_C.csr \
  -subj "/C=ID/O=TLS-Hybrid-Research/CN=TLS-Server-C" \
  2>/dev/null

openssl x509 -req \
  -provider oqs -provider default \
  -in server_C.csr \
  -CA ca_C.crt \
  -CAkey ca_C.key \
  -CAcreateserial \
  -out server_C.crt \
  -days $DAYS \
  2>/dev/null
rm -f server_C.csr
print_ok "server_C.crt dibuat"

openssl verify \
  -provider oqs -provider default \
  -CAfile ca_C.crt server_C.crt > /dev/null \
  && print_ok "Verifikasi rantai sertifikat C: OK" \
  || { print_err "Verifikasi rantai sertifikat C GAGAL"; exit 1; }

# ── Ringkasan ukuran artefak (validasi Tabel 3.1 di proposal) ────────────────
print_step "Ringkasan ukuran artefak kriptografi:"
echo ""
printf "  %-12s %-14s %-14s %-14s\n" "Artefak" "Skenario A" "Skenario B" "Skenario C"
printf "  %-12s %-14s %-14s %-14s\n" "----------" "-----------" "-----------" "-----------"

for f in ca server; do
  for ext in crt key; do
    a=$(wc -c < "${f}_A.${ext}" 2>/dev/null || echo 0)
    b=$(wc -c < "${f}_B.${ext}" 2>/dev/null || echo 0)
    c=$(wc -c < "${f}_C.${ext}" 2>/dev/null || echo 0)
    printf "  %-12s %-14s %-14s %-14s\n" \
      "${f}_*.${ext}" "${a} bytes" "${b} bytes" "${c} bytes"
  done
done
echo ""

# ── Set permissions ───────────────────────────────────────────────────────────
chmod 644 ./*.crt
chmod 600 ./*.key
print_ok "Permissions di-set (crt:644, key:600)"

echo ""
echo "════════════════════════════════════════════════════════════════════"
echo "  Semua sertifikat berhasil dibuat di: $CERTS_DIR"
echo ""
echo "  Yang perlu disalin ke mesin SERVER:"
echo "    server_A.crt, server_A.key  (port 4433)"
echo "    server_B.crt, server_B.key  (port 4434)"
echo "    server_C.crt, server_C.key  (port 4435)"
echo ""
echo "  yang tetap di CLIENT (trusted anchors):"
echo "    ca_A.crt, ca_B.crt, ca_C.crt"
echo "════════════════════════════════════════════════════════════════════"