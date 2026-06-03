# =============================================================================
# Dockerfile — Mesin CLIENT
# Base  : Ubuntu 22.04 (bawaan OpenSSL 3.0.x)
# Builds: liboqs 0.11.0 + oqs-provider 0.7.0
# Tools : Python 3, tshark, iproute2 (tc/netem), socat
# =============================================================================

# ── Stage 1: Build liboqs + oqs-provider ─────────────────────────────────────
FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
        build-essential cmake ninja-build \
        libssl-dev git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Versi dipinhole untuk reproducibility
ARG LIBOQS_VERSION=0.11.0
ARG OQS_PROVIDER_VERSION=0.7.0

# Build liboqs
WORKDIR /tmp
RUN git clone --depth 1 --branch ${LIBOQS_VERSION} \
        https://github.com/open-quantum-safe/liboqs.git liboqs \
    && cmake -S liboqs -B liboqs/build \
        -GNinja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DBUILD_SHARED_LIBS=ON \
        -DOQS_USE_OPENSSL=ON \
        -DOQS_DIST_BUILD=ON \
    && ninja -C liboqs/build \
    && ninja -C liboqs/build install

# Build oqs-provider
# Dipasang ke /usr/local tapi .so akan kita salin ke path yang benar di runtime stage
RUN git clone --depth 1 --branch ${OQS_PROVIDER_VERSION} \
        https://github.com/open-quantum-safe/oqs-provider.git oqs-provider \
    && cmake -S oqs-provider -B oqs-provider/build \
        -GNinja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DOPENSSL_MODULES_PATH=/usr/local/lib/ossl-modules \
        -Dliboqs_DIR=/usr/local/lib/cmake/liboqs \
    && ninja -C oqs-provider/build \
    && ninja -C oqs-provider/build install


# ── Stage 2: Runtime image ────────────────────────────────────────────────────
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Runtime dependencies:
#   openssl         : TLS client (s_client)
#   python3 + pip   : benchmark.py, analysis.py
#   tshark          : PCAP capture untuk pengukuran TTLB
#   iproute2        : tc/netem untuk simulasi kondisi jaringan (edge)
#   socat           : health check TCP port di server
#   tcpdump         : fallback capture bila tshark bermasalah
#   procps          : ps, top (monitoring proses)
RUN apt-get update && apt-get install -y \
        openssl \
        python3 python3-pip \
        tshark \
        iproute2 \
        socat \
        tcpdump \
        procps \
        net-tools \
    && rm -rf /var/lib/apt/lists/*

# Salin liboqs shared libraries dari builder
COPY --from=builder /usr/local/lib/liboqs*          /usr/local/lib/
COPY --from=builder /usr/local/lib/cmake/liboqs     /usr/local/lib/cmake/liboqs/

# Salin oqs-provider ke path yang OpenSSL Ubuntu cari:
# Ubuntu OpenSSL 3 mencari provider di /usr/lib/x86_64-linux-gnu/ossl-modules/
RUN mkdir -p /usr/lib64/ossl-modules
COPY --from=builder /usr/local/lib/ossl-modules/oqsprovider.so \
                    /usr/lib64/ossl-modules/

# Daftarkan liboqs ke dynamic linker
RUN echo '/usr/local/lib' > /etc/ld.so.conf.d/liboqs.conf && ldconfig

# Install Python dependencies untuk benchmark.py dan analysis.py
COPY setup/scripts/requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt

# OpenSSL config: load default + oqs-provider secara bersamaan
# Menggunakan file terpisah, bukan memodifikasi openssl.cnf sistem (lebih aman)
COPY setup/config/openssl-oqs.cnf /etc/ssl/openssl-oqs.cnf
ENV OPENSSL_CONF=/etc/ssl/openssl-oqs.cnf

# Izinkan tshark dijalankan tanpa root (CAP_NET_RAW tetap diperlukan di compose)
RUN chmod +x /usr/bin/dumpcap 2>/dev/null || true

# ── Validasi build ────────────────────────────────────────────────────────────
# Gagal saat build jika oqs-provider tidak ter-load dengan benar
RUN openssl list -providers 2>/dev/null | grep -q "oqsprovider" \
    && echo "✓ oqs-provider loaded" \
    || (echo "✗ oqs-provider NOT found — build failed" && exit 1)

RUN openssl list -signature-algorithms -provider oqs -provider default 2>/dev/null \
    | grep -q "p256_dilithium2" \
    && echo "✓ p256_dilithium2 available" \
    || (echo "✗ p256_dilithium2 NOT found" && exit 1)

# Direktori kerja sesuai dengan volume mount di docker-compose.yml
WORKDIR /measurement

CMD ["/bin/bash"]
