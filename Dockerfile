# =============================================================================
# Dockerfile — Mesin CLIENT (Two-Machine Mode)
# Base  : Ubuntu 24.04 LTS (OpenSSL 3.2.1 Native) -> STABIL & AMAN PQC
# Builds: liboqs 0.11.0 + oqs-provider 0.7.0
# Tools : Python 3.12, tshark, iproute2 (tc/netem), socat
# =============================================================================

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Install dependensi sistem (Ubuntu 24.04 LTS aktif, tidak perlu patch 404)
RUN apt-get update && apt-get install -y \
        build-essential cmake ninja-build \
        libssl-dev git ca-certificates \
        openssl \
        python3 python3-pip \
        tshark \
        iproute2 \
        socat \
        tcpdump \
        procps \
        net-tools \
    && rm -rf /var/lib/apt/lists/*

ARG LIBOQS_VERSION=0.11.0
ARG OQS_PROVIDER_VERSION=0.7.0

WORKDIR /tmp

# Build dan install liboqs dari source
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
    && ninja -C liboqs/build install \
    && echo '/usr/local/lib' > /etc/ld.so.conf.d/liboqs.conf \
    && ldconfig

# Build oqs-provider
RUN git clone --depth 1 --branch ${OQS_PROVIDER_VERSION} \
        https://github.com/open-quantum-safe/oqs-provider.git oqs-provider \
    && cmake -S oqs-provider -B oqs-provider/build \
        -GNinja \
        -DCMAKE_BUILD_TYPE=Release \
        -DOPENSSL_ROOT_DIR=/usr \
        -DCMAKE_PREFIX_PATH=/usr/local \
    && ninja -C oqs-provider/build \
    && ninja -C oqs-provider/build install \

# Bersihkan direktori temporary build
RUN rm -rf /tmp/liboqs /tmp/oqs-provider

# Install Python dependencies (Menggunakan flag PEP 668 khusus OS modern)
COPY setup/scripts/requirements.txt /tmp/requirements.txt
RUN pip3 install --break-system-packages --no-cache-dir -r /tmp/requirements.txt

# Menyalin berkas konfigurasi OpenSSL
COPY setup/config/openssl-oqs.cnf /etc/ssl/openssl-oqs.cnf
ENV OPENSSL_CONF=/etc/ssl/openssl-oqs.cnf

# Berikan hak akses dumpcap agar tshark bisa menyadap paket tanpa root priviliges
RUN chmod +x /usr/bin/dumpcap 2>/dev/null || true

# Validasi muatan provider
RUN openssl list -providers | grep -q "oqsprovider" \
    && echo "✓ oqs-provider loaded successfully" \
    || (echo "✗ oqs-provider NOT found" && exit 1)

# Validasi kesiapan algoritma hibrida/kuantum di sisi Klien
RUN openssl list -signature-algorithms -provider oqsprovider -provider default \
    | grep -q "p256_dilithium2" \
    && echo "✓ p256_dilithium2 available for benchmarking" \
    || (echo "✗ p256_dilithium2 NOT found" && exit 1)

WORKDIR /measurement

CMD ["/bin/bash"]
