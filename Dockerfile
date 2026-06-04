# =============================================================================
# Dockerfile — Mesin CLIENT (Single-Stage)
# Base  : Ubuntu 22.04 (OpenSSL 3.0.x)
# Builds: liboqs 0.11.0 + oqs-provider 0.7.0
# Tools : Python 3, tshark, iproute2 (tc/netem), socat
#
# Single-stage digunakan untuk menghindari masalah symlink liboqs.so
# antar build stage di Docker BuildKit.
# =============================================================================

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Build tools + runtime tools dalam satu layer
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

# Build dan install liboqs
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

# Build dan install oqs-provider
# find: salin .so ke path yang sesuai config, apapun path install cmake-nya
RUN git clone --depth 1 --branch ${OQS_PROVIDER_VERSION} \
        https://github.com/open-quantum-safe/oqs-provider.git oqs-provider \
    && cmake -S oqs-provider -B oqs-provider/build \
        -GNinja \
        -DCMAKE_BUILD_TYPE=Release \
        -DOPENSSL_ROOT_DIR=/usr \
        -DCMAKE_PREFIX_PATH=/usr/local \
    && ninja -C oqs-provider/build \
    && ninja -C oqs-provider/build install

# Bersihkan source build
RUN rm -rf /tmp/liboqs /tmp/oqs-provider

# Install Python dependencies
COPY setup/scripts/requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt

# OpenSSL config
COPY setup/config/openssl-oqs.cnf /etc/ssl/openssl-oqs.cnf
ENV OPENSSL_CONF=/etc/ssl/openssl-oqs.cnf

# Izinkan tshark tanpa root
RUN chmod +x /usr/bin/dumpcap 2>/dev/null || true

# Validasi
RUN openssl list -providers | grep -q "oqsprovider" \
    && echo "✓ oqs-provider loaded" \
    || (echo "✗ oqs-provider NOT found — build failed" && exit 1)

# Validasi algoritma signature
RUN openssl list -signature-algorithms -provider oqsprovider -provider default \
    | grep -q "p256_dilithium2" \
    && echo "✓ p256_dilithium2 available" \
    || (echo "✗ p256_dilithium2 NOT found" && exit 1)

WORKDIR /measurement

CMD ["/bin/bash"]
