# =============================================================================
# Dockerfile — TLS Client Container (Mesin Klien — Two-Machine Mode)
# Base  : Ubuntu 22.04 (OpenSSL 3.0.x)
# Builds: liboqs 0.11.0 + oqs-provider 0.7.0 (versi pinned, identik server)
# Tools : tshark, tcpdump, iproute2 (tc/netem), Python 3.10+
# =============================================================================

# ---- Stage 1: Build liboqs + oqs-provider -----------------------------------
FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
        cmake ninja-build gcc g++ make \
        libssl-dev \
        python3-dev \
        git \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

# --- Build liboqs ---
ARG LIBOQS_VERSION=0.11.0
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

# --- Build oqs-provider ---
# Ubuntu 22.04: cmake lib dir adalah /usr/local/lib (bukan lib64 seperti Fedora)
ARG OQS_PROVIDER_VERSION=0.7.0
RUN git clone --depth 1 --branch ${OQS_PROVIDER_VERSION} \
        https://github.com/open-quantum-safe/oqs-provider.git oqs-provider \
    && cmake -S oqs-provider -B oqs-provider/build \
        -GNinja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -Dliboqs_DIR=/usr/local/lib/cmake/liboqs \
    && ninja -C oqs-provider/build \
    && ninja -C oqs-provider/build install


# ---- Stage 2: Runtime image -------------------------------------------------
FROM ubuntu:22.04

LABEL maintainer="thesis-research"
LABEL description="TLS Hybrid Signature Client — Measurement Environment"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
        openssl \
        python3 python3-pip \
        tshark \
        tcpdump \
        iproute2 \
        net-tools \
        procps \
        iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Copy liboqs shared libraries (Ubuntu: /usr/local/lib, bukan lib64)
COPY --from=builder /usr/local/lib/liboqs.so*         /usr/local/lib/
COPY --from=builder /usr/local/lib/cmake/liboqs        /usr/local/lib/cmake/liboqs/

# Copy oqs-provider ke path yang sesuai dengan openssl-oqs.cnf:
#   module = /usr/lib64/ossl-modules/oqsprovider.so
RUN mkdir -p /usr/lib64/ossl-modules
COPY --from=builder /usr/local/lib/ossl-modules/oqsprovider.so \
                    /usr/lib64/ossl-modules/

# Register liboqs dengan dynamic linker
RUN echo '/usr/local/lib' > /etc/ld.so.conf.d/liboqs.conf && ldconfig

# Install Python measurement dependencies
COPY setup/scripts/requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt

# Copy OpenSSL config (aktifkan oqs-provider secara global di container ini)
COPY setup/config/openssl-oqs.cnf /etc/ssl/openssl-oqs.cnf
ENV OPENSSL_CONF=/etc/ssl/openssl-oqs.cnf

# Validasi: oqs-provider harus termuat saat build
RUN openssl list -providers | grep -q "oqsprovider" \
    && echo "oqs-provider loaded" \
    || (echo "oqs-provider NOT found — build failed" && exit 1)

# Validasi: algoritma hybrid harus tersedia
RUN openssl list -signature-algorithms -provider oqs -provider default \
    | grep -q "p256_dilithium2" \
    && echo "p256_dilithium2 available" \
    || (echo "p256_dilithium2 NOT found" && exit 1)

WORKDIR /measurement

CMD ["bash"]
