# =============================================================================
# Dockerfile — Mesin CLIENT (Two-Machine Mode)
# Base  : Fedora 40 (OpenSSL 3.2.1 + Python 3.12)
# Builds: liboqs 0.11.0 + oqs-provider 0.7.0
# Tools : Python 3.12, tshark, iproute, socat
# =============================================================================

FROM fedora:40

LABEL maintainer="thesis-research"
LABEL description="TLS Hybrid Signature Client — Fedora 40"

# Install dependensi sistem menggunakan DNF (Fedora)
RUN dnf install -y \
        gcc gcc-c++ cmake ninja-build make \
        openssl-devel openssl \
        git ca-certificates \
        python3 python3-pip \
        wireshark-cli \
        iproute \
        iproute-tc \
        socat \
        tcpdump \
        procps-ng \
        net-tools \
        pkg-config \
    && dnf clean all

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
    && echo '/usr/local/lib64' > /etc/ld.so.conf.d/liboqs.conf \
    && ldconfig

# Build oqs-provider dan atur path ke /usr/lib64
RUN git clone --depth 1 --branch ${OQS_PROVIDER_VERSION} \
        https://github.com/open-quantum-safe/oqs-provider.git oqs-provider \
    && cmake -S oqs-provider -B oqs-provider/build \
        -GNinja \
        -DCMAKE_BUILD_TYPE=Release \
        -DOPENSSL_ROOT_DIR=/usr \
        -DCMAKE_PREFIX_PATH=/usr/local \
    && ninja -C oqs-provider/build \
    && ninja -C oqs-provider/build install \
    && mkdir -p /usr/lib64/ossl-modules \
    && find /usr/local -name "oqsprovider.so" -exec cp {} /usr/lib64/ossl-modules/ \; \
    && ln -sf /usr/lib64/ossl-modules/oqsprovider.so /usr/lib64/ossl-modules/oqs.so

# Bersihkan direktori temporary build
RUN rm -rf /tmp/liboqs /tmp/oqs-provider

# Install Python dependencies (Python 3.12 sangat aman untuk dependensi data science)
COPY setup/scripts/requirements.txt /tmp/requirements.txt
RUN pip3 install --break-system-packages --no-cache-dir -r /tmp/requirements.txt

# Menyalin berkas konfigurasi OpenSSL bawaan host
COPY setup/config/openssl-oqs.cnf /etc/ssl/openssl-oqs.cnf
ENV OPENSSL_CONF=/etc/ssl/openssl-oqs.cnf

# Koreksi path OpenSSL secara dinamis (mengganti path Ubuntu/lama ke path sejati Fedora)
RUN OSSL_MOD_DIR=$(openssl version -a | grep MODULESDIR | cut -d'"' -f2) \
    && sed -i "s|/usr/lib/x86_64-linux-gnu/ossl-modules|$OSSL_MOD_DIR|g" /etc/ssl/openssl-oqs.cnf 2>/dev/null || true \
    && sed -i "s|/usr/lib64/ossl-modules|$OSSL_MOD_DIR|g" /etc/ssl/openssl-oqs.cnf 2>/dev/null || true

# Berikan hak akses dumpcap agar tshark bisa menyadap paket tanpa root
RUN chmod +x /usr/sbin/dumpcap 2>/dev/null || chmod +x /usr/bin/dumpcap 2>/dev/null || true

# Validasi muatan provider
RUN openssl list -providers | grep -q "oqsprovider" \
    && echo "✓ oqs-provider loaded successfully" \
    || (echo "✗ oqs-provider NOT found" && exit 1)

# Validasi kesiapan algoritma hibrida/kuantum di sisi Klien
RUN openssl list -signature-algorithms -provider oqs -provider default \
    | grep -q "p256_dilithium2" \
    && echo "✓ p256_dilithium2 available for benchmarking" \
    || (echo "✗ p256_dilithium2 NOT found" && exit 1)

WORKDIR /measurement

CMD ["/bin/bash"]
