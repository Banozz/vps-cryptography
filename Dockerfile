# Menggunakan base image Ubuntu 22.04 yang secara default sudah membawa OpenSSL 3.0
FROM ubuntu:22.04

# Set non-interactive agar instalasi tidak terhenti oleh prompt timezone
ENV DEBIAN_FRONTEND=noninteractive

# 1. Update system & Install dependencies untuk build
RUN apt-get update && apt-get install -y \
    build-essential cmake gcc ninja-build \
    libssl-dev git ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# 2. Build liboqs (C library untuk algoritma kuantum, termasuk Dilithium)
WORKDIR /opt
RUN git clone -b main https://github.com/open-quantum-safe/liboqs.git && \
    cd liboqs && \
    mkdir build && cd build && \
    cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local -DOQS_USE_OPENSSL=ON .. && \
    ninja && ninja install

# 3. Build oqs-provider (Agar OpenSSL bisa menggunakan algoritma dari liboqs)
WORKDIR /opt
RUN git clone -b main https://github.com/open-quantum-safe/oqs-provider.git && \
    cd oqs-provider && \
    cmake -DOPENSSL_ROOT_DIR=/usr -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=/usr/local -S . -B build && \
    cmake --build build && \
    cmake --install build

# 4. Konfigurasi OpenSSL untuk mengaktifkan oqs-provider secara default
RUN sed -i 's/default = default_sect/default = default_sect\noqsprovider = oqsprovider_sect/g' /etc/ssl/openssl.cnf && \
    sed -i 's/\[default_sect\]/\[default_sect\]\nactivate = 1\n\[oqsprovider_sect\]\nactivate = 1\n/g' /etc/ssl/openssl.cnf

# 5. Persiapkan direktori kerja klien
WORKDIR /client-workspace

# (Opsional) Salin sertifikat Root CA ke dalam container klien untuk verifikasi
# COPY ./root-ca.crt /client-workspace/

# Set command default saat container dijalankan
CMD ["/bin/bash"]