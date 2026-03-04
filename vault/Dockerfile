# ── build stage ────────────────────────────────────────────────────────────────
# Oracle Linux is required: go-oci8 (used by vault-plugin-database-oracle) needs
# Oracle Instant Client headers for CGO compilation, and the compiled binary
# needs glibc at runtime — Alpine (musl) is incompatible with Oracle IC.
FROM oraclelinux:9 AS builder

RUN dnf install -y oracle-instantclient-basic oracle-instantclient-devel gcc git curl && \
    dnf clean all

RUN find /usr/lib/oracle -name "libclntsh.so" -exec dirname {} \; \
        | head -1 > /etc/ld.so.conf.d/oracle-instantclient.conf && \
    ldconfig

ARG GO_VERSION=1.25.4
RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" | tar -C /usr/local -xz
ENV PATH=/usr/local/go/bin:$PATH

WORKDIR /build
RUN git clone https://github.com/hashicorp/vault-plugin-database-oracle.git .

RUN OIC_LIB=$(find /usr/lib/oracle   -name "libclntsh.so" -exec dirname {} \; | head -1) && \
    OIC_INC=$(find /usr/include/oracle -name "oci.h"        -exec dirname {} \; | head -1) && \
    CGO_ENABLED=1 CGO_CFLAGS="-I${OIC_INC}" CGO_LDFLAGS="-L${OIC_LIB}" \
    go build -o vault-plugin-database-oracle ./plugin

# ── runtime stage ──────────────────────────────────────────────────────────────
FROM oraclelinux:9-slim

ARG VAULT_VERSION=1.15.6

# Oracle IC runtime (needed by the CGO vault plugin), plus tools needed to
# start vault and drop privileges.
RUN dnf install -y \
        oracle-instantclient-basic \
        curl unzip libcap shadow-utils util-linux && \
    dnf clean all && \
    find /usr/lib/oracle -name "libclntsh.so" -exec dirname {} \; \
        | head -1 > /etc/ld.so.conf.d/oracle-instantclient.conf && \
    ldconfig

# Vault binary (architecture-aware download)
RUN arch=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/') && \
    curl -fsSL \
        "https://releases.hashicorp.com/vault/${VAULT_VERSION}/vault_${VAULT_VERSION}_linux_${arch}.zip" \
        -o /tmp/vault.zip && \
    unzip -d /usr/local/bin /tmp/vault.zip && \
    rm /tmp/vault.zip && \
    setcap cap_ipc_lock=+ep /usr/local/bin/vault

# Vault user and directories — mirrors the layout of the official image
RUN useradd --system --home-dir /vault --shell /sbin/nologin vault && \
    mkdir -p /vault/data /vault/plugins /vault/logs && \
    chown -R vault:vault /vault

COPY --from=builder /build/vault-plugin-database-oracle /vault/plugins/vault-plugin-database-oracle

VOLUME /vault/data
EXPOSE 8200
ENTRYPOINT ["vault"]
