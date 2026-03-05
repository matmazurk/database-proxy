# ── build stage ────────────────────────────────────────────────────────────────
# Oracle Linux is required: go-oci8 (used by vault-plugin-database-oracle) needs
# Oracle Instant Client headers for CGO compilation, and the compiled binary
# needs glibc at runtime — Alpine (musl) is incompatible with Oracle IC.
FROM oraclelinux:9 AS builder

RUN echo $'[ol9_oracle_instantclient]\nname=Oracle Instant Client for Oracle Linux 9 ($basearch)\nbaseurl=https://yum.oracle.com/repo/OracleLinux/OL9/oracle/instantclient/$basearch/\ngpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-oracle\ngpgcheck=1\nenabled=1' \
        > /etc/yum.repos.d/oracle-instantclient.repo && \
    dnf install -y oracle-instantclient19.28-basic oracle-instantclient19.28-devel gcc git curl && \
    dnf clean all

RUN find /usr/lib/oracle -name "libclntsh.so" -exec dirname {} \; \
        | head -1 > /etc/ld.so.conf.d/oracle-instantclient.conf && \
    ldconfig

ARG GO_VERSION=1.25.4
RUN arch=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/') && \
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${arch}.tar.gz" | tar -C /usr/local -xz
ENV PATH=/usr/local/go/bin:$PATH

WORKDIR /build
RUN git clone https://github.com/hashicorp/vault-plugin-database-oracle.git .

RUN OIC_LIB=$(find /usr/lib/oracle   -name "libclntsh.so" -exec dirname {} \; | head -1) && \
    OIC_INC=$(find /usr/include/oracle -name "oci.h"        -exec dirname {} \; | head -1) && \
    mkdir -p /usr/local/lib/pkgconfig && \
    printf 'prefix=%s\nlibdir=${prefix}\nincludedir=%s\n\nName: oci8\nDescription: Oracle Call Interface\nVersion: 19.28\nLibs: -L${libdir} -lclntsh\nCflags: -I${includedir}\n' \
        "$OIC_LIB" "$OIC_INC" > /usr/local/lib/pkgconfig/oci8.pc && \
    CGO_ENABLED=1 PKG_CONFIG_PATH=/usr/local/lib/pkgconfig \
    go build -o vault-plugin-database-oracle ./plugin

# ── runtime stage ──────────────────────────────────────────────────────────────
FROM oraclelinux:9-slim

ARG VAULT_VERSION=1.15.6

# Tools needed to start vault and drop privileges; all available in base OL9 repos.
# libaio is a runtime dependency of Oracle IC shared libraries.
RUN microdnf install -y \
        curl unzip libcap shadow-utils util-linux libaio && \
    microdnf clean all

# Oracle IC runtime libraries are not in the slim image repos; copy from builder.
COPY --from=builder /usr/lib/oracle /usr/lib/oracle
COPY --from=builder /etc/ld.so.conf.d/oracle-instantclient.conf /etc/ld.so.conf.d/oracle-instantclient.conf
RUN ldconfig

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

COPY --from=builder /build/vault-plugin-database-oracle /vault/plugins-baked/vault-plugin-database-oracle

VOLUME /vault/data
EXPOSE 8200
ENTRYPOINT ["vault"]
