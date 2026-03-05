#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="$DIR/out"
rm -rf "$OUT"
mkdir -p "$OUT"

# CA (v3 with basicConstraints CA:TRUE)
openssl genrsa -out "$OUT/ca.key" 2048
openssl req -new -x509 -key "$OUT/ca.key" -out "$OUT/ca.crt" -days 365 \
  -subj "/CN=database-proxy-ca" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

# Proxy server cert
openssl genrsa -out "$OUT/proxy-server.key" 2048
openssl req -new -key "$OUT/proxy-server.key" -out "$OUT/proxy-server.csr" \
  -subj "/CN=localhost"
openssl x509 -req -in "$OUT/proxy-server.csr" -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" \
  -CAcreateserial -out "$OUT/proxy-server.crt" -days 365 \
  -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1")

# Vault server cert
openssl genrsa -out "$OUT/vault-server.key" 2048
openssl req -new -key "$OUT/vault-server.key" -out "$OUT/vault-server.csr" \
  -subj "/CN=vault"
openssl x509 -req -in "$OUT/vault-server.csr" -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" \
  -CAcreateserial -out "$OUT/vault-server.crt" -days 365 \
  -extfile <(printf "subjectAltName=DNS:vault,DNS:localhost,IP:127.0.0.1")

# Client cert (used by psql to connect to proxy, and by proxy to auth to Vault)
openssl genrsa -out "$OUT/client.key" 2048
openssl req -new -key "$OUT/client.key" -out "$OUT/client.csr" \
  -subj "/CN=test-client"
openssl x509 -req -in "$OUT/client.csr" -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" \
  -CAcreateserial -out "$OUT/client.crt" -days 365

# Vault TLS dir (VAULT_DEV_TLS_CERT_DIR expects tls.crt and tls.key)
VAULT_TLS="$OUT/vault-tls"
mkdir -p "$VAULT_TLS"
cp "$OUT/vault-server.crt" "$VAULT_TLS/tls.crt"
cp "$OUT/vault-server.key" "$VAULT_TLS/tls.key"

# Oracle TCPS cert (SAN=DNS:oracle for proxy→oracle TLS verification)
openssl genrsa -out "$OUT/oracle-server.key" 2048
openssl req -new -key "$OUT/oracle-server.key" -out "$OUT/oracle-server.csr" \
  -subj "/CN=oracle"
openssl x509 -req -in "$OUT/oracle-server.csr" -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" \
  -CAcreateserial -out "$OUT/oracle-server.crt" -days 365 \
  -extfile <(printf "subjectAltName=DNS:oracle")

# Oracle Wallet PKCS12 bundle (no passphrase — orapki import_pkcs12 uses -pkcs12pwd "")
openssl pkcs12 -export \
  -in "$OUT/oracle-server.crt" \
  -inkey "$OUT/oracle-server.key" \
  -certfile "$OUT/ca.crt" \
  -out "$OUT/oracle.p12" \
  -passout pass:

# Cleanup CSRs
rm -f "$OUT"/*.csr "$OUT"/*.srl

echo "Certificates generated in $OUT/"
ls -la "$OUT/"
