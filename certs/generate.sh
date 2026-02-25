#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="$DIR/out"
rm -rf "$OUT"
mkdir -p "$OUT"

# CA
openssl genrsa -out "$OUT/ca.key" 2048
openssl req -new -x509 -key "$OUT/ca.key" -out "$OUT/ca.crt" -days 365 \
  -subj "/CN=database-proxy-ca"

# Proxy server cert
openssl genrsa -out "$OUT/proxy-server.key" 2048
openssl req -new -key "$OUT/proxy-server.key" -out "$OUT/proxy-server.csr" \
  -subj "/CN=localhost"
openssl x509 -req -in "$OUT/proxy-server.csr" -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" \
  -CAcreateserial -out "$OUT/proxy-server.crt" -days 365 \
  -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1")

# Client cert (used by psql to connect to proxy, and by proxy to auth to Vault)
openssl genrsa -out "$OUT/client.key" 2048
openssl req -new -key "$OUT/client.key" -out "$OUT/client.csr" \
  -subj "/CN=test-client"
openssl x509 -req -in "$OUT/client.csr" -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" \
  -CAcreateserial -out "$OUT/client.crt" -days 365

# Cleanup CSRs
rm -f "$OUT"/*.csr "$OUT"/*.srl

echo "Certificates generated in $OUT/"
ls -la "$OUT/"
