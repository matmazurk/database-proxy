#!/bin/bash
set -euo pipefail

# orapki requires a JRE. gvenzl/oracle-free:23-slim does not include Java,
# so we install a minimal headless JRE at container init time (once per volume).
microdnf install -y java-17-openjdk-headless

# Derive JAVA_HOME from the freshly installed java binary.
JAVA_BIN=$(readlink -f "$(which java)")
export JAVA_HOME="${JAVA_BIN%/bin/java}"

mkdir -p /opt/oracle/wallet

# Create auto-login wallet and import the PKCS12 bundle.
orapki wallet create -wallet /opt/oracle/wallet -auto_login_only
orapki wallet import_pkcs12 \
  -wallet /opt/oracle/wallet \
  -auto_login_only \
  -pkcs12file /tcps-certs/oracle.p12 \
  -pkcs12pwd ""

# Deploy Oracle network config to ORACLE_HOME (where the listener reads from).
TNS_DIR="${ORACLE_HOME}/network/admin"
cp /tcps-config/sqlnet.ora "${TNS_DIR}/sqlnet.ora"
cp /tcps-config/listener.ora "${TNS_DIR}/listener.ora"

# Restart the listener to register the new TCPS endpoint.
lsnrctl stop
lsnrctl start
