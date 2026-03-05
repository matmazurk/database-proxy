#!/bin/bash
set -euo pipefail

# orapki requires Java. Java is pre-installed in the custom Oracle image (oracle/Dockerfile).
# Derive JAVA_HOME from the java binary so orapki can find the JVM.
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
