#!/bin/bash
set -euo pipefail

# orapki's shell wrapper requires Java, but the Oracle 23ai binary is C-based.
# Provide a dummy JAVA_HOME to bypass the shell-level check.
mkdir -p /tmp/fake-jdk/bin
printf '#!/bin/sh\n' > /tmp/fake-jdk/bin/java
chmod +x /tmp/fake-jdk/bin/java
export JAVA_HOME=/tmp/fake-jdk
export TOOLHOME=/tmp/fake-jdk

mkdir -p /opt/oracle/wallet

# Create auto-login wallet and import the PKCS12 bundle
orapki wallet create -wallet /opt/oracle/wallet -auto_login_only
orapki wallet import_pkcs12 \
  -wallet /opt/oracle/wallet \
  -auto_login_only \
  -pkcs12file /tcps-certs/oracle.p12 \
  -pkcs12pwd ""

# Deploy Oracle network config to ORACLE_HOME (where the listener reads from)
TNS_DIR="${ORACLE_HOME}/network/admin"
cp /tcps-config/sqlnet.ora "${TNS_DIR}/sqlnet.ora"
cp /tcps-config/listener.ora "${TNS_DIR}/listener.ora"

# Restart the listener to register the new TCPS endpoint
lsnrctl stop
lsnrctl start
