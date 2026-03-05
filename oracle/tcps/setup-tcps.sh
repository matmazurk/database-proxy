#!/bin/bash
set -euo pipefail

mkdir -p /opt/oracle/wallet

# Create auto-login wallet and import the PKCS12 bundle
orapki wallet create -wallet /opt/oracle/wallet -auto_login_only
orapki wallet import_pkcs12 \
  -wallet /opt/oracle/wallet \
  -auto_login_only \
  -pkcs12file /tcps-certs/oracle.p12 \
  -pkcs12pwd ""

# Deploy Oracle network config
cp /tcps-config/sqlnet.ora /opt/oracle/oradata/tns/sqlnet.ora
cp /tcps-config/listener.ora /opt/oracle/oradata/tns/listener.ora

# Reload listener to pick up TCPS address
lsnrctl reload
