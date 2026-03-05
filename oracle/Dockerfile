FROM gvenzl/oracle-free:23-slim

# Install Java and download Oracle PKI JARs (required by orapki) as root.
# The gvenzl slim image omits these; we source them from Maven Central.
USER root
RUN microdnf install -y java-17-openjdk-headless curl && \
    microdnf clean all && \
    mkdir -p /opt/oracle/product/26ai/dbhomeFree/jlib && \
    curl -fsSL \
      "https://repo1.maven.org/maven2/com/oracle/database/security/oraclepki/23.7.0.25.01/oraclepki-23.7.0.25.01.jar" \
      -o /opt/oracle/product/26ai/dbhomeFree/jlib/oraclepki.jar && \
    curl -fsSL \
      "https://repo1.maven.org/maven2/com/oracle/database/security/osdt_core/21.9.0.0/osdt_core-21.9.0.0.jar" \
      -o /opt/oracle/product/26ai/dbhomeFree/jlib/cryptoj.jar
USER oracle
