FROM gvenzl/oracle-free:23-slim

# Install Java as root so orapki works in container-entrypoint-initdb.d scripts.
USER root
RUN microdnf install -y java-17-openjdk-headless && microdnf clean all
USER oracle
