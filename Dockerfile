FROM python:3.9-alpine

ARG VERSION="unknown"

LABEL org.opencontainers.image.source=https://github.com/initialgyw/gywadmin-oci
LABEL org.opencontainers.image.title="gywadmin-oci"
LABEL org.opencontainers.image.description="OCI Vault + initialization helpers for gywadmin-homelab"
LABEL org.opencontainers.image.documentation=https://github.com/initialgyw/gywadmin-oci/blob/main/README.md
LABEL org.opencontainers.image.version=$VERSION

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

RUN pip install --no-cache-dir .
