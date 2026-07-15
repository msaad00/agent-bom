## ── Builder stage ────────────────────────────────────────────────────────────
FROM python:3.14.6-alpine3.23@sha256:02da11a8d221ca167aa07de20b3cd7104c1f01227f4b02b1fa13cf6517280a81 AS builder

WORKDIR /app
ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG NO_PROXY
ARG SSL_CERT_FILE
ARG REQUESTS_CA_BUNDLE
ARG CURL_CA_BUNDLE
ARG PIP_CERT
ENV HTTP_PROXY=${HTTP_PROXY} \
    HTTPS_PROXY=${HTTPS_PROXY} \
    NO_PROXY=${NO_PROXY} \
    SSL_CERT_FILE=${SSL_CERT_FILE} \
    REQUESTS_CA_BUNDLE=${REQUESTS_CA_BUNDLE} \
    CURL_CA_BUNDLE=${CURL_CA_BUNDLE} \
    PIP_CERT=${PIP_CERT}

# Build-time deps for wheel compilation when musllinux wheels are unavailable.
RUN apk add --no-cache build-base ca-certificates git libffi-dev linux-headers \
    && apk upgrade --no-cache --available \
    && update-ca-certificates

COPY pyproject.toml README.md PYPI_README.md LICENSE ./
COPY src/ ./src/
COPY deploy/supabase/postgres/ ./deploy/supabase/postgres/

# Extras baked into the published control-plane image. Cloud SDKs (aws/azure/gcp)
# ship by default so self-hosted BYOC (connect an AWS/Azure/GCP account read-only,
# incl. IRSA/workload-identity) works out of the box (#3832). Override at build
# time for a lean image, e.g. --build-arg AGENT_BOM_EXTRAS=api,snowflake,postgres.
ARG AGENT_BOM_EXTRAS=api,snowflake,postgres,aws,azure,gcp
RUN pip install --no-cache-dir --prefix=/install ".[${AGENT_BOM_EXTRAS}]"

## ── Runtime stage ────────────────────────────────────────────────────────────
FROM python:3.14.6-alpine3.23@sha256:02da11a8d221ca167aa07de20b3cd7104c1f01227f4b02b1fa13cf6517280a81

ARG VERSION=0.95.0
ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG NO_PROXY
ARG SSL_CERT_FILE
ARG REQUESTS_CA_BUNDLE
ARG CURL_CA_BUNDLE
ARG PIP_CERT

LABEL maintainer="W S <34316639+msaad00@users.noreply.github.com>"
LABEL description="Security scanner for AI infrastructure — CVEs, blast radius, credential exposure, runtime enforcement"
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.source="https://github.com/msaad00/agent-bom"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# Copy only installed packages from builder (no compiler toolchain or git)
COPY --from=builder /install /usr/local
COPY --from=builder /app/LICENSE /app/LICENSE
COPY --from=builder /app/deploy/supabase/postgres /opt/agent-bom/deploy/supabase/postgres

RUN apk add --no-cache ca-certificates libffi libgcc libstdc++ \
    && apk upgrade --no-cache --available \
    && update-ca-certificates
COPY deploy/docker/pip-requirements.txt /tmp/pip-req.txt
RUN pip install --no-cache-dir --require-hashes -r /tmp/pip-req.txt && rm /tmp/pip-req.txt

# Create non-root user for least-privilege execution
RUN addgroup -S abom && adduser -S -G abom abom

WORKDIR /workspace
RUN chown abom:abom /workspace

# Pre-create the state dir and hand ownership to abom (uid/gid of the abom
# user) so a named volume or bind mount at /home/abom/.agent-bom is writable.
# Without this the mount lands root-owned and abom (non-root) cannot create
# jobs.db / vulns.db, crash-looping the API.
RUN mkdir -p /home/abom/.agent-bom && chown -R abom:abom /home/abom

USER abom

ENV PYTHONUNBUFFERED=1
ENV TERM=xterm-256color
ENV HTTP_PROXY=${HTTP_PROXY}
ENV HTTPS_PROXY=${HTTPS_PROXY}
ENV NO_PROXY=${NO_PROXY}
ENV SSL_CERT_FILE=${SSL_CERT_FILE}
ENV REQUESTS_CA_BUNDLE=${REQUESTS_CA_BUNDLE}
ENV CURL_CA_BUNDLE=${CURL_CA_BUNDLE}
ENV PIP_CERT=${PIP_CERT}

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD agent-bom --version || exit 1

ENTRYPOINT ["agent-bom"]
CMD ["--help"]
