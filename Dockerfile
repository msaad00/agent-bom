## ── Builder stage ────────────────────────────────────────────────────────────
FROM python:3.14.3-alpine3.23@sha256:faee120f7885a06fcc9677922331391fa690d911c020abb9e8025ff3d908e510 AS builder

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
RUN apk add --no-cache build-base ca-certificates git linux-headers && update-ca-certificates

COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

RUN pip install --no-cache-dir --prefix=/install ".[api]"

## ── Runtime stage ────────────────────────────────────────────────────────────
FROM python:3.14.3-alpine3.23@sha256:faee120f7885a06fcc9677922331391fa690d911c020abb9e8025ff3d908e510

ARG VERSION=0.75.14
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

RUN apk add --no-cache ca-certificates && update-ca-certificates && apk upgrade --no-cache zlib
COPY deploy/docker/pip-requirements.txt /tmp/pip-req.txt
RUN pip install --no-cache-dir --require-hashes -r /tmp/pip-req.txt && rm /tmp/pip-req.txt

# Create non-root user for least-privilege execution
RUN addgroup -S abom && adduser -S -G abom abom

WORKDIR /workspace
RUN chown abom:abom /workspace

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
