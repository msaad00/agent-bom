## ── Builder stage ────────────────────────────────────────────────────────────
FROM python:3.14.3-alpine3.23@sha256:faee120f7885a06fcc9677922331391fa690d911c020abb9e8025ff3d908e510 AS builder

WORKDIR /app

# Build-time deps for wheel compilation when musllinux wheels are unavailable.
RUN apk add --no-cache build-base git linux-headers

COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

RUN pip install --no-cache-dir --prefix=/install ".[api]"

## ── Runtime stage ────────────────────────────────────────────────────────────
FROM python:3.14.3-alpine3.23@sha256:faee120f7885a06fcc9677922331391fa690d911c020abb9e8025ff3d908e510

ARG VERSION=0.75.10

LABEL maintainer="W S <34316639+msaad00@users.noreply.github.com>"
LABEL description="Security scanner for AI infrastructure — CVEs, blast radius, credential exposure, runtime enforcement"
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.source="https://github.com/msaad00/agent-bom"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# Copy only installed packages from builder (no compiler toolchain or git)
COPY --from=builder /install /usr/local
COPY --from=builder /app/LICENSE /app/LICENSE

RUN apk upgrade --no-cache zlib
RUN pip install --no-cache-dir "pip==26.0.1" --hash=sha256:bdb1b08f4274833d62c1aa29e20907365a2ceb950410df15fc9521bad440122b

# Create non-root user for least-privilege execution
RUN addgroup -S abom && adduser -S -G abom abom

WORKDIR /workspace
RUN chown abom:abom /workspace

USER abom

ENV PYTHONUNBUFFERED=1
ENV TERM=xterm-256color

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD agent-bom --version || exit 1

ENTRYPOINT ["agent-bom"]
CMD ["--help"]
