FROM python:3.11-slim@sha256:fba6f3b73795df99960f4269b297420bdbe01a8631fc31ea3f121f2486d332d0

ARG VERSION=dev

LABEL maintainer="W S <34316639+msaad00@users.noreply.github.com>"
LABEL description="agent-bom: AI supply chain security scanner — CVEs, config security, blast radius, compliance"
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.source="https://github.com/msaad00/agent-bom"

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy package files
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

# Install agent-bom with API extras
RUN pip install --no-cache-dir -e ".[api]"

# Create non-root user for least-privilege execution
RUN addgroup --system abom && adduser --system --ingroup abom abom

# Create workspace directory for mounting
WORKDIR /workspace
RUN chown abom:abom /workspace

USER abom

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV TERM=xterm-256color

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD agent-bom --version || exit 1

# Default entrypoint
ENTRYPOINT ["agent-bom"]

# Default command (show help)
CMD ["--help"]
