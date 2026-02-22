FROM python:3.11-slim

ARG VERSION=dev

LABEL maintainer="Wagdy Saad <crewnycgiving@gmail.com>"
LABEL description="agent-bom: AI Bill of Materials generator and vulnerability scanner for AI agents and MCP servers"
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

# Install agent-bom
RUN pip install --no-cache-dir -e .

# Create workspace directory for mounting
WORKDIR /workspace

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
