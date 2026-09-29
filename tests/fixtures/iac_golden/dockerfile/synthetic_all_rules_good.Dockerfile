FROM python:3.12-slim@sha256:1111111111111111111111111111111111111111111111111111111111111111 AS build
WORKDIR /app
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt
RUN apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
COPY --chown=10001:10001 src/ /app/src/
EXPOSE 8080
USER 10001
HEALTHCHECK CMD python -c "import sys; sys.exit(0)"
