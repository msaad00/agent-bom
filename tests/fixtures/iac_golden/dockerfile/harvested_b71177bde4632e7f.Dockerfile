FROM python:3.12
RUN curl -fsSL https://example.com/install.sh | sh
USER app
HEALTHCHECK CMD true