FROM python:3.12
ADD https://example.com/install.sh /tmp/install.sh
USER app
HEALTHCHECK CMD true