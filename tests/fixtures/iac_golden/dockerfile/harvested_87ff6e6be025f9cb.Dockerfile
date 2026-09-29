FROM python:3.12
HEALTHCHECK CMD curl -f http://localhost/ || exit 1
USER app