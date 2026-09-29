FROM python:3.12
COPY --chmod=0777 scripts/ /app/scripts/
USER app
HEALTHCHECK CMD true