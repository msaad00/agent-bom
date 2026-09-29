FROM python:3.12
COPY . /app
USER app
HEALTHCHECK CMD true