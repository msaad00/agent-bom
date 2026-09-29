FROM python:3.12
ADD . /app
USER app
HEALTHCHECK CMD true