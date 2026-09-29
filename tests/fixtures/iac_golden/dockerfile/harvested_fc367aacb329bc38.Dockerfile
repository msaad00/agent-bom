FROM python:3.12
RUN apt-get install -y curl
USER app
HEALTHCHECK CMD true