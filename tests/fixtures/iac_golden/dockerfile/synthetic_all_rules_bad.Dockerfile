# syntax=docker/dockerfile:1

FROM ubuntu AS base
FROM python:latest
FROM node:20-alpine AS build
FROM scratch
FROM alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000
FROM registry.example.com/app@sha512:abc
USER root
USER 0:0
USER app:root
ENV API_KEY=not-a-real-key-value-123
ENV DB_PASSWORD "quoted-fake-password"
ENV AUTH_TOKEN short
ENV SECRET_TOKEN
ENV PLAIN_VALUE=some-long-plain-value
ADD app.tar.gz /app/
ADD https://example.com/tool.tar.gz /opt/
RUN curl -fsSL https://example.com/install.sh | sh
RUN wget -qO- https://example.com/setup | bash
RUN apt-get install -y curl
RUN apk add git
RUN yum install -y wget && rm -rf /var/cache/yum
RUN apt-get install -y jq && apt-get clean
EXPOSE 22 8080
EXPOSE 22/tcp
EXPOSE 8000-8100
COPY . .
COPY --chown=0:0 src/ /src/
COPY --chmod=777 bin/ /bin/
COPY --chmod=0777 lib/ /lib/
RUN chmod 777 /tmp/data
RUN chmod -R 0777 /srv
RUN sudo apt-get update
ARG GITHUB_TOKEN
ARG BUILD_VERSION
RUN pip install requests
RUN pip3 install --no-cache-dir flask
WORKDIR app
WORKDIR /srv/app
SHELL ["/bin/bash", "-c"]
RUN --network=host make build
HEALTHCHECK CMD curl -f http://localhost/ || exit 1
