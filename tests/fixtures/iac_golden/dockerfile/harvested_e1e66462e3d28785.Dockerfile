FROM alpine:3.18
RUN apk add --no-cache curl
USER app
HEALTHCHECK CMD true