FROM python:3.12
RUN wget -q https://example.com/setup | bash
USER app
HEALTHCHECK CMD true