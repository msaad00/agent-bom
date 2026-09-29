FROM ubuntu
ENV API_KEY=sk-verylongsecretvalue123
ADD https://x.com/i /tmp/i
COPY --chmod=777 app /app
RUN curl https://x.com/i | sh
EXPOSE 22
