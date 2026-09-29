FROM ubuntu
RUN apt-get install -y curl
ADD . /app
EXPOSE 22