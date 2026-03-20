FROM ubuntu:latest

RUN apt-get update && apt-get install -y \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

USER root

COPY . /app
WORKDIR /app

CMD ["echo", "Hello World"]
