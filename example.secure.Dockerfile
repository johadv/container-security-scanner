FROM alpine:3.20

RUN addgroup -S app && adduser -S app -G app

WORKDIR /app
COPY . /app

USER app

CMD ["sh"]
