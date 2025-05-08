FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o steamdb-bot ./cmd/steamdb-update-discord-bot

FROM alpine:3.21

RUN apk --no-cache add ca-certificates

RUN adduser -D -g '' appuser

RUN mkdir -p /app/data && \
    chown -R appuser:appuser /app

WORKDIR /app

COPY --from=builder /app/steamdb-bot .

USER appuser

ENV DISCORD_TOKEN=""

EXPOSE 8080

CMD ["./steamdb-bot"]
