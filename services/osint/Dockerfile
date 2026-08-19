# Build
FROM golang:1.22-alpine AS build

WORKDIR /src

RUN apk add --no-cache git ca-certificates

COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
COPY data ./data

RUN CGO_ENABLED=0 GOOS=linux go test ./...
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/osint ./cmd/server

# Runtime
FROM alpine:3.20

RUN apk add --no-cache ca-certificates wget

WORKDIR /app
COPY --from=build /out/osint /app/osint
COPY --from=build /src/data /app/data

ENV OSINT_LISTEN_ADDR=:8080 \
    OSINT_SITES_PATH=/app/data/sites.json \
    OSINT_MAX_CONCURRENCY=50

EXPOSE 8080

USER nobody
ENTRYPOINT ["/app/osint"]
