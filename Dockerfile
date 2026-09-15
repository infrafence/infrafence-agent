FROM golang:1.26-alpine AS builder

RUN apk add --no-cache git

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=0.0.0
ARG BUILD_TAGS=""
RUN CGO_ENABLED=0 GOOS=linux go build \
    -tags "${BUILD_TAGS}" \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o /infrafence-agent \
    ./cmd/infrafence-agent

# ── Runtime ──────────────────────────────────────────────────────────────────
FROM alpine:3.24

RUN apk add --no-cache \
    iptables \
    ip6tables \
    ipset \
    ca-certificates \
    curl \
    bash

COPY --from=builder /infrafence-agent /usr/local/bin/infrafence-agent
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh /usr/local/bin/infrafence-agent

ARG VERSION
ENV INFRAFENCE_CONFIG=/etc/infrafence/config.json
ENV INFRAFENCE_SERVER_URL=https://infrafence.com
ENV INFRAFENCE_VERSION=${VERSION}

ENTRYPOINT ["docker-entrypoint.sh"]
