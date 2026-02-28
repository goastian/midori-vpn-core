# ── Stage 1: Build ──
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git

WORKDIR /src
COPY . .
RUN go mod tidy && CGO_ENABLED=0 GOOS=linux go build -o /vpn-core ./cmd/vpn-core

# ── Stage 2: Runtime ──
FROM alpine:3.20

RUN apk add --no-cache \
    wireguard-tools \
    wireguard-tools-wg \
    wireguard-tools-wg-quick \
    iproute2 \
    iptables \
    ip6tables \
    ca-certificates \
    tzdata

COPY --from=builder /vpn-core /usr/local/bin/vpn-core
COPY migrations /migrations

RUN mkdir -p /etc/wireguard

EXPOSE 8080/tcp
EXPOSE 51820/udp

ENTRYPOINT ["/usr/local/bin/vpn-core"]
