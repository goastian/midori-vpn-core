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

# The container runs as root so that child processes (ip, wg, iptables)
# inherit NET_ADMIN granted via cap_add in docker-compose.yml.
# Network namespace isolation already limits the blast radius.

EXPOSE 8080/tcp
EXPOSE 51820/udp

ENTRYPOINT ["/usr/local/bin/vpn-core"]
