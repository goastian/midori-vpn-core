# ── Stage 1: Build ──
FROM golang:alpine AS builder

RUN apk add --no-cache git bash gcc musl-dev

WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN go mod tidy && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /vpn-core ./cmd/vpn-core

# ── Stage 2: Runtime ──
FROM alpine:3.21

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

EXPOSE 8080/tcp
EXPOSE 51820/udp
EXPOSE 8888/tcp

ENTRYPOINT ["/usr/local/bin/vpn-core"]

