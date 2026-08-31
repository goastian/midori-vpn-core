# ── Stage 1: Build ──
FROM docker.io/library/golang:1.27.0-alpine3.24@sha256:c0ef102fd47cc7cfb3db3e93c4830f500307e37dad1dca44a3795e783cb0bf58 AS builder

RUN apk add --no-cache git bash gcc musl-dev

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux go build -mod=readonly -trimpath -ldflags="-s -w" -o /vpn-core ./cmd/vpn-core

# ── Stage 2: Runtime ──
FROM docker.io/library/alpine:3.24.1@sha256:79ff19e9084a00eece421b2523fb93e22d730e2c0e525905de047e848e56d95f

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

ENTRYPOINT ["/usr/local/bin/vpn-core"]
