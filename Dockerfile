# ── Stage 1: Build ──
FROM docker.io/library/golang:1.27-alpine AS builder

RUN apk add --no-cache git bash gcc musl-dev

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux go build -mod=readonly -trimpath -ldflags="-s -w" -o /vpn-core ./cmd/vpn-core

# ── Stage 2: Runtime ──
FROM alpine:3.24

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
