ARG SOURCE_DATE_EPOCH=0

# ── Stage 1: Build ──
FROM docker.io/library/golang:1.27.4-alpine3.24@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS builder

RUN apk add --no-cache git bash gcc musl-dev

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux go build -mod=readonly -trimpath -ldflags="-s -w" -o /vpn-core ./cmd/vpn-core
RUN CGO_ENABLED=0 GOOS=linux go build -mod=readonly -trimpath -ldflags="-s -w" -o /midorivpn-migrate ./cmd/midorivpn-migrate

# ── Stage 2: Runtime ──
FROM docker.io/library/alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf

RUN apk add --no-cache \
    libcrypto3=3.5.9-r0 \
    libssl3=3.5.9-r0 \
    wireguard-tools \
    wireguard-tools-wg \
    wireguard-tools-wg-quick \
    iproute2 \
    iptables \
    ip6tables \
    ca-certificates \
    tzdata && \
    : > /var/log/apk.log

COPY --from=builder /vpn-core /usr/local/bin/vpn-core
COPY --from=builder /midorivpn-migrate /usr/local/bin/midorivpn-migrate

ENTRYPOINT ["/usr/local/bin/vpn-core"]
