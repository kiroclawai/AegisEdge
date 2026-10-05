FROM golang:1.27-alpine AS builder

RUN apk add --no-cache git

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o aegisedge .

# ---
FROM alpine:3.19

RUN apk add --no-cache ca-certificates iptables ip6tables

WORKDIR /app
COPY --from=builder /build/aegisedge .
COPY --from=builder /build/config.json .

# Optional: copy GeoIP database if present
COPY --from=builder /build/GeoLite2-Country.mmdb* ./

EXPOSE 8080 9090 9091

# NOTE: container runs as root by design — iptables/ip6tables Hot Takeover
# and HardenOS (sysctl, rp_filter, syncookies) require CAP_NET_ADMIN.
# If you do not use Hot Takeover, add `--cap-drop ALL --cap-add NET_BIND_SERVICE`
# and a `USER app` line here.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:9091/api/status | grep -q active || exit 1

ENTRYPOINT ["./aegisedge"]
