# FilterREX Connector Host — Dockerfile
# Multi-stage build for minimal runtime image

FROM golang:1.22-alpine AS builder

WORKDIR /build
COPY go.mod go.sum ./
# Copy root .go files AND internal subpackages (brocadecli, brocadeexport,
# evidencebundle, cmd) so `go build .` can resolve module-internal imports.
# `COPY *.go` alone omitted the subpackage directories and broke the image build.
COPY . ./

ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
  -ldflags="-s -w -X main.HostVersion=${VERSION}" \
  -o connector-agent .

# ── Runtime ──
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /build/connector-agent /usr/local/bin/connector-agent

LABEL org.opencontainers.image.source="https://github.com/filterrex-ai/connector-agent"
LABEL org.opencontainers.image.description="FilterREX SAN Connector — read-only Brocade evidence collection agent"
LABEL org.opencontainers.image.vendor="FilterREX-AI"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# Non-root user + config directory
# Create dirs BEFORE declaring VOLUME so ownership is baked into the image layer.
# When Docker initializes an empty named volume it copies this layer's contents/perms.
RUN adduser -D -u 1000 filterrex \
 && mkdir -p /etc/filterrex/secrets \
 && chown -R filterrex:filterrex /etc/filterrex

VOLUME /etc/filterrex

USER filterrex

ENTRYPOINT ["connector-agent"]
