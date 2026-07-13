# ForgeAI Connector Host — Dockerfile
# Multi-stage build for minimal runtime image

FROM golang:1.22-alpine AS builder

WORKDIR /build
COPY go.mod go.sum ./
COPY *.go ./

ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
  -ldflags="-s -w -X main.HostVersion=${VERSION}" \
  -o connector-agent .

# ── Runtime ──
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /build/connector-agent /usr/local/bin/connector-agent

LABEL org.opencontainers.image.source="https://github.com/filterrex-ai/connector-agent"
LABEL org.opencontainers.image.description="FilterREX-AI Connector Host — Multi-Target Agent"
LABEL org.opencontainers.image.vendor="FilterREX-AI"

# Non-root user + config directory
# Create dirs BEFORE declaring VOLUME so ownership is baked into the image layer.
# When Docker initializes an empty named volume it copies this layer's contents/perms.
RUN adduser -D -u 1000 forgeai \
 && mkdir -p /etc/forgeai/secrets \
 && chown -R forgeai:forgeai /etc/forgeai

VOLUME /etc/forgeai

USER forgeai

ENTRYPOINT ["connector-agent"]
