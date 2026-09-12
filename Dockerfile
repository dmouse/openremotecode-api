# syntax=docker/dockerfile:1

# --- Build stage -------------------------------------------------------
FROM golang:1.27-alpine AS builder

WORKDIR /src

# Cached separately from source so `go mod download` only reruns when
# dependencies actually change.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH

# CGO_ENABLED=0 produces a static binary (no cgo dependency in this module's
# graph, so this never touches gcc/musl-dev the way Dockerfile.dev does).
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server

# --- Runtime stage -------------------------------------------------------
# distroless: no shell, no package manager, non-root by default. CA certs are
# included, which this binary needs for postgres sslmode, SMTP STARTTLS/TLS,
# and verifying Google ID tokens.
FROM gcr.io/distroless/static-debian12:nonroot AS runtime

WORKDIR /app
COPY --from=builder /out/server ./server

# Config default (HTTP_ADDR=127.0.0.1:8080) only binds loopback. Set
# HTTP_ADDR=0.0.0.0:8080 in the environment so the container is reachable.
# Production also requires PAIRING_CODE_KEY, SERVICE_ID,
# PAIRING_VERIFICATION_URI (https), TLS_CERT_FILE/TLS_KEY_FILE, and SMTP_*
# — see README.md. Mount the TLS cert/key as files (e.g. a secret or bind
# mount) and point TLS_CERT_FILE/TLS_KEY_FILE at them.
EXPOSE 8080

USER nonroot:nonroot

# No HEALTHCHECK: this image has no shell or exec'able health-check tool by
# design. Have the orchestrator probe GET /health/live (liveness) and
# GET /health/ready (readiness, checks the DB) over HTTP instead.
ENTRYPOINT ["/app/server"]
