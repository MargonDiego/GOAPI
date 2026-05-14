# ============================================================
# Dockerfile — Go API (Clean Architecture)
# ============================================================
# Build multi-stage: compila binario estático y lo empaqueta
# en una imagen mínima sin toolchain de Go (~15 MB final).
# ============================================================

# --- Stage 1: Build ---
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git ca-certificates
WORKDIR /app

# Copiar todo el código fuente
COPY . .

# Compilar binario estático (sin CGO, compatible con alpine)
RUN CGO_ENABLED=0 GOOS=linux \
    go build -ldflags="-s -w" -o /app/api ./cmd/api/

# --- Stage 2: Runtime ---
FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app

COPY --from=builder /app/api .
COPY --from=builder /app/migrations ./migrations

RUN adduser -D -g '' appuser
USER appuser

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=3s --retries=3 \
    CMD wget -qO- http://localhost:${PORT:-8080}/health/liveness || exit 1

ENTRYPOINT ["./api"]
