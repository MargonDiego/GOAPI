# ============================================================
# Dockerfile — Go API (Clean Architecture)
# ============================================================
# Build multi-stage: compila binario estático y lo empaqueta
# en una imagen mínima sin toolchain de Go (~15 MB final).
# ============================================================

# --- Stage 1: Build ---
FROM golang:1.24-alpine AS builder

# Instalar git para resolver dependencias privadas (si las hay)
RUN apk add --no-cache git ca-certificates

WORKDIR /app

# Cache de dependencias (capa separada para builds rápidos)
COPY go.mod go.sum ./
RUN go mod download

# Compilar binario estático (sin CGO, compatible con alpine)
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /app/api ./cmd/api/

# --- Stage 2: Runtime ---
FROM alpine:3.21

# Certificados CA para HTTPS saliente
RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

# Copiar binario compilado
COPY --from=builder /app/api .

# Copiar migraciones (necesarias en runtime para golang-migrate)
COPY --from=builder /app/migrations ./migrations

# Usuario no-root por seguridad
RUN adduser -D -g '' appuser
USER appuser

# Puerto expuesto (documentación, el runtime usa la variable PORT)
EXPOSE 8080

# Health check para orquestadores
HEALTHCHECK --interval=15s --timeout=3s --retries=3 \
    CMD wget -qO- http://localhost:${PORT:-8080}/health/liveness || exit 1

ENTRYPOINT ["./api"]
