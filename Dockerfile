# ── Build Stage ──────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Download dependencies first for better layer caching.
# (Daha iyi katman önbelleği için önce bağımlılıkları indir.)
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux \
    go build -ldflags="-w -s" -o ai-firewall .

# ── Production Stage ──────────────────────────────────────────────────────────
# Distroless-style minimal image: only ca-certificates and tzdata added.
# Final image is typically ~15 MB.
# (Minimal üretim imajı: yalnızca ca-certificates ve tzdata eklendi. ~15 MB.)
FROM alpine:3.19

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

COPY --from=builder /app/ai-firewall .

# Run as non-root for security (kök olmayan kullanıcı olarak çalıştır).
RUN adduser -D -u 10001 appuser
USER appuser

EXPOSE 8080

# FORWARD_API_KEY must be provided at runtime — never bake into the image.
# (FORWARD_API_KEY çalışma zamanında sağlanmalıdır — imaja gömülmemelidir.)
ENTRYPOINT ["./ai-firewall"]
