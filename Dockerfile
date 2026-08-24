# ── Build Stage ──────────────────────────────────────────────────────────────
FROM golang:1.26.6-alpine@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83 AS builder

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
FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

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
