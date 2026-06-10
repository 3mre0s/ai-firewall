.PHONY: build test vet clean docker run release

VERSION ?= dev
BINARY  := ai-firewall

# ── Development ───────────────────────────────────────────────────────────────

build:
	CGO_ENABLED=0 go build -ldflags="-w -s -X main.version=$(VERSION)" -o $(BINARY) .

test:
	go test ./... -v -count=1 -race -timeout 60s

vet:
	go vet ./...

clean:
	rm -f $(BINARY) $(BINARY).exe
	rm -rf dist/

# Run locally with .env loaded (Linux/macOS).
# (Yerel olarak .env ile çalıştır.)
run: build
	@[ -f .env ] && export $$(cat .env | xargs) ; ./$(BINARY)

# ── Docker ────────────────────────────────────────────────────────────────────

docker:
	docker build -t localai/firewall:$(VERSION) .

docker-run:
	docker run --rm -p 8080:8080 \
		-e FORWARD_API_KEY=$(FORWARD_API_KEY) \
		-e UPSTREAM_URL=$(UPSTREAM_URL) \
		localai/firewall:$(VERSION)

# ── Release ───────────────────────────────────────────────────────────────────
# Usage: make release VERSION=1.0.0
# Runs tests, tags, and pushes — GitHub Actions handles the binary builds.
# (Testleri çalıştırır, etiketler ve gönderir — binary build'leri GitHub Actions üstlenir.)

release: test vet
	@if [ -z "$(VERSION)" ] || [ "$(VERSION)" = "dev" ]; then \
		echo "Usage: make release VERSION=1.0.0"; exit 1; fi
	@echo "→ Tagging v$(VERSION) and pushing..."
	git tag -a v$(VERSION) -m "Release v$(VERSION)"
	git push origin v$(VERSION)
	@echo "✅ Tag pushed. GitHub Actions will build and publish the release."
