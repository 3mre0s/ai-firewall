#!/usr/bin/env bash
# Cross-compile ai-firewall for all supported platforms.
# Usage: scripts/build-all.sh [version]

set -euo pipefail

version="${1:-dev}"
root="$(cd "$(dirname "$0")/.." && pwd)"
dist="$root/dist"

rm -rf "$dist"
mkdir -p "$dist"

targets=(
  "linux   amd64 ai-firewall-linux-amd64"
  "darwin  amd64 ai-firewall-darwin-amd64"
  "darwin  arm64 ai-firewall-darwin-arm64"
  "windows amd64 ai-firewall-windows-amd64.exe"
)

cd "$root"

for spec in "${targets[@]}"; do
  read -r goos goarch asset <<<"$spec"
  out="$dist/$asset"
  echo "→ building $goos/$goarch → $out"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build -trimpath -ldflags "-s -w -X main.version=$version" -o "$out" .
  ( cd "$dist" && sha256sum "$asset" > "$asset.sha256" )
done

echo ""
echo "Artifacts in $dist:"
ls -la "$dist"
