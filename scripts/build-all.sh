#!/usr/bin/env bash
# Cross-compile Anonmyz and the ai-firewall compatibility binary.
# Usage: scripts/build-all.sh [version]

set -euo pipefail

version="${1:-dev}"
root="$(cd "$(dirname "$0")/.." && pwd)"
dist="$root/dist"

rm -rf "$dist"
mkdir -p "$dist"

targets=(
  "linux   amd64 anonmyz-linux-amd64       ai-firewall-linux-amd64"
  "linux   arm64 anonmyz-linux-arm64       ai-firewall-linux-arm64"
  "darwin  amd64 anonmyz-darwin-amd64      ai-firewall-darwin-amd64"
  "darwin  arm64 anonmyz-darwin-arm64      ai-firewall-darwin-arm64"
  "windows amd64 anonmyz-windows-amd64.exe ai-firewall-windows-amd64.exe"
)

cd "$root"

for spec in "${targets[@]}"; do
  read -r goos goarch asset legacy_asset <<<"$spec"
  out="$dist/$asset"
  echo "→ building $goos/$goarch → $out"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build -buildvcs=false -trimpath -ldflags "-s -w -X main.version=$version" -o "$out" .
  ( cd "$dist" && sha256sum "$asset" > "$asset.sha256" )

	legacy_out="$dist/$legacy_asset"
	CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
		go build -buildvcs=false -trimpath -ldflags "-s -w -X main.version=$version" -o "$legacy_out" .
	( cd "$dist" && sha256sum "$legacy_asset" > "$legacy_asset.sha256" )
done

(
  cd "$dist"
  sha256sum anonmyz-* ai-firewall-* | grep -v '\.sha256$' | sort -k2 > checksums.txt
)

echo ""
echo "Artifacts in $dist:"
ls -la "$dist"
