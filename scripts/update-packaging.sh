#!/usr/bin/env bash
# Fill the Homebrew formula and Scoop manifest with the real checksums and
# version of a published release.
#
# Usage: scripts/update-packaging.sh <version> <path-to-checksums.txt>
# Run after a release: download checksums.txt from the GitHub release,
# then run this script and commit the result (or push it to your
# homebrew-ai-firewall / scoop-bucket tap repos).

set -euo pipefail

version="${1:?usage: update-packaging.sh <version> <checksums.txt>}"
checksums="${2:?usage: update-packaging.sh <version> <checksums.txt>}"
version="${version#v}"
root="$(cd "$(dirname "$0")/.." && pwd)"

sha() {
  awk -v f="$1" '$2 == f { print $1 }' "$checksums"
}

darwin_arm64=$(sha "ai-firewall-darwin-arm64.tar.gz")
darwin_amd64=$(sha "ai-firewall-darwin-amd64.tar.gz")
linux_arm64=$(sha "ai-firewall-linux-arm64.tar.gz")
linux_amd64=$(sha "ai-firewall-linux-amd64.tar.gz")
windows_amd64=$(sha "ai-firewall-windows-amd64.zip")

for name in darwin_arm64 darwin_amd64 linux_arm64 linux_amd64 windows_amd64; do
  if [ -z "${!name}" ]; then
    echo "error: checksum for $name not found in $checksums" >&2
    exit 1
  fi
done

formula="$root/packaging/homebrew/ai-firewall.rb"
sed -i \
  -e "s/version \"[^\"]*\"/version \"$version\"/" \
  -e "s/v[0-9][0-9.]*\/ai-firewall-darwin-arm64/v$version\/ai-firewall-darwin-arm64/" \
  -e "s/v[0-9][0-9.]*\/ai-firewall-darwin-amd64/v$version\/ai-firewall-darwin-amd64/" \
  -e "s/v[0-9][0-9.]*\/ai-firewall-linux-arm64/v$version\/ai-firewall-linux-arm64/" \
  -e "s/v[0-9][0-9.]*\/ai-firewall-linux-amd64/v$version\/ai-firewall-linux-amd64/" \
  -e "s/REPLACE_WITH_DARWIN_ARM64_SHA256/$darwin_arm64/" \
  -e "s/REPLACE_WITH_DARWIN_AMD64_SHA256/$darwin_amd64/" \
  -e "s/REPLACE_WITH_LINUX_ARM64_SHA256/$linux_arm64/" \
  -e "s/REPLACE_WITH_LINUX_AMD64_SHA256/$linux_amd64/" \
  "$formula"

manifest="$root/packaging/scoop/ai-firewall.json"
sed -i \
  -e "s/\"version\": \"[^\"]*\"/\"version\": \"$version\"/" \
  -e "s/v[0-9][0-9.]*\/ai-firewall-windows-amd64.zip\"/v$version\/ai-firewall-windows-amd64.zip\"/" \
  -e "s/REPLACE_WITH_WINDOWS_AMD64_SHA256/$windows_amd64/" \
  "$manifest"

echo "Updated $formula and $manifest for v$version"
