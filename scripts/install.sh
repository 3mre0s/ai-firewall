#!/bin/sh

set -eu

repo="3mre0s/ai-firewall"
version="${ANONMYZ_VERSION:-latest}"
install_dir="${ANONMYZ_INSTALL_DIR:-${HOME}/.local/bin}"

case "$(uname -s)" in
  Linux) os="linux" ;;
  Darwin) os="darwin" ;;
  *) echo "anonmyz: unsupported operating system: $(uname -s)" >&2; exit 1 ;;
esac

case "$(uname -m)" in
  x86_64|amd64) arch="amd64" ;;
  arm64|aarch64) arch="arm64" ;;
  *) echo "anonmyz: unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

archive="anonmyz-${os}-${arch}.tar.gz"
if [ "$version" = "latest" ]; then
  base_url="https://github.com/${repo}/releases/latest/download"
else
  case "$version" in
    v*) tag="$version" ;;
    *) tag="v${version}" ;;
  esac
  base_url="https://github.com/${repo}/releases/download/${tag}"
fi

if command -v curl >/dev/null 2>&1; then
  download() { curl --fail --silent --show-error --location "$1" --output "$2"; }
elif command -v wget >/dev/null 2>&1; then
  download() { wget --quiet "$1" --output-document "$2"; }
else
  echo "anonmyz: curl or wget is required" >&2
  exit 1
fi

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -f "${tmp_dir}/${archive}" "${tmp_dir}/checksums.txt" "${tmp_dir}/anonmyz"
  rmdir "$tmp_dir" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

echo "Downloading ${archive}..."
download "${base_url}/${archive}" "${tmp_dir}/${archive}"
download "${base_url}/checksums.txt" "${tmp_dir}/checksums.txt"

expected="$(awk -v name="$archive" '$2 == name || $2 == "*" name { print $1; exit }' "${tmp_dir}/checksums.txt")"
if [ -z "$expected" ]; then
  echo "anonmyz: ${archive} is missing from checksums.txt" >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "${tmp_dir}/${archive}" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  actual="$(shasum -a 256 "${tmp_dir}/${archive}" | awk '{print $1}')"
else
  echo "anonmyz: sha256sum or shasum is required to verify the download" >&2
  exit 1
fi

if [ "$actual" != "$expected" ]; then
  echo "anonmyz: checksum verification failed" >&2
  exit 1
fi

tar -xzf "${tmp_dir}/${archive}" -C "$tmp_dir" anonmyz
mkdir -p "$install_dir"
install -m 0755 "${tmp_dir}/anonmyz" "${install_dir}/anonmyz"

echo "Installed anonmyz to ${install_dir}/anonmyz (SHA-256 verified)."
case ":${PATH}:" in
  *":${install_dir}:"*) echo "Run: anonmyz demo --non-interactive" ;;
  *) echo "Add ${install_dir} to PATH, or run: ${install_dir}/anonmyz demo --non-interactive" ;;
esac
