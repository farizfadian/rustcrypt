#!/usr/bin/env bash
# Turns the release archives of a tag into GoCrypt-style raw binaries.
#
# The Release workflow uploads one archive per target
# (rustcrypt-<version>-<target>.tar.gz / .zip). This script downloads those
# archives, verifies them against their .sha256 files, and extracts the CLI
# under a directly downloadable name:
#
#   rustcrypt-windows-amd64.exe   rustcrypt-linux-amd64   rustcrypt-darwin-amd64
#                                 rustcrypt-linux-arm64   rustcrypt-darwin-arm64
#
# plus a checksums.txt covering them. Nothing is rebuilt: the binaries are the
# ones CI already built and published.
#
# Usage: scripts/raw-release-assets.sh <tag> <out-dir>
# Needs: gh (authenticated; set GH_REPO outside a clone), tar, unzip, sha256sum.
set -euo pipefail

tag="${1:?usage: raw-release-assets.sh <tag> <out-dir>}"
out="${2:?usage: raw-release-assets.sh <tag> <out-dir>}"
version="${tag#v}"

mkdir -p "$out"
if [ -n "$(ls -A "$out")" ]; then
  echo "error: output directory '$out' is not empty" >&2
  exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

gh release download "$tag" --dir "$work" \
  --pattern "rustcrypt-${version}-*.tar.gz" \
  --pattern "rustcrypt-${version}-*.zip" \
  --pattern "rustcrypt-${version}-*.sha256"

count=0
for archive in "$work"/rustcrypt-"${version}"-*.tar.gz "$work"/rustcrypt-"${version}"-*.zip; do
  [ -e "$archive" ] || continue
  file="$(basename "$archive")"
  base="${file%.tar.gz}"
  base="${base%.zip}"
  target="${base#rustcrypt-"${version}"-}"

  # The archive must match the checksum published next to it.
  (cd "$work" && sha256sum --check --quiet "$base.sha256")

  case "$target" in
    x86_64-*) arch=amd64 ;;
    aarch64-*) arch=arm64 ;;
    i686-*) arch=386 ;;
    *) echo "error: unknown architecture in target '$target'" >&2; exit 1 ;;
  esac
  case "$target" in
    *-windows-*) os=windows; bin=rustcrypt.exe; ext=.exe ;;
    *-linux-*) os=linux; bin=rustcrypt; ext= ;;
    *-apple-darwin) os=darwin; bin=rustcrypt; ext= ;;
    *-freebsd) os=freebsd; bin=rustcrypt; ext= ;;
    *) echo "error: unknown operating system in target '$target'" >&2; exit 1 ;;
  esac

  extracted="$work/extracted/$target"
  mkdir -p "$extracted"
  case "$file" in
    *.zip) unzip -q "$archive" -d "$extracted" ;;
    *) tar -xzf "$archive" -C "$extracted" ;;
  esac

  src="$(find "$extracted" -type f -name "$bin" | head -n 1)"
  if [ -z "$src" ]; then
    echo "error: $file does not contain $bin" >&2
    exit 1
  fi
  cp "$src" "$out/rustcrypt-${os}-${arch}${ext}"
  count=$((count + 1))
done

if [ "$count" -eq 0 ]; then
  echo "error: release $tag has no rustcrypt-${version}-* archives" >&2
  exit 1
fi

# Same layout as `sha256sum` on Linux, whatever platform this runs on.
(
  cd "$out"
  for f in rustcrypt-*; do
    printf '%s  %s\n' "$(sha256sum "$f" | cut -d ' ' -f 1)" "$f"
  done > checksums.txt
)

echo "wrote $count binaries and checksums.txt to $out"
