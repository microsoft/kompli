#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -euo pipefail

if [[ $# -ne 1 ]]; then
    cat >&2 <<EOF
Usage: ${0##*/} <manifest-root>

  manifest-root  Directory containing the project's vcpkg.json manifest
                 (for example, src).

Required environment variables:
  KOMPLI_VCPKG_ROOT           vcpkg source tree to bootstrap and use.
  VCPKG_DOWNLOADS             Directory for downloaded sources and helper tools.
  VCPKG_DEFAULT_BINARY_CACHE  Directory for cached binary packages.
  X_VCPKG_REGISTRIES_CACHE    Directory for cached vcpkg registries.
EOF
    exit 1
fi

manifest_root="$1"
install_root="$(mktemp -d)"
trap 'rm -rf -- "$install_root"' EXIT

mkdir -p "$VCPKG_DOWNLOADS" "$VCPKG_DEFAULT_BINARY_CACHE" "$X_VCPKG_REGISTRIES_CACHE"
bash "$KOMPLI_VCPKG_ROOT/bootstrap-vcpkg.sh" -disableMetrics
"$KOMPLI_VCPKG_ROOT/vcpkg" install \
    "--x-asset-sources=x-script,bash /usr/local/bin/download-vcpkg-asset.sh {url} {dst}" \
    --x-manifest-root="$manifest_root" \
    --x-install-root="$install_root"
cp "$install_root/vcpkg/vcpkg-lock.json" "$KOMPLI_VCPKG_ROOT/vcpkg-lock.json"
