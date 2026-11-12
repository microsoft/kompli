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

final_version="$(jq -er '
    [.tools[] | select(.name == "cmake" and .os == "linux" and .arch == "amd64")]
    | if length == 1 then .[0].version else error("Expected one Linux amd64 CMake tool") end
' "$KOMPLI_VCPKG_ROOT/scripts/vcpkg-tools.json")"

if ninja="$("$KOMPLI_VCPKG_ROOT/vcpkg" fetch ninja --x-stderr-status)"; then
    if [[ ! -x "$ninja" ]]; then
        echo "vcpkg did not return an executable Ninja tool: $ninja" >&2
        exit 1
    fi
else
    status="$?"
    printf '%s\n' "$ninja" >&2
    exit "$status"
fi
export PATH="$(dirname "$ninja"):$PATH"

install_arguments=(
    "--x-asset-sources=x-script,bash /usr/local/bin/download-vcpkg-asset.sh {url} {dst}"
    --triplet=x64-linux
    --x-manifest-root="$manifest_root"
    --x-install-root="$install_root"
)
VCPKG_FORCE_SYSTEM_BINARIES=1 "$KOMPLI_VCPKG_ROOT/vcpkg" install "${install_arguments[@]}"

bash "$(dirname "${BASH_SOURCE[0]}")/install-container-cmake" \
    "v$final_version" /usr/local "$install_root/x64-linux"

# Refresh package ABIs and binary caches with the final CMake toolchain.
"$KOMPLI_VCPKG_ROOT/vcpkg" install "${install_arguments[@]}"
cp "$install_root/vcpkg/vcpkg-lock.json" "$KOMPLI_VCPKG_ROOT/vcpkg-lock.json"
