#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
    cat >&2 <<EOF
Usage: ${0##*/} <version> <prefix> [openssl-root]

  version       CMake release to build from source, with an optional leading v
                (for example, v3.30.1 or 3.30.1).
  prefix        Installation directory; tools are installed under <prefix>/bin
                (for example, /usr/local).
  openssl-root  Optional OpenSSL installation directory containing include/,
                lib/libssl.a, lib/libcrypto.a, and lib/pkgconfig/.
                If omitted, CMake uses system OpenSSL discovery.
EOF
    exit 1
fi

version="${1#v}"
prefix="$2"
openssl_root="${3:-}"
jobs="$(nproc)"

build_root="$(mktemp -d)"
trap 'rm -rf -- "$build_root"' EXIT

git clone --depth 1 --recursive --branch "v$version" \
    https://github.com/Kitware/CMake "$build_root/source"
cd "$build_root/source"

cmake_options=()
if [[ -n "$openssl_root" ]]; then
    cmake_options+=("-DOPENSSL_ROOT_DIR=$openssl_root" -DOPENSSL_USE_STATIC_LIBS=TRUE)
    export PKG_CONFIG_PATH="$openssl_root/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
fi
./bootstrap --prefix="$prefix" --parallel="$jobs" -- "${cmake_options[@]}"

if [[ -n "$openssl_root" ]]; then
    for entry in \
        "OPENSSL_INCLUDE_DIR:PATH=$openssl_root/include" \
        "OPENSSL_SSL_LIBRARY:FILEPATH=$openssl_root/lib/libssl.a" \
        "OPENSSL_CRYPTO_LIBRARY:FILEPATH=$openssl_root/lib/libcrypto.a"; do
        if ! grep -Fx "$entry" CMakeCache.txt; then
            echo "CMake did not select the static vcpkg OpenSSL installation: $entry" >&2
            exit 1
        fi
    done
fi

make -j"$jobs"
make install
for executable in cmake ctest cpack; do
    actual_version="$("$prefix/bin/$executable" --version)"
    if ! printf '%s\n' "$actual_version" | grep -Fx "$executable version $version"; then
        echo "$executable does not match the requested CMake version ($version)" >&2
        exit 1
    fi
done
