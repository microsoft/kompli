#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -euo pipefail

if [[ $# -ne 2 ]]; then
    cat >&2 <<EOF
Usage: ${0##*/} <url> <destination>

  url          Original Lua archive URL (https://www.lua.org/ftp/lua-<version>.tar.gz).
               The archive is downloaded from the MacPorts mirror.
  destination  Local output file path for the downloaded archive.
EOF
    exit 1
fi

url="$1"
destination="$2"

# vcpkg checks the downloaded file against the port's SHA512 before using it.
if [[ "$url" =~ ^https://www\.lua\.org/ftp/(lua-[0-9.]+\.tar\.gz)$ ]]; then
    curl --fail --location --retry 3 --connect-timeout 15 --max-time 120 \
        "https://distfiles.macports.org/lua/${BASH_REMATCH[1]}" \
        --output "$destination"
else
    # A cache miss lets vcpkg use the original URL.
    exit 1
fi
