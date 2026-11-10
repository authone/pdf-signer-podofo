#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Installs what PoDoFo 1.1.2 needs to build, on Debian/Ubuntu/Kali.
# This is the only step that needs root.

set -euo pipefail

PACKAGES=(
    build-essential
    pkg-config
    libssl-dev
    libfreetype-dev
    libfontconfig-dev
    libxml2-dev
    # RFC 3161 timestamp client
    libcurl4-openssl-dev
    zlib1g-dev
    # Optional in PoDoFo, but cheap and avoids surprises with image-bearing PDFs
    libjpeg-dev
    libpng-dev
    libtiff-dev
    # Not needed to build, but pdfsig is the quickest way to check the result
    poppler-utils
)

# cmake >= 3.23 is required. Debian-family repos sometimes lag, in which case
# `pipx install cmake` gives a current one without root.
if ! command -v cmake >/dev/null 2>&1; then
    PACKAGES+=(cmake)
fi

echo "About to install:"
printf '  %s\n' "${PACKAGES[@]}"
echo

if [ "$(id -u)" -eq 0 ]; then
    apt-get update
    apt-get install -y "${PACKAGES[@]}"
else
    sudo apt-get update
    sudo apt-get install -y "${PACKAGES[@]}"
fi

echo
echo "Done. Next: scripts/build-podofo.sh"
