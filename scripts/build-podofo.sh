#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Fetches and builds PoDoFo into third_party/prefix, so this example does not
# depend on whatever PoDoFo version the distribution happens to ship.
#
# This matters: Debian-family repos still carry PoDoFo 0.9.8, whose signing API
# is completely different and no longer documented upstream.

set -euo pipefail

PODOFO_TAG="${PODOFO_TAG:-1.1.2}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/third_party/podofo"
BUILD="$ROOT/third_party/podofo-build"
PREFIX="$ROOT/third_party/prefix"

if ! command -v cmake >/dev/null 2>&1; then
    echo "cmake not found. Run scripts/install-deps.sh, or 'pipx install cmake'." >&2
    exit 1
fi

echo "==> PoDoFo $PODOFO_TAG -> $PREFIX"

if [ ! -d "$SRC/.git" ]; then
    mkdir -p "$(dirname "$SRC")"
    git clone --depth 1 --branch "$PODOFO_TAG" https://github.com/podofo/podofo.git "$SRC"
else
    git -C "$SRC" fetch --depth 1 origin "refs/tags/$PODOFO_TAG:refs/tags/$PODOFO_TAG" || true
    git -C "$SRC" checkout -q "$PODOFO_TAG"
fi

# Library only: the tools are explicitly unmaintained upstream and the tests
# pull in extra dependencies we do not need here.
cmake -S "$SRC" -B "$BUILD" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$PREFIX" \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DPODOFO_BUILD_LIB_ONLY=TRUE \
    -DPODOFO_BUILD_TEST=FALSE \
    -DPODOFO_BUILD_EXAMPLES=FALSE

cmake --build "$BUILD" --parallel "$(nproc 2>/dev/null || echo 4)"
cmake --install "$BUILD"

echo
echo "PoDoFo installed into $PREFIX"
echo "Next: cmake -S . -B build && cmake --build build"
