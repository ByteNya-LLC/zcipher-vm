#!/usr/bin/env bash
#
# build-local.sh - Build the extension against a locally installed PHP dev
# toolchain (requires the matching php-dev / php-devel package so that
# `phpize` and `php-config` are present).
#
# Usage:
#   ./build-local.sh                          # uses phpize / php-config on PATH
#   PHP_CONFIG=php-config8.0 ./build-local.sh  # pick a specific version
#
set -euo pipefail

cd "$(dirname "$0")"

PHP_CONFIG="${PHP_CONFIG:-php-config}"
PHPIZE="${PHPIZE:-phpize}"

if ! command -v "$PHPIZE" >/dev/null 2>&1; then
    echo "error: '$PHPIZE' not found. Install the PHP development package" >&2
    echo "       (e.g. 'apt install php-dev' / 'dnf install php-devel')." >&2
    exit 1
fi

# Start from a clean tree.
[ -f Makefile ] && make distclean >/dev/null 2>&1 || true
"$PHPIZE" --clean >/dev/null 2>&1 || true

"$PHPIZE"
./configure --enable-hydra-stream --with-php-config="$PHP_CONFIG"
make -j"$(nproc 2>/dev/null || echo 2)"

echo
echo "Built: $(pwd)/modules/hydra_stream.so"
echo "Run the tests with:  make test"
echo "Load it with:        php -d extension=$(pwd)/modules/hydra_stream.so -m | grep hydra"
