#!/usr/bin/env bash
#
# build-docker.sh - Build the hydra_stream extension for several PHP versions
# using the official php:<ver>-cli Docker images, then run the .phpt test
# suite for each. Resulting .so files are copied to ./dist/.
#
# Usage:
#   ./build-docker.sh                # builds 8.0 and 8.4 (default)
#   ./build-docker.sh 8.1 8.2 8.3    # builds the given versions
#
set -euo pipefail

EXT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$EXT_DIR/.." && pwd)"

VERSIONS=("$@")
if [ ${#VERSIONS[@]} -eq 0 ]; then
    VERSIONS=(8.0 8.4)
fi

mkdir -p "$EXT_DIR/dist"

for ver in "${VERSIONS[@]}"; do
    image="php:${ver}-cli"
    echo "========================================================"
    echo "  Building hydra_stream for PHP ${ver}  (${image})"
    echo "========================================================"

    docker run --rm \
        -v "$REPO_ROOT":/src \
        -e PHP_MAJOR_MINOR="$ver" \
        "$image" \
        bash -euo pipefail -c '
            apt-get update -qq
            apt-get install -y -qq $PHPIZE_DEPS >/dev/null

            # Build in a throwaway copy so the mounted repo stays clean.
            mkdir -p /work/php-ext
            cp /src/hydra_stream.h /work/hydra_stream.h
            cp -r /src/php-ext/. /work/php-ext/
            cd /work/php-ext
            rm -rf dist

            phpize
            ./configure --enable-hydra-stream
            make -j"$(nproc)"

            echo "---- running test suite ----"
            NO_INTERACTION=1 REPORT_EXIT_STATUS=1 TEST_PHP_ARGS="-q" \
                make test || { echo "TESTS FAILED"; exit 1; }

            cp modules/hydra_stream.so "/src/php-ext/dist/hydra_stream-php${PHP_MAJOR_MINOR}.so"
            echo "---- module info ----"
            php -d extension="$(pwd)/modules/hydra_stream.so" --re hydra_stream || true
        '

    echo ">> dist/hydra_stream-php${ver}.so"
done

echo
echo "Done. Built modules:"
ls -1 "$EXT_DIR/dist/"
