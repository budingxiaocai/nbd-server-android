#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
IMG="${ROOT}/test.img"

dd if=/dev/zero of="${IMG}" bs=1M count=8 status=none
printf 'ANDROID-NBD-TEST\n' | dd of="${IMG}" conv=notrunc status=none

echo "Build host binary with: make"
echo "Then in one shell: ./nbd-server-android -v 10809 ${IMG}"
echo "And in another shell use an NBD client against 127.0.0.1:10809."
