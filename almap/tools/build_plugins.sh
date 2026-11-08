#!/usr/bin/env bash
# tools/build_plugins.sh - build all AlScript C plugins in plugins/.
#
# Compiles every plugins/*.c into plugins/<name>.so with
#   gcc -std=c99 -Wall -Wextra -shared -fPIC
# Run:
#   bash tools/build_plugins.sh
#   ./almap -t 127.0.0.1 -p 80 --scan connect --script ./plugins/http_title.so
#
# Authorized use only. See README.md.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

if ! command -v gcc >/dev/null 2>&1; then
    echo "[build_plugins] error: gcc not found in PATH" >&2
    exit 1
fi

# shellcheck disable=SC2086
shopt -s nullglob
sources=(plugins/*.c)
if [ ${#sources[@]} -eq 0 ]; then
    echo "[build_plugins] error: no plugins/*.c found" >&2
    exit 1
fi

for src in "${sources[@]}"; do
    base="$(basename "$src" .c)"
    out="plugins/${base}.so"
    echo "[build_plugins] gcc -std=c99 -Wall -Wextra -shared -fPIC -o $out $src" >&2
    gcc -std=c99 -Wall -Wextra -shared -fPIC -o "$out" "$src"
    echo "[build_plugins] built $out" >&2
done

echo "[build_plugins] done: ${#sources[@]} plugin(s) built" >&2
