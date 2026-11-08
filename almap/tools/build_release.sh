#!/usr/bin/env bash
# tools/build_release.sh - build ALmap and package a release tarball.
#
# Builds the scanner and the sample AlScript plugin, then stages the
# binary, README, VERSION, the shipped service signature DB, and an
# optional OS signature DB in dist/ before creating a .tar.gz.
#
# The OS DB is taken from --osdb (already prepared), --nmap-os-db
# (imported with tools/import_nmap_os.py), an os-signatures.db in the
# repository root, or a standard Nmap installation path. If none is
# available the release is still packaged, but without an OS DB.
#
# Examples:
#   tools/build_release.sh
#   tools/build_release.sh --nmap-os-db /usr/share/nmap/nmap-os-db
#   tools/build_release.sh --osdb "$HOME/.almap/os-signatures.db"
#
# Authorized use only. See README.md.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

DIST_DIR="$ROOT_DIR/dist"
OSDB_PATH=""
OSDB_IMPORT=""
MAX_OS=256
KEEP_STAGE=0

usage() {
    cat <<'EOF'
Usage: tools/build_release.sh [options]

Build ALmap and package dist/almap-<version>-linux-<arch>.tar.gz.

Options:
  --osdb PATH          Include an already-prepared os-signatures.db.
  --nmap-os-db PATH    Import PATH with tools/import_nmap_os.py and include it.
  --max-os N           Maximum imported OS rows, 1..256 (default: 256).
  --keep-stage         Keep the unpacked staging directory in dist/.
  -h, --help           Show this help and exit.

The package contains: almap, signatures.db, os-signatures.db, plugins/, sample_banner.so, README.md,
VERSION.
EOF
}

log() {
    echo "[build_release] $*" >&2
}

die() {
    echo "[build_release] error: $*" >&2
    exit 1
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --osdb)
            [ "$#" -ge 2 ] || die "--osdb requires a path"
            OSDB_PATH="$2"
            shift 2
            ;;
        --nmap-os-db)
            [ "$#" -ge 2 ] || die "--nmap-os-db requires a path"
            OSDB_IMPORT="$2"
            shift 2
            ;;
        --max-os)
            [ "$#" -ge 2 ] || die "--max-os requires a number"
            MAX_OS="$2"
            shift 2
            ;;
        --keep-stage)
            KEEP_STAGE=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "unknown option '$1' (use --help)"
            ;;
    esac
done

[ -n "$OSDB_PATH" ] && [ -n "$OSDB_IMPORT" ] &&
    die "--osdb and --nmap-os-db are mutually exclusive"
case "$MAX_OS" in
    ''|*[!0-9]*) die "--max-os must be an integer in 1..256" ;;
esac
[ "$MAX_OS" -ge 1 ] && [ "$MAX_OS" -le 256 ] ||
    die "--max-os must be an integer in 1..256"

[ -f VERSION ] || die "VERSION not found in $ROOT_DIR"
VERSION="$(tr -d '[:space:]' < VERSION)"
[ -n "$VERSION" ] || die "VERSION is empty"
printf '%s\n' "$VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' ||
    die "VERSION must look like 4.0.0 (got '$VERSION')"
[ -f almap.goose ] || die "almap.goose not found"
[ -f signatures.db ] || die "signatures.db not found"
[ -f plugins/sample_banner.c ] || die "plugins/sample_banner.c not found"
command -v goose >/dev/null 2>&1 || die "goose not found in PATH"
command -v gcc >/dev/null 2>&1 || die "gcc not found in PATH"
command -v tar >/dev/null 2>&1 || die "tar not found in PATH"

# If the caller did not export GOOSE_STDLIB, try the common local
# toolchain layout. goose may still discover it on its own.
if [ -z "${GOOSE_STDLIB:-}" ]; then
    for candidate in "$HOME"/Downloads/goose-*/stdlib; do
        if [ -d "$candidate" ]; then
            GOOSE_STDLIB="$candidate"
            export GOOSE_STDLIB
            log "using GOOSE_STDLIB=$GOOSE_STDLIB"
            break
        fi
    done
fi

ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64) ARCH="x86_64" ;;
    aarch64|arm64) ARCH="aarch64" ;;
esac
PLATFORM="linux-$ARCH"
PKG_NAME="almap-$VERSION-$PLATFORM"
STAGE="$DIST_DIR/$PKG_NAME"
ARCHIVE="$DIST_DIR/$PKG_NAME.tar.gz"

log "ALmap $VERSION ($PLATFORM)"
log "checking Goose sources"
goose check almap.goose

log "building ./almap"
goose build almap.goose --cc gcc -o almap
[ -x ./almap ] || die "goose build did not produce ./almap"

HELP_LINE="$(./almap --help | head -n 1 || true)"
case "$HELP_LINE" in
    "ALmap v$VERSION"*) ;;
    *) die "built binary reports '$HELP_LINE', expected 'ALmap v$VERSION'" ;;
esac

rm -rf "$STAGE" "$ARCHIVE" "$ARCHIVE.sha256"
mkdir -p "$STAGE"

log "staging binary, service DB, README, and VERSION"
install -m 0755 almap "$STAGE/almap"
install -m 0644 README.md "$STAGE/README.md"
install -m 0644 VERSION "$STAGE/VERSION"
install -m 0644 signatures.db "$STAGE/signatures.db"
mkdir -p "$STAGE/plugins"
cp -r plugins/. "$STAGE/plugins/"

log "building sample AlScript plugin"
gcc -std=c99 -Wall -Wextra -shared -fPIC \
    -o "$STAGE/sample_banner.so" plugins/sample_banner.c

OSDB_SOURCE=""
if [ -n "$OSDB_PATH" ]; then
    [ -f "$OSDB_PATH" ] || die "OS DB not found: $OSDB_PATH"
    install -m 0644 "$OSDB_PATH" "$STAGE/os-signatures.db"
    OSDB_SOURCE="prepared: $OSDB_PATH"
elif [ -n "$OSDB_IMPORT" ]; then
    [ -f "$OSDB_IMPORT" ] || die "Nmap OS DB not found: $OSDB_IMPORT"
    command -v python3 >/dev/null 2>&1 ||
        die "python3 is required to import --nmap-os-db"
    log "importing OS signatures from $OSDB_IMPORT"
    python3 tools/import_nmap_os.py "$OSDB_IMPORT" --max "$MAX_OS" \
        -o "$STAGE/os-signatures.db"
    OSDB_SOURCE="imported: $OSDB_IMPORT"
elif [ -f "$ROOT_DIR/os-signatures.db" ]; then
    install -m 0644 "$ROOT_DIR/os-signatures.db" "$STAGE/os-signatures.db"
    OSDB_SOURCE="repository: $ROOT_DIR/os-signatures.db"
else
    AUTO_OSDB=""
    for candidate in "${NMAP_OS_DB:-}" \
        /usr/share/nmap/nmap-os-db \
        /usr/local/share/nmap/nmap-os-db \
        /opt/homebrew/share/nmap/nmap-os-db; do
        if [ -n "$candidate" ] && [ -f "$candidate" ]; then
            AUTO_OSDB="$candidate"
            break
        fi
    done
    if [ -z "$AUTO_OSDB" ] && command -v nmap >/dev/null 2>&1; then
        NMAP_DATADIR="$(nmap --datadir 2>/dev/null || true)"
        if [ -n "$NMAP_DATADIR" ] && [ -f "$NMAP_DATADIR/nmap-os-db" ]; then
            AUTO_OSDB="$NMAP_DATADIR/nmap-os-db"
        fi
    fi
    if [ -n "$AUTO_OSDB" ]; then
        command -v python3 >/dev/null 2>&1 ||
            die "python3 is required to import $AUTO_OSDB"
        log "importing OS signatures from $AUTO_OSDB"
        python3 tools/import_nmap_os.py "$AUTO_OSDB" --max "$MAX_OS" \
            -o "$STAGE/os-signatures.db"
        OSDB_SOURCE="imported: $AUTO_OSDB"
    fi
fi

if [ -n "$OSDB_SOURCE" ]; then
    [ -s "$STAGE/os-signatures.db" ] || die "OS signature DB is empty"
    if ! grep -q -v -e '^[[:space:]]*#' -e '^[[:space:]]*$' \
        "$STAGE/os-signatures.db"; then
        die "OS signature DB has no signature rows"
    fi
    log "OS DB: $OSDB_SOURCE"
else
    log "warning: no OS signature DB found, generating fallback os-signatures.db"
    log "         pass --osdb or --nmap-os-db to override"
    cat > "$STAGE/os-signatures.db" <<'OSDBEOF'
# os-signatures.db - ALmap V3.0 fallback OS signature database
# Format: OS_NAME|MIN_TTL|MAX_TTL|WINDOW_SIZE|TCP_OPTIONS_FLAG
# WINDOW_SIZE 0 = any window; TCP_OPTIONS_FLAG empty = any options.
Linux 6.x|55|64|0|MSS,SACK,TIMESTAMPS
Linux 5.x|55|64|0|MSS,SACK,TIMESTAMPS
Windows 10/11|110|128|64240|MSS,SACK,TIMESTAMPS
Windows Server|110|128|0|MSS,SACK
Network Device|250|255|0|
Cisco IOS|250|255|0|MSS
OSDBEOF
    OSDB_SOURCE="fallback: generated for V3.0 release"
fi

mkdir -p dist
mkdir -p "$DIST_DIR"
log "packaging $ARCHIVE"
tar -C "$DIST_DIR" -czf "$ARCHIVE" "$PKG_NAME"
[ -s "$ARCHIVE" ] || die "archive was not created"

if command -v sha256sum >/dev/null 2>&1; then
    (cd "$DIST_DIR" && sha256sum "$PKG_NAME.tar.gz" >"$PKG_NAME.tar.gz.sha256")
fi

log "archive contents:"
tar -tzf "$ARCHIVE" | sed 's/^/  /' >&2

if [ "$KEEP_STAGE" -eq 0 ]; then
    rm -rf "$STAGE"
fi

log "done: $ARCHIVE"
