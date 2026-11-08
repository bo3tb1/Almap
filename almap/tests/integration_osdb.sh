#!/usr/bin/env bash
# tests/integration_osdb.sh - Step 26 integration test for the external
# OS signature database (--osdb).
# Loopback only: starts a listener on 127.0.0.1:12355, writes a small
# wildcard os-signatures.db, and checks the text and JSON output, the
# default ~/.almap/os-signatures.db path via a temporary HOME, explicit
# --osdb error handling, and the nmap-os-db importer on a synthetic
# input.
# Skips with a clear message if not root and CAP_NET_RAW is unavailable.
# Use only on networks you own or have permission to scan; this test
# only uses loopback.
set -u

cd "$(dirname "$0")/.." || exit 1

HOST=127.0.0.1
PORT=12355
CLOSED_PORT=12356

# Privilege check: probe whether a raw socket can be created here.
# This mirrors almap_syn_can_raw() (socket(AF_INET, SOCK_RAW, TCP)).
if command -v python3 >/dev/null 2>&1; then
    if ! python3 -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP); s.close()' >/dev/null 2>&1; then
        echo "skipping OS DB integration test: not root and CAP_NET_RAW is unavailable"
        exit 0
    fi
elif [ "$(id -u)" -ne 0 ]; then
    echo "skipping OS DB integration test: not root and CAP_NET_RAW is unavailable"
    exit 0
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "error: need python3 for the listener and JSON checks" >&2
    exit 1
fi

if [ ! -x ./almap ]; then
    echo "building ./almap ..." >&2
    goose build almap.goose --cc gcc || exit 1
fi
if [ ! -x ./almap ]; then
    echo "error: ./almap not found after build" >&2
    exit 1
fi

# If almap itself reports missing privileges, treat it as a skip.
pre_output=$(./almap -t "$HOST" -p "$PORT" --scan syn --os --timeout 1000 2>&1 || true)
case "$pre_output" in
    *"error: --os requires --scan syn and root or CAP_NET_RAW"*)
        echo "skipping OS DB integration test: not root and CAP_NET_RAW is unavailable (almap check)"
        exit 0
        ;;
esac

TMPDIR_OSDB=$(mktemp -d "${TMPDIR:-/tmp}/almap-osdb.XXXXXX") || exit 1
LISTENER_PID=""
cleanup() {
    if [ -n "$LISTENER_PID" ]; then
        kill "$LISTENER_PID" 2>/dev/null || true
        wait "$LISTENER_PID" 2>/dev/null || true
        LISTENER_PID=""
    fi
    rm -rf "$TMPDIR_OSDB"
}
trap cleanup EXIT

DB="$TMPDIR_OSDB/os-signatures.db"
cat >"$DB" <<'EOF'
# Dummy DB used by tests/integration_osdb.sh
TestOS|1|255|0|
EOF

echo "starting python3 listener on $HOST:$PORT" >&2
python3 -c '
import socket, sys, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1])))
s.listen(5)
time.sleep(30)
s.close()
' "$PORT" >/dev/null 2>&1 &
LISTENER_PID=$!

sleep 1

# Text mode: the explicit DB row must win over the hardcoded fallback.
echo "running ./almap ... --scan syn --os --osdb <dummy>" >&2
output=$(./almap -t "$HOST" -p "$PORT,$CLOSED_PORT" --scan syn --os --osdb "$DB" --timeout 1000)
status=$?
echo "$output"
if [ "$status" -ne 0 ]; then
    echo "integration test FAILED: text --os --osdb exited $status" >&2
    exit 1
fi
case "$output" in
    *"${HOST}:${PORT} open os=\"TestOS\""*)
        ;;
    *)
        echo "integration test FAILED: explicit DB did not produce os=TestOS" >&2
        exit 1
        ;;
esac
case "$output" in
    *"${HOST}:${CLOSED_PORT} closed os=\"TestOS\""*)
        ;;
    *)
        echo "integration test FAILED: closed row should carry the host-level DB label" >&2
        exit 1
        ;;
esac

# A host with no SYN+ACK at all must stay unknown even with a DB loaded:
# the wildcard row requires a positive TTL, and no fingerprint exists.
echo "running ./almap ... --scan syn --os --osdb <dummy> (closed only)" >&2
closed_output=$(./almap -t "$HOST" -p "$CLOSED_PORT" --scan syn --os --osdb "$DB" --timeout 1000)
closed_status=$?
echo "$closed_output"
if [ "$closed_status" -ne 0 ]; then
    echo "integration test FAILED: closed-only --os --osdb exited $closed_status" >&2
    exit 1
fi
case "$closed_output" in
    *"${HOST}:${CLOSED_PORT} closed os=\"unknown\""*)
        ;;
    *)
        echo "integration test FAILED: closed-only host should stay os=unknown with a DB" >&2
        exit 1
        ;;
esac

# JSON mode: the open row carries the DB name; both rows share the
# host-level classification.
echo "running ./almap ... --scan syn --os --osdb <dummy> --json" >&2
json_output=$(./almap -t "$HOST" -p "$PORT,$CLOSED_PORT" --scan syn --os --osdb "$DB" --json --timeout 1000)
json_status=$?
echo "$json_output"
if [ "$json_status" -ne 0 ]; then
    echo "integration test FAILED: JSON --os --osdb exited $json_status" >&2
    exit 1
fi
printf '%s\n' "$json_output" | python3 -c '
import json, sys
data = json.load(sys.stdin)
assert isinstance(data, list) and data, "empty JSON array"
open_rows = [r for r in data if r["state"] == "open"]
assert open_rows and open_rows[0]["os"] == "TestOS", data
closed_rows = [r for r in data if r["state"] == "closed"]
assert closed_rows and closed_rows[0]["os"] == "TestOS", data
' || {
    echo "integration test FAILED: JSON --os --osdb shape check" >&2
    exit 1
}

# Default path: HOME/.almap/os-signatures.db is used when --osdb is absent.
FAKE_HOME="$TMPDIR_OSDB/home"
mkdir -p "$FAKE_HOME/.almap"
cat >"$FAKE_HOME/.almap/os-signatures.db" <<'EOF'
HomeOS|1|255|0|
EOF
echo "running ./almap ... --scan syn --os with HOME default DB" >&2
home_output=$(HOME="$FAKE_HOME" ./almap -t "$HOST" -p "$PORT" --scan syn --os --timeout 1000)
home_status=$?
echo "$home_output"
if [ "$home_status" -ne 0 ]; then
    echo "integration test FAILED: default-OSDB scan exited $home_status" >&2
    exit 1
fi
case "$home_output" in
    *"${HOST}:${PORT} open os=\"HomeOS\""*)
        ;;
    *)
        echo "integration test FAILED: default HOME DB did not produce os=HomeOS" >&2
        exit 1
        ;;
esac

# CLI errors: --osdb needs --os (exit 2), and an explicit missing file
# is a hard error (exit 1) instead of quietly falling back.
echo "running --osdb without --os (expect exit 2)" >&2
set +u
err_output=$(./almap -t "$HOST" -p "$PORT" --scan syn --osdb "$DB" 2>&1)
err_status=$?
set -u
echo "$err_output"
if [ "$err_status" -ne 2 ]; then
    echo "integration test FAILED: --osdb without --os exited $err_status, expected 2" >&2
    exit 1
fi
case "$err_output" in
    *"error: --osdb requires --os"*)
        ;;
    *)
        echo "integration test FAILED: --osdb --os validation message missing" >&2
        exit 1
        ;;
esac

echo "running --os --osdb <missing> (expect exit 1)" >&2
set +u
missing_output=$(./almap -t "$HOST" -p "$PORT" --scan syn --os --osdb "$TMPDIR_OSDB/does-not-exist.db" --timeout 500 2>&1)
missing_status=$?
set -u
echo "$missing_output"
if [ "$missing_status" -ne 1 ]; then
    echo "integration test FAILED: missing --osdb exited $missing_status, expected 1" >&2
    exit 1
fi
case "$missing_output" in
    *"error: cannot read --osdb file"*)
        ;;
    *)
        echo "integration test FAILED: missing --osdb error message missing" >&2
        exit 1
        ;;
esac

# Importer smoke test with a synthetic nmap-os-db: one Linux, one
# Windows, and one embedded fingerprint.  Hex TTL/window values must be
# converted to decimal, options inferred, and the multi-value W1 turned
# into the window wildcard 0.
NMAP_DB="$TMPDIR_OSDB/nmap-os-db"
cat >"$NMAP_DB" <<'EOF'
Fingerprint Synthetic Linux
Class Linux | Linux | 2.6.X | general purpose
OPS(O1=M5B4NNSNNT11NW4)
WIN(W1=16D0)
T1(R=Y%DF=N%T=3B-45%TG=40%S=O%A=S+%F=AS%RD=0%Q=)

Fingerprint Synthetic Windows
Class Microsoft | Windows | 10 | general purpose
OPS(O1=M5B4NNS)
WIN(W1=2000)
T1(R=Y%DF=Y%T=7B-85%TG=80%S=O%A=S+%F=AS%RD=0%Q=)

Fingerprint Synthetic Device
Class Foo | embedded || router
OPS(O1=)
WIN(W1=0|16D0)
T1(R=Y%DF=N%T=3B-45%TG=FF%S=O%A=S+%F=AS%RD=0%Q=)

Fingerprint Synthetic Corrupt TTL
Class Bar | embedded || switch
OPS(O1=)
WIN(W1=16D0)
T1(R=Y%DF=N%T=FA-104%TG=FF%S=O%A=S+%F=AS%RD=0%Q=)
EOF
IMPORTED="$TMPDIR_OSDB/imported.db"
echo "running tools/import_nmap_os.py on synthetic nmap-os-db" >&2
python3 tools/import_nmap_os.py "$NMAP_DB" -o "$IMPORTED" --max 4 --quiet || {
    echo "integration test FAILED: importer exited nonzero" >&2
    exit 1
}
for expected in \
    'Linux|59|69|5840|MSS,SACK,TIMESTAMPS' \
    'Windows|123|133|8192|MSS,SACK' \
    'Network Device|59|69|0|' \
    'Network Device|250|255|5840|'
do
    if ! grep -qxF "$expected" "$IMPORTED"; then
        echo "integration test FAILED: importer output missing '$expected'" >&2
        cat "$IMPORTED" >&2
        exit 1
    fi
done
imported_count=$(grep -vc '^#' "$IMPORTED")
if [ "$imported_count" -ne 4 ]; then
    echo "integration test FAILED: importer emitted $imported_count rows, expected 4" >&2
    exit 1
fi

# The imported file must be directly usable by --osdb.
echo "running ./almap ... --os --osdb <imported>" >&2
imported_output=$(./almap -t "$HOST" -p "$PORT" --scan syn --os --osdb "$IMPORTED" --timeout 1000)
imported_status=$?
echo "$imported_output"
if [ "$imported_status" -ne 0 ]; then
    echo "integration test FAILED: imported --osdb scan exited $imported_status" >&2
    exit 1
fi
case "$imported_output" in
    *"${HOST}:${PORT} open os=\"Linux\""*|*"${HOST}:${PORT} open os=\"Windows\""*|*"${HOST}:${PORT} open os=\"Network Device\""*)
        ;;
    *)
        echo "integration test FAILED: imported DB did not match the open row" >&2
        exit 1
        ;;
esac

echo "integration test passed: --osdb explicit/default paths, JSON/text, CLI errors, and importer verified"
