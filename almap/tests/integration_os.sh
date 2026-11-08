#!/usr/bin/env bash
# tests/integration_os.sh - Step 19 integration test for minimal
# SYN/ACK OS fingerprinting (--os).
# Loopback only: starts a listener on 127.0.0.1:12345, runs a SYN scan
# with --os, and checks the text, JSON, table, and XML forms plus the
# invalid-mode error.
# Skips with a clear message if not root and CAP_NET_RAW is unavailable.
# Use only on networks you own or have permission to scan; this test
# only uses loopback.
set -u

cd "$(dirname "$0")/.." || exit 1

HOST=127.0.0.1
PORT=12345
CLOSED_PORT=12346

# Privilege check: probe whether a raw socket can be created here.
# This mirrors almap_syn_can_raw() (socket(AF_INET, SOCK_RAW, TCP)).
if command -v python3 >/dev/null 2>&1; then
    if ! python3 -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP); s.close()' >/dev/null 2>&1; then
        echo "skipping OS integration test: not root and CAP_NET_RAW is unavailable"
        exit 0
    fi
elif [ "$(id -u)" -ne 0 ]; then
    echo "skipping OS integration test: not root and CAP_NET_RAW is unavailable"
    exit 0
fi

if command -v python3 >/dev/null 2>&1; then
    :
else
    echo "error: need python3 for the listener and JSON/XML checks" >&2
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

# If almap itself reports missing privileges, treat it as a skip. This
# also catches a restricted user namespace where the probe above passed.
pre_output=$(./almap -t "$HOST" -p "$PORT" --scan syn --os --timeout 1000 2>&1 || true)
case "$pre_output" in
    *"error: --os requires --scan syn and root or CAP_NET_RAW"*)
        echo "skipping OS integration test: not root and CAP_NET_RAW is unavailable (almap check)"
        exit 0
        ;;
esac

LISTENER_PID=""
# Step 26 adds a default ~/.almap/os-signatures.db lookup. Isolate this
# step-19 fallback test with an empty HOME so a user-provided default DB
# cannot replace the coarse labels this test expects.
TMP_HOME=$(mktemp -d "${TMPDIR:-/tmp}/almap-os-home.XXXXXX") || exit 1
export HOME="$TMP_HOME"
cleanup() {
    if [ -n "$LISTENER_PID" ]; then
        kill "$LISTENER_PID" 2>/dev/null || true
        wait "$LISTENER_PID" 2>/dev/null || true
        LISTENER_PID=""
    fi
    rm -rf "$TMP_HOME"
}
trap cleanup EXIT

echo "starting python3 listener on $HOST:$PORT" >&2
python3 -c '
import socket, sys, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1])))
s.listen(5)
time.sleep(15)
s.close()
' "$PORT" >/dev/null 2>&1 &
LISTENER_PID=$!

sleep 1

# Text mode: every row has an os field; the open row must not be unknown.
echo "running ./almap -t $HOST -p $PORT,$CLOSED_PORT --scan syn --os --timeout 1000" >&2
output=$(./almap -t "$HOST" -p "$PORT,$CLOSED_PORT" --scan syn --os --timeout 1000)
status=$?
echo "$output"
if [ "$status" -ne 0 ]; then
    echo "integration test FAILED: text --os exited $status" >&2
    exit 1
fi
case "$output" in
    *"${HOST}:${PORT} open os=\""*)
        ;;
    *)
        echo "integration test FAILED: text output missing open row with os field" >&2
        exit 1
        ;;
esac
case "$output" in
    *'os="linux-like"'*|*'os="windows-like"'*|*'os="network-device"'*)
        ;;
    *)
        echo "integration test FAILED: text open row has no allowed OS label" >&2
        exit 1
        ;;
esac
case "$output" in
    *"${HOST}:${CLOSED_PORT} closed os=\""*)
        ;;
    *)
        echo "integration test FAILED: text closed row missing os field" >&2
        exit 1
        ;;
esac

# A host with no SYN+ACK at all (only a closed port) must be unknown.
echo "running ./almap -t $HOST -p $CLOSED_PORT --scan syn --os (closed only)" >&2
closed_output=$(./almap -t "$HOST" -p "$CLOSED_PORT" --scan syn --os --timeout 1000)
closed_status=$?
echo "$closed_output"
if [ "$closed_status" -ne 0 ]; then
    echo "integration test FAILED: closed-only --os exited $closed_status" >&2
    exit 1
fi
case "$closed_output" in
    *"${HOST}:${CLOSED_PORT} closed os=\"unknown\""*)
        ;;
    *)
        echo "integration test FAILED: closed-only host should report os=unknown" >&2
        exit 1
        ;;
esac

# The sequential --workers 1 path must produce the same label shape.
echo "running ./almap ... --scan syn --os --workers 1" >&2
one_output=$(./almap -t "$HOST" -p "$PORT" --scan syn --os --workers 1 --timeout 1000)
one_status=$?
echo "$one_output"
if [ "$one_status" -ne 0 ]; then
    echo "integration test FAILED: --os --workers 1 exited $one_status" >&2
    exit 1
fi
case "$one_output" in
    *"${HOST}:${PORT} open os=\"linux-like\""*|*"${HOST}:${PORT} open os=\"windows-like\""*|*"${HOST}:${PORT} open os=\"network-device\""*)
        ;;
    *)
        echo "integration test FAILED: --os --workers 1 missing open OS label" >&2
        exit 1
        ;;
esac

# JSON mode: valid JSON with an "os" string on every object.
echo "running ./almap ... --scan syn --os --json" >&2
json_output=$(./almap -t "$HOST" -p "$PORT,$CLOSED_PORT" --scan syn --os --json --timeout 1000)
json_status=$?
echo "$json_output"
if [ "$json_status" -ne 0 ]; then
    echo "integration test FAILED: JSON --os exited $json_status" >&2
    exit 1
fi
printf '%s\n' "$json_output" | python3 -c '
import json, sys
data = json.load(sys.stdin)
assert isinstance(data, list) and data, "empty JSON array"
labels = {"linux-like", "windows-like", "network-device", "unknown"}
for row in data:
    assert row["scan"] == "syn", row
    assert isinstance(row.get("os"), str), row
    assert row["os"] in labels, row
open_rows = [r for r in data if r["state"] == "open"]
assert open_rows, data
assert open_rows[0]["os"] != "unknown", data
' || {
    echo "integration test FAILED: JSON --os shape/label check" >&2
    exit 1
}

# Table mode: dedicated OS column and a label on the open row.
echo "running ./almap ... --scan syn --os --table" >&2
table_output=$(./almap -t "$HOST" -p "$PORT,$CLOSED_PORT" --scan syn --os --table --timeout 1000)
table_status=$?
echo "$table_output"
if [ "$table_status" -ne 0 ]; then
    echo "integration test FAILED: table --os exited $table_status" >&2
    exit 1
fi
TAB=$(printf '\t')
case "$table_output" in
    "IP${TAB}PORT${TAB}STATE${TAB}SCAN${TAB}OS"*)
        ;;
    *)
        echo "integration test FAILED: table --os header missing OS column" >&2
        exit 1
        ;;
esac
case "$table_output" in
    *"${HOST}${TAB}${PORT}${TAB}open${TAB}syn${TAB}linux-like"*|*"${HOST}${TAB}${PORT}${TAB}open${TAB}syn${TAB}windows-like"*|*"${HOST}${TAB}${PORT}${TAB}open${TAB}syn${TAB}network-device"*)
        ;;
    *)
        echo "integration test FAILED: table --os open row missing OS label" >&2
        exit 1
        ;;
esac

# XML mode: parseable document with an os attribute.
echo "running ./almap ... --scan syn --os --xml" >&2
xml_output=$(./almap -t "$HOST" -p "$PORT,$CLOSED_PORT" --scan syn --os --xml --timeout 1000)
xml_status=$?
echo "$xml_output"
if [ "$xml_status" -ne 0 ]; then
    echo "integration test FAILED: XML --os exited $xml_status" >&2
    exit 1
fi
printf '%s\n' "$xml_output" | python3 -c '
import sys, xml.etree.ElementTree as ET
root = ET.fromstring(sys.stdin.read())
labels = {"linux-like", "windows-like", "network-device", "unknown"}
rows = root.findall("./scan/result")
assert rows, "no XML result elements"
for row in rows:
    assert row.get("scan") == "syn", row.attrib
    assert row.get("os") in labels, row.attrib
open_rows = [r for r in rows if r.get("state") == "open"]
assert open_rows, [r.attrib for r in rows]
assert open_rows[0].get("os") != "unknown", [r.attrib for r in open_rows]
' || {
    echo "integration test FAILED: XML --os shape/label check" >&2
    exit 1
}

# Invalid combinations: --os is SYN-only, so these must fail with the
# exact clear message and exit 2 before any scan output.
echo "running --os with --scan connect (expect exit 2)" >&2
set +u
err_output=$(./almap -t "$HOST" -p "$PORT" --scan connect --os 2>&1)
err_status=$?
set -u
echo "$err_output"
if [ "$err_status" -ne 2 ]; then
    echo "integration test FAILED: --os --scan connect exited $err_status, expected 2" >&2
    exit 1
fi
case "$err_output" in
    *"error: --os requires --scan syn and root or CAP_NET_RAW"*)
        ;;
    *)
        echo "integration test FAILED: --os mode error message missing" >&2
        exit 1
        ;;
esac

echo "running --os with default connect (expect exit 2)" >&2
set +u
err2_output=$(./almap -t "$HOST" -p "$PORT" --os 2>&1)
err2_status=$?
set -u
echo "$err2_output"
if [ "$err2_status" -ne 2 ]; then
    echo "integration test FAILED: --os default connect exited $err2_status, expected 2" >&2
    exit 1
fi
case "$err2_output" in
    *"error: --os requires --scan syn and root or CAP_NET_RAW"*)
        ;;
    *)
        echo "integration test FAILED: --os default-connect error message missing" >&2
        exit 1
        ;;
esac

echo "integration test passed: --os text/JSON/table/XML labels and validation verified"
