#!/usr/bin/env bash
# tests/integration_xml.sh - Step 14 integration test for XML output.
# Loopback only, no root required. Starts a python3 listener on
# 127.0.0.1:12345, runs a connect scan with --xml and checks the
# document shape plus ElementTree parsing, runs discovery with --xml
# and checks its document shape, and verifies --xml --json and
# --xml --table are rejected with exit 2 and the exact error.
# Use only on networks you own or have permission to scan; this test
# only uses loopback.
set -u

cd "$(dirname "$0")/.." || exit 1

HOST=127.0.0.1
PORT=12345

if [ ! -x ./almap ]; then
    echo "building ./almap ..." >&2
    goose build almap.goose --cc gcc || exit 1
fi
if [ ! -x ./almap ]; then
    echo "error: ./almap not found after build" >&2
    exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "error: need python3 for the listener and XML parser" >&2
    exit 1
fi

xml_parse() {
    python3 -c 'import sys, xml.etree.ElementTree as ET; ET.fromstring(sys.stdin.read())'
}

LISTENER_PID=""
cleanup() {
    if [ -n "$LISTENER_PID" ]; then
        kill "$LISTENER_PID" 2>/dev/null || true
        wait "$LISTENER_PID" 2>/dev/null || true
        LISTENER_PID=""
    fi
}
trap cleanup EXIT

echo "starting python3 listener on $HOST:$PORT" >&2
python3 -c '
import socket, sys
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1])))
s.listen(5)
s.settimeout(15)
try:
    while True:
        c, _ = s.accept()
        c.close()
except socket.timeout:
    pass
s.close()
' "$PORT" >/dev/null 2>&1 &
LISTENER_PID=$!

sleep 1

echo "running ./almap -t $HOST -p $PORT --scan connect --xml --timeout 1000" >&2
xml_output=$(./almap -t "$HOST" -p "$PORT" --scan connect --xml --timeout 1000)
xml_status=$?
echo "$xml_output"
if [ "$xml_status" -ne 0 ]; then
    echo "integration test FAILED: ./almap --xml exited $xml_status" >&2
    exit 1
fi
case "$xml_output" in
    "<almap><scan>"*"</scan></almap>")
        ;;
    *)
        echo "integration test FAILED: scan XML does not start with <almap><scan> and end with </scan></almap>" >&2
        exit 1
        ;;
esac
case "$xml_output" in
    *"<result ip=\"$HOST\" port=\"$PORT\" state=\"open\" scan=\"connect\""*)
        ;;
    *)
        echo "integration test FAILED: scan XML lacks the open 12345 connect result" >&2
        exit 1
        ;;
esac
case "$xml_output" in
    *"warning:"*)
        echo "integration test FAILED: scan XML contains a warning line" >&2
        exit 1
        ;;
esac
if ! printf "%s" "$xml_output" | xml_parse; then
    echo "integration test FAILED: scan XML does not parse with ElementTree" >&2
    exit 1
fi

echo "running ./almap -t $HOST --discover --xml" >&2
disc_output=$(./almap -t "$HOST" --discover --xml)
disc_status=$?
echo "$disc_output"
if [ "$disc_status" -ne 0 ]; then
    echo "integration test FAILED: ./almap --discover --xml exited $disc_status" >&2
    exit 1
fi
case "$disc_output" in
    "<almap><discovery>"*"</discovery></almap>")
        ;;
    *)
        echo "integration test FAILED: discovery XML does not start with <almap><discovery> and end with </discovery></almap>" >&2
        exit 1
        ;;
esac
case "$disc_output" in
    *"<host ip=\"$HOST\" up=\"true\"/>"*)
        ;;
    *)
        echo "integration test FAILED: discovery XML lacks the up host element" >&2
        exit 1
        ;;
esac
case "$disc_output" in
    *"warning:"*)
        echo "integration test FAILED: discovery XML contains a warning line" >&2
        exit 1
        ;;
esac
if ! printf "%s" "$disc_output" | xml_parse; then
    echo "integration test FAILED: discovery XML does not parse with ElementTree" >&2
    exit 1
fi

echo "running ./almap -t $HOST -p $PORT --scan connect --xml --json" >&2
combo_output=$(./almap -t "$HOST" -p "$PORT" --scan connect --xml --json 2>&1)
combo_status=$?
echo "$combo_output"
if [ "$combo_status" -ne 2 ]; then
    echo "integration test FAILED: --xml --json exited $combo_status (expected 2)" >&2
    exit 1
fi
case "$combo_output" in
    *"error: --xml cannot be combined with --json or --table"*)
        ;;
    *)
        echo "integration test FAILED: --xml --json lacks the combined-flags error" >&2
        exit 1
        ;;
esac

echo "running ./almap -t $HOST -p $PORT --scan connect --xml --table" >&2
combo2_output=$(./almap -t "$HOST" -p "$PORT" --scan connect --xml --table 2>&1)
combo2_status=$?
echo "$combo2_output"
if [ "$combo2_status" -ne 2 ]; then
    echo "integration test FAILED: --xml --table exited $combo2_status (expected 2)" >&2
    exit 1
fi
case "$combo2_output" in
    *"error: --xml cannot be combined with --json or --table"*)
        ;;
    *)
        echo "integration test FAILED: --xml --table lacks the combined-flags error" >&2
        exit 1
        ;;
esac

echo "integration test passed: scan/discovery XML validate and exclusive flags exit 2"
