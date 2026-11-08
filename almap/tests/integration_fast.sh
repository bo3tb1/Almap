#!/usr/bin/env bash
# tests/integration_fast.sh - Step 20 asynchronous connect scan test.
# Loopback only, no root: starts a python3 listener on 127.0.0.1:12345,
# scans an open and a closed port through the epoll engine with --fast,
# checks text/JSON/table/XML output, deterministic host -> port order,
# --workers 1 (still the async path), --rate pacing, and the exclusive
# flag errors. Use only on networks you own or have permission to scan.
set -u

cd "$(dirname "$0")/.." || exit 1

HOST=127.0.0.1
HOST2=127.0.0.2
PORT=12345
CLOSED=12346

if [ ! -x ./almap ]; then
    echo "building ./almap ..." >&2
    goose build almap.goose --cc gcc || exit 1
fi
if [ ! -x ./almap ]; then
    echo "error: ./almap not found after build" >&2
    exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "error: need python3 for the listener and JSON checks" >&2
    exit 1
fi

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
import socket, sys, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1])))
s.listen(128)
s.settimeout(30)
end = time.time() + 30
while time.time() < end:
    try:
        c, _ = s.accept()
        c.close()
    except socket.timeout:
        break
s.close()
' "$PORT" >/dev/null 2>&1 &
LISTENER_PID=$!
sleep 1

fail() {
    echo "integration test FAILED: $1" >&2
    exit 1
}

echo "running text --fast scan" >&2
text_output=$(./almap -t "$HOST" -p "$PORT,$CLOSED" --scan connect --fast --timeout 1000)
status=$?
echo "$text_output"
[ "$status" -eq 0 ] || fail "./almap exited $status"
case "$text_output" in
    *"$HOST:$PORT open"*) ;;
    *) fail "text output does not contain '$HOST:$PORT open'" ;;
esac
case "$text_output" in
    *"$HOST:$CLOSED closed"*) ;;
    *) fail "text output does not contain '$HOST:$CLOSED closed'" ;;
esac
case "$text_output" in
    *"warning:"*) fail "fast text output contains a warning" ;;
esac

echo "running JSON --fast scan" >&2
json_output=$(./almap -t "$HOST" -p "$PORT,$CLOSED" --scan connect --fast --timeout 1000 --json)
status=$?
echo "$json_output"
[ "$status" -eq 0 ] || fail "JSON run exited $status"
case "$json_output" in
    "["*"]") ;;
    *) fail "JSON output does not start with [ and end with ]" ;;
esac
if ! printf '%s' "$json_output" | python3 -c '
import json, sys
d = json.load(sys.stdin)
assert len(d) == 2, d
assert d[0]["ip"] == "127.0.0.1" and d[0]["port"] == 12345, d
assert d[0]["state"] == "open" and d[0]["scan"] == "connect", d
assert d[1]["ip"] == "127.0.0.1" and d[1]["port"] == 12346, d
assert d[1]["state"] == "closed" and d[1]["scan"] == "connect", d
'; then
    fail "JSON shape/state/order check failed"
fi

echo "running table --fast scan" >&2
table_output=$(./almap -t "$HOST" -p "$PORT,$CLOSED" --scan connect --fast --timeout 1000 --table)
status=$?
echo "$table_output"
[ "$status" -eq 0 ] || fail "table run exited $status"
header=$'IP\tPORT\tSTATE\tSCAN\tBANNER'
case "$table_output" in
    *"$header"*) ;;
    *) fail "table output does not contain the connect header" ;;
esac
case "$table_output" in
    *"$HOST"$'\t'"$PORT"$'\t'"open"$'\t'"connect"*) ;;
    *) fail "table output does not contain the open row" ;;
esac
case "$table_output" in
    *"$HOST"$'\t'"$CLOSED"$'\t'"closed"$'\t'"connect"*) ;;
    *) fail "table output does not contain the closed row" ;;
esac

echo "running XML --fast scan" >&2
xml_output=$(./almap -t "$HOST" -p "$PORT,$CLOSED" --scan connect --fast --timeout 1000 --xml)
status=$?
echo "$xml_output"
[ "$status" -eq 0 ] || fail "XML run exited $status"
if ! printf '%s' "$xml_output" | python3 -c '
import sys
import xml.etree.ElementTree as ET
root = ET.fromstring(sys.stdin.read())
rows = root.findall("./scan/result")
assert len(rows) == 2, rows
assert rows[0].attrib["ip"] == "127.0.0.1" and rows[0].attrib["port"] == "12345", rows
assert rows[0].attrib["state"] == "open" and rows[0].attrib["scan"] == "connect", rows
assert rows[1].attrib["port"] == "12346" and rows[1].attrib["state"] == "closed", rows
'; then
    fail "XML shape/state/order check failed"
fi

echo "running multi-host --fast JSON order check" >&2
multi_output=$(./almap -t "$HOST,$HOST2" -p "$PORT,$CLOSED" --scan connect --fast --timeout 1000 --json)
status=$?
echo "$multi_output"
[ "$status" -eq 0 ] || fail "multi-host run exited $status"
if ! printf '%s' "$multi_output" | python3 -c '
import json, sys
d = json.load(sys.stdin)
assert len(d) == 4, d
want = [
    ("127.0.0.1", 12345, "open"),
    ("127.0.0.1", 12346, "closed"),
    ("127.0.0.2", 12345, "closed"),
    ("127.0.0.2", 12346, "closed"),
]
got = [(r["ip"], r["port"], r["state"]) for r in d]
assert got == want, (got, want)
assert all(r["scan"] == "connect" for r in d), d
'; then
    fail "multi-host deterministic order check failed"
fi

echo "running --fast --workers 1 (must still use the async path)" >&2
workers_output=$(./almap -t "$HOST" -p "$PORT" --scan connect --fast --workers 1 --timeout 1000)
status=$?
echo "$workers_output"
[ "$status" -eq 0 ] || fail "--fast --workers 1 exited $status"
case "$workers_output" in
    *"$HOST:$PORT open"*) ;;
    *) fail "--fast --workers 1 did not report open" ;;
esac
case "$workers_output" in
    *"warning:"*) fail "--fast --workers 1 printed a sequential warning" ;;
esac

if date +%s%N >/dev/null 2>&1; then
    echo "running --fast --rate 5 pacing check" >&2
    start_ns=$(date +%s%N)
    ./almap -t "$HOST" -p 1-10 --scan connect --fast --rate 5 --timeout 1000 >/dev/null
    status=$?
    end_ns=$(date +%s%N)
    elapsed_ms=$(( (end_ns - start_ns) / 1000000 ))
    [ "$status" -eq 0 ] || fail "rate-limited run exited $status"
    echo "rate-limited 10-port scan took ${elapsed_ms}ms" >&2
    if [ "$elapsed_ms" -lt 1200 ]; then
        fail "--fast --rate 5 finished too quickly (${elapsed_ms}ms)"
    fi
fi

echo "running --fast validation errors" >&2
err_output=$(./almap -t "$HOST" -p "$PORT" --scan syn --fast 2>&1)
status=$?
[ "$status" -eq 2 ] || fail "--fast --scan syn exited $status (expected 2)"
case "$err_output" in
    *"error: --fast requires --scan connect"*) ;;
    *) fail "--fast --scan syn missing exact mode error" ;;
esac

err_output=$(./almap -t "$HOST" -p "$PORT" --scan connect --fast --banners 2>&1)
status=$?
[ "$status" -eq 2 ] || fail "--fast --banners exited $status (expected 2)"
case "$err_output" in
    *"error: --fast cannot be combined with --banners or --service"*) ;;
    *) fail "--fast --banners missing exact conflict error" ;;
esac

err_output=$(./almap -t "$HOST" -p "$PORT" --scan connect --fast --service 2>&1)
status=$?
[ "$status" -eq 2 ] || fail "--fast --service exited $status (expected 2)"
case "$err_output" in
    *"error: --fast cannot be combined with --banners or --service"*) ;;
    *) fail "--fast --service missing exact conflict error" ;;
esac

err_output=$(./almap -t ::1 -p "$PORT" --scan connect --fast 2>&1)
status=$?
[ "$status" -eq 2 ] || fail "--fast IPv6 exited $status (expected 2)"
case "$err_output" in
    *"error: fast connect scan not implemented for IPv6"*) ;;
    *) fail "--fast IPv6 missing exact error" ;;
esac

echo "integration test passed: --fast text/JSON/table/XML, ordering, pacing, and errors verified"
