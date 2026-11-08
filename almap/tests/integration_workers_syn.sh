#!/usr/bin/env bash
# tests/integration_workers_syn.sh - Step 12 integration test for the
# bounded SYN worker pool.
# Loopback only: starts a python3 listener on 127.0.0.1:12345 that
# stays listening for all three scans (a SYN scan never completes the
# handshake, so accept() is not required; the kernel answers SYN with
# SYN+ACK while the socket is listening). Runs text, JSON, and table
# scans with --workers 4, checks deterministic results and that the
# sequential warning is absent, then cleans up the listener.
# Skips with a clear message if not root and CAP_NET_RAW is unavailable.
# Use only on networks you own or have permission to scan; this test
# only uses loopback.
set -u

cd "$(dirname "$0")/.." || exit 1

HOST=127.0.0.1
PORT=12345

# Privilege check: probe whether a raw socket can be created here.
# This mirrors almap_syn_can_raw() (socket(AF_INET, SOCK_RAW, TCP)).
if command -v python3 >/dev/null 2>&1; then
    if ! python3 -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP); s.close()' >/dev/null 2>&1; then
        echo "skipping SYN worker integration test: not root and CAP_NET_RAW is unavailable"
        exit 0
    fi
elif [ "$(id -u)" -ne 0 ]; then
    echo "skipping SYN worker integration test: not root and CAP_NET_RAW is unavailable"
    exit 0
fi

if [ ! -x ./almap ]; then
    echo "building ./almap ..." >&2
    goose build almap.goose --cc gcc || exit 1
fi
if [ ! -x ./almap ]; then
    echo "error: ./almap not found after build" >&2
    exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "error: need python3 for the listener and JSON validation" >&2
    exit 1
fi

# If almap itself reports missing privileges, treat it as a skip.
pre_output=$(./almap -t "$HOST" -p "$PORT" --scan syn --workers 4 --timeout 1000 2>&1 || true)
case "$pre_output" in
    *"SYN scan requires root or CAP_NET_RAW"*)
        echo "skipping SYN worker integration test: not root and CAP_NET_RAW is unavailable (almap check)"
        exit 0
        ;;
esac

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
s.listen(64)
time.sleep(20)
s.close()
' "$PORT" >/dev/null 2>&1 &
LISTENER_PID=$!

sleep 1

echo "running ./almap -t $HOST -p $PORT --scan syn --workers 4 --timeout 1000" >&2
output=$(./almap -t "$HOST" -p "$PORT" --scan syn --workers 4 --timeout 1000)
status=$?
echo "$output"
if [ "$status" -ne 0 ]; then
    echo "integration test FAILED: syn workers text exited $status" >&2
    exit 1
fi
case "$output" in
    *"$HOST:$PORT open"*) ;;
    *)
        echo "integration test FAILED: text output does not contain '$HOST:$PORT open'" >&2
        exit 1
        ;;
esac
case "$output" in
    *"warning:"*)
        echo "integration test FAILED: text output contains a warning" >&2
        exit 1
        ;;
esac

echo "running ./almap ... --json" >&2
json_output=$(./almap -t "$HOST" -p "$PORT" --scan syn --workers 4 --timeout 1000 --json)
json_status=$?
echo "$json_output"
if [ "$json_status" -ne 0 ]; then
    echo "integration test FAILED: syn workers json exited $json_status" >&2
    exit 1
fi
case "$json_output" in
    \[*\]*) ;;
    *)
        echo "integration test FAILED: JSON output is not an array" >&2
        exit 1
        ;;
esac
case "$json_output" in
    *"\"port\":$PORT"*"\"state\":\"open\""*"\"scan\":\"syn\""*) ;;
    *)
        echo "integration test FAILED: JSON output missing open syn object" >&2
        exit 1
        ;;
esac
case "$json_output" in
    *"warning:"*)
        echo "integration test FAILED: JSON output contains a warning" >&2
        exit 1
        ;;
esac
printf '%s' "$json_output" | python3 -m json.tool >/dev/null 2>&1 || {
    echo "integration test FAILED: JSON does not parse" >&2
    exit 1
}

TAB=$(printf '\t')
echo "running ./almap ... --table" >&2
table_output=$(./almap -t "$HOST" -p "$PORT" --scan syn --workers 4 --timeout 1000 --table)
table_status=$?
echo "$table_output"
if [ "$table_status" -ne 0 ]; then
    echo "integration test FAILED: syn workers table exited $table_status" >&2
    exit 1
fi
case "$table_output" in
    "IP${TAB}PORT${TAB}STATE${TAB}SCAN${TAB}BANNER"*) ;;
    *)
        echo "integration test FAILED: table output does not start with scan header" >&2
        exit 1
        ;;
esac
case "$table_output" in
    *"${HOST}${TAB}${PORT}${TAB}open${TAB}syn"*) ;;
    *)
        echo "integration test FAILED: table output missing open syn row" >&2
        exit 1
        ;;
esac
case "$table_output" in
    *"warning:"*)
        echo "integration test FAILED: table output contains a warning" >&2
        exit 1
        ;;
esac

echo "integration test passed: SYN worker pool text/JSON/table verified"
