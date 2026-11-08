#!/usr/bin/env bash
# tests/integration_connect.sh - Step 3 integration test for TCP connect scan.
# Loopback only: starts a listener on 127.0.0.1:12345, scans it with
# ./almap, and checks the output contains `open`.
# Listener: prefers `nc -l`, then ncat, then python3 (similar fallback).
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

LISTENER_PID=""
cleanup() {
    if [ -n "$LISTENER_PID" ]; then
        kill "$LISTENER_PID" 2>/dev/null || true
        wait "$LISTENER_PID" 2>/dev/null || true
        LISTENER_PID=""
    fi
}
trap cleanup EXIT

if command -v nc >/dev/null 2>&1; then
    echo "starting nc listener on $HOST:$PORT" >&2
    nc -l "$HOST" "$PORT" >/dev/null 2>&1 &
    LISTENER_PID=$!
elif command -v ncat >/dev/null 2>&1; then
    echo "starting ncat listener on $HOST:$PORT" >&2
    ncat -l "$HOST" "$PORT" >/dev/null 2>&1 &
    LISTENER_PID=$!
elif command -v python3 >/dev/null 2>&1; then
    echo "starting python3 listener on $HOST:$PORT" >&2
    python3 -c 'import socket,sys; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("127.0.0.1",int(sys.argv[1]))); s.listen(1); s.settimeout(10); c,_=s.accept(); c.close(); s.close()' "$PORT" >/dev/null 2>&1 &
    LISTENER_PID=$!
else
    echo "error: need nc, ncat, or python3 for the listener" >&2
    exit 1
fi

# Give the listener time to bind. Do not probe with a connect: that
# would consume the single accept of nc/python listeners.
sleep 1

echo "running ./almap -t $HOST -p $PORT --scan connect --timeout 1000" >&2
output=$(./almap -t "$HOST" -p "$PORT" --scan connect --timeout 1000)
status=$?
echo "$output"

# Allow the listener to finish/close after one connection.
wait "$LISTENER_PID" 2>/dev/null || true
LISTENER_PID=""

if [ "$status" -ne 0 ]; then
    echo "integration test FAILED: ./almap exited $status" >&2
    exit 1
fi
case "$output" in
    *"$HOST:$PORT open"*)
        ;;
    *)
        echo "integration test FAILED: output does not contain '$HOST:$PORT open'" >&2
        exit 1
        ;;
esac

# JSON check on the now-closed port (listener already consumed above):
# output must be a valid JSON array and parse with python3 if present.
# No worker warning line may appear (it would corrupt the array).
echo "running ./almap -t $HOST -p $PORT --scan connect --timeout 1000 --json (closed port)" >&2
json_output=$(./almap -t "$HOST" -p "$PORT" --scan connect --timeout 1000 --json)
json_status=$?
echo "$json_output"
if [ "$json_status" -ne 0 ]; then
    echo "integration test FAILED: ./almap --json exited $json_status" >&2
    exit 1
fi
case "$json_output" in
    "["*"]")
        ;;
    *)
        echo "integration test FAILED: JSON output does not start with [ and end with ]" >&2
        exit 1
        ;;
esac
case "$json_output" in
    *'"scan":"connect"'*)
        ;;
    *)
        echo "integration test FAILED: JSON output does not contain scan connect" >&2
        exit 1
        ;;
esac
case "$json_output" in
    *"warning:"*)
        echo "integration test FAILED: JSON output contains worker warning" >&2
        exit 1
        ;;
esac
if command -v python3 >/dev/null 2>&1; then
    if ! printf "%s" "$json_output" | python3 -m json.tool >/dev/null 2>&1; then
        echo "integration test FAILED: JSON output does not parse as JSON" >&2
        exit 1
    fi
fi
echo "integration test passed: output contains open"
