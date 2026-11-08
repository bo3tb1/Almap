#!/usr/bin/env bash
# tests/integration_banner.sh - Step 8 integration test for banners.
# Loopback only: starts a python3 listener on 127.0.0.1:12345 that
# sends HELLO-ALMAP on each accepted connection, scans it with
# ./almap --scan connect --banners (text and --json), and checks
# for the banner. The connect scan opens two connections per open
# port (probe + grab), so the listener loops over multiple accepts.
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
    echo "error: need python3 for the banner listener" >&2
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
import socket, sys
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1])))
s.listen(5)
s.settimeout(15)
try:
    while True:
        c, _ = s.accept()
        try:
            c.sendall(b"HELLO-ALMAP\n")
        except BrokenPipeError:
            pass
        c.close()
except socket.timeout:
    pass
s.close()
' "$PORT" >/dev/null 2>&1 &
LISTENER_PID=$!

sleep 1

echo "running ./almap -t $HOST -p $PORT --scan connect --banners --timeout 1000" >&2
output=$(./almap -t "$HOST" -p "$PORT" --scan connect --banners --timeout 1000)
status=$?
echo "$output"
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
case "$output" in
    *'banner="HELLO-ALMAP"'*)
        ;;
    *)
        echo "integration test FAILED: text output does not contain banner HELLO-ALMAP" >&2
        exit 1
        ;;
esac

echo "running ./almap -t $HOST -p $PORT --scan connect --banners --timeout 1000 --json" >&2
json_output=$(./almap -t "$HOST" -p "$PORT" --scan connect --banners --timeout 1000 --json)
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
    *'"banner":"HELLO-ALMAP"'*)
        ;;
    *)
        echo "integration test FAILED: JSON output does not contain banner HELLO-ALMAP" >&2
        exit 1
        ;;
esac
case "$json_output" in
    *"warning:"*)
        echo "integration test FAILED: JSON output contains worker warning" >&2
        exit 1
        ;;
esac
if ! printf "%s" "$json_output" | python3 -m json.tool >/dev/null 2>&1; then
    echo "integration test FAILED: JSON output does not parse as JSON" >&2
    exit 1
fi

# Stop the looping listener.
kill "$LISTENER_PID" 2>/dev/null || true
wait "$LISTENER_PID" 2>/dev/null || true
LISTENER_PID=""
echo "integration test passed: output contains open and banner"
