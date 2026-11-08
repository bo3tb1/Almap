#!/usr/bin/env bash
# tests/integration_table.sh - Step 11 integration test for table output.
# Loopback only, no root required. Starts a python3 listener that
# loops over multiple accepts (banner scans open two connections
# per open port), runs table scans for connect/banner/discovery,
# checks the exact tab-separated headers, and checks --table --json
# is rejected with exit 2.
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

TAB=$(printf '\t')

echo "running ./almap -t $HOST -p $PORT --scan connect --table --timeout 1000" >&2
output=$(./almap -t "$HOST" -p "$PORT" --scan connect --table --timeout 1000)
status=$?
echo "$output"
if [ "$status" -ne 0 ]; then
    echo "integration test FAILED: table connect exited $status" >&2
    exit 1
fi
case "$output" in
    "IP${TAB}PORT${TAB}STATE${TAB}SCAN${TAB}BANNER"*)
        ;;
    *)
        echo "integration test FAILED: table output does not start with scan header" >&2
        exit 1
        ;;
esac
case "$output" in
    *"${HOST}${TAB}${PORT}${TAB}open${TAB}connect"*)
        ;;
    *)
        echo "integration test FAILED: table output missing open row" >&2
        exit 1
        ;;
esac

echo "running ./almap -t $HOST -p $PORT --scan connect --table --banners --timeout 1000" >&2
banner_output=$(./almap -t "$HOST" -p "$PORT" --scan connect --table --banners --timeout 1000)
banner_status=$?
echo "$banner_output"
if [ "$banner_status" -ne 0 ]; then
    echo "integration test FAILED: banner table exited $banner_status" >&2
    exit 1
fi
case "$banner_output" in
    "IP${TAB}PORT${TAB}STATE${TAB}SCAN${TAB}BANNER"*)
        ;;
    *)
        echo "integration test FAILED: banner table does not start with scan header" >&2
        exit 1
        ;;
esac
case "$banner_output" in
    *"${HOST}${TAB}${PORT}${TAB}open${TAB}connect${TAB}HELLO-ALMAP"*)
        ;;
    *)
        echo "integration test FAILED: banner table does not contain HELLO-ALMAP banner" >&2
        exit 1
        ;;
esac

echo "running ./almap -t $HOST --discover --table" >&2
disc_output=$(./almap -t "$HOST" --discover --table)
disc_status=$?
echo "$disc_output"
if [ "$disc_status" -ne 0 ]; then
    echo "integration test FAILED: discovery table exited $disc_status" >&2
    exit 1
fi
case "$disc_output" in
    "IP${TAB}UP"*)
        ;;
    *)
        echo "integration test FAILED: discovery table does not start with IP UP header" >&2
        exit 1
        ;;
esac
case "$disc_output" in
    *"${HOST}${TAB}up"*)
        ;;
    *)
        echo "integration test FAILED: discovery table does not contain up row" >&2
        exit 1
        ;;
esac

kill "$LISTENER_PID" 2>/dev/null || true
wait "$LISTENER_PID" 2>/dev/null || true
LISTENER_PID=""

echo "running ./almap -t $HOST -p $PORT --scan connect --table --json (expect exit 2)" >&2
err_output=$(./almap -t "$HOST" -p "$PORT" --scan connect --table --json 2>&1 || true)
echo "$err_output"
set +e
./almap -t "$HOST" -p "$PORT" --scan connect --table --json >/dev/null 2>&1
err_status=$?
set -u
if [ "$err_status" -ne 2 ]; then
    echo "integration test FAILED: --table --json exited $err_status, expected 2" >&2
    exit 1
fi
case "$err_output" in
    *"error: --table cannot be combined with --json"*)
        ;;
    *)
        echo "integration test FAILED: --table --json error message missing" >&2
        exit 1
        ;;
esac
echo "integration test passed: table headers, rows, and JSON rejection verified"
