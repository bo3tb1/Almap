#!/usr/bin/env bash
# tests/integration_service.sh - Step 16 integration test for --service.
# Loopback only: two python3 listeners (an HTTP server on 127.0.0.1:8080
# and an SSH-like banner server on 127.0.0.1:12345) plus a closed port,
# then checks the service field in text, JSON, table and XML output, the
# sequential-only rule, and the --service + --discover/--scan syn errors.
# Use only on networks you own or have permission to scan; this test only
# uses loopback.
set -u

cd "$(dirname "$0")/.." || exit 1

HOST=127.0.0.1
HTTP_PORT=8080
SSH_PORT=12345
CLOSED_PORT=9

if [ ! -x ./almap ]; then
    echo "building ./almap ..." >&2
    goose build almap.goose --cc gcc || exit 1
fi
if [ ! -x ./almap ]; then
    echo "error: ./almap not found after build" >&2
    exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "error: need python3 for the service listeners" >&2
    exit 1
fi

HTTP_PID=""
SSH_PID=""
cleanup() {
    for pid in "$HTTP_PID" "$SSH_PID"; do
        if [ -n "$pid" ]; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    HTTP_PID=""
    SSH_PID=""
}
trap cleanup EXIT

echo "starting python3 HTTP listener on $HOST:$HTTP_PORT" >&2
python3 -c '
import socket, sys
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1])))
s.listen(8)
s.settimeout(20)
try:
    while True:
        c, _ = s.accept()
        try:
            c.settimeout(2)
            try:
                c.recv(1024)
            except Exception:
                pass
            c.sendall(b"HTTP/1.0 200 OK\r\nServer: TestHTTP/1.0\r\nContent-Length: 0\r\n\r\n")
        except BrokenPipeError:
            pass
        c.close()
except socket.timeout:
    pass
s.close()
' "$HTTP_PORT" >/dev/null 2>&1 &
HTTP_PID=$!

echo "starting python3 SSH-like listener on $HOST:$SSH_PORT" >&2
python3 -c '
import socket, sys
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1])))
s.listen(8)
s.settimeout(20)
try:
    while True:
        c, _ = s.accept()
        try:
            c.sendall(b"SSH-2.0-OpenSSH_9.6-test\r\n")
        except BrokenPipeError:
            pass
        c.close()
except socket.timeout:
    pass
s.close()
' "$SSH_PORT" >/dev/null 2>&1 &
SSH_PID=$!

sleep 1

PORTS="$HTTP_PORT,$SSH_PORT"

echo "running ./almap -t $HOST -p $PORTS --scan connect --service --timeout 1000" >&2
output=$(./almap -t "$HOST" -p "$PORTS" --scan connect --service --timeout 1000)
status=$?
echo "$output"
if [ "$status" -ne 0 ]; then
    echo "integration test FAILED: ./almap exited $status" >&2
    exit 1
fi
case "$output" in
    *'service="http"'*) ;;
    *)
        echo "integration test FAILED: text output does not contain service=\"http\"" >&2
        exit 1
        ;;
esac
case "$output" in
    *'service="ssh"'*) ;;
    *)
        echo "integration test FAILED: text output does not contain service=\"ssh\"" >&2
        exit 1
        ;;
esac

echo "running ./almap -t $HOST -p $PORTS --scan connect --service --timeout 1000 --json" >&2
json_output=$(./almap -t "$HOST" -p "$PORTS" --scan connect --service --timeout 1000 --json)
json_status=$?
echo "$json_output"
if [ "$json_status" -ne 0 ]; then
    echo "integration test FAILED: ./almap --json exited $json_status" >&2
    exit 1
fi
case "$json_output" in
    "["*"]") ;;
    *)
        echo "integration test FAILED: JSON output does not start with [ and end with ]" >&2
        exit 1
        ;;
esac
case "$json_output" in
    *'"service":"http"'*) ;;
    *)
        echo "integration test FAILED: JSON output does not contain \"service\":\"http\"" >&2
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

echo "running ./almap -t $HOST -p $PORTS --scan connect --service --timeout 1000 --table" >&2
table_output=$(./almap -t "$HOST" -p "$PORTS" --scan connect --service --timeout 1000 --table)
table_status=$?
echo "$table_output"
if [ "$table_status" -ne 0 ]; then
    echo "integration test FAILED: ./almap --table exited $table_status" >&2
    exit 1
fi
service_header=$'IP\tPORT\tSTATE\tSCAN\tSERVICE\tBANNER'
if ! printf "%s\n" "$table_output" | grep -F -x -- "$service_header" >/dev/null 2>&1; then
    echo "integration test FAILED: table output does not contain the SERVICE header" >&2
    exit 1
fi

echo "running ./almap -t $HOST -p $PORTS --scan connect --service --timeout 1000 --xml" >&2
xml_output=$(./almap -t "$HOST" -p "$PORTS" --scan connect --service --timeout 1000 --xml)
xml_status=$?
echo "$xml_output"
if [ "$xml_status" -ne 0 ]; then
    echo "integration test FAILED: ./almap --xml exited $xml_status" >&2
    exit 1
fi
case "$xml_output" in
    *'service="http"'*) ;;
    *)
        echo "integration test FAILED: XML output does not contain service=\"http\"" >&2
        exit 1
        ;;
esac

echo "running ./almap -t $HOST -p $CLOSED_PORT --scan connect --service --timeout 1000" >&2
closed_output=$(./almap -t "$HOST" -p "$CLOSED_PORT" --scan connect --service --timeout 1000)
closed_status=$?
echo "$closed_output"
if [ "$closed_status" -ne 0 ]; then
    echo "integration test FAILED: ./almap closed-port run exited $closed_status" >&2
    exit 1
fi
case "$closed_output" in
    *'service='*)
        echo "integration test FAILED: closed port must not emit a service field" >&2
        exit 1
        ;;
esac

echo "checking --service exclusive errors" >&2
error_output=$(./almap -t "$HOST" -p 80 --service --discover 2>&1)
error_status=$?
if [ "$error_status" -ne 2 ]; then
    echo "integration test FAILED: --service --discover exit $error_status (want 2)" >&2
    exit 1
fi
case "$error_output" in
    *"error: --service requires --scan connect and -p"*) ;;
    *)
        echo "integration test FAILED: missing --service+--discover error text" >&2
        exit 1
        ;;
esac
error_output=$(./almap -t "$HOST" -p 80 --scan syn --service 2>&1)
error_status=$?
if [ "$error_status" -ne 2 ]; then
    echo "integration test FAILED: --service --scan syn exit $error_status (want 2)" >&2
    exit 1
fi
case "$error_output" in
    *"error: --service requires --scan connect and -p"*) ;;
    *)
        echo "integration test FAILED: missing --service+--scan syn error text" >&2
        exit 1
        ;;
esac
error_output=$(./almap -t "$HOST" --service 2>&1)
error_status=$?
if [ "$error_status" -ne 2 ]; then
    echo "integration test FAILED: --service without -p exit $error_status (want 2)" >&2
    exit 1
fi
case "$error_output" in
    *"error: --service requires --scan connect and -p"*) ;;
    *)
        echo "integration test FAILED: missing --service without -p error text" >&2
        exit 1
        ;;
esac

cleanup
echo "integration test passed: service detection works on loopback"
