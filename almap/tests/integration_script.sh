#!/usr/bin/env bash
# tests/integration_script.sh - Step 30 AlScript integration test.
# Loopback only, no root: builds all plugins via tools/build_plugins.sh,
# runs ALmap with --script against python3 SSH and HTTP listeners,
# and verifies script_out for sample_banner (text/JSON/table/XML) and
# http_title (title/server extraction). Only uses loopback.
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
    echo "error: need python3 for the listener" >&2
    exit 1
fi
if ! command -v gcc >/dev/null 2>&1; then
    echo "error: need gcc to compile the sample plugin" >&2
    exit 1
fi

PLUGIN=/tmp/opencode/sample_banner.so
mkdir -p /tmp/opencode
echo "building all plugins via tools/build_plugins.sh" >&2
bash tools/build_plugins.sh || exit 1
for so in plugins/sample_banner.so plugins/http_title.so plugins/ftp_anon.so plugins/ssh_version.so plugins/http_methods.so plugins/redis_info.so; do
    if [ ! -f "$so" ]; then
        echo "error: plugin $so not built" >&2
        exit 1
    fi
done
gcc -shared -fPIC -o "$PLUGIN" plugins/sample_banner.c || exit 1
if [ ! -f "$PLUGIN" ]; then
    echo "error: plugin $PLUGIN not built" >&2
    exit 1
fi

# A missing plugin must fail fast with exit 1 and a clear error.
./almap -t "$HOST" -p "$PORT" --scan connect --script /tmp/does_not_exist_12345.so >/dev/null 2>&1
if [ $? -ne 1 ]; then
    echo "integration test FAILED: missing plugin did not exit 1" >&2
    exit 1
fi
./almap -t "$HOST" -p "$PORT" --scan connect --script /tmp/does_not_exist_12345.so 2>&1 | grep -F "error: cannot load --script" >/dev/null || {
    echo "integration test FAILED: missing plugin error message mismatch" >&2
    exit 1
}
# Validation errors (no plugin build needed).
./almap -t "$HOST" -p "$PORT" --scan udp --script "$PLUGIN" >/dev/null 2>&1
if [ $? -ne 2 ]; then
    echo "integration test FAILED: --script with --scan udp did not exit 2" >&2
    exit 1
fi
./almap -t "$HOST" -p "$PORT" --scan connect --script "$PLUGIN" --fast >/dev/null 2>&1
if [ $? -ne 2 ]; then
    echo "integration test FAILED: --script with --fast did not exit 2" >&2
    exit 1
fi
./almap -t ::1 -p "$PORT" --scan connect --script "$PLUGIN" >/dev/null 2>&1
if [ $? -ne 2 ]; then
    echo "integration test FAILED: --script with IPv6 did not exit 2" >&2
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
s.listen(16)
s.settimeout(30)
end = time.time() + 30
while time.time() < end:
    try:
        c, _ = s.accept()
        try:
            c.sendall(b"SSH-2.0-OpenSSH_9.6-test\n")
        except BrokenPipeError:
            pass
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

echo "running text --script scan" >&2
text_output=$(./almap -t "$HOST" -p "$PORT,12346" --scan connect --script "$PLUGIN" --timeout 1000)
status=$?
echo "$text_output"
[ "$status" -eq 0 ] || fail "text run exited $status"
case "$text_output" in
    *"$HOST:$PORT open"*) ;;
    *) fail "text output missing open line" ;;
esac
case "$text_output" in
    *'script_out="SSH-2.0-OpenSSH_9.6-test"'*) ;;
    *) fail "text output missing script_out" ;;
esac
case "$text_output" in
    *"$HOST:12346 closed"*) ;;
    *) fail "text output missing closed line" ;;
esac
case "$text_output" in
    *":12346 closed script_out"*) fail "closed port should not carry script_out" ;;
esac

echo "running JSON --script scan" >&2
json_output=$(./almap -t "$HOST" -p "$PORT" --scan connect --script "$PLUGIN" --timeout 1000 --json)
status=$?
echo "$json_output"
[ "$status" -eq 0 ] || fail "JSON run exited $status"
if ! printf '%s' "$json_output" | python3 -c '
import json, sys
d = json.load(sys.stdin)
assert len(d) == 1 and d[0]["ip"] == "127.0.0.1", d
assert d[0]["port"] == 12345 and d[0]["state"] == "open", d
assert d[0]["scan"] == "connect", d
assert d[0]["script_out"] == "SSH-2.0-OpenSSH_9.6-test", d
'; then
    fail "JSON shape or script_out check failed"
fi

echo "running table --script scan" >&2
table_output=$(./almap -t "$HOST" -p "$PORT" --scan connect --script "$PLUGIN" --timeout 1000 --table)
status=$?
echo "$table_output"
[ "$status" -eq 0 ] || fail "table run exited $status"
table_header=$'IP\tPORT\tSTATE\tSCAN\tSCRIPT'
case "$table_output" in
    *"$table_header"*) ;;
    *) fail "table output missing SCRIPT header" ;;
esac

echo "running XML --script scan" >&2
xml_output=$(./almap -t "$HOST" -p "$PORT" --scan connect --script "$PLUGIN" --timeout 1000 --xml)
status=$?
echo "$xml_output"
[ "$status" -eq 0 ] || fail "XML run exited $status"
if ! printf '%s' "$xml_output" | python3 -c '
import sys
import xml.etree.ElementTree as ET
root = ET.fromstring(sys.stdin.read())
rows = root.findall("./scan/result")
assert len(rows) == 1, rows
assert rows[0].attrib["script_out"] == "SSH-2.0-OpenSSH_9.6-test", rows
assert rows[0].attrib["scan"] == "connect", rows
'; then
    fail "XML script_out check failed"
fi

# Step 30 arsenal: http_title extracts <title> and Server: via --script.
HTTP_PORT=18080
HTTP_LISTENER_PID=""
http_cleanup() {
    if [ -n "$HTTP_LISTENER_PID" ]; then
        kill "$HTTP_LISTENER_PID" 2>/dev/null || true
        wait "$HTTP_LISTENER_PID" 2>/dev/null || true
        HTTP_LISTENER_PID=""
    fi
}
echo "starting http listener on $HOST:$HTTP_PORT" >&2
python3 -c '
import socket, sys, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1])))
s.listen(16)
s.settimeout(20)
end = time.time() + 20
resp = b"HTTP/1.0 200 OK\r\nServer: nginx/1.18.0\r\nAllow: GET, HEAD, OPTIONS\r\n\r\n<html><head><title>Arsenal Test Title</title></head><body>hi</body></html>"
while time.time() < end:
    try:
        c, _ = s.accept()
    except socket.timeout:
        break
    try:
        c.settimeout(5)
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = c.recv(4096)
            if not chunk:
                break
            data += chunk
    except Exception:
        pass
    try:
        c.sendall(resp)
    except Exception:
        pass
    try:
        c.close()
    except Exception:
        pass
s.close()
' "$HTTP_PORT" >/dev/null 2>&1 &
HTTP_LISTENER_PID=$!
sleep 1

echo "running http_title --script scan (text)" >&2
title_output=$(./almap -t "$HOST" -p "$HTTP_PORT" --scan connect --script ./plugins/http_title.so --timeout 1000)
status=$?
echo "$title_output"
[ "$status" -eq 0 ] || fail "http_title text run exited $status"
case "$title_output" in
    *'script_out="'*'Arsenal Test Title'*) ;;
    *) fail "http_title did not extract title" ;;
esac
case "$title_output" in
    *'nginx/1.18.0'*) ;;
    *) fail "http_title did not extract server" ;;
esac

echo "running http_title --script scan (JSON)" >&2
title_json=$(./almap -t "$HOST" -p "$HTTP_PORT" --scan connect --script ./plugins/http_title.so --timeout 1000 --json)
status=$?
echo "$title_json"
[ "$status" -eq 0 ] || fail "http_title JSON run exited $status"
if ! printf '%s' "$title_json" | python3 -c '
import json, sys
d = json.load(sys.stdin)
assert len(d) == 1 and d[0]["state"] == "open", d
assert "Arsenal Test Title" in d[0]["script_out"], d
assert "nginx/1.18.0" in d[0]["script_out"], d
'; then
    fail "http_title JSON script_out check failed"
fi

http_cleanup

echo "integration test passed: AlScript text/JSON/table/XML script_out verified"
