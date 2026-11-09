#!/usr/bin/env bash
# tests/integration_web.sh - Step 28 Web UI test.
# Loopback only: starts the ALmap Web UI, checks GET /api/status
# (health), GET / (HTML contains ALmap Web UI), and POST /api/scan
# (connect scan of a python listener through the JSON API, plus a
# 400 on an invalid request and a 404 on an unknown path).
# Use only on networks you own or have permission to scan; this test
# only uses loopback.
set -u

cd "$(dirname "$0")/.." || exit 1

WEB_PORT=18081
SCAN_PORT=18082
HOST=127.0.0.1

if [ ! -x ./almap ]; then
    echo "building ./almap ..." >&2
    goose build almap.goose --cc gcc || exit 1
fi
if [ ! -x ./almap ]; then
    echo "error: ./almap not found after build" >&2
    exit 1
fi
if ! command -v curl >/dev/null 2>&1; then
    echo "error: need curl for the Web UI test" >&2
    exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "error: need python3 for the listener" >&2
    exit 1
fi

WEB_PID=""
LISTENER_PID=""
cleanup() {
    if [ -n "$WEB_PID" ]; then
        kill "$WEB_PID" 2>/dev/null || true
        wait "$WEB_PID" 2>/dev/null || true
        WEB_PID=""
    fi
    if [ -n "$LISTENER_PID" ]; then
        kill "$LISTENER_PID" 2>/dev/null || true
        wait "$LISTENER_PID" 2>/dev/null || true
        LISTENER_PID=""
    fi
}
trap cleanup EXIT

fail() {
    echo "FAIL: $1" >&2
    exit 1
}

echo "starting python3 listener on $HOST:$SCAN_PORT" >&2
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
' "$SCAN_PORT" >/dev/null 2>&1 &
LISTENER_PID=$!

echo "starting ./almap --web on $HOST:$WEB_PORT" >&2
./almap --web --web-port "$WEB_PORT" >/tmp/integration_web.log 2>&1 &
WEB_PID=$!
sleep 2

# Health check: the server must respond on the requested port.
STATUS=$(curl -s -o /tmp/web_status.out -w "%{http_code}" "http://$HOST:$WEB_PORT/api/status" 2>/dev/null) || fail "curl /api/status failed"
[ "$STATUS" = "200" ] || fail "expected 200 on /api/status, got $STATUS"
grep -q '"status":"ok"' /tmp/web_status.out || fail "/api/status missing status ok"
grep -q '"version":"5.0.0"' /tmp/web_status.out || fail "/api/status missing version 5.0.0"
echo "GET /api/status OK" >&2

# Index page: HTML shell with the scan form and terminal output.
INDEX=$(curl -s -o /tmp/web_index.out -w "%{http_code}" "http://$HOST:$WEB_PORT/" 2>/dev/null) || fail "curl / failed"
[ "$INDEX" = "200" ] || fail "expected 200 on /, got $INDEX"
grep -q "ALmap Web UI" /tmp/web_index.out || fail "/ missing ALmap Web UI"
grep -q "/api/scan" /tmp/web_index.out || fail "/ missing /api/scan JS"
echo "GET / OK" >&2

# Scan: POST JSON connect scan against the listener, expect open.
SCAN_CODE=$(curl -s -o /tmp/web_scan.out -w "%{http_code}" -X POST "http://$HOST:$WEB_PORT/api/scan" -H "Content-Type: application/json" -d "{\"targets\":\"$HOST\",\"ports\":\"$SCAN_PORT\",\"scan_type\":\"connect\",\"timeout\":1000}" 2>/dev/null) || fail "curl /api/scan failed"
[ "$SCAN_CODE" = "200" ] || fail "expected 200 on /api/scan, got $SCAN_CODE: $(cat /tmp/web_scan.out)"
grep -q "\"ip\":\"$HOST\"" /tmp/web_scan.out || fail "/api/scan missing ip"
grep -q '"state":"open"' /tmp/web_scan.out || fail "/api/scan missing open state"
echo "POST /api/scan connect OK" >&2

# Invalid scan: missing targets must be 400 with an error field.
BAD_CODE=$(curl -s -o /tmp/web_bad.out -w "%{http_code}" -X POST "http://$HOST:$WEB_PORT/api/scan" -H "Content-Type: application/json" -d '{"ports":"80"}' 2>/dev/null) || fail "curl bad scan failed"
[ "$BAD_CODE" = "400" ] || fail "expected 400 on invalid scan, got $BAD_CODE"
grep -q '"error"' /tmp/web_bad.out || fail "invalid scan missing error field"
echo "POST /api/scan invalid -> 400 OK" >&2

# Unknown path must be 404.
NOTFOUND=$(curl -s -o /tmp/web_404.out -w "%{http_code}" "http://$HOST:$WEB_PORT/does-not-exist" 2>/dev/null) || fail "curl 404 failed"
[ "$NOTFOUND" = "404" ] || fail "expected 404 on unknown path, got $NOTFOUND"
echo "GET unknown -> 404 OK" >&2

echo "ok: web ui / status / scan / errors" >&2
exit 0
