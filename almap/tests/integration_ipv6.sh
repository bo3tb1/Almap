#!/usr/bin/env bash
# tests/integration_ipv6.sh - Step 18 limited IPv6 integration test.
#
# Loopback only (::1). IPv6 is supported for --scan connect and
# --discover only; SYN, UDP, banners, and service detection must reject
# IPv6 targets with "not implemented for IPv6" and exit 2.
#
# If the loopback IPv6 stack or python3 is unavailable the script skips
# with exit 0 (no network, no root needed otherwise).

set -u
cd "$(dirname "$0")/.."

fail() {
    echo "FAIL: $1" >&2
    exit 1
}

check_err() {
    expected_code=$1
    needle=$2
    shift 2
    out=$("$@" 2>&1)
    rc=$?
    [ "$rc" -eq "$expected_code" ] || fail "expected exit $expected_code, got $rc: $*"
    case "$out" in
        *"$needle"*) ;;
        *) fail "missing [$needle] in: $out" ;;
    esac
}

if ! command -v python3 >/dev/null 2>&1; then
    echo "SKIP: python3 not found; IPv6 listener checks skipped"
    exit 0
fi

if [ ! -x ./almap ]; then
    GOOSE_STDLIB="${GOOSE_STDLIB:-$HOME/Downloads/goose-v2026.3-linux-x64/stdlib}" \
        goose build almap.goose --cc gcc -o almap || fail "goose build failed"
fi

# Probe ::1 availability with Python before requiring anything else.
if ! python3 - <<'PY' 2>/dev/null
import socket
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.bind(("::1", 0))
s.close()
PY
then
    echo "SKIP: IPv6 loopback ::1 is unavailable"
    exit 0
fi

PORT=12345

cleanup() {
    if [ -n "${LISTENER_PID:-}" ]; then
        kill "$LISTENER_PID" 2>/dev/null || true
        wait "$LISTENER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

python3 - "$PORT" <<'PY' &
import socket
import sys

port = int(sys.argv[1])
srv = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("::1", port))
srv.listen(16)
while True:
    try:
        conn, _ = srv.accept()
    except Exception:
        break
    conn.close()
PY
LISTENER_PID=$!

ready=0
i=0
while [ "$i" -lt 60 ]; do
    if python3 - "$PORT" <<'PY' 2>/dev/null
import socket
import sys
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.settimeout(0.1)
s.connect(("::1", int(sys.argv[1])))
s.close()
PY
    then
        ready=1
        break
    fi
    sleep 0.05
    i=$((i + 1))
done
[ "$ready" -eq 1 ] || fail "IPv6 listener on [::1]:$PORT did not start"

# 1. Text connect: bracketed address, plain state.
out=$(./almap -t ::1 -p "$PORT" --scan connect --timeout 1000 2>&1)
rc=$?
[ "$rc" -eq 0 ] || fail "IPv6 connect exit $rc: $out"
case "$out" in
    *"[::1]:$PORT open"*) ;;
    *) fail "IPv6 text output missing [::1]:$PORT open: $out" ;;
esac

# 2. JSON connect: plain address, no brackets, parseable array.
json=$(./almap -t ::1 -p "$PORT" --scan connect --timeout 1000 --json 2>&1)
rc=$?
[ "$rc" -eq 0 ] || fail "IPv6 JSON connect exit $rc: $json"
python3 - "$PORT" "$json" <<'PY' || exit 1
import json
import sys

port = int(sys.argv[1])
data = json.loads(sys.argv[2])
assert isinstance(data, list) and len(data) == 1, data
item = data[0]
assert item["ip"] == "::1", item
assert item["port"] == port, item
assert item["state"] == "open", item
assert item["scan"] == "connect", item
PY
case "$json" in
    *"[::1]"*) fail "JSON must use the plain IPv6 address" ;;
esac

# 3. Table connect: bracketed host, standard five-column header.
table=$(./almap -t ::1 -p "$PORT" --scan connect --timeout 1000 --table 2>&1)
rc=$?
[ "$rc" -eq 0 ] || fail "IPv6 table connect exit $rc: $table"
case "$table" in
    *$'IP\tPORT\tSTATE\tSCAN\tBANNER'*) ;;
    *) fail "IPv6 table header missing: $table" ;;
esac
case "$table" in
    *$'[::1]\t'"$PORT"$'\topen\tconnect'*) ;;
    *) fail "IPv6 table row missing: $table" ;;
esac

# 4. XML connect: plain address in the attribute.
xml=$(./almap -t ::1 -p "$PORT" --scan connect --timeout 1000 --xml 2>&1)
rc=$?
[ "$rc" -eq 0 ] || fail "IPv6 XML connect exit $rc: $xml"
case "$xml" in
    *"<almap><scan>"*) ;;
    *) fail "IPv6 XML missing scan document: $xml" ;;
esac
case "$xml" in
    *"<result ip=\"::1\" port=\"$PORT\" state=\"open\" scan=\"connect\"/>"*) ;;
    *) fail "IPv6 XML result missing: $xml" ;;
esac

# 5. CIDR /128 is one host and behaves like the plain address.
cidr=$(./almap -t ::1/128 -p "$PORT" --scan connect --timeout 1000 2>&1)
rc=$?
[ "$rc" -eq 0 ] || fail "IPv6 /128 connect exit $rc: $cidr"
case "$cidr" in
    *"[::1]:$PORT open"*) ;;
    *) fail "IPv6 /128 output missing: $cidr" ;;
esac

# 6. Discovery: TCP-only IPv6 detection over loopback.
disc=$(./almap -t ::1 --discover --timeout 500 2>&1)
rc=$?
[ "$rc" -eq 0 ] || fail "IPv6 discovery exit $rc: $disc"
case "$disc" in
    *"[::1] up"*) ;;
    *) fail "IPv6 discovery missing [::1] up: $disc" ;;
esac
disc_json=$(./almap -t ::1 --discover --timeout 500 --json 2>&1)
case "$disc_json" in
    *'"ip":"::1"'*'"up":true'*) ;;
    *) fail "IPv6 discovery JSON missing plain ip/up: $disc_json" ;;
esac
disc_table=$(./almap -t ::1 --discover --timeout 500 --table 2>&1)
case "$disc_table" in
    *$'[::1]\tup'*) ;;
    *) fail "IPv6 discovery table row missing: $disc_table" ;;
esac

# 7. Mixed list keeps input order (IPv4 first, then IPv6).
mixed=$(./almap -t 127.0.0.1,::1 -p "$PORT" --scan connect --timeout 1000 --json 2>&1)
rc=$?
[ "$rc" -eq 0 ] || fail "mixed connect exit $rc: $mixed"
python3 - "$mixed" <<'PY' || exit 1
import json
import sys

data = json.loads(sys.argv[1])
assert isinstance(data, list) and len(data) == 2, data
assert data[0]["ip"] == "127.0.0.1", data
assert data[1]["ip"] == "::1", data
PY

# 8. -iL with mixed family targets preserves file order.
tmp_targets=$(mktemp /tmp/almap-ipv6-targets.XXXXXX)
printf '# mixed families\n127.0.0.1\n\n::1\n' > "$tmp_targets"
il_out=$(./almap -iL "$tmp_targets" -p "$PORT" --scan connect --timeout 1000 2>&1)
rc=$?
rm -f "$tmp_targets"
[ "$rc" -eq 0 ] || fail "-iL mixed connect exit $rc: $il_out"
case "$il_out" in
    *"127.0.0.1:$PORT"*"[::1]:$PORT"*) ;;
    *) fail "-iL mixed order missing: $il_out" ;;
esac

# 9. IPv6 is rejected for SYN, UDP, banners, and service detection.
check_err 2 "error: syn scan not implemented for IPv6" ./almap -t ::1 -p 80 --scan syn
check_err 2 "error: udp scan not implemented for IPv6" ./almap -t ::1 -p 80 --scan udp
check_err 2 "error: service detection not implemented for IPv6" ./almap -t ::1 -p 80 --service
check_err 2 "error: banner grabbing not implemented for IPv6" ./almap -t ::1 -p 80 --banners

# 10. IPv6 CIDR host limit: /111 is too large for this step.
check_err 1 "CIDR prefix too large for this step; use /24 (IPv4) or /112 (IPv6) or smaller range" ./almap -t 2001:db8::/111 -p 80 --scan connect

echo "integration test passed: limited IPv6 connect/discovery, bracketed output, mixed lists and family errors work"
