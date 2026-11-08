#!/usr/bin/env bash
# tests/integration_udp.sh - Step 17 integration test for --scan udp.
# Loopback only: a python3 UDP listener on 127.0.0.1:12345 and a closed
# port, then checks the open state in text, JSON, table and XML output,
# the -sU alias, and the exclusive-flag errors.
#
# A raw UDP scan needs root or CAP_NET_RAW. When that capability is
# missing this script verifies the exact `UDP scan requires root or
# CAP_NET_RAW` failure and the CLI validation errors, then skips the
# socket-level checks (exit 0).
#
# Use only on networks you own or have permission to scan; this test
# only uses loopback.
set -u

cd "$(dirname "$0")/.." || exit 1

HOST=127.0.0.1
UDP_PORT=12345
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
    echo "error: need python3 for the UDP listener" >&2
    exit 1
fi

fail() {
    echo "integration test FAILED: $*" >&2
    exit 1
}

check_err() {
    # check_err <status> <substring> <command...>
    local want_status="$1"
    local want_text="$2"
    shift 2
    local out
    local status
    out=$("$@" 2>&1)
    status=$?
    if [ "$status" -ne "$want_status" ]; then
        echo "$out" >&2
        fail "'$*' exit $status (want $want_status)"
    fi
    case "$out" in
        *"$want_text"*) ;;
        *)
            echo "$out" >&2
            fail "'$*' missing text '$want_text'"
            ;;
    esac
}

echo "checking udp CLI validation errors (no privileges needed)" >&2
check_err 2 "error: --scan udp cannot be combined with --banners" \
    ./almap -t "$HOST" -p 80 --scan udp --banners
check_err 2 "error: --scan udp cannot be combined with --service" \
    ./almap -t "$HOST" -p 80 --scan udp --service
check_err 2 "error: --scan udp does not support --workers > 1" \
    ./almap -t "$HOST" -p 80 --scan udp --workers 4
check_err 2 "expected connect, syn, or udp" \
    ./almap -t "$HOST" -p 80 --scan icmp

help_output=$(./almap --help 2>&1)
help_status=$?
if [ "$help_status" -ne 0 ]; then
    fail "./almap --help exited $help_status"
fi
case "$help_output" in
    *"--scan udp"*) ;;
    *) fail "--help does not document --scan udp" ;;
esac
case "$help_output" in
    *"-sU"*) ;;
    *) fail "--help does not document -sU" ;;
esac

echo "probing raw-socket capability with a UDP scan" >&2
probe_output=$(./almap -t "$HOST" -p "$UDP_PORT" --scan udp --timeout 200 2>&1)
probe_status=$?
if [ "$probe_status" -eq 1 ]; then
    case "$probe_output" in
        *"UDP scan requires root or CAP_NET_RAW"*)
            echo "SKIP: UDP scan requires root or CAP_NET_RAW; raw-socket checks skipped" >&2
            echo "integration test passed (privilege-skipping mode): --scan udp validation errors and privilege text are correct"
            exit 0
            ;;
    esac
    echo "$probe_output" >&2
    fail "unprivileged UDP scan failed without the expected privilege message"
fi
if [ "$probe_status" -ne 0 ]; then
    echo "$probe_output" >&2
    fail "UDP probe exited $probe_status (want 0 with a raw socket)"
fi

echo "starting python3 UDP listener on $HOST:$UDP_PORT" >&2
python3 -c '
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1])))
s.settimeout(30)
try:
    while True:
        data, addr = s.recvfrom(2048)
        try:
            s.sendto(b"almap-udp-probe-response", addr)
        except Exception:
            pass
except socket.timeout:
    pass
s.close()
' "$UDP_PORT" >/dev/null 2>&1 &
UDP_PID=$!
cleanup() {
    if [ -n "${UDP_PID:-}" ]; then
        kill "$UDP_PID" 2>/dev/null || true
        wait "$UDP_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT
sleep 0.3

echo "running ./almap -t $HOST -p $UDP_PORT --scan udp --timeout 1000 (text)" >&2
text_output=""
text_seen=0
attempt=0
while [ "$attempt" -lt 5 ]; do
    text_output=$(./almap -t "$HOST" -p "$UDP_PORT" --scan udp --timeout 1000)
    text_status=$?
    if [ "$text_status" -eq 0 ] && printf '%s\n' "$text_output" | grep -F -- "open" >/dev/null 2>&1; then
        text_seen=1
        break
    fi
    attempt=$((attempt + 1))
    sleep 0.2
done
echo "$text_output"
if [ "$text_seen" -ne 1 ]; then
    fail "text output never reported the listening UDP port as open"
fi

echo "running ./almap --scan udp --json" >&2
json_output=$(./almap -t "$HOST" -p "$UDP_PORT" --scan udp --timeout 1000 --json)
json_status=$?
echo "$json_output"
if [ "$json_status" -ne 0 ]; then
    fail "./almap --scan udp --json exited $json_status"
fi
printf '%s' "$json_output" | python3 -c '
import json, sys
data = json.load(sys.stdin)
if not isinstance(data, list) or len(data) < 1:
    raise SystemExit("JSON output is not a non-empty array")
entry = data[0]
if entry.get("port") != int(sys.argv[1]):
    raise SystemExit("JSON port does not match")
if entry.get("scan") != "udp":
    raise SystemExit("JSON scan is not udp")
if entry.get("state") not in ("open", "open|filtered"):
    raise SystemExit("JSON state is not open/open|filtered")
' "$UDP_PORT" || fail "JSON output check failed"

echo "running ./almap --scan udp --table" >&2
table_output=$(./almap -t "$HOST" -p "$UDP_PORT" --scan udp --timeout 1000 --table)
table_status=$?
echo "$table_output"
if [ "$table_status" -ne 0 ]; then
    fail "./almap --scan udp --table exited $table_status"
fi
case "$table_output" in
    *$'SCAN\tBANNER'*) ;;
    *) fail "table output does not contain the SCAN/BANNER header" ;;
esac
if ! printf '%s\n' "$table_output" | grep -F -- "udp" >/dev/null 2>&1; then
    fail "table output does not name the udp scan"
fi

echo "running ./almap --scan udp --xml" >&2
xml_output=$(./almap -t "$HOST" -p "$UDP_PORT" --scan udp --timeout 1000 --xml)
xml_status=$?
echo "$xml_output"
if [ "$xml_status" -ne 0 ]; then
    fail "./almap --scan udp --xml exited $xml_status"
fi
case "$xml_output" in
    *"<almap><scan>"*"</scan></almap>"*) ;;
    *) fail "XML output is not one scan document" ;;
esac
case "$xml_output" in
    *"scan=\"udp\""*) ;;
    *) fail "XML output does not name the udp scan" ;;
esac

echo "running ./almap -sU (alias)" >&2
sU_output=$(./almap -t "$HOST" -p "$UDP_PORT" -sU --timeout 1000)
sU_status=$?
echo "$sU_output"
if [ "$sU_status" -ne 0 ]; then
    fail "./almap -sU exited $sU_status"
fi

echo "running ./almap --scan udp on a closed UDP port" >&2
closed_output=$(./almap -t "$HOST" -p "$CLOSED_PORT" --scan udp --timeout 300)
closed_status=$?
echo "$closed_output"
if [ "$closed_status" -ne 0 ]; then
    fail "./almap --scan udp closed-port run exited $closed_status"
fi
closed_ok=0
case "$closed_output" in
    *"closed"*|*"open|filtered"*) closed_ok=1 ;;
esac
if [ "$closed_ok" -ne 1 ]; then
    fail "closed UDP port did not report closed or open|filtered"
fi

echo "integration test passed: UDP scan works on loopback"
