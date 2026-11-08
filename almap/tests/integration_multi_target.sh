#!/usr/bin/env bash
# tests/integration_multi_target.sh - Step 15 integration test for
# multiple targets.
# Loopback only, no root required. Starts a python3 listener on
# 127.0.0.1:12345, then checks:
#   - -t accepts a comma-separated list and scans targets in input order
#   - -t accepts a CIDR and enumerates its hosts ascending
#   - -iL reads targets from a file (comments/blank lines ignored)
#   - -iL and -t cannot be combined (exit 2, exact error)
#   - more than 64 targets are rejected (exit 1, exact error)
#   - invalid target lines in an -iL file are rejected (exit 1)
#   - a comment-only -iL file is rejected (exit 1)
#   - --json output is one array and result order follows targets, then
#     hosts, then ports
# Use only on networks you own or have permission to scan; this test
# only uses loopback.
set -u

cd "$(dirname "$0")/.." || exit 1

HOST=127.0.0.1
HOST2=127.0.0.2
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
    echo "error: need python3 for the listener and JSON checks" >&2
    exit 1
fi

TMP_TARGETS="$(mktemp "${TMPDIR:-/tmp}/almap-targets.XXXXXX")" || exit 1
LISTENER_PID=""
cleanup() {
    if [ -n "$LISTENER_PID" ]; then
        kill "$LISTENER_PID" 2>/dev/null || true
        wait "$LISTENER_PID" 2>/dev/null || true
        LISTENER_PID=""
    fi
    rm -f "$TMP_TARGETS"
}
trap cleanup EXIT

echo "starting python3 listener on $HOST:$PORT" >&2
python3 -c '
import socket, sys
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1])))
s.listen(5)
s.settimeout(30)
try:
    while True:
        c, _ = s.accept()
        c.close()
except socket.timeout:
    pass
s.close()
' "$PORT" >/dev/null 2>&1 &
LISTENER_PID=$!

sleep 1

json_check() {
    # $1 = raw json, $2 = expected json array as python literal, $3 = label
    python3 - "$1" "$2" "$3" <<'PY'
import json, sys
raw, expected, label = sys.argv[1], sys.argv[2], sys.argv[3]
data = json.loads(raw)
want = eval(expected)
if data != want:
    sys.stderr.write("FAILED: %s: got %r want %r\n" % (label, data, want))
    sys.exit(1)
print("ok: %s" % label)
PY
}

echo "running ./almap -t $HOST2,$HOST -p $PORT --scan connect --json" >&2
out=$(./almap -t "$HOST2,$HOST" -p "$PORT" --scan connect --json --timeout 1000)
status=$?
echo "$out"
if [ "$status" -ne 0 ]; then
    echo "integration test FAILED: comma target list exited $status" >&2
    exit 1
fi
json_check "$out" "[{'ip': '$HOST2', 'port': $PORT, 'state': 'closed', 'scan': 'connect'}, {'ip': '$HOST', 'port': $PORT, 'state': 'open', 'scan': 'connect'}]" \
    "-t list preserves input order" || exit 1

echo "running ./almap -t 127.0.0.0/30 -p $PORT --scan connect --json" >&2
out=$(./almap -t "127.0.0.0/30" -p "$PORT" --scan connect --json --timeout 1000)
status=$?
echo "$out"
if [ "$status" -ne 0 ]; then
    echo "integration test FAILED: CIDR target exited $status" >&2
    exit 1
fi
json_check "$out" "[{'ip': '$HOST', 'port': $PORT, 'state': 'open', 'scan': 'connect'}, {'ip': '$HOST2', 'port': $PORT, 'state': 'closed', 'scan': 'connect'}]" \
    "-t CIDR enumerates hosts ascending" || exit 1

printf '# a comment\n\n%s\n   %s  \n' "$HOST2" "$HOST" > "$TMP_TARGETS"
echo "running ./almap -iL $TMP_TARGETS -p $PORT --scan connect --json" >&2
out=$(./almap -iL "$TMP_TARGETS" -p "$PORT" --scan connect --json --timeout 1000)
status=$?
echo "$out"
if [ "$status" -ne 0 ]; then
    echo "integration test FAILED: -iL exited $status" >&2
    exit 1
fi
json_check "$out" "[{'ip': '$HOST2', 'port': $PORT, 'state': 'closed', 'scan': 'connect'}, {'ip': '$HOST', 'port': $PORT, 'state': 'open', 'scan': 'connect'}]" \
    "-iL preserves file order and skips comments/blanks" || exit 1

echo "running ./almap -t $HOST -iL $TMP_TARGETS -p $PORT (must fail)" >&2
combo=$(./almap -t "$HOST" -iL "$TMP_TARGETS" -p "$PORT" 2>&1)
combo_status=$?
echo "$combo"
if [ "$combo_status" -ne 2 ]; then
    echo "integration test FAILED: -t with -iL exited $combo_status (expected 2)" >&2
    exit 1
fi
case "$combo" in
    *"error: -t and -iL cannot be combined"*) ;;
    *)
        echo "integration test FAILED: -t with -iL lacks the cannot-be-combined error" >&2
        exit 1
        ;;
esac

echo "running ./almap with 65 -t targets (must fail)" >&2
many=$(python3 -c 'print(",".join("127.0.0.%d" % i for i in range(1, 66)))')
many_out=$(./almap -t "$many" -p "$PORT" 2>&1)
many_status=$?
echo "$many_out"
if [ "$many_status" -ne 1 ]; then
    echo "integration test FAILED: 65 targets exited $many_status (expected 1)" >&2
    exit 1
fi
case "$many_out" in
    *"error: too many targets in -t list (max 64)"*) ;;
    *)
        echo "integration test FAILED: 65 targets lacks the max-64 error" >&2
        exit 1
        ;;
esac

printf '%s\nnot-a-target\n' "$HOST" > "$TMP_TARGETS"
echo "running ./almap -iL with an invalid line (must fail)" >&2
bad_out=$(./almap -iL "$TMP_TARGETS" -p "$PORT" 2>&1)
bad_status=$?
echo "$bad_out"
if [ "$bad_status" -ne 1 ]; then
    echo "integration test FAILED: invalid -iL line exited $bad_status (expected 1)" >&2
    exit 1
fi
case "$bad_out" in
    *"error: invalid target in -iL file"*) ;;
    *)
        echo "integration test FAILED: invalid -iL line lacks the invalid-target error" >&2
        exit 1
        ;;
esac

printf '# comments only\n\n' > "$TMP_TARGETS"
echo "running ./almap -iL with only comments (must fail)" >&2
empty_out=$(./almap -iL "$TMP_TARGETS" -p "$PORT" 2>&1)
empty_status=$?
echo "$empty_out"
if [ "$empty_status" -ne 1 ]; then
    echo "integration test FAILED: comment-only -iL exited $empty_status (expected 1)" >&2
    exit 1
fi
case "$empty_out" in
    *"error: no targets found in -iL file"*) ;;
    *)
        echo "integration test FAILED: comment-only -iL lacks the no-targets error" >&2
        exit 1
        ;;
esac

echo "running ./almap -t $HOST,$HOST2 -p $PORT --xml" >&2
xml_out=$(./almap -t "$HOST,$HOST2" -p "$PORT" --scan connect --xml --timeout 1000)
xml_status=$?
echo "$xml_out"
if [ "$xml_status" -ne 0 ]; then
    echo "integration test FAILED: multi-target XML exited $xml_status" >&2
    exit 1
fi
case "$xml_out" in
    "<almap><scan>"*"</scan></almap>") ;;
    *)
        echo "integration test FAILED: multi-target XML is not a single document" >&2
        exit 1
        ;;
esac
if ! printf "%s" "$xml_out" | python3 -c 'import sys, xml.etree.ElementTree as ET; ET.fromstring(sys.stdin.read())'; then
    echo "integration test FAILED: multi-target XML does not parse with ElementTree" >&2
    exit 1
fi

echo "integration test passed: lists, CIDRs, -iL, ordering and errors behave"
