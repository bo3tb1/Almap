#!/usr/bin/env bash
# tests/integration_sigdb.sh - Step 25 external signature DB test.
# Loopback only, no root: runs the C regex unit tests, writes temporary
# DBs with REGEX and EXACT signatures, scans a python3 listener, and
# verifies regex matching, first-match precedence, the shipped
# signatures.db, JSON shape, and the CLI errors.
set -u

cd "$(dirname "$0")/.." || exit 1

HOST=127.0.0.1
PORT=12345
CC=${CC:-gcc}

if ! command -v python3 >/dev/null 2>&1; then
    echo "error: need python3 for the listener" >&2
    exit 1
fi
if [ ! -f ./signatures.db ]; then
    echo "error: shipped signatures.db not found" >&2
    exit 1
fi

mkdir -p /tmp/opencode

# C regex layer unit tests (Step 25). No network or root needed.
echo "building and running C regex unit tests" >&2
$CC -std=c99 -Wall -Wextra -pthread -Ic tests/test_sigdb_regex.c c/sigdb.c \
    -o /tmp/opencode/test_sigdb_regex || exit 1
/tmp/opencode/test_sigdb_regex || exit 1

if [ ! -x ./almap ]; then
    echo "building ./almap ..." >&2
    goose build almap.goose --cc gcc || exit 1
fi
if [ ! -x ./almap ]; then
    echo "error: ./almap not found after build" >&2
    exit 1
fi

# CLI validation (no listener needed).
./almap -t "$HOST" -p "$PORT" --scan connect --sigdb /tmp/nonexistent_db_12345.db >/dev/null 2>&1
if [ $? -ne 2 ]; then
    echo "integration test FAILED: --sigdb without --service did not exit 2" >&2
    exit 1
fi
./almap -t "$HOST" -p "$PORT" --scan connect --service --sigdb /tmp/nonexistent_db_12345.db >/dev/null 2>&1
if [ $? -ne 1 ]; then
    echo "integration test FAILED: missing --sigdb file did not exit 1" >&2
    exit 1
fi

DB=/tmp/opencode/test_sigdb.db
EXACT_DB=/tmp/opencode/test_sigdb_exact.db
cat > "$DB" <<'DBEOF'
# Step 25 custom test signatures: REGEX first, then EXACT.
REGEX|any|^(ACME|WIDGET)-[0-9]+\.[0-9]+|acme-regex
EXACT|any|ACME-2.0|acme-exact
DBEOF
cat > "$EXACT_DB" <<'DBEOF'
# Step 25 EXACT-only fallback check.
EXACT|any|ACME-2.0|acme-exact
REGEX|any|^NOPE-[0-9]+|nope
DBEOF

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
            c.sendall(b"ACME-2.0 test banner\n")
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

echo "running --service --sigdb with REGEX-first DB" >&2
text_output=$(./almap -t "$HOST" -p "$PORT" --scan connect --service --sigdb "$DB" --timeout 1000)
status=$?
echo "$text_output"
[ "$status" -eq 0 ] || fail "regex DB run exited $status"
case "$text_output" in
    *'service="acme-regex"'*) ;;
    *) fail "REGEX signature with alternation did not match first" ;;
esac
case "$text_output" in
    *'acme-exact'*) fail "EXACT signature should not have produced output" ;;
esac

echo "running --service --sigdb with EXACT-only DB" >&2
exact_output=$(./almap -t "$HOST" -p "$PORT" --scan connect --service --sigdb "$EXACT_DB" --timeout 1000)
status=$?
echo "$exact_output"
[ "$status" -eq 0 ] || fail "exact DB run exited $status"
case "$exact_output" in
    *'service="acme-exact"'*) ;;
    *) fail "EXACT signature did not match after non-matching REGEX" ;;
esac

echo "running --service --sigdb with shipped signatures.db" >&2
# Without a custom ACME line, the default DB falls back to the
# banner text for this banner (no ACME-2.0 entry in the shipped file).
shipped_output=$(./almap -t "$HOST" -p "$PORT" --scan connect --service --sigdb ./signatures.db --timeout 1000)
status=$?
echo "$shipped_output"
[ "$status" -eq 0 ] || fail "shipped DB run exited $status"
case "$shipped_output" in
    *"$HOST:$PORT open"*) ;;
    *) fail "shipped DB output missing open line" ;;
esac

echo "running JSON --sigdb check" >&2
json_output=$(./almap -t "$HOST" -p "$PORT" --scan connect --service --sigdb "$DB" --timeout 1000 --json)
status=$?
echo "$json_output"
[ "$status" -eq 0 ] || fail "JSON run exited $status"
if ! printf '%s' "$json_output" | python3 -c '
import json, sys
d = json.load(sys.stdin)
assert len(d) == 1 and d[0]["ip"] == "127.0.0.1", d
assert d[0]["service"] == "acme-regex", d
'; then
    fail "JSON service / REGEX DB shape failed"
fi

echo "integration test passed: C regex units, REGEX alternation precedence, EXACT fallback, shipped DB, CLI errors verified"
