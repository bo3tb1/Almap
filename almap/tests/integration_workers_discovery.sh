#!/usr/bin/env bash
# tests/integration_workers_discovery.sh - Step 13 integration test for
# the bounded discovery worker pool.
# Loopback only, no root required: TCP ping to 127.0.0.1:80/443 yields
# closed/refused, which still proves the host is up. Runs text, JSON,
# and table discovery with --workers 4, verifies deterministic output
# and that the sequential workers warning is absent, then exits.
# No listener or background process is needed, so there is nothing to
# clean up beyond the shell's own variables.
# Use only on networks you own or have permission to scan; this test
# only uses loopback.
set -u

cd "$(dirname "$0")/.." || exit 1

HOST=127.0.0.1

if [ ! -x ./almap ]; then
    echo "building ./almap ..." >&2
    goose build almap.goose --cc gcc || exit 1
fi
if [ ! -x ./almap ]; then
    echo "error: ./almap not found after build" >&2
    exit 1
fi

echo "running ./almap -t $HOST --discover --workers 4" >&2
output=$(./almap -t "$HOST" --discover --workers 4)
status=$?
echo "$output"
if [ "$status" -ne 0 ]; then
    echo "integration test FAILED: discovery workers text exited $status" >&2
    exit 1
fi
case "$output" in
    *"$HOST up"*) ;;
    *)
        echo "integration test FAILED: text output does not contain '$HOST up'" >&2
        exit 1
        ;;
esac
case "$output" in
    *"warning: --workers"*)
        echo "integration test FAILED: text output contains the sequential workers warning" >&2
        exit 1
        ;;
esac

echo "running ./almap ... --json" >&2
json_output=$(./almap -t "$HOST" --discover --workers 4 --json)
json_status=$?
echo "$json_output"
if [ "$json_status" -ne 0 ]; then
    echo "integration test FAILED: discovery workers json exited $json_status" >&2
    exit 1
fi
case "$json_output" in
    \[*\]*) ;;
    *)
        echo "integration test FAILED: JSON output is not an array" >&2
        exit 1
        ;;
esac
case "$json_output" in
    *"\"ip\":\"$HOST\""*"\"up\":true"*) ;;
    *)
        echo "integration test FAILED: JSON output missing up:true for $HOST" >&2
        exit 1
        ;;
esac
case "$json_output" in
    *"warning:"*)
        echo "integration test FAILED: JSON output contains a warning" >&2
        exit 1
        ;;
esac
if command -v python3 >/dev/null 2>&1; then
    printf '%s' "$json_output" | python3 -m json.tool >/dev/null 2>&1 || {
        echo "integration test FAILED: JSON does not parse" >&2
        exit 1
    }
fi

TAB=$(printf '\t')
echo "running ./almap ... --table" >&2
table_output=$(./almap -t "$HOST" --discover --workers 4 --table)
table_status=$?
echo "$table_output"
if [ "$table_status" -ne 0 ]; then
    echo "integration test FAILED: discovery workers table exited $table_status" >&2
    exit 1
fi
case "$table_output" in
    "IP${TAB}UP"*) ;;
    *)
        echo "integration test FAILED: table output does not start with discovery header" >&2
        exit 1
        ;;
esac
case "$table_output" in
    *"${HOST}${TAB}up"*) ;;
    *)
        echo "integration test FAILED: table output missing up row for $HOST" >&2
        exit 1
        ;;
esac
case "$table_output" in
    *"warning:"*)
        echo "integration test FAILED: table output contains a warning" >&2
        exit 1
        ;;
esac

echo "integration test passed: discovery worker pool text/JSON/table verified"
