#!/usr/bin/env bash
# tests/integration_discovery.sh - Step 7 integration test for discovery.
# Loopback only: runs ./almap -t 127.0.0.1 --discover and expects
# `127.0.0.1 up` (TCP ping to 80/443 on loopback yields closed = up).
# Does not require ICMP or root: ICMP unavailability falls back to
# TCP ping only. Runs with --json and validates the JSON shape with
# python3 -m json.tool when available.
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

echo "running ./almap -t $HOST --discover" >&2
output=$(./almap -t "$HOST" --discover)
status=$?
echo "$output"
if [ "$status" -ne 0 ]; then
    echo "integration test FAILED: ./almap exited $status" >&2
    exit 1
fi
case "$output" in
    *"$HOST up"*)
        ;;
    *)
        echo "integration test FAILED: output does not contain '$HOST up'" >&2
        exit 1
        ;;
esac

echo "running ./almap -t $HOST --discover --json" >&2
json_output=$(./almap -t "$HOST" --discover --json)
json_status=$?
echo "$json_output"
if [ "$json_status" -ne 0 ]; then
    echo "integration test FAILED: ./almap --discover --json exited $json_status" >&2
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
    *'"up":true'*)
        ;;
    *)
        echo "integration test FAILED: JSON output does not contain up true" >&2
        exit 1
        ;;
esac
case "$json_output" in
    *"warning:"*)
        echo "integration test FAILED: JSON output contains a warning line" >&2
        exit 1
        ;;
esac
if command -v python3 >/dev/null 2>&1; then
    if ! printf "%s" "$json_output" | python3 -m json.tool >/dev/null 2>&1; then
        echo "integration test FAILED: JSON output does not parse as JSON" >&2
        exit 1
    fi
fi
echo "integration test passed: output contains up"
