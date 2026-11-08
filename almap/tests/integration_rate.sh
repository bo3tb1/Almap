#!/usr/bin/env bash
# tests/integration_rate.sh - Step 9 integration test for rate limiting.
# Loopback only, no root needed: connect scan on closed ports.
# Times --rate 5 vs --rate 0 over -p 1-20; expects the rate-limited
# run to take at least ~3s and the unlimited run to finish sooner.
# If date +%s%N is unavailable, skips the timing assertion.
# Use only on networks you own or have permission to scan; this test
# only uses loopback.
set -u

cd "$(dirname "$0")/.." || exit 1

if [ ! -x ./almap ]; then
    echo "building ./almap ..." >&2
    goose build almap.goose --cc gcc || exit 1
fi
if [ ! -x ./almap ]; then
    echo "error: ./almap not found after build" >&2
    exit 1
fi

# Check nanosecond timing is available.
start_probe=$(date +%s%N 2>/dev/null || echo "unavailable")
case "$start_probe" in
    *[!0-9]*|"")
        echo "skipping timing assertion: date +%s%N unavailable"
        ./almap -t 127.0.0.1 -p 1-20 --scan connect --rate 5 --timeout 100 >/dev/null || exit 1
        ./almap -t 127.0.0.1 -p 1-20 --scan connect --rate 0 --timeout 100 >/dev/null || exit 1
        echo "integration test passed: timing skipped"
        exit 0
        ;;
esac

echo "running rate 5 ..." >&2
start_ns=$(date +%s%N)
./almap -t 127.0.0.1 -p 1-20 --scan connect --rate 5 --timeout 100 >/dev/null
status=$?
end_ns=$(date +%s%N)
if [ "$status" -ne 0 ]; then
    echo "integration test FAILED: rate 5 run exited $status" >&2
    exit 1
fi
elapsed_ns=$((end_ns - start_ns))
echo "rate 5 elapsed_ns=$elapsed_ns" >&2
# Expect at least 3 seconds (19 intervals * 200ms = 3.8s nominal).
if [ "$elapsed_ns" -lt 3000000000 ]; then
    echo "integration test FAILED: rate 5 elapsed ${elapsed_ns}ns < 3s" >&2
    exit 1
fi

echo "running rate 0 ..." >&2
start_fast=$(date +%s%N)
./almap -t 127.0.0.1 -p 1-20 --scan connect --rate 0 --timeout 100 >/dev/null
status=$?
end_fast=$(date +%s%N)
if [ "$status" -ne 0 ]; then
    echo "integration test FAILED: rate 0 run exited $status" >&2
    exit 1
fi
elapsed_fast=$((end_fast - start_fast))
echo "rate 0 elapsed_ns=$elapsed_fast" >&2
if [ "$elapsed_fast" -ge "$elapsed_ns" ]; then
    echo "integration test FAILED: rate 0 ($elapsed_fast) not faster than rate 5 ($elapsed_ns)" >&2
    exit 1
fi

echo "integration test passed: rate limiting slowed the scan as expected"
