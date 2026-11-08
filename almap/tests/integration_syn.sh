#!/usr/bin/env bash
# tests/integration_syn.sh - Step 5 integration test for TCP SYN scan.
# Loopback only: starts a listener on 127.0.0.1:12345, scans it with
# ./almap --scan syn, and checks the output contains `open`.
# Listener: prefers `nc -l`, then ncat, then python3 (similar fallback).
# Skips with a clear message if not root and CAP_NET_RAW is unavailable.
# Step 21: also exercises --fragment (CLI parsing is always checked even
# when the raw scan itself requires privileges).
# Use only on networks you own or have permission to scan; this test
# only uses loopback.
set -u

cd "$(dirname "$0")/.." || exit 1

HOST=127.0.0.1
PORT=12345

# Step 21 CLI parsing checks (no privileges needed): evasion flags
# must be accepted with --scan syn/connect and rejected with UDP.
if [ ! -x ./almap ]; then
    goose build almap.goose --cc gcc || exit 1
fi
./almap -t "$HOST" -p "$PORT" --scan udp --fragment >/dev/null 2>&1
if [ $? -ne 2 ]; then
    echo "integration test FAILED: --fragment with --scan udp did not exit 2" >&2
    exit 1
fi
./almap -t "$HOST" -p "$PORT" --scan udp --fragment 2>&1 | grep -F "error: evasion flags require --scan syn or --scan connect" >/dev/null || {
    echo "integration test FAILED: --fragment UDP error message mismatch" >&2
    exit 1
}
./almap -t "$HOST" -p "$PORT" --scan connect --fast --fragment >/dev/null 2>&1
if [ $? -ne 2 ]; then
    echo "integration test FAILED: --fragment with --fast did not exit 2" >&2
    exit 1
fi
./almap -t "$HOST" -p "$PORT" --scan udp --mtu 30 >/dev/null 2>&1
if [ $? -ne 2 ]; then
    echo "integration test FAILED: invalid --mtu 30 did not exit 2" >&2
    exit 1
fi
./almap -t "$HOST" -p "$PORT" --scan udp --decoys 10.0.0.1,10.0.0.2 >/dev/null 2>&1
if [ $? -ne 2 ]; then
    echo "integration test FAILED: --decoys with --scan udp did not exit 2" >&2
    exit 1
fi
./almap -t "$HOST" -p "$PORT" --scan udp --spoof-mac AA:BB:CC:DD:EE:FF >/dev/null 2>&1
if [ $? -ne 2 ]; then
    echo "integration test FAILED: --spoof-mac with --scan udp did not exit 2" >&2
    exit 1
fi
./almap -t "$HOST" -p "$PORT" --scan connect --mtu 32 --json >/dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "integration test FAILED: --mtu 32 with --scan connect did not exit 0" >&2
    exit 1
fi
echo "evasion CLI parsing checks passed" >&2

# Privilege check: probe whether a raw socket can be created here.
# This mirrors almap_syn_can_raw() (socket(AF_INET, SOCK_RAW, TCP)).
# A Python probe reflects the calling process's effective capabilities.
if command -v python3 >/dev/null 2>&1; then
    if ! python3 -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP); s.close()' >/dev/null 2>&1; then
        echo "skipping SYN integration test: not root and CAP_NET_RAW is unavailable"
        exit 0
    fi
elif [ "$(id -u)" -ne 0 ]; then
    echo "skipping SYN integration test: not root and CAP_NET_RAW is unavailable"
    exit 0
fi

# Also skip cleanly if this process has no CAP_NET_RAW but is root on a
# restricted user namespace. The probe above already covers that; the
# almap check below is a second guard.
if [ ! -x ./almap ]; then
    echo "building ./almap ..." >&2
    goose build almap.goose --cc gcc || exit 1
fi
if [ ! -x ./almap ]; then
    echo "error: ./almap not found after build" >&2
    exit 1
fi

# If almap itself reports missing privileges, treat it as a skip.
pre_output=$(./almap -t "$HOST" -p "$PORT" --scan syn --timeout 1000 2>&1 || true)
case "$pre_output" in
    *"SYN scan requires root or CAP_NET_RAW"*)
        echo "skipping SYN integration test: not root and CAP_NET_RAW is unavailable (almap check)"
        exit 0
        ;;
esac

LISTENER_PID=""
cleanup() {
    if [ -n "$LISTENER_PID" ]; then
        kill "$LISTENER_PID" 2>/dev/null || true
        wait "$LISTENER_PID" 2>/dev/null || true
        LISTENER_PID=""
    fi
}
trap cleanup EXIT

if command -v nc >/dev/null 2>&1; then
    echo "starting nc listener on $HOST:$PORT" >&2
    nc -l "$HOST" "$PORT" >/dev/null 2>&1 &
    LISTENER_PID=$!
elif command -v ncat >/dev/null 2>&1; then
    echo "starting ncat listener on $HOST:$PORT" >&2
    ncat -l "$HOST" "$PORT" >/dev/null 2>&1 &
    LISTENER_PID=$!
elif command -v python3 >/dev/null 2>&1; then
    echo "starting python3 listener on $HOST:$PORT" >&2
    python3 -c 'import socket,sys; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("127.0.0.1",int(sys.argv[1]))); s.listen(1); s.settimeout(10); c,_=s.accept(); c.close(); s.close()' "$PORT" >/dev/null 2>&1 &
    LISTENER_PID=$!
else
    echo "error: need nc, ncat, or python3 for the listener" >&2
    exit 1
fi

# Give the listener time to bind. Do not probe with a connect: that
# would consume the single accept of nc/python listeners.
sleep 1

echo "running ./almap -t $HOST -p $PORT --scan syn --timeout 1000" >&2
output=$(./almap -t "$HOST" -p "$PORT" --scan syn --timeout 1000)
status=$?
echo "$output"

# Allow the listener to finish/close after one connection.
wait "$LISTENER_PID" 2>/dev/null || true
LISTENER_PID=""

if [ "$status" -ne 0 ]; then
    echo "integration test FAILED: ./almap exited $status" >&2
    exit 1
fi
case "$output" in
    *"$HOST:$PORT open"*)
        ;;
    *)
        echo "integration test FAILED: output does not contain '$HOST:$PORT open'" >&2
        exit 1
        ;;
esac

# Step 21: fragmented scan against a fresh listener (needs the same
# privileges; fragmented IP on loopback may or may not be delivered
# by every kernel, so `open` is best-effort here - success means the
# scan completed without error and returned a parseable result).
echo "starting fresh listener for --fragment scan" >&2
python3 -c 'import socket,sys,time; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("127.0.0.1",int(sys.argv[1]))); s.listen(8); s.settimeout(12); end=time.time()+12
while time.time()<end:
  try:
    c,_=s.accept(); c.close()
  except socket.timeout: break
s.close()' "$PORT" >/dev/null 2>&1 &
LISTENER_PID=$!
sleep 1
echo "running ./almap -t $HOST -p $PORT --scan syn --fragment --timeout 1000" >&2
frag_output=$(./almap -t "$HOST" -p "$PORT" --scan syn --fragment --timeout 1000)
frag_status=$?
echo "$frag_output"
kill "$LISTENER_PID" 2>/dev/null || true
wait "$LISTENER_PID" 2>/dev/null || true
LISTENER_PID=""
if [ "$frag_status" -ne 0 ]; then
    echo "integration test FAILED: --fragment scan exited $frag_status" >&2
    exit 1
fi
case "$frag_output" in
    *"$HOST:$PORT"*)
        ;;
    *)
        echo "integration test FAILED: --fragment output does not contain $HOST:$PORT" >&2
        exit 1
        ;;
esac
case "$frag_output" in
    *"error:"*)
        echo "integration test FAILED: --fragment output contains an error" >&2
        exit 1
        ;;
esac
echo "integration test passed: output contains open and --fragment CLI + scan verified"
