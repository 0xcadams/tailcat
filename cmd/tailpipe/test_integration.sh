#!/usr/bin/env bash
#
# Integration test for tailpipe.
#
# Test 1 (pipe): starts a server, reads its address,
# then connects a client and pipes "hello world" through it.
#
# Test 2 (ssh): starts a server with --serve=no-auth-ssh,
# then uses "tailpipe ssh" to run a command through the
# built-in Tailscale SSH server.
#
set -euo pipefail

cd "$(dirname "$0")/../.."

# macOS doesn't have coreutils timeout; use a perl one-liner as fallback.
if ! command -v timeout &>/dev/null; then
    timeout() { perl -e 'alarm shift; exec @ARGV' "$@"; }
fi

TAILPIPE=""
SERVER_PID=""
ADDR_FILE=""

cleanup() {
    if [[ -n "${SERVER_PID:-}" ]]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -f "${ADDR_FILE:-}" "${TAILPIPE:-}" \
        /tmp/tailpipe-server-stdout.log \
        /tmp/tailpipe-server-stderr.log \
        /tmp/tailpipe-client-stderr.log
}
trap cleanup EXIT

fail() {
    echo "FAIL: $1"
    for f in /tmp/tailpipe-server-stderr.log /tmp/tailpipe-client-stderr.log; do
        if [[ -s "$f" ]]; then
            echo "--- $(basename "$f") ---"
            tail -30 "$f"
            echo "---"
        fi
    done
    exit 1
}

wait_for_addr_file() {
    echo "Waiting for server address file..."
    for i in $(seq 1 30); do
        if [[ -s "$ADDR_FILE" ]]; then
            return 0
        fi
        sleep 0.2
    done
    fail "server did not write address file after 6 seconds"
}

echo "=== Building tailpipe (with SSH support) ==="
TAILPIPE=$(mktemp /tmp/tailpipe.XXXXXX)
go build -o "$TAILPIPE" ./cmd/tailpipe
echo "Built: $TAILPIPE"

# ------------------------------------------------------------------
# Test 1: pipe mode
# ------------------------------------------------------------------

echo ""
echo "=== Test 1: pipe mode ==="

ADDR_FILE=$(mktemp /tmp/tailpipe-addr.XXXXXX)
rm -f "$ADDR_FILE"

echo "Starting server (pipe mode, no --serve)..."
DC_ADDR_FILE="$ADDR_FILE" "$TAILPIPE" --key=new \
    >/tmp/tailpipe-server-stdout.log \
    2>/tmp/tailpipe-server-stderr.log &
SERVER_PID=$!

wait_for_addr_file
ADDR=$(cat "$ADDR_FILE")
echo "Server address: $ADDR"

echo "Connecting client..."
echo "hello world" | timeout 30 "$TAILPIPE" "$ADDR" \
    2>/tmp/tailpipe-client-stderr.log || fail "client exited with error"

sleep 1

kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=""

RESULT=$(cat /tmp/tailpipe-server-stdout.log)
echo "Server received: '$RESULT'"

if echo "$RESULT" | grep -q "hello world"; then
    echo "PASS: pipe mode"
else
    fail "expected 'hello world' in server stdout, got: '$RESULT'"
fi

# ------------------------------------------------------------------
# Test 2: built-in Tailscale SSH server (no-auth-ssh)
# ------------------------------------------------------------------

echo ""
echo "=== Test 2: built-in SSH server (no-auth-ssh) ==="

ADDR_FILE=$(mktemp /tmp/tailpipe-addr.XXXXXX)
rm -f "$ADDR_FILE"

echo "Starting server with --serve=no-auth-ssh..."
DC_ADDR_FILE="$ADDR_FILE" "$TAILPIPE" --key=new --serve=no-auth-ssh \
    >/dev/null \
    2>/tmp/tailpipe-server-stderr.log &
SERVER_PID=$!

wait_for_addr_file
ADDR=$(cat "$ADDR_FILE")
echo "Server address: $ADDR"

# Give the server a moment to be ready for connections.
sleep 2

echo "SSHing through tailpipe tunnel..."
SSH_RESULT=$(timeout 30 "$TAILPIPE" ssh "$ADDR" echo hello-from-ssh \
    2>/tmp/tailpipe-client-stderr.log) || fail "tailpipe ssh exited with error"

echo "SSH output: '$SSH_RESULT'"

kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=""

if echo "$SSH_RESULT" | grep -q "hello-from-ssh"; then
    echo "PASS: SSH mode"
else
    fail "expected 'hello-from-ssh' in SSH output, got: '$SSH_RESULT'"
fi

echo ""
echo "=== All tests passed ==="
