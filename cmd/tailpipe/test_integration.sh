#!/usr/bin/env bash
#
# Integration test for tailpipe: starts a server, reads its address,
# then connects a client and pipes "hello world" through it.
#
set -euo pipefail

cd "$(dirname "$0")/../.."

cleanup() {
    if [[ -n "${SERVER_PID:-}" ]]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -f "${ADDR_FILE:-}" "${TAILPIPE:-}" /tmp/tailpipe-server-stdout.log
}
trap cleanup EXIT

echo "=== Building tailpipe ==="
TAILPIPE=$(mktemp /tmp/tailpipe.XXXXXX)
go build -tags ts_omit_ssh -o "$TAILPIPE" ./cmd/tailpipe
echo "Built: $TAILPIPE"

ADDR_FILE=$(mktemp /tmp/tailpipe-addr.XXXXXX)
rm -f "$ADDR_FILE"

echo "=== Starting server (pipe mode, no --serve) ==="
# With no --serve flag, the server runs in pipe mode:
# any incoming TCP connection gets copied to stdout.
DC_ADDR_FILE="$ADDR_FILE" "$TAILPIPE" --key=new \
    >/tmp/tailpipe-server-stdout.log \
    2>/tmp/tailpipe-server-stderr.log &
SERVER_PID=$!

echo "Waiting for server address file..."
for i in $(seq 1 30); do
    if [[ -s "$ADDR_FILE" ]]; then
        break
    fi
    sleep 0.2
done

if [[ ! -s "$ADDR_FILE" ]]; then
    echo "FAIL: server did not write address file after 6 seconds"
    echo "--- server stderr ---"
    cat /tmp/tailpipe-server-stderr.log
    echo "---"
    exit 1
fi

ADDR=$(cat "$ADDR_FILE")
echo "Server address: $ADDR"

echo "=== Connecting client ==="
# Client sends "hello world" to the server via the derpcat tunnel.
# The server (in pipe mode) copies the received data to its stdout.
echo "hello world" | timeout 30 "$TAILPIPE" "$ADDR" \
    2>/tmp/tailpipe-client-stderr.log || {
    echo "FAIL: client exited with error"
    echo "--- client stderr ---"
    cat /tmp/tailpipe-client-stderr.log
    echo "---"
    exit 1
}

# Give the server a moment to flush stdout
sleep 1

# The server process should have exited (it exits after one
# connection in pipe mode). If not, kill it.
kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=""

RESULT=$(cat /tmp/tailpipe-server-stdout.log)
echo "Server received: '$RESULT'"

if echo "$RESULT" | grep -q "hello world"; then
    echo "PASS"
    exit 0
else
    echo "FAIL: expected 'hello world' in server stdout, got: '$RESULT'"
    echo "--- server stderr ---"
    cat /tmp/tailpipe-server-stderr.log
    echo "---"
    echo "--- client stderr ---"
    cat /tmp/tailpipe-client-stderr.log
    echo "---"
    exit 1
fi
