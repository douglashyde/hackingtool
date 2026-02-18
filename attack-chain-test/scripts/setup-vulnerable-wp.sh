#!/bin/bash
# =============================================================================
# Setup script: Starts the mock WordPress server and runs the brute-force test
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "============================================="
echo "  Attack Chain 1 — Quick Start"
echo "============================================="
echo ""
echo "Starting mock WordPress server..."
echo ""

# Start the mock server in background
python3 "$SCRIPT_DIR/mock_wordpress.py" --port 8080 --admin-pass admin123 &
SERVER_PID=$!

# Wait for server to be ready
sleep 2

echo ""
echo "Running brute-force test..."
echo ""

# Run the brute-force test
python3 "$SCRIPT_DIR/bruteforce_test.py" --url http://localhost:8080

# Clean up
kill $SERVER_PID 2>/dev/null
echo ""
echo "Server stopped. Test complete."
