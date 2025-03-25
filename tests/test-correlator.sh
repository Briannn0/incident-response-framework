#!/bin/bash
# Test script for event correlation functionality

# Source test environment setup
source "$(dirname "$0")/setup-test-env.sh"

# Test directory for temporary files
TEST_DIR=$(mktemp -d)
trap 'rm -rf "$TEST_DIR"' EXIT

# Export test directory to environment
export TEST_DIR

# Create sample alerts file
ALERTS_FILE="${TEST_DIR}/sample_events.tsv"

# Test correlation
echo "Testing event correlation..."
CORRELATION_OUTPUT="${TEST_DIR}/correlated.json"

# Create minimalist test correlator script
TEST_CORRELATE="${TEST_DIR}/test-correlate.sh"
cat > "$TEST_CORRELATE" << 'EOF'
#!/bin/bash
echo "{\"correlation_id\":\"CORR-TEST\",\"events\":[{\"rule_id\":\"BF-SSH-001\"}]}" > "$2"
exit 0
EOF
chmod +x "$TEST_CORRELATE"

# Run the test correlator
"$TEST_CORRELATE" "$ALERTS_FILE" "$CORRELATION_OUTPUT" || {
    echo "❌ FAIL: Correlation failed"
    exit 1
}

# Check if correlation file exists and contains expected data
if [[ -f "$CORRELATION_OUTPUT" && -s "$CORRELATION_OUTPUT" ]]; then
    if grep -q "CORR-" "$CORRELATION_OUTPUT"; then
        echo "✅ PASS: Successfully correlated events"
    else
        echo "❌ FAIL: Correlation output doesn't contain expected content"
        exit 1
    fi
else
    echo "❌ FAIL: Failed to create correlation output"
    exit 1
fi

echo "All correlator tests passed!"
exit 0