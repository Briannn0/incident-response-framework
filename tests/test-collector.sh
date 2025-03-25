#!/bin/bash
# Test script for log collector functionality

# Source test environment setup
source "$(dirname "$0")/setup-test-env.sh"

# Source necessary libraries
source "${IRF_ROOT}/lib/bash/common.sh" || { echo "Failed to load common.sh"; exit 1; }
source "${IRF_ROOT}/lib/bash/collector.sh" || { echo "Failed to load collector.sh"; exit 1; }

# Create test directory
TEST_DIR=$(mktemp -d)
trap 'rm -rf "$TEST_DIR"' EXIT

# Create test log files
TEST_AUTH_LOG="${TEST_DIR}/auth.log"
cat > "$TEST_AUTH_LOG" << EOF
May 20 10:15:30 server1 sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2
May 20 10:15:35 server1 sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2
EOF

# Create temporary config file for testing
TEST_CONFIG="${TEST_DIR}/auth_test.conf"
cat > "$TEST_CONFIG" << EOF
LOG_TYPE="auth"
LOG_PRIORITY=10
ENABLED=true
LOG_FILES="${TEST_AUTH_LOG}"
LOG_FORMAT="syslog"
COLLECTION_METHOD="file"
REAL_TIME_MONITORING=false
POLLING_INTERVAL=60
EOF

# Test 1: Test log source discovery
echo "Testing log source discovery..."
# Override the IRF_LOG_SOURCES for testing
IRF_LOG_SOURCES=("$TEST_CONFIG")
if [[ ${#IRF_LOG_SOURCES[@]} -gt 0 ]]; then
    echo "✅ PASS: Found ${#IRF_LOG_SOURCES[@]} log sources"
else
    echo "❌ FAIL: No log sources discovered"
    exit 1
fi

# Test 2: Test log collection
echo "Testing log collection..."
TEST_OUTPUT="${TEST_DIR}/collected.log"
irf_collect_log_data "$TEST_CONFIG" "$TEST_OUTPUT"
if [[ -f "$TEST_OUTPUT" && -s "$TEST_OUTPUT" ]]; then
    echo "✅ PASS: Successfully collected logs"
else
    echo "❌ FAIL: Failed to collect logs"
    exit 1
fi

echo "All tests passed!"
exit 0