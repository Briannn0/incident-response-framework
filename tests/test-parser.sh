#!/bin/bash
# Test script for log parser functionality

# Set IRF root
IRF_ROOT=$(dirname "$(dirname "$(readlink -f "$0")")")
export IRF_ROOT

# Source necessary libraries
source "${IRF_ROOT}/lib/bash/common.sh"
source "${IRF_ROOT}/lib/bash/parser.sh"

# Create test directory
TEST_DIR=$(mktemp -d)
trap 'rm -rf "$TEST_DIR"' EXIT

# Create sample log file
TEST_LOG="${TEST_DIR}/test.log"
cat > "$TEST_LOG" << EOF
May 20 10:15:30 server1 sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2
May 20 10:15:35 server1 sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
EOF

# Test 1: Test log parsing
echo "Testing log parsing..."
TEST_OUTPUT="${TEST_DIR}/parsed.tsv"
irf_parse_log_file "$TEST_LOG" "syslog" "auth" "$TEST_OUTPUT"

if [[ -f "$TEST_OUTPUT" && -s "$TEST_OUTPUT" ]]; then
    echo "✅ PASS: Successfully parsed log file"
    
    # Verify field extraction
    if grep -q "admin" "$TEST_OUTPUT" && grep -q "192.168.1.100" "$TEST_OUTPUT"; then
        echo "✅ PASS: Field extraction verified"
    else
        echo "❌ FAIL: Field extraction failed"
        exit 1
    fi
else
    echo "❌ FAIL: Failed to parse log file"
    exit 1
fi

# Test 2: Test malformed log handling
MALFORMED_LOG="${TEST_DIR}/malformed.log"
cat > "$MALFORMED_LOG" << EOF
This is not a valid syslog entry
May 20 10:15:30 server1 
EOF

MALFORMED_OUTPUT="${TEST_DIR}/malformed_parsed.tsv"
irf_parse_log_file "$MALFORMED_LOG" "syslog" "auth" "$MALFORMED_OUTPUT"

if [[ -f "$MALFORMED_OUTPUT" && -s "$MALFORMED_OUTPUT" ]]; then
    echo "✅ PASS: Handled malformed log gracefully"
else
    echo "❌ FAIL: Failed with malformed log"
    exit 1
fi

echo "All parser tests passed!"
exit 0