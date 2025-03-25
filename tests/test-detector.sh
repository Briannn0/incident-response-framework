#!/bin/bash
# Test script for threat detection functionality

# Set IRF root
IRF_ROOT=$(dirname "$(dirname "$(readlink -f "$0")")")
export IRF_ROOT

# Source necessary libraries
source "${IRF_ROOT}/lib/bash/common.sh"
source "${IRF_ROOT}/lib/bash/detector.sh"

# Create test directory
TEST_DIR=$(mktemp -d)
trap 'rm -rf "$TEST_DIR"' EXIT

# Create test rule file
TEST_RULES="${TEST_DIR}/test.rules"
cat > "$TEST_RULES" << EOF
# Test rules
TEST-001;Failed SSH Login;Failed password;MEDIUM;9
TEST-002;Root Login Attempt;root;HIGH;4,9
EOF

# Create normalized log file for testing
TEST_LOG="${TEST_DIR}/normalized.tsv"
cat > "$TEST_LOG" << EOF
timestamp	source_type	source_name	log_level	username	hostname	ip_address	service	process_id	message
May 20 10:15:30	auth	server1	INFO	admin	server1	192.168.1.100	sshd	1234	Failed password for admin from 192.168.1.100 port 22 ssh2
May 20 10:15:35	auth	server1	INFO	root	server1	192.168.1.100	sshd	1235	Failed password for root from 192.168.1.100 port 22 ssh2
EOF

# Test 1: Test rule loading
echo "Testing rule loading..."
irf_load_rule_file "$TEST_RULES"
if [[ ${#IRF_LOADED_RULES[@]} -gt 0 ]]; then
    echo "✅ PASS: Successfully loaded ${#IRF_LOADED_RULES[@]} rules"
else
    echo "❌ FAIL: Failed to load rules"
    exit 1
fi

# Test 2: Test threat detection
echo "Testing threat detection..."
TEST_ALERTS="${TEST_DIR}/alerts.tsv"
irf_detect_threats "$TEST_LOG" "$TEST_ALERTS"

if [[ -f "$TEST_ALERTS" && -s "$TEST_ALERTS" ]]; then
    # Check if both rules were triggered
    if grep -q "TEST-001" "$TEST_ALERTS" && grep -q "TEST-002" "$TEST_ALERTS"; then
        echo "✅ PASS: Detected threats correctly"
    else
        echo "❌ FAIL: Did not detect expected threats"
        exit 1
    fi
else
    echo "❌ FAIL: Failed to detect threats"
    exit 1
fi

echo "All detector tests passed!"
exit 0