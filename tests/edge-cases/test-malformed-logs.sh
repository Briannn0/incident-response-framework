#!/bin/bash
#
# Test handling of malformed log data
# Verifies that the parser can handle corrupt/unexpected input

set -e

# Get the project root directory
IRF_ROOT=$(dirname "$(dirname "$(readlink -f "$0")")")/../..

# Source common functions
source "${IRF_ROOT}/lib/bash/common.sh"
source "${IRF_ROOT}/lib/bash/parser.sh"

# Create test directory
TEST_DIR=$(mktemp -d)
trap 'rm -rf "$TEST_DIR"' EXIT

# Create test files with various edge cases
echo "Creating test files with malformed log data"

# 1. Empty lines
cat > "${TEST_DIR}/empty_lines.log" << EOF

May 20 10:15:30 server1 sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2

EOF

# 2. Truncated lines
cat > "${TEST_DIR}/truncated.log" << EOF
May 20 10:15:30 server1 ssh
May 20 10:15:35 server1 sshd[
May 20 10:15:40 server1 sshd[1234]: Failed password
EOF

# 3. Binary data mixed with text
cat > "${TEST_DIR}/binary_mix.log" << EOF
May 20 10:15:30 server1 sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2
$(echo -e "\x00\x01\x02\x03\x04Binary data\x00Test")
May 20 10:15:40 server1 sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
EOF

# 4. Extremely long lines
LONG_LINE=$(printf 'X%.0s' {1..10000})
cat > "${TEST_DIR}/long_line.log" << EOF
May 20 10:15:30 server1 sshd[1234]: $LONG_LINE
May 20 10:15:40 server1 sshd[1234]: Normal line after very long line
EOF

# 5. Mixed charsets and encodings
cat > "${TEST_DIR}/mixed_charset.log" << EOF
May 20 10:15:30 server1 sshd[1234]: ASCII text
May 20 10:15:35 server1 sshd[1234]: UTF-8 text with émojis 🔒 and special chars €£¥
$(echo -e "\xC0\xA0\xE0\xA0\xA0Invalid UTF-8 sequence")
May 20 10:15:45 server1 sshd[1234]: Text after invalid sequence
EOF

# Function to test parser with a malformed log file
test_malformed_file() {
    local file="$1"
    local description="$2"
    local output_file="${TEST_DIR}/output_$(basename "$file")"
    
    echo "Testing parser with $description"
    
    # Try to parse the file
    if irf_parse_log_file "$file" "syslog" "test" "$output_file"; then
        # Check that output exists and has at least a header
        if [[ -f "$output_file" && $(wc -l < "$output_file") -gt 0 ]]; then
            echo "✅ Parser successfully handled $description"
            return 0
        else
            echo "❌ Parser produced empty output for $description"
            return 1
        fi
    else
        echo "❌ Parser failed on $description"
        return 1
    fi
}

# Run tests for each malformed file
test_malformed_file "${TEST_DIR}/empty_lines.log" "file with empty lines"
test_malformed_file "${TEST_DIR}/truncated.log" "file with truncated lines"
test_malformed_file "${TEST_DIR}/binary_mix.log" "file with binary data"
test_malformed_file "${TEST_DIR}/long_line.log" "file with extremely long lines"
test_malformed_file "${TEST_DIR}/mixed_charset.log" "file with mixed charsets"

echo "All malformed log tests completed successfully!"
exit 0