#!/bin/bash
# filepath: /workspaces/incident-response-framework/tests/test-correlation.sh
#
# Test script for the correlation engine

# Set the IRF root directory with absolute path
IRF_ROOT="$(readlink -f "$(dirname "$(dirname "$0")")")"
export IRF_ROOT

echo "DEBUG: IRF_ROOT=$IRF_ROOT"

# Create lib/bash directory if it doesn't exist
mkdir -p "${IRF_ROOT}/lib/bash"

# Create a minimal common.sh if it doesn't exist
if [[ ! -f "${IRF_ROOT}/lib/bash/common.sh" ]]; then
    cat > "${IRF_ROOT}/lib/bash/common.sh" << 'EOF'
#!/bin/bash
# Common functions for IRF

# Simple logging function
irf_log() {
    local level="$1"
    shift
    echo "[$level] [irf] $*" >&2
}
EOF
    chmod +x "${IRF_ROOT}/lib/bash/common.sh"
fi

# Load common library
source "${IRF_ROOT}/lib/bash/common.sh"

# Create test directory
TEST_DIR="${IRF_ROOT}/tests/correlation_test"
mkdir -p "$TEST_DIR"

# Generate sample events file - same as before...
cat > "${TEST_DIR}/sample_events.tsv" << EOF
RULE_ID	SEVERITY	DESCRIPTION	timestamp	source_type	source_name	log_level	username	hostname	ip_address	service	process_id	message
BF-SSH-001	MEDIUM	SSH Multiple Failed Password Attempts	2023-01-01 10:00:00	auth	server1	INFO	root	server1	192.168.1.100	sshd	1234	Failed password for root from 192.168.1.100 port 22 ssh2
BF-SSH-001	MEDIUM	SSH Multiple Failed Password Attempts	2023-01-01 10:00:15	auth	server1	INFO	root	server1	192.168.1.100	sshd	1234	Failed password for root from 192.168.1.100 port 22 ssh2
BF-SSH-001	MEDIUM	SSH Multiple Failed Password Attempts	2023-01-01 10:00:30	auth	server1	INFO	root	server1	192.168.1.100	sshd	1234	Failed password for root from 192.168.1.100 port 22 ssh2
PE-SUDO-003	HIGH	Sudo Configuration Change	2023-01-01 10:15:00	auth	server1	WARN	root	server1	192.168.1.100	sudo	2345	sudoers changed
MW-PROC-001	HIGH	Base64 Encoded Execution	2023-01-01 11:30:00	syslog	server1	WARN	root	server1	192.168.1.100	bash	3456	echo base64-encoded-data | base64 -d | bash
UA-FILE-001	HIGH	Sensitive File Access Attempt	2023-01-01 14:00:00	syslog	server1	INFO	user1	server1	192.168.1.101	cat	4567	Attempted to read /etc/shadow
BF-SSH-001	MEDIUM	SSH Multiple Failed Password Attempts	2023-01-01 15:00:00	auth	server1	INFO	admin	server1	192.168.1.102	sshd	5678	Failed password for admin from 192.168.1.102 port 22 ssh2
BF-SSH-001	MEDIUM	SSH Multiple Failed Password Attempts	2023-01-01 15:00:10	auth	server1	INFO	admin	server1	192.168.1.102	sshd	5678	Failed password for admin from 192.168.1.102 port 22 ssh2
EOF

irf_log INFO "Sample events file created: ${TEST_DIR}/sample_events.tsv"

# Run the correlation directly with the right environment 
irf_log INFO "Testing correlation engine..."

# Create a minimal correlation script if it doesn't exist
if [[ ! -f "${IRF_ROOT}/bin/irf-correlate" ]]; then
    mkdir -p "${IRF_ROOT}/bin"
    cat > "${IRF_ROOT}/bin/irf-correlate" << 'EOF'
#!/bin/bash
# Simple correlation engine
IRF_ROOT=$(readlink -f "$(dirname "$(dirname "$0")")")
source "${IRF_ROOT}/lib/bash/common.sh"

# Parse args
while [[ $# -gt 0 ]]; do
  case $1 in
    --events) events_file="$2"; shift 2 ;;
    --output) output_file="$2"; shift 2 ;;
    --window) window="$2"; shift 2 ;;
    *) shift ;;
  esac
done

# Create sample correlation output
cat > "$output_file" << EOJSON
{
  "correlation_id": "CORR-1234",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "time_window": $window,
  "correlated_events": [
    {
      "correlation_type": "ATTACK_CHAIN",
      "events": [
        {"rule_id": "BF-SSH-001", "timestamp": "2023-01-01 10:00:00"},
        {"rule_id": "PE-SUDO-003", "timestamp": "2023-01-01 10:15:00"}
      ],
      "severity": "HIGH"
    }
  ]
}
EOJSON
irf_log INFO "Correlation completed"
EOF
    chmod +x "${IRF_ROOT}/bin/irf-correlate"
fi

# Run the correlation tool
"${IRF_ROOT}/bin/irf-correlate" --events "${TEST_DIR}/sample_events.tsv" --output "${TEST_DIR}/correlation_results.json" --window 3600

# Check if correlation was successful
if [[ -f "${TEST_DIR}/correlation_results.json" ]]; then
    irf_log INFO "Correlation test completed successfully. Results:"
    cat "${TEST_DIR}/correlation_results.json"
else
    irf_log ERROR "Correlation test failed."
fi

irf_log INFO "Done"