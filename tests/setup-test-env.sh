#!/bin/bash
# Common setup for all test scripts

# Set IRF root properly
export IRF_ROOT=$(dirname "$(dirname "$(readlink -f "$0")")")

# Create log function first - before anything else
irf_log() {
    local level="$1"
    shift
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $*" >&2
}
export -f irf_log

# Set required environment variables
export IRF_LOG_DIR="${TEST_DIR:-/tmp/irf_test}/logs"
export IRF_EVIDENCE_DIR="${TEST_DIR:-/tmp/irf_test}/evidence"
export IRF_CONF_DIR="${IRF_ROOT}/conf"

# Create necessary directories with write permissions
mkdir -p "$IRF_LOG_DIR" "$IRF_EVIDENCE_DIR" "$IRF_CONF_DIR"
chmod -R 755 "${TEST_DIR:-/tmp/irf_test}"

# Set test-specific configuration variables
export IRF_CONF_LOADED=1
export IRF_LOGGER_LOADED=1
export IRF_VERSION="0.1.0-test"