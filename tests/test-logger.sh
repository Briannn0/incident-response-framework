#!/bin/bash
# Test script for logging functionality

# Source test environment setup
source "$(dirname "$0")/setup-test-env.sh" || { echo "Failed to load test environment"; exit 1; }

# Create fallback log function to bootstrap
_log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$1] $2" >&2
}

# Source common library
source "${IRF_ROOT}/lib/bash/common.sh" || { _log ERROR "Failed to load common.sh"; exit 1; }

# Now load the logger
source "${IRF_ROOT}/lib/bash/logger.sh" || { _log ERROR "Failed to load logger.sh"; exit 1; }

# Verify the logger loaded correctly by checking if irf_log function exists
if ! type irf_log >/dev/null 2>&1; then
    _log ERROR "irf_log function not found after loading logger.sh"
    exit 1
else
    echo "✅ PASS: Logger loaded successfully"
fi

# Initialize counters for test results
TESTS_PASSED=0
TESTS_FAILED=0

# Helper function to report test results
report_test() {
    local test_name="$1"
    local result="$2"
    
    if [[ "$result" == "PASS" ]]; then
        echo "✅ PASS: $test_name"
        ((TESTS_PASSED++))
    else
        echo "❌ FAIL: $test_name"
        ((TESTS_FAILED++))
    fi
}

# Test 1: Test basic logging
echo "Testing basic logging..."
TEST_MESSAGE="This is a test log message"
irf_log INFO "$TEST_MESSAGE"

if grep -q "$TEST_MESSAGE" "${IRF_LOG_DIR}/irf.log"; then
    report_test "Successfully wrote log message" "PASS"
else
    report_test "Failed to write log message" "FAIL"
fi

# Test 2: Test different log levels
echo "Testing log levels..."
irf_log DEBUG "Debug message"
irf_log WARN "Warning message"
irf_log ERROR "Error message"
irf_log CRITICAL "Critical message"

if grep -q "WARN" "${IRF_LOG_DIR}/irf.log" && grep -q "ERROR" "${IRF_LOG_DIR}/irf.log"; then
    report_test "Successfully logged at different levels" "PASS"
else
    report_test "Failed to log at different levels" "FAIL"
fi

# Test 3: Test alert logging
echo "Testing alert logging..."
irf_log ERROR "This is an alert" 

if [[ -f "${IRF_LOG_DIR}/alerts.log" && -s "${IRF_LOG_DIR}/alerts.log" ]]; then
    report_test "Successfully created alerts log" "PASS"
else
    report_test "Failed to create alerts log" "FAIL"
fi

# Test 4: Test log formatting
echo "Testing log formatting..."
TEST_FORMAT_MSG="Format test message"
irf_log INFO "$TEST_FORMAT_MSG"

if grep -q "\[[0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\} [0-9]\{2\}:[0-9]\{2\}:[0-9]\{2\}\] \[INFO\]" "${IRF_LOG_DIR}/irf.log"; then
    report_test "Log format is correct" "PASS"
else
    report_test "Log format is incorrect" "FAIL"
fi

# Test 5: Test custom log message with additional context
echo "Testing context in log messages..."
TEST_CONTEXT="custom-component"
irf_log INFO "$TEST_MESSAGE" "$TEST_CONTEXT"

if grep -q "$TEST_CONTEXT" "${IRF_LOG_DIR}/irf.log"; then
    report_test "Successfully logged with custom context" "PASS"
else
    report_test "Failed to log with custom context" "FAIL"
fi

# Test 6: Test log file permissions
echo "Testing log file permissions..."
if [[ -r "${IRF_LOG_DIR}/irf.log" && -w "${IRF_LOG_DIR}/irf.log" ]]; then
    report_test "Log file has correct permissions" "PASS"
else
    report_test "Log file has incorrect permissions" "FAIL"
fi

# Print test summary
echo "============================"
echo "SUMMARY: $TESTS_PASSED tests passed, $TESTS_FAILED tests failed"

# Return appropriate exit code
if [[ $TESTS_FAILED -eq 0 ]]; then
    echo "All logger tests passed!"
    exit 0
else
    echo "Some logger tests failed!"
    exit 1
fi