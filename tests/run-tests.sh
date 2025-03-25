#!/bin/bash
#
# Master test script for Incident Response Framework
# Runs all unit and integration tests

set -e

# Get the project root directory
IRF_ROOT=$(dirname "$(readlink -f "$0")")/..

# Source common functions
source "${IRF_ROOT}/lib/bash/common.sh"

# Define test categories
UNIT_TESTS=(
    "test-collector.sh"
    "test-parser.sh"
    "test-detector.sh"
    "test-logger.sh"
    "test-correlator.sh"
)

INTEGRATION_TESTS=(
    "integration/test-full-pipeline.sh"
    "integration/test-detection-response.sh"
)

EDGE_CASE_TESTS=(
    "edge-cases/test-malformed-logs.sh"
    "edge-cases/test-large-files.sh"
    "edge-cases/test-concurrent-access.sh"
)

# Function to run a test suite
run_test_suite() {
    local suite_name="$1"
    local tests=("${!2}")
    local pass_count=0
    local fail_count=0

    echo "=== Running $suite_name ==="
    for test in "${tests[@]}"; do
        echo "Running test: $test"
        if "${IRF_ROOT}/tests/$test"; then
            echo "✅ PASS: $test"
            pass_count=$((pass_count + 1))
        else
            echo "❌ FAIL: $test"
            fail_count=$((fail_count + 1))
            FAILED_TESTS+=("$test")
        fi
    done
    echo "$pass_count passed, $fail_count failed"
    echo "=========================="
    return $fail_count
}

# Track failed tests
FAILED_TESTS=()

# Run each test suite
run_test_suite "Unit Tests" UNIT_TESTS[@]
run_test_suite "Integration Tests" INTEGRATION_TESTS[@]
run_test_suite "Edge Case Tests" EDGE_CASE_TESTS[@]

# Report results
if [ ${#FAILED_TESTS[@]} -eq 0 ]; then
    echo "All tests passed successfully!"
    exit 0
else
    echo "Failed tests:"
    for test in "${FAILED_TESTS[@]}"; do
        echo "  - $test"
    done
    exit 1
fi