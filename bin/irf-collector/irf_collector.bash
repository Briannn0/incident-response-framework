#!/bin/bash
#
# Incident Response Framework (IRF) - Log Collection Utility
# This script handles collecting logs from configured sources

# Get the directory where this script is located
IRF_BIN_DIR=$(dirname "$(readlink -f "$0")")
IRF_ROOT=$(dirname "$IRF_BIN_DIR")
export IRF_ROOT

# Ensure common libraries are loaded
if [[ ! -f "${IRF_ROOT}/lib/bash/common.sh" ]]; then
    echo "ERROR: Required library not found: ${IRF_ROOT}/lib/bash/common.sh" >&2
    exit 1
fi

# shellcheck source=/dev/null
source "${IRF_ROOT}/lib/bash/common.sh"

# Load the collector library
source "${IRF_ROOT}/lib/bash/collector.sh" || {
    irf_log ERROR "Failed to load collector library"
    exit 1
}

# Initialize variables
OUTPUT_DIR="${IRF_EVIDENCE_DIR:-${IRF_ROOT}/evidence}/collected"
SPECIFIC_SOURCE=""

# Display usage information
show_usage() {
    cat << EOF
Usage: irf-collector [OPTIONS]

Collect logs from configured sources.

Options:
  --source NAME  Collect logs only from specified source
  --output DIR   Directory to store collected logs
  --list         List available log sources
  --help         Display this help message
EOF
}

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --source)
            if [[ -n "$2" ]]; then
                SPECIFIC_SOURCE="$2"
                shift 2
            else
                irf_log ERROR "Missing argument for --source"
                show_usage
                exit 1
            fi
            ;;
            
        --output)
            if [[ -n "$2" ]]; then
                OUTPUT_DIR="$2"
                shift 2
            else
                irf_log ERROR "Missing argument for --output"
                show_usage
                exit 1
            fi
            ;;
            
        --list)
            irf_log INFO "Discovering available log sources..."
            irf_discover_log_sources
            
            echo "Available log sources:"
            for config_file in "${IRF_LOG_SOURCES[@]}"; do
                # Reset variables
                LOG_TYPE=""
                
                # Load configuration to get the log type
                # shellcheck source=/dev/null
                source "$config_file"
                
                echo "  $LOG_TYPE (${config_file})"
            done
            
            exit 0
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

# Create output directory if it doesn't exist
if [[ ! -d "$OUTPUT_DIR" ]]; then
    mkdir -p "$OUTPUT_DIR" || {
        irf_log ERROR "Failed to create output directory: $OUTPUT_DIR"
        exit 1
    }
fi

# Collect logs
irf_log INFO "Starting log collection..."

# Discover log sources if not already done
if [[ ${#IRF_LOG_SOURCES[@]} -eq 0 ]]; then
    irf_discover_log_sources || {
        irf_log ERROR "Failed to discover log sources"
        exit 1
    }
fi

# Create timestamp directory for this collection run
timestamp=$(date +"%Y%m%d_%H%M%S")
RUN_DIR="${OUTPUT_DIR}/${timestamp}"

mkdir -p "$RUN_DIR" || {
    irf_log ERROR "Failed to create run directory: $RUN_DIR"
    exit 1
}

# Track success and failure
SUCCESS=0
FAILED=0

# Collect logs based on source preference
if [[ -n "$SPECIFIC_SOURCE" ]]; then
    # Collect from specific source
    SOURCE_FOUND=0
    
    for config_file in "${IRF_LOG_SOURCES[@]}"; do
        # Reset variables
        LOG_TYPE=""
        
        # Load configuration to get the log type
        # shellcheck source=/dev/null
        source "$config_file"
        
        if [[ "$LOG_TYPE" == "$SPECIFIC_SOURCE" ]]; then
            SOURCE_FOUND=1
            source_output="${RUN_DIR}/${LOG_TYPE}.log"
            
            irf_log INFO "Collecting logs for source: $LOG_TYPE"
            
            if irf_collect_log_data "$config_file" "$source_output"; then
                SUCCESS=$((SUCCESS + 1))
                irf_log INFO "Successfully collected logs for: $LOG_TYPE"
            else
                FAILED=$((FAILED + 1))
                irf_log ERROR "Failed to collect logs for: $LOG_TYPE"
            fi
            
            break
        fi
    done
    
    if [[ $SOURCE_FOUND -eq 0 ]]; then
        irf_log ERROR "Log source not found: $SPECIFIC_SOURCE"
        exit 1
    fi
else
    # Collect from all sources
    for config_file in "${IRF_LOG_SOURCES[@]}"; do
        # Reset variables
        LOG_TYPE=""
        
        # Load configuration to get the log type
        # shellcheck source=/dev/null
        source "$config_file"
        
        source_output="${RUN_DIR}/${LOG_TYPE}.log"
        
        irf_log INFO "Collecting logs for source: $LOG_TYPE"
        
        if irf_collect_log_data "$config_file" "$source_output"; then
            SUCCESS=$((SUCCESS + 1))
            irf_log INFO "Successfully collected logs for: $LOG_TYPE"
        else
            FAILED=$((FAILED + 1))
            irf_log ERROR "Failed to collect logs for: $LOG_TYPE"
        fi
    done
fi

# Print summary
irf_log INFO "Log collection completed"
irf_log INFO "Successful: $SUCCESS, Failed: $FAILED"
irf_log INFO "Logs saved to: $RUN_DIR"

# Return appropriate exit code
if [[ $FAILED -gt 0 ]]; then
    exit 1
fi

exit 0