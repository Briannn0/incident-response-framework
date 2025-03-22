#!/bin/bash
#
# Incident Response Framework (IRF) - Log Collection Utility
# This script handles collecting logs from configured sources

# Get the directory where this script is located
IRF_BIN_DIR=$(dirname "$(readlink -f "$0")")
IRF_ROOT=$(dirname "$(dirname "$IRF_BIN_DIR")")
export IRF_ROOT

# Set up key directory locations
export IRF_LOG_DIR="${IRF_ROOT}/logs"
export IRF_EVIDENCE_DIR="${IRF_ROOT}/evidence"
export IRF_CONF_DIR="${IRF_ROOT}/conf"

# Enhanced debugging
echo "DEBUG: IRF_ROOT=$IRF_ROOT" >&2
echo "DEBUG: IRF_LOG_DIR=$IRF_LOG_DIR" >&2
echo "DEBUG: IRF_EVIDENCE_DIR=$IRF_EVIDENCE_DIR" >&2

# Enhanced debugging
echo "DEBUG: IRF_ROOT=$IRF_ROOT" >&2

# Ensure common libraries are loaded
if [[ ! -f "${IRF_ROOT}/lib/bash/common.sh" ]]; then
    echo "ERROR: Required library not found: ${IRF_ROOT}/lib/bash/common.sh" >&2
    exit 1
fi

# Source common library with better error handling
echo "DEBUG: Loading common.sh from ${IRF_ROOT}/lib/bash/common.sh" >&2
# shellcheck source=/dev/null
source "${IRF_ROOT}/lib/bash/common.sh" || {
    echo "ERROR: Failed to load common.sh library" >&2
    exit 1
}

# Define a basic logging function in case the logger isn't loaded
irf_log() {
    local level="$1"
    shift
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $*" >&2
}

# Check logger library explicitly
LOGGER_LIB="${IRF_ROOT}/lib/bash/logger.sh"
if [[ ! -f "$LOGGER_LIB" ]]; then
    echo "ERROR: Logger library not found: $LOGGER_LIB" >&2
    exit 1
fi

echo "DEBUG: Loading logger from $LOGGER_LIB" >&2
# shellcheck source=/dev/null
source "$LOGGER_LIB" || {
    echo "ERROR: Failed to load logger library" >&2
    exit 1
}

echo "DEBUG: Logger loaded, checking irf_log function" >&2
# Verify logger function exists
if ! type irf_log >/dev/null 2>&1; then
    echo "ERROR: irf_log function not available after loading libraries" >&2
    # Continue with our fallback implementation
    echo "DEBUG: Using fallback logger implementation" >&2
fi

# Load the collector library
echo "DEBUG: Loading collector library" >&2
COLLECTOR_LIB="${IRF_ROOT}/lib/bash/collector.sh"
if [[ ! -f "$COLLECTOR_LIB" ]]; then
    irf_log ERROR "Collector library not found: $COLLECTOR_LIB"
    exit 1
fi

# shellcheck source=/dev/null
source "$COLLECTOR_LIB" || {
    irf_log ERROR "Failed to load collector library"
    exit 1
}


# Initialize variables
OUTPUT_DIR="${IRF_EVIDENCE_DIR:-${IRF_ROOT}/evidence}/collected"
SPECIFIC_SOURCE=""

# Add input validation function
validate_arguments() {
    local source_name="$1"
    local output_dir="$2"
    
    # Validate source name if provided
    if [[ -n "$source_name" ]]; then
        if [[ "$source_name" =~ [^a-zA-Z0-9_-] ]]; then
            irf_log ERROR "Invalid source name: $source_name (only alphanumeric, hyphen, underscore allowed)"
            return 1
        fi
    fi
    
    # Validate output directory
    if [[ -n "$output_dir" ]]; then
        if [[ "$output_dir" == *".."* || "$output_dir" == *"~"* ]]; then
            irf_log ERROR "Invalid output directory path: $output_dir"
            return 1
        fi
    fi
    
    return 0
}

# Add resource monitoring
monitor_resources() {
    # Get current process ID
    local pid=$$
    
    # Check CPU usage
    local cpu_usage
    cpu_usage=$(ps -p "$pid" -o %cpu | tail -n 1 | tr -d ' ')
    
    if (( $(echo "$cpu_usage > 80.0" | bc -l) )); then
        irf_log WARN "High CPU usage detected: ${cpu_usage}%"
    fi
    
    # Check memory usage
    local mem_usage
    mem_usage=$(ps -p "$pid" -o %mem | tail -n 1 | tr -d ' ')
    
    if (( $(echo "$mem_usage > 70.0" | bc -l) )); then
        irf_log WARN "High memory usage detected: ${mem_usage}%"
    fi
}

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

# Validate arguments
if ! validate_arguments "$SPECIFIC_SOURCE" "$OUTPUT_DIR"; then
    exit 1
fi

# Create output directory if it doesn't exist
if [[ ! -d "$OUTPUT_DIR" ]]; then
    mkdir -p "$OUTPUT_DIR" || {
        irf_log ERROR "Failed to create output directory: $OUTPUT_DIR"
        exit 1
    }
fi

# Add periodic resource monitoring during collection
(
    while true; do
        sleep 60
        monitor_resources
    done
) &
MONITOR_PID=$!

# Cleanup on exit
trap 'kill $MONITOR_PID 2>/dev/null || true' EXIT

# Collect logs
irf_log INFO "Starting log collection..."

# Discover log sources if not already done
if [[ -z "${IRF_LOG_SOURCES+x}" ]] || [[ ${#IRF_LOG_SOURCES[@]} -eq 0 ]]; then
    echo "DEBUG: Calling irf_discover_log_sources()" >&2
    irf_discover_log_sources || {
        irf_log ERROR "Failed to discover log sources"
        exit 1
    }
    
    # Check if we have sources after discovery
    if [[ ${#IRF_LOG_SOURCES[@]} -eq 0 ]]; then
        irf_log ERROR "No log sources found after discovery"
        exit 1
    fi
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