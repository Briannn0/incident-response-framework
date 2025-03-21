#!/bin/bash
#
# Common utility functions for the Incident Response Framework
# This library provides foundational functions used across all modules

# Ensure we fail on errors and undefined variables
set -o errexit
set -o nounset
set -o pipefail

# Global variables
IRF_VERSION="0.1.0"
IRF_ROOT=${IRF_ROOT:-$(dirname "$(dirname "$(readlink -f "$0")")")}

# Import configuration if not already loaded
if [[ -z "${IRF_CONF_LOADED:-}" ]]; then
    IRF_CONF_FILE="${IRF_ROOT}/conf/main.conf"
    if [[ -f "$IRF_CONF_FILE" ]]; then
        # shellcheck source=/dev/null
        source "$IRF_CONF_FILE"
        export IRF_CONF_LOADED=1
    else
        echo "ERROR: Configuration file not found: $IRF_CONF_FILE" >&2
        exit 1
    fi
fi

# Load logger functions if required
if [[ -z "${IRF_LOGGER_LOADED:-}" ]] && [[ -f "${IRF_ROOT}/lib/bash/logger.sh" ]]; then
    # shellcheck source=/dev/null
    source "${IRF_ROOT}/lib/bash/logger.sh"
fi

#
# Function: irf_verify_command
# Description: Verify that a command exists in the system
# Arguments:
#   $1 - Command to verify
# Returns:
#   0 if command exists, 1 otherwise
#
irf_verify_command() {
    local cmd="$1"
    if ! command -v "$cmd" &>/dev/null; then
        irf_log ERROR "Required command not found: $cmd"
        return 1
    fi
    return 0
}

#
# Function: irf_validate_file
# Description: Validate that a file exists and is readable
# Arguments:
#   $1 - File path to validate
# Returns:
#   0 if file exists and is readable, 1 otherwise
#
irf_validate_file() {
    local file_path="$1"
    if [[ ! -f "$file_path" ]]; then
        irf_log ERROR "File does not exist: $file_path"
        return 1
    fi
    if [[ ! -r "$file_path" ]]; then
        irf_log ERROR "File is not readable: $file_path"
        return 1
    fi
    return 0
}

#
# Function: irf_validate_directory
# Description: Validate that a directory exists and is writable
# Arguments:
#   $1 - Directory path to validate
# Returns:
#   0 if directory exists and is writable, 1 otherwise
#
irf_validate_directory() {
    local dir_path="$1"
    if [[ ! -d "$dir_path" ]]; then
        irf_log ERROR "Directory does not exist: $dir_path"
        return 1
    fi
    if [[ ! -w "$dir_path" ]]; then
        irf_log ERROR "Directory is not writable: $dir_path"
        return 1
    fi
    return 0
}

#
# Function: irf_load_config
# Description: Load a configuration file
# Arguments:
#   $1 - Configuration file path
# Returns:
#   0 if successful, 1 if file not found or not readable
#
irf_load_config() {
    local config_file="$1"
    
    if irf_validate_file "$config_file"; then
        # shellcheck source=/dev/null
        source "$config_file"
        irf_log DEBUG "Loaded configuration file: $config_file"
        return 0
    else
        return 1
    fi
}

#
# Function: irf_timestamp
# Description: Get current timestamp in specified format
# Arguments:
#   $1 - Format (optional, default: "%Y-%m-%d %H:%M:%S")
# Returns:
#   Timestamp string
#
irf_timestamp() {
    local format="${1:-%Y-%m-%d %H:%M:%S}"
    date +"$format"
}

#
# Function: irf_create_temp_file
# Description: Create a secure temporary file
# Arguments:
#   $1 - Prefix for temporary file (optional)
# Returns:
#   Path to temporary file
#
irf_create_temp_file() {
    local prefix="${1:-irf}"
    mktemp "/tmp/${prefix}.XXXXXX"
}

#
# Function: irf_cleanup_temp_file
# Description: Securely remove a temporary file
# Arguments:
#   $1 - Path to temporary file
# Returns:
#   0 if successful, 1 otherwise
#
irf_cleanup_temp_file() {
    local temp_file="$1"
    if [[ -f "$temp_file" ]]; then
        rm -f "$temp_file"
        return $?
    fi
    return 0
}

#
# Function: irf_check_dependencies
# Description: Check all required dependencies for the framework
# Arguments:
#   None
# Returns:
#   0 if all dependencies are present, 1 otherwise
#
irf_check_dependencies() {
    local missing=0
    local required_cmds=("grep" "awk" "sed" "tee" "date" "mktemp" "basename" "dirname")
    
    for cmd in "${required_cmds[@]}"; do
        if ! irf_verify_command "$cmd"; then
            missing=$((missing + 1))
        fi
    done
    
    # Check for inotify-tools if we need real-time monitoring
    if [[ "${ENABLE_MONITORING:-true}" == "true" ]] && 
       [[ "${REAL_TIME_MONITORING:-true}" == "true" ]]; then
        if ! irf_verify_command "inotifywait"; then
            irf_log WARN "inotifywait not found. Real-time monitoring will be disabled."
            irf_log WARN "Install inotify-tools package for real-time monitoring."
            missing=$((missing + 1))
        fi
    fi
    
    return $missing
}

# Initialize the framework environment
irf_init() {
    # Check required directories
    for dir in "$IRF_LOG_DIR" "$IRF_EVIDENCE_DIR"; do
        if ! irf_validate_directory "$dir"; then
            mkdir -p "$dir" || {
                echo "ERROR: Failed to create directory: $dir" >&2
                exit 1
            }
        fi
    done
    
    # Check dependencies
    irf_check_dependencies || {
        irf_log WARN "Some dependencies are missing."
    }
    
    irf_log INFO "Incident Response Framework initialized (v$IRF_VERSION)"
    return 0
}