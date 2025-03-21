#!/bin/bash
#
# Logging library for the Incident Response Framework
# Handles all logging functionality for the framework

# Prevent multiple includes
if [[ -n "${IRF_LOGGER_LOADED:-}" ]]; then
    return 0
fi
export IRF_LOGGER_LOADED=1

# Default values if configuration isn't loaded
IRF_LOG_DIR=${IRF_LOG_DIR:-"/var/log/irf"}
LOG_LEVEL=${LOG_LEVEL:-"INFO"}
MAX_LOG_SIZE=${MAX_LOG_SIZE:-104857600}  # 100MB
MAX_LOG_FILES=${MAX_LOG_FILES:-10}

# Log file paths
IRF_MAIN_LOG="${IRF_LOG_DIR}/irf.log"
IRF_ALERT_LOG="${IRF_LOG_DIR}/alerts.log"
IRF_AUDIT_LOG="${IRF_LOG_DIR}/audit.log"

# Log levels with their numeric values
declare -A LOG_LEVELS
LOG_LEVELS=([DEBUG]=10 [INFO]=20 [WARN]=30 [ERROR]=40 [CRITICAL]=50)

# ANSI color codes for terminal output
declare -A LOG_COLORS
LOG_COLORS=([DEBUG]="\033[36m" [INFO]="\033[32m" [WARN]="\033[33m" [ERROR]="\033[31m" [CRITICAL]="\033[35m")
RESET_COLOR="\033[0m"

#
# Function: irf_log_init
# Description: Initialize the logging system
# Arguments:
#   None
# Returns:
#   0 if successful, 1 otherwise
#
irf_log_init() {
    # Create log directory if it doesn't exist
    if [[ ! -d "$IRF_LOG_DIR" ]]; then
        mkdir -p "$IRF_LOG_DIR" || {
            echo "ERROR: Failed to create log directory: $IRF_LOG_DIR" >&2
            return 1
        }
    fi
    
    # Create log files if they don't exist
    for log_file in "$IRF_MAIN_LOG" "$IRF_ALERT_LOG" "$IRF_AUDIT_LOG"; do
        if [[ ! -f "$log_file" ]]; then
            touch "$log_file" || {
                echo "ERROR: Failed to create log file: $log_file" >&2
                return 1
            }
        fi
    done
    
    return 0
}

#
# Function: irf_rotate_logs
# Description: Rotate log files if they exceed maximum size
# Arguments:
#   $1 - Log file path
# Returns:
#   0 if successful, 1 otherwise
#
irf_rotate_logs() {
    local log_file="$1"
    
    # Check if rotation is needed
    if [[ -f "$log_file" ]] && [[ -s "$log_file" ]]; then
        local size
        size=$(stat -c%s "$log_file" 2>/dev/null || stat -f%z "$log_file" 2>/dev/null)
        
        if [[ $size -gt $MAX_LOG_SIZE ]]; then
            # Rotate logs
            for i in $(seq $((MAX_LOG_FILES-1)) -1 1); do
                if [[ -f "${log_file}.$i" ]]; then
                    mv "${log_file}.$i" "${log_file}.$((i+1))" || {
                        echo "ERROR: Failed to rotate log file: ${log_file}.$i" >&2
                        return 1
                    }
                fi
            done
            
            # Rotate the main log
            mv "$log_file" "${log_file}.1" || {
                echo "ERROR: Failed to rotate main log file: $log_file" >&2
                return 1
            }
            
            # Create a new log file
            touch "$log_file" || {
                echo "ERROR: Failed to create new log file: $log_file" >&2
                return 1
            }
            
            # Log the rotation event
            irf_log_message "INFO" "irf_logger" "Log file rotated: $log_file" "$log_file"
        fi
    fi
    
    return 0
}

#
# Function: irf_log_message
# Description: Write a log message to the specified log file
# Arguments:
#   $1 - Log level (DEBUG, INFO, WARN, ERROR, CRITICAL)
#   $2 - Component name
#   $3 - Message text
#   $4 - Log file (optional, defaults to IRF_MAIN_LOG)
# Returns:
#   0 if successful, 1 otherwise
#
irf_log_message() {
    local level="$1"
    local component="$2"
    local message="$3"
    local log_file="${4:-$IRF_MAIN_LOG}"
    
    # Create timestamp
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    # Get process ID
    local pid=$$
    
    # Format log message
    local log_entry="[$timestamp] [$level] [$component] [$pid] $message"
    
    # Write to log file
    echo "$log_entry" >> "$log_file" || {
        echo "ERROR: Failed to write to log file: $log_file" >&2
        return 1
    }
    
    return 0
}

#
# Function: irf_log
# Description: Main logging function that respects log level settings
# Arguments:
#   $1 - Log level (DEBUG, INFO, WARN, ERROR, CRITICAL)
#   $2 - Message text
#   $3 - Component name (optional, defaults to "irf")
# Returns:
#   0 if successful, 1 otherwise
#
irf_log() {
    local level="$1"
    local message="$2"
    local component="${3:-irf}"
    
    # Check if the log level is valid
    if [[ -z "${LOG_LEVELS[$level]:-}" ]]; then
        echo "ERROR: Invalid log level: $level" >&2
        return 1
    fi
    
    # Check if we should log this message based on configured level
    if [[ ${LOG_LEVELS[$level]} -ge ${LOG_LEVELS[$LOG_LEVEL]} ]]; then
        # Write to main log file
        irf_log_message "$level" "$component" "$message" "$IRF_MAIN_LOG"
        
        # If it's an alert-worthy message, also log to alerts
        if [[ -n "${ALERT_LOG_LEVEL:-}" ]] && 
           [[ ${LOG_LEVELS[$level]} -ge ${LOG_LEVELS[$ALERT_LOG_LEVEL]} ]]; then
            irf_log_message "$level" "$component" "$message" "$IRF_ALERT_LOG"
        fi
        
        # Print to console with colors if we're in interactive mode
        if [[ -t 1 ]]; then
            echo -e "${LOG_COLORS[$level]}[$level] [$component] $message${RESET_COLOR}"
        fi
    fi
    
    # Rotate logs if needed
    irf_rotate_logs "$IRF_MAIN_LOG"
    irf_rotate_logs "$IRF_ALERT_LOG"
    
    return 0
}

#
# Function: irf_audit
# Description: Log an audit event (security-relevant action)
# Arguments:
#   $1 - Action performed
#   $2 - User who performed the action
#   $3 - Additional details (optional)
# Returns:
#   0 if successful, 1 otherwise
#
irf_audit() {
    local action="$1"
    local user="$2"
    local details="${3:-}"
    
    # Get timestamp with milliseconds
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S.%3N")
    
    # Format audit message
    local audit_entry="[$timestamp] [AUDIT] [user=$user] [action=$action]"
    
    # Add details if provided
    if [[ -n "$details" ]]; then
        audit_entry="$audit_entry [details=$details]"
    fi
    
    # Write to audit log
    echo "$audit_entry" >> "$IRF_AUDIT_LOG" || {
        echo "ERROR: Failed to write to audit log: $IRF_AUDIT_LOG" >&2
        return 1
    }
    
    # Rotate audit log if needed
    irf_rotate_logs "$IRF_AUDIT_LOG"
    
    return 0
}

# Initialize the logging system
irf_log_init || {
    echo "ERROR: Failed to initialize logging system" >&2
    exit 1
}