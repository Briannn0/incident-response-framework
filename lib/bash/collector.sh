#!/bin/bash
#
# Log collection library for the Incident Response Framework
# Handles gathering logs from various sources

# Prevent multiple includes
if [[ -n "${IRF_COLLECTOR_LOADED:-}" ]]; then
    return 0
fi
export IRF_COLLECTOR_LOADED=1

# Validate file paths to prevent path traversal
irf_validate_path() {
    local path="$1"
    if [[ "$path" == *".."* || "$path" == *"~"* ]]; then
        irf_log ERROR "Invalid path detected: $path"
        return 1
    fi
    return 0
}

# Make sure common functions are loaded
if [[ -z "${IRF_COMMON_LOADED:-}" ]]; then
    # shellcheck source=/dev/null
    source "${IRF_ROOT:-$(dirname "$(dirname "$(readlink -f "$0")")")}/lib/bash/common.sh"
fi

# Array to store enabled log sources
declare -a IRF_LOG_SOURCES

#
# Function: irf_discover_log_sources
# Description: Discover available log sources from configuration
# Arguments:
#   None
# Returns:
#   0 if successful, 1 otherwise
#
irf_discover_log_sources() {
    local sources_dir="${IRF_CONF_DIR:-${IRF_ROOT}/conf}/sources"
    local count=0
    
    # Clear the array
    IRF_LOG_SOURCES=()
    
    # Validate sources directory
    if [[ ! -d "$sources_dir" ]]; then
        irf_log ERROR "Log sources directory not found: $sources_dir"
        return 1
    fi
    
    # Load each source configuration
    for config_file in "$sources_dir"/*.conf; do
        if [[ -f "$config_file" ]]; then
            # Reset variables for safety
            LOG_TYPE=""
            ENABLED="false"
            
            # Load configuration
            # shellcheck source=/dev/null
            source "$config_file"
            
            # Check if this source is enabled
            if [[ "${ENABLED}" == "true" ]]; then
                IRF_LOG_SOURCES+=("$config_file")
                count=$((count + 1))
                irf_log DEBUG "Discovered log source: $LOG_TYPE (${config_file})"
            fi
        fi
    done
    
    irf_log INFO "Discovered $count enabled log sources"
    
    if [[ $count -eq 0 ]]; then
        irf_log WARN "No enabled log sources found"
        return 1
    fi
    
    return 0
}

#
# Function: irf_validate_log_file
# Description: Validate that a log file exists and is readable
# Arguments:
#   $1 - Log file path
# Returns:
#   0 if file exists and is readable, 1 otherwise
#
irf_validate_log_file() {
    local log_file="$1"
    
    # Skip non-existent files in arrays when file globbing returned nothing
    [[ "$log_file" == *\** ]] && return 1
    
    # Check file existence and readability
    if [[ ! -f "$log_file" ]]; then
        irf_log WARN "Log file does not exist: $log_file"
        return 1
    fi
    
    if [[ ! -r "$log_file" ]]; then
        irf_log ERROR "Log file is not readable: $log_file"
        return 1
    fi
    
    return 0
}

#
# Function: irf_collect_log_data
# Description: Collect log data from a specified source
# Arguments:
#   $1 - Log source configuration file
#   $2 - Output file (optional)
# Returns:
#   0 if successful, 1 otherwise
#
irf_collect_log_data() {
    local config_file="$1"
    local output_file="${2:-}"
    local temp_file=""
    local return_code=0
    
    # Validate config file path
    if ! irf_validate_path "$config_file"; then
        return 1
    fi
    
    # Check if output file specified, create temp file if not
    if [[ -z "$output_file" ]]; then
        temp_file=$(irf_create_temp_file "irf_collect")
        output_file="$temp_file"
        chmod 600 "$output_file" || irf_log WARN "Failed to set secure permissions"
    fi
    
    # Reset variables to avoid contamination from previous invocations
    LOG_TYPE=""
    LOG_FILES=""
    COLLECTION_METHOD="file"
    FILTER_REGEX=""
    EXCLUDE_REGEX=""
    
    # Load the log source configuration
    # shellcheck source=/dev/null
    source "$config_file"
    
    irf_log DEBUG "Collecting logs for source: $LOG_TYPE"
    
    # Add locking for file access
    (
        if ! flock -n 200; then
            irf_log ERROR "Another process is accessing the log file"
            return 1
        fi
        
        # Process based on collection method
        case "$COLLECTION_METHOD" in
            file)
                # Split log files by space into an array
                IFS=' ' read -ra log_file_array <<< "$LOG_FILES"
                
                for log_file in "${log_file_array[@]}"; do
                    if irf_validate_log_file "$log_file"; then
                        irf_log DEBUG "Processing log file: $log_file"
                        
                        # Apply filtering if specified
                        if [[ -n "$FILTER_REGEX" ]] && [[ -n "$EXCLUDE_REGEX" ]]; then
                            grep -E "$FILTER_REGEX" "$log_file" | grep -v -E "$EXCLUDE_REGEX" >> "$output_file" || true
                        elif [[ -n "$FILTER_REGEX" ]]; then
                            grep -E "$FILTER_REGEX" "$log_file" >> "$output_file" || true
                        elif [[ -n "$EXCLUDE_REGEX" ]]; then
                            grep -v -E "$EXCLUDE_REGEX" "$log_file" >> "$output_file" || true
                        else
                            cat "$log_file" >> "$output_file" || {
                                irf_log ERROR "Failed to read log file: $log_file"
                                return_code=1
                            }
                        fi
                    else
                        irf_log WARN "Skipping invalid log file: $log_file"
                    fi
                done
                ;;
                
            syslog)
                irf_log WARN "Syslog collection method not yet implemented"
                return_code=1
                ;;
                
            journald)
                if irf_verify_command "journalctl"; then
                    # Use journalctl to collect logs
                    local journald_args=("-u" "$LOG_TYPE" "--no-pager")
                    
                    journalctl "${journald_args[@]}" >> "$output_file" || {
                        irf_log ERROR "Failed to collect journald logs for: $LOG_TYPE"
                        return_code=1
                    }
                else
                    irf_log ERROR "journalctl command not found, cannot collect journald logs"
                    return_code=1
                fi
                ;;
                
            *)
                irf_log ERROR "Unknown collection method: $COLLECTION_METHOD"
                return_code=1
                ;;
        esac
        
        flock -u 200
    ) 200>"${IRF_LOG_DIR}/.collector_lock"
    
    # If using a temp file, output the content and clean up
    if [[ -n "$temp_file" ]]; then
        if [[ -s "$temp_file" ]]; then
            cat "$temp_file"
        fi
        irf_cleanup_temp_file "$temp_file"
    fi
    
    if [[ $return_code -eq 0 ]]; then
        irf_log INFO "Successfully collected logs for source: $LOG_TYPE"
    else
        irf_log ERROR "Failed to collect logs for source: $LOG_TYPE"
    fi
    
    return $return_code
}

#
# Function: irf_setup_realtime_monitoring
# Description: Set up real-time monitoring for a log file using inotify
# Arguments:
#   $1 - Log file path
#   $2 - Callback function to execute when file changes
# Returns:
#   Process ID of the monitor process, or 0 if failed
#
irf_setup_realtime_monitoring() {
    local log_file="$1"
    local callback="$2"
    
    # Validate inotifywait command
    if ! irf_verify_command "inotifywait"; then
        irf_log ERROR "inotifywait command not found, cannot set up real-time monitoring"
        return 0
    fi
    
    # Validate log file
    if ! irf_validate_log_file "$log_file"; then
        irf_log ERROR "Cannot monitor invalid log file: $log_file"
        return 0
    fi
    
    # Set up monitor in the background
    (
        irf_log DEBUG "Starting real-time monitoring for: $log_file"
        
        # Monitor the file for modifications
        while inotifywait -q -e modify "$log_file"; do
            irf_log DEBUG "Detected change in log file: $log_file"
            
            # Execute the callback with the log file as argument
            "$callback" "$log_file" || {
                irf_log ERROR "Error in monitoring callback for: $log_file"
                break
            }
        done
        
        irf_log WARN "Real-time monitoring stopped for: $log_file"
    ) &
    
    local pid=$!
    irf_log INFO "Started real-time monitoring for $log_file (PID: $pid)"
    return $pid
}

#
# Function: irf_collect_all_logs
# Description: Collect logs from all enabled sources
# Arguments:
#   $1 - Output directory for collected logs
# Returns:
#   0 if successful, 1 if any source failed
#
irf_collect_all_logs() {
    local output_dir="${1:-${IRF_EVIDENCE_DIR}/collected}"
    local timestamp
    local success=0
    local failed=0
    
    # Create output directory if it doesn't exist
    if [[ ! -d "$output_dir" ]]; then
        mkdir -p "$output_dir" || {
            irf_log ERROR "Failed to create output directory: $output_dir"
            return 1
        }
    fi
    
    # Create timestamp directory for this collection run
    timestamp=$(date +"%Y%m%d_%H%M%S")
    local run_dir="${output_dir}/${timestamp}"
    
    mkdir -p "$run_dir" || {
        irf_log ERROR "Failed to create run directory: $run_dir"
        return 1
    }
    
    # Discover log sources if not already done
    if [[ ${#IRF_LOG_SOURCES[@]} -eq 0 ]]; then
        irf_discover_log_sources || {
            irf_log ERROR "Failed to discover log sources"
            return 1
        }
    fi
    
    # Collect logs from each source
    for config_file in "${IRF_LOG_SOURCES[@]}"; do
        # Reset variables to avoid contamination
        LOG_TYPE=""
        
        # Load configuration to get the log type
        # shellcheck source=/dev/null
        source "$config_file"
        
        local source_output="${run_dir}/${LOG_TYPE}.log"
        
        if irf_collect_log_data "$config_file" "$source_output"; then
            success=$((success + 1))
        else
            failed=$((failed + 1))
        fi
    done
    
    irf_log INFO "Log collection complete: $success succeeded, $failed failed"
    
    if [[ $failed -gt 0 ]]; then
        return 1
    fi
    
    return 0
}