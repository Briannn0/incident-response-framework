#!/bin/bash
#
# Common utility functions for the Incident Response Framework
# This library provides foundational functions used across all modules

# Find these lines near the beginning
set -o errexit
set -o nounset
# Add this line
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
# Function: irf_validate_safe_path
# Description: Validate that a path is safe and doesn't contain directory traversal
# Arguments:
#   $1 - Path to validate
# Returns:
#   0 if path is safe, 1 otherwise
#
irf_validate_safe_path() {
    local path="$1"
    local normalized_path
    
    # Check for common path traversal patterns
    if [[ "$path" == *".."* || "$path" == *"/./"* || "$path" == *"~"* ]]; then
        irf_log ERROR "Path contains potentially unsafe patterns: $path"
        return 1
    fi
    
    # Check for absolute paths starting with / if not allowed
    if [[ "$path" == /* && "${ALLOW_ABSOLUTE_PATHS:-false}" != "true" ]]; then
        irf_log ERROR "Absolute paths not allowed in this context: $path"
        return 1
    fi
    
    # Check path length to prevent buffer overflow exploits
    if [[ "${#path}" -gt 4096 ]]; then
        irf_log ERROR "Path exceeds maximum allowed length: ${#path} characters"
        return 1
    fi
    
    # Verify path doesn't contain invalid characters
    if [[ "$path" =~ [[:cntrl:]] ]]; then
        irf_log ERROR "Path contains control characters: $path"
        return 1
    fi
    
    return 0
}

#
# Function: irf_generate_checksum
# Description: Generate a checksum for a file
# Arguments:
#   $1 - File path
# Returns:
#   Checksum string, or empty if error
#
irf_generate_checksum() {
    local file_path="$1"
    
    if [[ ! -f "$file_path" ]]; then
        irf_log ERROR "File not found for checksum: $file_path"
        return 1
    fi
    
    # Use sha256sum if available, otherwise fallback to md5sum
    if command -v sha256sum &>/dev/null; then
        sha256sum "$file_path" | awk '{print $1}'
    elif command -v md5sum &>/dev/null; then
        md5sum "$file_path" | awk '{print $1}'
    else
        irf_log ERROR "No checksum tool available"
        return 1
    fi
}

#
# Function: irf_verify_file_integrity
# Description: Verify file integrity against stored checksum
# Arguments:
#   $1 - File path
#   $2 - Optional checksum to verify against (if not provided, checks against stored checksum)
# Returns:
#   0 if integrity verified, 1 otherwise
#
irf_verify_file_integrity() {
    local file_path="$1"
    local expected_checksum="${2:-}"
    local checksum_file="${IRF_EVIDENCE_DIR}/checksums/$(basename "$file_path").sha256"
    
    # Create checksums directory if it doesn't exist
    if [[ ! -d "${IRF_EVIDENCE_DIR}/checksums" ]]; then
        mkdir -p "${IRF_EVIDENCE_DIR}/checksums" || {
            irf_log ERROR "Failed to create checksums directory"
            return 1
        }
    fi
    
    # Generate current checksum
    local current_checksum
    current_checksum=$(irf_generate_checksum "$file_path") || return 1
    
    # If expected checksum provided, verify against it
    if [[ -n "$expected_checksum" ]]; then
        if [[ "$current_checksum" != "$expected_checksum" ]]; then
            irf_log ERROR "Integrity check failed for $file_path"
            irf_log ERROR "Expected: $expected_checksum"
            irf_log ERROR "Actual:   $current_checksum"
            return 1
        fi
        
        # Store checksum for future checks
        echo "$current_checksum $file_path" > "$checksum_file"
        return 0
    fi
    
    # Otherwise check against stored checksum
    if [[ -f "$checksum_file" ]]; then
        expected_checksum=$(awk '{print $1}' "$checksum_file")
        if [[ "$current_checksum" != "$expected_checksum" ]]; then
            irf_log ERROR "Integrity check failed for $file_path"
            irf_log ERROR "Expected: $expected_checksum"
            irf_log ERROR "Actual:   $current_checksum"
            return 1
        fi
    else
        # No stored checksum, store current one
        echo "$current_checksum $file_path" > "$checksum_file"
        irf_log INFO "Stored initial checksum for $file_path"
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
# Function: irf_validate_environment
# Description: Validate the environment for the framework
# Arguments:
#   None
# Returns:
#   0 if environment is valid, 1 otherwise
#
irf_validate_environment() {
    # Validate and create required directories
    local required_dirs=(
        "$IRF_ROOT"
        "$IRF_LOG_DIR"
        "$IRF_EVIDENCE_DIR"
        "$IRF_CONF_DIR"
    )
    
    for dir in "${required_dirs[@]}"; do
        if [[ ! -d "$dir" ]]; then
            irf_log INFO "Creating directory: $dir"
            mkdir -p "$dir" || {
                irf_log ERROR "Failed to create directory: $dir"
                return 1
            }
        fi
        
        if [[ ! -w "$dir" ]]; then
            irf_log ERROR "Directory not writable: $dir"
            return 1
        fi
    done
    
    # Check disk space
    for dir in "$IRF_LOG_DIR" "$IRF_EVIDENCE_DIR"; do
        local available_space=$(df -k "$dir" | awk 'NR==2 {print $4 * 1024}')
        if [[ $available_space -lt 104857600 ]]; then # 100MB
            irf_log ERROR "Insufficient disk space for $dir: $((available_space / 1048576))MB available"
            return 1
        fi
    done
    
    return 0
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
# Function: irf_with_temp_file
# Description: Execute a callback with a temporary file that's automatically cleaned up
# Arguments:
#   $1 - Callback function to execute with the temporary file
#   $2 - Prefix for temporary file (optional)
# Returns:
#   Exit code from the callback function
#
irf_with_temp_file() {
    local callback="$1"
    local prefix="${2:-irf}"
    
    # Create temporary file
    local temp_file=$(mktemp "/tmp/${prefix}.XXXXXX") || {
        irf_log ERROR "Failed to create temporary file"
        return 1
    }
    
    # Set up cleanup trap
    trap 'rm -f "$temp_file"' EXIT
    
    # Call callback with temporary file
    "$callback" "$temp_file"
    local exit_code=$?
    
    # Clean up and return exit code
    rm -f "$temp_file"
    trap - EXIT
    
    return $exit_code
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

#
# Function: irf_execute_python_script
# Description: Execute a Python script and handle error reporting
# Arguments:
#   $1 - Path to Python script
#   $@ - Additional arguments passed to the Python script
# Returns:
#   Exit code from the Python script
#
irf_execute_python_script() {
    local script="$1"
    shift
    
    python3 "$script" "$@" 2> >(tee /tmp/python_error.$$.log >&2)
    local exit_code=$?
    
    if [[ $exit_code -ne 0 ]]; then
        # Extract error message from JSON if available
        local error_info=$(grep -m1 '{"status":"error"' /tmp/python_error.$$.log 2>/dev/null)
        if [[ -n "$error_info" ]]; then
            local error_message=$(echo "$error_info" | python3 -c "import sys,json; print(json.load(sys.stdin).get('error_message', ''))")
            irf_log ERROR "Python error: $error_message"
        fi
        rm -f /tmp/python_error.$$.log
        return $exit_code
    fi
    
    rm -f /tmp/python_error.$$.log
    return 0
}

#
# Function: irf_monitor_resources
# Description: Monitor system resources and adjust framework behavior
# Arguments:
#   $1 - CPU threshold percentage (optional, default 80)
#   $2 - Memory threshold percentage (optional, default 70)
# Returns:
#   0 if resources are below thresholds, 1 if any threshold is exceeded
#
irf_monitor_resources() {
    local cpu_threshold="${1:-80}"
    local mem_threshold="${2:-70}"
    local resource_state=0

    # Get current CPU usage (average over all cores)
    local cpu_usage
    if command -v mpstat &>/dev/null; then
        # Using mpstat if available
        cpu_usage=$(mpstat 1 1 | awk '/Average:/ {print 100 - $NF}')
    else
        # Fallback method
        cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}')
    fi

    # Get current memory usage
    local mem_usage
    mem_usage=$(free | grep Mem | awk '{print int($3/$2 * 100)}')

    # Log current resource usage periodically
    if [[ -n "${IRF_LAST_RESOURCE_LOG:-}" ]]; then
        local now=$(date +%s)
        if (( now - IRF_LAST_RESOURCE_LOG > 300 )); then  # Log every 5 minutes
            irf_log DEBUG "Resource usage: CPU=${cpu_usage}%, Memory=${mem_usage}%"
            export IRF_LAST_RESOURCE_LOG=$now
        fi
    else
        export IRF_LAST_RESOURCE_LOG=$(date +%s)
    fi

    # Check against thresholds and apply throttling
    if (( $(echo "$cpu_usage > $cpu_threshold" | bc -l) )); then
        irf_log WARN "High CPU usage: ${cpu_usage}% (threshold: ${cpu_threshold}%)"
        resource_state=1

        # Apply CPU throttling
        export IRF_CPU_THROTTLE=1
        export IRF_BATCH_SIZE=$((IRF_BATCH_SIZE / 2))
    elif [[ -n "${IRF_CPU_THROTTLE:-}" ]]; then
        # Remove throttling if CPU usage returns to normal
        unset IRF_CPU_THROTTLE
        export IRF_BATCH_SIZE=${IRF_ORIGINAL_BATCH_SIZE:-1000}
    fi

    if (( $(echo "$mem_usage > $mem_threshold" | bc -l) )); then
        irf_log WARN "High memory usage: ${mem_usage}% (threshold: ${mem_threshold}%)"
        resource_state=1

        # Apply memory optimization
        export IRF_MEM_OPTIMIZE=1
    elif [[ -n "${IRF_MEM_OPTIMIZE:-}" ]]; then
        # Remove optimization if memory usage returns to normal
        unset IRF_MEM_OPTIMIZE
    fi

    return $resource_state
}

#
# Function: irf_init_cache
# Description: Initialize the caching system
# Arguments:
#   $1 - Cache size (optional, default 1000)
# Returns:
#   0 if successful
#
irf_init_cache() {
    local cache_size="${1:-1000}"

    # Create cache directory
    local cache_dir="${IRF_ROOT}/cache"
    if [[ ! -d "$cache_dir" ]]; then
        mkdir -p "$cache_dir"
    fi

    # Initialize cache variables
    declare -A IRF_CACHE
    declare -a IRF_CACHE_KEYS
    export IRF_CACHE_SIZE=$cache_size
    export IRF_CACHE_HITS=0
    export IRF_CACHE_MISSES=0

    irf_log DEBUG "Cache initialized with size: $cache_size"
    return 0
}

#
# Function: irf_cache_get
# Description: Get a value from the cache
# Arguments:
#   $1 - Cache key
# Returns:
#   Cache value if found, empty string otherwise
#   Sets IRF_CACHE_HIT=1 if found, IRF_CACHE_HIT=0 if not found
#
irf_cache_get() {
    local key="$1"
    local value="${IRF_CACHE[$key]:-}"

    if [[ -n "$value" ]]; then
        # Cache hit
        IRF_CACHE_HIT=1
        IRF_CACHE_HITS=$((IRF_CACHE_HITS + 1))

        # Update access time
        IRF_CACHE["${key}_time"]=$(date +%s)

        echo "$value"
    else
        # Cache miss
        IRF_CACHE_HIT=0
        IRF_CACHE_MISSES=$((IRF_CACHE_MISSES + 1))
        echo ""
    fi
}

#
# Function: irf_cache_set
# Description: Set a value in the cache
# Arguments:
#   $1 - Cache key
#   $2 - Cache value
#   $3 - TTL in seconds (optional, default 3600)
# Returns:
#   0 if successful
#
irf_cache_set() {
    local key="$1"
    local value="$2"
    local ttl="${3:-3600}"

    # Get current cache size
    local current_size=${#IRF_CACHE_KEYS[@]}

    # If cache is full, remove least recently used item
    if (( current_size >= IRF_CACHE_SIZE )); then
        local oldest_key=""
        local oldest_time=$(date +%s)

        for k in "${IRF_CACHE_KEYS[@]}"; do
            local access_time=${IRF_CACHE["${k}_time"]:-0}
            if (( access_time < oldest_time )); then
                oldest_time=$access_time
                oldest_key=$k
            fi
        done

        if [[ -n "$oldest_key" ]]; then
            # Remove oldest entry
            unset IRF_CACHE["$oldest_key"]
            unset IRF_CACHE["${oldest_key}_time"]
            unset IRF_CACHE["${oldest_key}_ttl"]

            # Remove from keys array
            local new_keys=()
            for k in "${IRF_CACHE_KEYS[@]}"; do
                if [[ "$k" != "$oldest_key" ]]; then
                    new_keys+=("$k")
                fi
            done
            IRF_CACHE_KEYS=("${new_keys[@]}")
        fi
    fi

    # Store in cache
    IRF_CACHE["$key"]="$value"
    IRF_CACHE["${key}_time"]=$(date +%s)
    IRF_CACHE["${key}_ttl"]=$ttl

    # Add to keys if not already present
    local key_exists=0
    for k in "${IRF_CACHE_KEYS[@]}"; do
        if [[ "$k" == "$key" ]]; then
            key_exists=1
            break
        fi
    done

    if (( key_exists == 0 )); then
        IRF_CACHE_KEYS+=("$key")
    fi

    return 0
}

# Initialize the framework environment
irf_init() {
    # Check if already initialized
    if [[ -n "${IRF_INITIALIZED:-}" ]]; then
        return 0
    fi
    
    # Set timezone based on configuration
    if [[ -n "${TIMEZONE:-}" ]]; then
        export TZ="$TIMEZONE"
    fi
    
    # Check required directories with better error handling
    for dir in "$IRF_LOG_DIR" "$IRF_EVIDENCE_DIR"; do
        if ! irf_validate_directory "$dir"; then
            mkdir -p "$dir" 2>/dev/null || {
                echo "ERROR: Failed to create directory: $dir" >&2
                return 1
            }
            chmod 750 "$dir" 2>/dev/null || echo "WARNING: Failed to set directory permissions: $dir" >&2
        fi
    done
    
    # Enhanced dependency checking
    local missing_critical=0
    local missing_optional=0
    
    # Critical dependencies
    for cmd in "bash" "grep" "awk" "sed"; do
        if ! command -v "$cmd" &>/dev/null; then
            echo "ERROR: Critical dependency not found: $cmd" >&2
            missing_critical=$((missing_critical + 1))
        fi
    done
    
    # Optional dependencies
    for cmd in "inotifywait" "journalctl"; do
        if ! command -v "$cmd" &>/dev/null; then
            echo "WARNING: Optional dependency not found: $cmd" >&2
            missing_optional=$((missing_optional + 1))
        fi
    done
    
    if [[ $missing_critical -gt 0 ]]; then
        echo "ERROR: $missing_critical critical dependencies missing. Cannot continue." >&2
        return 1
    fi
    
    export IRF_INITIALIZED=1
    irf_log INFO "Incident Response Framework initialized (v$IRF_VERSION)"
    return 0
}

#
# Function: irf_monitor_process
# Description: Monitor a process and restart it if it fails
# Arguments:
#   $1 - Process name
#   $2 - Command to start the process
#   $3 - Max restarts (default: 5)
#   $4 - Check interval in seconds (default: 60)
# Returns:
#   Process ID of the monitor
#
irf_monitor_process() {
    local process_name="$1"
    local start_command="$2"
    local max_restarts="${3:-5}"
    local check_interval="${4:-60}"
    
    # Start monitor in the background
    (
        local restart_count=0
        local last_restart=0
        
        while true; do
            # Check if process is running
            if ! pgrep -f "$process_name" > /dev/null; then
                # Process not running, check if we should restart
                local current_time=$(date +%s)
                
                # If last restart was more than 5 minutes ago, reset counter
                if (( current_time - last_restart > 300 )); then
                    restart_count=0
                fi
                
                # Check if we've hit the max restarts
                if (( restart_count >= max_restarts )); then
                    irf_log ERROR "Process $process_name has crashed $restart_count times. Not restarting."
                    break
                fi
                
                # Restart the process
                irf_log WARN "Process $process_name not running. Restarting..."
                $start_command
                
                # Update counter
                restart_count=$((restart_count + 1))
                last_restart=$current_time
            fi
            
            # Wait before checking again
            sleep $check_interval
        done
    ) &
    
    echo $! # Return PID of monitor process
}

#
# Function: irf_create_checkpoint
# Description: Save state checkpoint for recovery
# Arguments:
#   $1 - Checkpoint identifier
#   $2 - Data to save (serialized)
# Returns:
#   0 if successful, 1 otherwise
#
irf_create_checkpoint() {
    local checkpoint_id="$1"
    local checkpoint_data="$2"
    local checkpoint_dir="${IRF_ROOT}/checkpoints"
    local checkpoint_file="${checkpoint_dir}/${checkpoint_id}.checkpoint"
    
    # Create checkpoint directory if it doesn't exist
    mkdir -p "$checkpoint_dir" || {
        irf_log ERROR "Failed to create checkpoint directory: $checkpoint_dir"
        return 1
    }
    
    # Save checkpoint data
    echo "$checkpoint_data" > "$checkpoint_file" || {
        irf_log ERROR "Failed to write checkpoint: $checkpoint_file"
        return 1
    }
    
    # Create timestamp file
    date -u +"%Y-%m-%dT%H:%M:%SZ" > "${checkpoint_file}.timestamp" || {
        irf_log WARN "Failed to create checkpoint timestamp file"
    }
    
    irf_log INFO "Created checkpoint: $checkpoint_id"
    return 0
}

#
# Function: irf_restore_checkpoint
# Description: Restore state from checkpoint
# Arguments:
#   $1 - Checkpoint identifier
# Returns:
#   Checkpoint data or empty if not found
#
irf_restore_checkpoint() {
    local checkpoint_id="$1"
    local checkpoint_dir="${IRF_ROOT}/checkpoints"
    local checkpoint_file="${checkpoint_dir}/${checkpoint_id}.checkpoint"
    
    if [[ -f "$checkpoint_file" ]]; then
        cat "$checkpoint_file"
        irf_log INFO "Restored checkpoint: $checkpoint_id"
        return 0
    else
        irf_log WARN "Checkpoint not found: $checkpoint_id"
        return 1
    fi
}