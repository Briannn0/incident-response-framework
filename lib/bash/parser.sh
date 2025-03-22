#!/bin/bash
#
# Log parsing library for the Incident Response Framework
# Handles parsing and normalizing log data from various formats

# Prevent multiple includes
if [[ -n "${IRF_PARSER_LOADED:-}" ]]; then
    return 0
fi
export IRF_PARSER_LOADED=1

# Make sure common functions are loaded
if [[ -z "${IRF_COMMON_LOADED:-}" ]]; then
    # shellcheck source=/dev/null
    source "${IRF_ROOT:-$(dirname "$(dirname "$(readlink -f "$0")")")}/lib/bash/common.sh"
fi

# Field names for normalized log format
IRF_FIELDS=(
    "timestamp"
    "source_type"
    "source_name"
    "log_level"
    "username"
    "hostname"
    "ip_address"
    "service"
    "process_id"
    "message"
)

#
# Function: irf_sanitize_log_line
# Description: Sanitizes log lines by removing control characters and null bytes
# Arguments:
#   $1 - Log line to sanitize
# Returns:
#   Sanitized log line to stdout
#
irf_sanitize_log_line() {
    local line="$1"
    # Remove control characters and null bytes
    echo "$line" | tr -d '\000-\037\177'
}

#
# Function: irf_parse_log_line
# Description: Parse a single log line based on the specified format
# Arguments:
#   $1 - Log line to parse
#   $2 - Log format (syslog, json, custom)
#   $3 - Log type (auth, syslog, etc.)
# Returns:
#   Normalized log fields as tab-separated values to stdout
#
irf_parse_log_line() {
    local log_line="$1"
    local log_format="$2"
    local log_type="$3"
    
    # Sanitize log line
    log_line=$(irf_sanitize_log_line "$log_line")
    
    # Initialize fields with explicit declaration
    declare -A parsed_fields
    for field in "${IRF_FIELDS[@]}"; do
        parsed_fields["$field"]=""
    done
    
    # Set source_type to the log type
    parsed_fields["source_type"]="$log_type"
    
    # Try-catch style error handling for parsing
    {
        # Parse based on format
        case "$log_format" in
            syslog)
                # Extract timestamp (standard syslog format)
                if [[ "$log_line" =~ ^([A-Za-z]+[[:space:]]+[0-9]+[[:space:]]+[0-9:]+)[[:space:]]+(.*) ]]; then
                    parsed_fields["timestamp"]="${BASH_REMATCH[1]}"
                    log_line="${BASH_REMATCH[2]}"
                fi
                
                # Extract hostname if present
                if [[ "$log_line" =~ ^([^[:space:]]+)[[:space:]]+(.*) ]]; then
                    parsed_fields["hostname"]="${BASH_REMATCH[1]}"
                    log_line="${BASH_REMATCH[2]}"
                fi
                
                # Extract service/process (e.g. sshd, sudo, etc.)
                if [[ "$log_line" =~ ^([^:[:space:]]+)(\[[0-9]+\])?:[[:space:]]+(.*) ]]; then
                    parsed_fields["service"]="${BASH_REMATCH[1]}"
                    log_line="${BASH_REMATCH[3]}"
                fi
                
                # Extract process ID if present
                if [[ "$log_line" =~ \[([0-9]+)\] ]]; then
                    parsed_fields["process_id"]="${BASH_REMATCH[1]}"
                fi
                
                # Extract IP address if present (this is a simplified pattern)
                if [[ "$log_line" =~ ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}) ]]; then
                    parsed_fields["ip_address"]="${BASH_REMATCH[1]}"
                fi
                
                # Extract username if present
                if [[ "$log_line" =~ user[[:space:]]*[=:]?[[:space:]]*([^[:space:]]+) ]]; then
                    parsed_fields["username"]="${BASH_REMATCH[1]}"
                elif [[ "$log_line" =~ for[[:space:]]user[[:space:]]([^[:space:]]+) ]]; then
                    parsed_fields["username"]="${BASH_REMATCH[1]}"
                fi
                
                # The remaining part is the message
                parsed_fields["message"]="$log_line"
                ;;
            
            json)
                # Use jq if available, otherwise basic parsing with grep
                if command -v jq &>/dev/null; then
                    # Parse with jq and extract known fields
                    # This assumes the JSON structure matches our field names
                    for field in "${IRF_FIELDS[@]}"; do
                        local value
                        value=$(echo "$log_line" | jq -r ".$field // empty" 2>/dev/null)
                        if [[ -n "$value" && "$value" != "null" ]]; then
                            parsed_fields["$field"]="$value"
                        fi
                    done
                else
                    # Fallback basic parsing for JSON logs
                    for field in "${IRF_FIELDS[@]}"; do
                        if [[ "$log_line" =~ \"$field\":\"([^\"]+)\" ]]; then
                            parsed_fields["$field"]="${BASH_REMATCH[1]}"
                        fi
                    done
                fi
                ;;
            
            custom)
                # For custom format, we rely on regex patterns defined in the log source config
                if [[ -n "${TIMESTAMP_REGEX:-}" && "$log_line" =~ $TIMESTAMP_REGEX ]]; then
                    parsed_fields["timestamp"]="${BASH_REMATCH[1]}"
                fi
                
                if [[ -n "${USERNAME_REGEX:-}" && "$log_line" =~ $USERNAME_REGEX ]]; then
                    parsed_fields["username"]="${BASH_REMATCH[1]}"
                fi
                
                if [[ -n "${IP_ADDRESS_REGEX:-}" && "$log_line" =~ $IP_ADDRESS_REGEX ]]; then
                    parsed_fields["ip_address"]="${BASH_REMATCH[1]}"
                fi
                
                if [[ -n "${HOSTNAME_REGEX:-}" && "$log_line" =~ $HOSTNAME_REGEX ]]; then
                    parsed_fields["hostname"]="${BASH_REMATCH[1]}"
                fi
                
                if [[ -n "${SERVICE_REGEX:-}" && "$log_line" =~ $SERVICE_REGEX ]]; then
                    parsed_fields["service"]="${BASH_REMATCH[1]}"
                fi
                
                # The original message is kept intact
                parsed_fields["message"]="$log_line"
                ;;
            
            *)
                # Unknown format - store the whole line as the message
                parsed_fields["message"]="$log_line"
                irf_log WARN "Unknown log format: $log_format, storing raw message"
                ;;
        esac
    } || {
        irf_log WARN "Failed to parse log line: ${log_line:0:100}..."
        parsed_fields["message"]="$log_line"
    }
    
    # Output with proper quoting and escaping
    local output=""
    for field in "${IRF_FIELDS[@]}"; do
        # Escape tab characters in field values
        value="${parsed_fields[$field]//	/\\t}"
        output+="$value"$'\t'
    done
    
    # Remove trailing tab
    output=${output%$'\t'}
    
    echo "$output"
}

#
# Function: irf_parse_log_file
# Description: Parse a log file into a normalized format
# Arguments:
#   $1 - Log file to parse
#   $2 - Log format (syslog, json, custom)
#   $3 - Log type (auth, syslog, etc.)
#   $4 - Output file (optional)
# Returns:
#   0 if successful, 1 otherwise
#   Outputs normalized log to stdout or specified file
#
irf_parse_log_file() {
    local log_file="$1"
    local log_format="$2"
    local log_type="$3"
    local output_file="${4:-}"
    local temp_file=""
    
    # Validate log file
    if ! irf_validate_file "$log_file"; then
        irf_log ERROR "Invalid log file for parsing: $log_file"
        return 1
    fi
    
    # Create temporary file if output file not specified
    if [[ -z "$output_file" ]]; then
        temp_file=$(irf_create_temp_file "irf_parsed")
        output_file="$temp_file"
    fi
    
    # Write header line with field names
    (IFS=$'\t'; echo "${IRF_FIELDS[*]}") > "$output_file"
    
    # Parse each line of the log file
    local line_count=0
    while IFS= read -r line; do
        # Skip empty lines
        [[ -z "$line" ]] && continue
        
        # Parse the line and append to output
        irf_parse_log_line "$line" "$log_format" "$log_type" >> "$output_file"
        line_count=$((line_count + 1))
    done < "$log_file"
    
    irf_log INFO "Parsed $line_count lines from $log_file"
    
    # If using a temp file, output the content and clean up
    if [[ -n "$temp_file" ]]; then
        cat "$temp_file"
        irf_cleanup_temp_file "$temp_file"
    fi
    
    return 0
}

#
# Function: irf_parse_log_file_chunked
# Description: Parse a large log file into a normalized format using memory-efficient chunking
# Arguments:
#   $1 - Log file to parse
#   $2 - Log format (syslog, json, custom)
#   $3 - Log type (auth, syslog, etc.)
#   $4 - Output file
#   $5 - Chunk size (optional, default 10000 lines)
# Returns:
#   0 if successful, 1 otherwise
#
irf_parse_log_file_chunked() {
    local log_file="$1"
    local log_format="$2"
    local log_type="$3"
    local output_file="$4"
    local chunk_size="${5:-10000}"  # Process 10,000 lines at a time by default
    
    # Validate log file
    if ! irf_validate_file "$log_file"; then
        irf_log ERROR "Invalid log file for chunked parsing: $log_file"
        return 1
    fi
    
    # Write header
    (IFS=$'\t'; echo "${IRF_FIELDS[*]}") > "$output_file"
    
    # Count total lines for progress reporting
    local total_lines=$(wc -l < "$log_file")
    irf_log INFO "Starting chunked processing of $total_lines lines from $log_file"
    
    # Process in chunks
    local chunk_start=1  # Start with first line of actual log data
    local chunk_file=""
    local line_count=0
    local return_code=0
    
    while true; do
        # Check memory usage (more portable version)
        local memory_usage=$(free | grep Mem | awk '{print int($3/$2 * 100)}')
        if [[ "$memory_usage" -gt 70 ]]; then
            irf_log WARN "High memory usage: ${memory_usage}%, pausing for 10 seconds"
            sleep 10
            continue
        fi
        
        # Create temp file for chunk
        chunk_file=$(irf_create_temp_file "log_chunk")
        
        # Extract chunk of lines
        sed -n "${chunk_start},$((chunk_start + chunk_size - 1))p" "$log_file" > "$chunk_file"
        
        # If chunk is empty, we're done
        if [[ ! -s "$chunk_file" ]]; then
            irf_cleanup_temp_file "$chunk_file"
            break
        fi
        
        # Process chunk
        while IFS= read -r line; do
            # Skip empty lines
            [[ -z "$line" ]] && continue
            
            # Parse the line and append to output
            irf_parse_log_line "$line" "$log_format" "$log_type" >> "$output_file" || {
                irf_log ERROR "Failed to parse line: ${line:0:100}..."
                return_code=1
            }
            line_count=$((line_count + 1))
            
            # Report progress periodically
            if (( line_count % 5000 == 0 )); then
                irf_log DEBUG "Processed $line_count/$total_lines lines ($(( line_count * 100 / total_lines ))%)"
            fi
        done < "$chunk_file"
        
        # Update chunk start position
        chunk_start=$((chunk_start + chunk_size))
        
        # Clean up
        irf_cleanup_temp_file "$chunk_file"
    done
    
    irf_log INFO "Completed chunked processing of $line_count lines from $log_file"
    return $return_code
}

#
# Function: irf_parse_logs
# Description: Parse logs from a specific source based on its configuration
# Arguments:
#   $1 - Log source configuration file
#   $2 - Input log file (optional, uses LOG_FILES from config if not specified)
#   $3 - Output file (optional)
# Returns:
#   0 if successful, 1 otherwise
#
irf_parse_logs() {
    local config_file="$1"
    local input_file="${2:-}"
    local output_file="${3:-}"
    local return_code=0
    
    # Reset variables to avoid contamination from previous calls
    LOG_TYPE=""
    LOG_FILES=""
    LOG_FORMAT="syslog"  # Default format
    
    # Load the log source configuration
    # shellcheck source=/dev/null
    source "$config_file"
    
    # If no input file specified, use the first log file from config
    if [[ -z "$input_file" ]]; then
        # Split log files by space into an array
        IFS=' ' read -ra log_file_array <<< "$LOG_FILES"
        input_file="${log_file_array[0]}"
    fi
    
    # Validate input file
    if ! irf_validate_file "$input_file"; then
        irf_log ERROR "Invalid input file for parsing: $input_file"
        return 1
    fi
    
    # Parse the log file
    if ! irf_parse_log_file "$input_file" "$LOG_FORMAT" "$LOG_TYPE" "$output_file"; then
        irf_log ERROR "Failed to parse log file: $input_file"
        return_code=1
    fi
    
    return $return_code
}

#
# Function: irf_filter_normalized_logs
# Description: Filter normalized logs based on field values
# Arguments:
#   $1 - Input normalized log file
#   $2 - Field name to filter on
#   $3 - Value to match (exact match)
#   $4 - Output file (optional)
# Returns:
#   Filtered logs to stdout or specified file
#
irf_filter_normalized_logs() {
    local input_file="$1"
    local field="$2"
    local value="$3"
    local output_file="${4:-}"
    local temp_file=""
    
    # Validate input file
    if ! irf_validate_file "$input_file"; then
        irf_log ERROR "Invalid input file for filtering: $input_file"
        return 1
    fi
    
    # Create temporary file if output file not specified
    if [[ -z "$output_file" ]]; then
        temp_file=$(irf_create_temp_file "irf_filtered")
        output_file="$temp_file"
    fi
    
    # Get field index (first line contains headers)
    local field_index
    field_index=$(head -1 "$input_file" | tr '\t' '\n' | grep -n "^$field$" | cut -d: -f1)
    
    if [[ -z "$field_index" ]]; then
        irf_log ERROR "Field not found in normalized logs: $field"
        return 1
    fi
    
    # Copy header to output
    head -1 "$input_file" > "$output_file"
    
    # Filter lines where the specified field matches the value
    awk -F'\t' -v idx="$field_index" -v val="$value" 'NR > 1 && $idx == val' "$input_file" >> "$output_file"
    
    # If using a temp file, output the content and clean up
    if [[ -n "$temp_file" ]]; then
        cat "$temp_file"
        irf_cleanup_temp_file "$temp_file"
    fi
    
    return 0
}