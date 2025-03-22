#!/bin/bash
#
# Detection engine for the Incident Response Framework
# Handles pattern matching and rule-based detection

# Prevent multiple includes
if [[ -n "${IRF_DETECTOR_LOADED:-}" ]]; then
    return 0
fi
export IRF_DETECTOR_LOADED=1

# Make sure common functions are loaded
if [[ -z "${IRF_COMMON_LOADED:-}" ]]; then
    # shellcheck source=/dev/null
    source "${IRF_ROOT:-$(dirname "$(dirname "$(readlink -f "$0")")")}/lib/bash/common.sh"
fi

# Global array to store loaded rules
declare -a IRF_LOADED_RULES=()

# Rule severity levels
declare -A IRF_SEVERITY_LEVELS
IRF_SEVERITY_LEVELS=([INFO]=10 [LOW]=20 [MEDIUM]=30 [HIGH]=40 [CRITICAL]=50)

#
# Function: irf_load_rule_file
# Description: Load rules from a rule file
# Arguments:
#   $1 - Path to the rule file
# Returns:
#   0 if successful, 1 otherwise
#
irf_load_rule_file() {
    local rule_file="$1"
    local rule_count=0
    
    # Validate rule file
    if ! irf_validate_file "$rule_file"; then
        irf_log ERROR "Invalid rule file: $rule_file"
        return 1
    }
    
    # Parse the rule file
    while IFS= read -r line; do
        # Skip comments and empty lines
        [[ -z "${line}" || "${line}" =~ ^[[:space:]]*# ]] && continue
        
        # Store the rule in the global array
        IRF_LOADED_RULES+=("$line")
        rule_count=$((rule_count + 1))
    done < "$rule_file"
    
    irf_log INFO "Loaded $rule_count rules from $rule_file"
    
    if [[ $rule_count -eq 0 ]]; then
        irf_log WARN "No rules found in rule file: $rule_file"
        return 1
    fi
    
    return 0
}

#
# Function: irf_load_all_rules
# Description: Load all rule files from the rules directory
# Arguments:
#   None
# Returns:
#   0 if successful, 1 if any rule file failed to load
#
irf_load_all_rules() {
    local rules_dir="${IRF_CONF_DIR:-${IRF_ROOT}/conf}/rules"
    local loaded=0
    local failed=0
    
    # Clear the rules array
    IRF_LOADED_RULES=()
    
    # Validate rules directory
    if [[ ! -d "$rules_dir" ]]; then
        irf_log ERROR "Rules directory not found: $rules_dir"
        return 1
    fi
    
    # Load each rule file
    for rule_file in "$rules_dir"/*.rules; do
        if [[ -f "$rule_file" ]]; then
            if irf_load_rule_file "$rule_file"; then
                loaded=$((loaded + 1))
            else
                failed=$((failed + 1))
            fi
        fi
    done
    
    irf_log INFO "Rule loading complete: $loaded files loaded, $failed files failed"
    
    if [[ ${#IRF_LOADED_RULES[@]} -eq 0 ]]; then
        irf_log WARN "No rules loaded"
        return 1
    fi
    
    return $failed
}

#
# Function: irf_parse_rule
# Description: Parse a rule into its components
# Arguments:
#   $1 - Rule string
# Returns:
#   Sets global variables RULE_ID, RULE_DESCRIPTION, RULE_PATTERN, RULE_SEVERITY, RULE_FIELDS
#
irf_parse_rule() {
    local rule="$1"
    
    # Reset variables
    RULE_ID=""
    RULE_DESCRIPTION=""
    RULE_PATTERN=""
    RULE_SEVERITY="MEDIUM"  # Default severity
    RULE_FIELDS=""
    
    # Expected format: ID;DESCRIPTION;PATTERN;SEVERITY;FIELDS
    IFS=';' read -r RULE_ID RULE_DESCRIPTION RULE_PATTERN RULE_SEVERITY RULE_FIELDS <<< "$rule"
    
    # Validate required fields
    if [[ -z "$RULE_ID" || -z "$RULE_PATTERN" ]]; then
        irf_log ERROR "Invalid rule format: $rule"
        return 1
    fi
    
    # Validate severity level
    if [[ -n "$RULE_SEVERITY" && -z "${IRF_SEVERITY_LEVELS[$RULE_SEVERITY]:-}" ]]; then
        irf_log WARN "Invalid severity level in rule $RULE_ID: $RULE_SEVERITY, using MEDIUM"
        RULE_SEVERITY="MEDIUM"
    fi
    
    return 0
}

#
# Function: irf_apply_rule
# Description: Apply a detection rule to a log line
# Arguments:
#   $1 - Rule string
#   $2 - Log line (tab-separated fields)
# Returns:
#   0 if rule matched, 1 if not matched, 2 if error
#
irf_apply_rule() {
    local rule="$1"
    local log_line="$2"
    
    # Parse the rule
    if ! irf_parse_rule "$rule"; then
        return 2
    fi
    
    # Apply the rule pattern based on specified fields
    if [[ -z "$RULE_FIELDS" ]]; then
        # Apply to full log line
        if [[ "$log_line" =~ $RULE_PATTERN ]]; then
            return 0  # Match found
        fi
    else
        # Apply to specific fields
        IFS=',' read -ra field_indices <<< "$RULE_FIELDS"
        
        for index in "${field_indices[@]}"; do
            # Extract field value (assumes tab-separated fields)
            local field_value
            field_value=$(echo "$log_line" | cut -f "$index" 2>/dev/null)
            
            # Apply pattern to the field
            if [[ -n "$field_value" && "$field_value" =~ $RULE_PATTERN ]]; then
                return 0  # Match found
            fi
        done
    fi
    
    return 1  # No match
}

#
# Function: irf_detect_threats
# Description: Detect threats in log data using loaded rules
# Arguments:
#   $1 - Input log file (normalized format)
#   $2 - Output alerts file (optional)
# Returns:
#   0 if successful, 1 otherwise
#   Writes alerts to stdout or specified file
#
irf_detect_threats() {
    local input_file="$1"
    local output_file="${2:-}"
    local temp_file=""
    local header=""
    local match_count=0
    
    # Validate input file
    if ! irf_validate_file "$input_file"; then
        irf_log ERROR "Invalid input file for threat detection: $input_file"
        return 1
    fi
    
    # Create temporary file if output file not specified
    if [[ -z "$output_file" ]]; then
        temp_file=$(irf_create_temp_file "irf_alerts")
        output_file="$temp_file"
    fi
    
    # Get header line (field names)
    header=$(head -1 "$input_file")
    
    # Write header for alerts file
    echo -e "RULE_ID\tSEVERITY\tDESCRIPTION\t$header" > "$output_file"
    
    # Load rules if not already loaded
    if [[ ${#IRF_LOADED_RULES[@]} -eq 0 ]]; then
        irf_load_all_rules || {
            irf_log ERROR "Failed to load detection rules"
            return 1
        }
    fi
    
    # Process each log line
    local line_count=0
    while IFS= read -r log_line; do
        # Skip header line
        if [[ $line_count -eq 0 ]]; then
            line_count=$((line_count + 1))
            continue
        fi
        
        # Apply each rule to the log line
        for rule in "${IRF_LOADED_RULES[@]}"; do
            if irf_apply_rule "$rule" "$log_line" == 0; then
                # Match found - write alert
                echo -e "${RULE_ID}\t${RULE_SEVERITY}\t${RULE_DESCRIPTION}\t${log_line}" >> "$output_file"
                match_count=$((match_count + 1))
                
                # Log the alert
                irf_log WARN "Rule match: ${RULE_ID} - ${RULE_DESCRIPTION}"
                
                # Break after first match for efficiency (optional)
                # break
            fi
        done
        
        line_count=$((line_count + 1))
    done < "$input_file"
    
    irf_log INFO "Processed $((line_count - 1)) log lines, found $match_count potential threats"
    
    # If using a temp file, output the content and clean up
    if [[ -n "$temp_file" ]]; then
        if [[ -s "$temp_file" && $(wc -l < "$temp_file") -gt 1 ]]; then
            cat "$temp_file"
        fi
        irf_cleanup_temp_file "$temp_file"
    fi
    
    return 0
}

#
# Function: irf_get_severity_level
# Description: Get numeric severity level for a severity name
# Arguments:
#   $1 - Severity name (INFO, LOW, MEDIUM, HIGH, CRITICAL)
# Returns:
#   Numeric severity level (10-50) or 0 if invalid
#
irf_get_severity_level() {
    local severity="$1"
    
    echo "${IRF_SEVERITY_LEVELS[$severity]:-0}"
}

#
# Function: irf_filter_alerts_by_severity
# Description: Filter alerts based on minimum severity level
# Arguments:
#   $1 - Input alerts file
#   $2 - Minimum severity level (INFO, LOW, MEDIUM, HIGH, CRITICAL)
#   $3 - Output file (optional)
# Returns:
#   Filtered alerts to stdout or specified file
#
irf_filter_alerts_by_severity() {
    local input_file="$1"
    local min_severity="$2"
    local output_file="${3:-}"
    local temp_file=""
    
    # Validate input file
    if ! irf_validate_file "$input_file"; then
        irf_log ERROR "Invalid alerts file: $input_file"
        return 1
    fi
    
    # Create temporary file if output file not specified
    if [[ -z "$output_file" ]]; then
        temp_file=$(irf_create_temp_file "irf_filtered_alerts")
        output_file="$temp_file"
    fi
    
    # Get numeric severity level
    local min_level
    min_level=$(irf_get_severity_level "$min_severity")
    
    if [[ $min_level -eq 0 ]]; then
        irf_log ERROR "Invalid severity level: $min_severity"
        return 1
    fi
    
    # Write header line
    head -1 "$input_file" > "$output_file"
    
    # Filter alerts by severity
    while IFS= read -r line; do
        # Skip header line
        if [[ "$line" =~ ^RULE_ID ]]; then
            continue
        fi
        
        # Extract severity
        local severity
        severity=$(echo "$line" | cut -f2)
        
        # Get numeric level for the severity
        local level
        level=$(irf_get_severity_level "$severity")
        
        # Include alert if severity is at or above the minimum level
        if [[ $level -ge $min_level ]]; then
            echo "$line" >> "$output_file"
        fi
    done < "$input_file"
    
    # If using a temp file, output the content and clean up
    if [[ -n "$temp_file" ]]; then
        cat "$temp_file"
        irf_cleanup_temp_file "$temp_file"
    fi
    
    return 0
}