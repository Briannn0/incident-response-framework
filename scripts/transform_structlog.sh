#!/bin/bash
#
# Transformation script for structured logs
# This script converts various structured log formats to a consistent format

# Read input line from stdin
read -r input_line

# Check if it's already in key=value format
if [[ "$input_line" =~ [a-zA-Z0-9_]+=.*[a-zA-Z0-9_]+= ]]; then
    # Already in expected format, no transformation needed
    echo "$input_line"
    exit 0
fi

# Check if it's JSON format
if [[ "$input_line" =~ ^\s*\{ && "$input_line" =~ \}\s*$ ]]; then
    # Convert JSON to key=value format using jq if available
    if command -v jq &>/dev/null; then
        # Write to temp file to handle special characters
        temp_file=$(mktemp)
        echo "$input_line" > "$temp_file"
        
        # Extract timestamp first for consistent format
        timestamp=$(jq -r '.timestamp // .time // .ts // .@timestamp // empty' "$temp_file" 2>/dev/null)
        
        # If no timestamp found, use current time
        if [[ -z "$timestamp" ]]; then
            timestamp=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")
        fi
        
        # Start with timestamp
        result="$timestamp "
        
        # Convert all fields to key=value format
        # Extract keys first
        keys=$(jq -r 'keys | .[]' "$temp_file" 2>/dev/null)
        
        for key in $keys; do
            # Get value and escape quotes
            value=$(jq -r ".[\"$key\"] | tostring" "$temp_file" 2>/dev/null)
            
            # Add quotes if value contains spaces
            if [[ "$value" =~ [[:space:]] ]]; then
                result+="$key=\"$value\" "
            else
                result+="$key=$value "
            fi
        done
        
        # Clean up
        rm -f "$temp_file"
        
        echo "$result"
        exit 0
    fi
fi

# Check for logfmt format (key=value without quotes)
if [[ "$input_line" =~ ^[0-9TZ:.-]+ ]]; then
    # Assume timestamp is at the beginning, keep as is
    echo "$input_line"
    exit 0
fi

# If nothing else matched, just pass through unchanged
echo "$input_line"
exit 0