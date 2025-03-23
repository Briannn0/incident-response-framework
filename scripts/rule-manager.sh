#!/bin/bash
#
# Rule Management Script for Incident Response Framework
# Handles rule versioning, diffs, and deployment

# Source common libraries
IRF_ROOT=$(dirname "$(dirname "$(readlink -f "$0")")")
source "${IRF_ROOT}/lib/bash/common.sh"

# Constants
RULES_DIR="${IRF_ROOT}/conf/rules"
RULES_HISTORY_DIR="${IRF_ROOT}/conf/rules_history"
RULES_DIFF_DIR="${IRF_ROOT}/conf/rules_diff"

# Make sure directories exist
mkdir -p "$RULES_HISTORY_DIR" "$RULES_DIFF_DIR"

#
# Function: show_usage
# Description: Display usage information
#
show_usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS] COMMAND

Commands:
  list                  List all rules
  show RULE_ID          Show details for a specific rule
  diff RULE_FILE        Show differences between current and previous version
  tag RULE_FILE TAG     Add a tag to a rule file
  untag RULE_FILE TAG   Remove a tag from a rule file
  commit RULE_FILE MSG  Commit changes to a rule file with a message
  history RULE_FILE     Show change history for a rule file
  version RULE_FILE VER Update version number for a rule file
  search TAG            Find rules with specific tag

Options:
  --output FORMAT       Output format (text, json) (default: text)
  --help                Show this help message
EOF
}

#
# Function: list_rules
# Description: List all rules with their metadata
#
list_rules() {
    echo "Rule Files:"
    echo "----------------------------------------------"
    
    for rule_file in "$RULES_DIR"/*.rules; do
        if [[ -f "$rule_file" ]]; then
            basename=$(basename "$rule_file" .rules)
            
            # Extract metadata
            version=$(grep -m 1 "^# Version:" "$rule_file" | cut -d ':' -f 2- | xargs)
            category=$(grep -m 1 "^# Category:" "$rule_file" | cut -d ':' -f 2- | xargs)
            last_updated=$(grep -m 1 "^# Last updated:" "$rule_file" | cut -d ':' -f 2- | xargs)
            
            # Count rules
            rule_count=$(grep -v "^#" "$rule_file" | grep -c ";")
            
            printf "%-20s | v%-10s | %-15s | %-12s | %d rules\n" \
                "$basename" "$version" "$category" "$last_updated" "$rule_count"
        fi
    done
}

#
# Function: rule_diff
# Description: Show differences between current and previous versions
# Arguments:
#   $1 - Rule file
#
rule_diff() {
    local rule_file="$1"
    local basename=$(basename "$rule_file" .rules)
    local history_dir="${RULES_HISTORY_DIR}/${basename}"
    
    # Check if rule file exists
    if [[ ! -f "$rule_file" ]]; then
        echo "Error: Rule file not found: $rule_file"
        return 1
    fi
    
    # Find latest version in history
    local latest_version=""
    if [[ -d "$history_dir" ]]; then
        latest_version=$(ls -v "$history_dir" | tail -n 1)
    fi
    
    if [[ -z "$latest_version" ]]; then
        echo "No previous version found for comparison"
        return 0
    fi
    
    # Generate diff
    diff -u "${history_dir}/${latest_version}" "$rule_file"
}

#
# Function: commit_rule_changes
# Description: Save current version of a rule file with a commit message
# Arguments:
#   $1 - Rule file
#   $2 - Commit message
#
commit_rule_changes() {
    local rule_file="$1"
    local message="$2"
    local basename=$(basename "$rule_file" .rules)
    local history_dir="${RULES_HISTORY_DIR}/${basename}"
    local diff_dir="${RULES_DIFF_DIR}/${basename}"
    
    # Check if rule file exists
    if [[ ! -f "$rule_file" ]]; then
        echo "Error: Rule file not found: $rule_file"
        return 1
    fi
    
    # Create history and diff directories
    mkdir -p "$history_dir" "$diff_dir"
    
    # Extract current version
    local current_version=$(grep -m 1 "^# Version:" "$rule_file" | cut -d ':' -f 2- | xargs)
    if [[ -z "$current_version" ]]; then
        current_version="1.0"
    fi
    
    # Timestamp for filename
    local timestamp=$(date +"%Y%m%d_%H%M%S")
    local history_file="${history_dir}/${timestamp}_v${current_version//./_}.rules"
    local diff_file="${diff_dir}/${timestamp}_v${current_version//./_}.diff"
    
    # Copy current file to history
    cp "$rule_file" "$history_file"
    
    # Generate diff if previous version exists
    local prev_version=$(ls -v "$history_dir" | tail -n 2 | head -n 1)
    if [[ -n "$prev_version" && -f "${history_dir}/${prev_version}" ]]; then
        diff -u "${history_dir}/${prev_version}" "$rule_file" > "$diff_file"
    else
        # No previous version, just copy the file
        cp "$rule_file" "$diff_file"
    fi
    
    # Add commit message
    echo "# Commit: $timestamp" >> "$diff_file"
    echo "# Message: $message" >> "$diff_file"
    
    echo "Changes committed. Version: $current_version, Timestamp: $timestamp"
    return 0
}

#
# Function: update_rule_version
# Description: Update version number in a rule file
# Arguments:
#   $1 - Rule file
#   $2 - New version
#
update_rule_version() {
    local rule_file="$1"
    local new_version="$2"
    
    # Check if rule file exists
    if [[ ! -f "$rule_file" ]]; then
        echo "Error: Rule file not found: $rule_file"
        return 1
    fi
    
    # Check if version line exists
    if grep -q "^# Version:" "$rule_file"; then
        # Update existing version line
        sed -i "s/^# Version:.*$/# Version: $new_version/" "$rule_file"
    else
        # Add version line after first line
        sed -i "1a # Version: $new_version" "$rule_file"
    fi
    
    # Update last updated date
    local today=$(date +"%Y-%m-%d")
    if grep -q "^# Last updated:" "$rule_file"; then
        sed -i "s/^# Last updated:.*$/# Last updated: $today/" "$rule_file"
    else
        # Add last updated line after version
        sed -i "/^# Version:/a # Last updated: $today" "$rule_file"
    fi
    
    echo "Updated version to $new_version"
    return 0
}

# Parse command line arguments
if [[ $# -lt 1 ]]; then
    show_usage
    exit 1
fi

COMMAND="$1"
shift

case "$COMMAND" in
    list)
        list_rules
        ;;
    diff)
        if [[ $# -lt 1 ]]; then
            echo "Error: Missing rule file argument"
            show_usage
            exit 1
        fi
        rule_file="${RULES_DIR}/$1"
        rule_diff "$rule_file"
        ;;
    commit)
        if [[ $# -lt 2 ]]; then
            echo "Error: Missing arguments (rule_file and/or message)"
            show_usage
            exit 1
        fi
        rule_file="${RULES_DIR}/$1"
        message="$2"
        commit_rule_changes "$rule_file" "$message"
        ;;
    version)
        if [[ $# -lt 2 ]]; then
            echo "Error: Missing arguments (rule_file and/or version)"
            show_usage
            exit 1
        fi
        rule_file="${RULES_DIR}/$1"
        new_version="$2"
        update_rule_version "$rule_file" "$new_version"
        ;;
    *)
        echo "Error: Unknown command: $COMMAND"
        show_usage
        exit 1
        ;;
esac

exit 0