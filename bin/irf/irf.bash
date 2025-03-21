#!/bin/bash
#
# Incident Response Framework (IRF) - Main executable wrapper
# This script provides a unified command-line interface to the framework

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

# Display usage information
show_usage() {
    cat << EOF
Incident Response Framework (IRF) v${IRF_VERSION}

Usage: irf [COMMAND] [OPTIONS]

Commands:
  collect  Collect logs from configured sources
  parse    Parse logs into normalized format
  monitor  Start monitoring logs in real-time
  respond  Execute response actions for detected incidents
  test     Test framework components
  help     Display this help message

Common Options:
  --config FILE   Path to alternative configuration file
  --verbose       Increase output verbosity
  --quiet         Suppress non-error output
  --version       Display version information and exit

Run 'irf help COMMAND' for more information on a specific command.
EOF
}

# Display version information
show_version() {
    echo "Incident Response Framework (IRF) v${IRF_VERSION}"
    echo "Copyright (c) $(date +%Y)"
}

# Parse command-line arguments
if [[ $# -lt 1 ]]; then
    show_usage
    exit 1
fi

COMMAND="$1"
shift

case "$COMMAND" in
    collect)
        # Ensure collector binary exists
        if [[ -x "${IRF_BIN_DIR}/irf-collector" ]]; then
            exec "${IRF_BIN_DIR}/irf-collector" "$@"
        else
            irf_log ERROR "Collector binary not found: ${IRF_BIN_DIR}/irf-collector"
            exit 1
        fi
        ;;
        
    parse)
        # Parse logs using the built-in functions
        source "${IRF_ROOT}/lib/bash/parser.sh" || {
            irf_log ERROR "Failed to load parser library"
            exit 1
        }
        
        if [[ $# -lt 1 ]]; then
            irf_log ERROR "No source configuration specified for parsing"
            echo "Usage: irf parse SOURCE_CONFIG [INPUT_FILE] [OUTPUT_FILE]" >&2
            exit 1
        fi
        
        irf_parse_logs "$@"
        exit $?
        ;;
        
    monitor)
        # Ensure monitor binary exists
        if [[ -x "${IRF_BIN_DIR}/irf-monitor" ]]; then
            exec "${IRF_BIN_DIR}/irf-monitor" "$@"
        else
            irf_log ERROR "Monitor binary not found: ${IRF_BIN_DIR}/irf-monitor"
            exit 1
        fi
        ;;
        
    respond)
        # Ensure respond binary exists
        if [[ -x "${IRF_BIN_DIR}/irf-respond" ]]; then
            exec "${IRF_BIN_DIR}/irf-respond" "$@"
        else
            irf_log ERROR "Respond binary not found: ${IRF_BIN_DIR}/irf-respond"
            exit 1
        fi
        ;;
        
    test)
        irf_log INFO "Testing framework components..."
        
        # Test libraries
        irf_log INFO "Testing common library..."
        if irf_check_dependencies; then
            irf_log INFO "Common library test: PASS"
        else
            irf_log WARN "Common library test: WARNING - Some dependencies missing"
        fi
        
        # Test log collection
        irf_log INFO "Testing log collector..."
        source "${IRF_ROOT}/lib/bash/collector.sh" || {
            irf_log ERROR "Failed to load collector library"
            exit 1
        }
        
        if irf_discover_log_sources; then
            irf_log INFO "Log source discovery test: PASS"
        else
            irf_log ERROR "Log source discovery test: FAIL"
        fi
        
        # Test parser
        irf_log INFO "Testing log parser..."
        source "${IRF_ROOT}/lib/bash/parser.sh" || {
            irf_log ERROR "Failed to load parser library"
            exit 1
        }
        
        irf_log INFO "All tests completed"
        ;;
        
    help)
        if [[ $# -eq 0 ]]; then
            show_usage
        else
            case "$1" in
                collect)
                    echo "Usage: irf collect [OPTIONS]"
                    echo ""
                    echo "Collect logs from configured sources."
                    echo ""
                    echo "Options:"
                    echo "  --source NAME  Collect logs only from specified source"
                    echo "  --output DIR   Directory to store collected logs"
                    ;;
                    
                parse)
                    echo "Usage: irf parse SOURCE_CONFIG [INPUT_FILE] [OUTPUT_FILE]"
                    echo ""
                    echo "Parse logs into normalized format."
                    echo ""
                    echo "Arguments:"
                    echo "  SOURCE_CONFIG  Path to the log source configuration file"
                    echo "  INPUT_FILE     Path to the input log file (optional)"
                    echo "  OUTPUT_FILE    Path to the output file (optional)"
                    ;;
                    
                monitor)
                    echo "Usage: irf monitor [OPTIONS]"
                    echo ""
                    echo "Start monitoring logs in real-time."
                    echo ""
                    echo "Options:"
                    echo "  --source NAME  Monitor only specified log source"
                    echo "  --daemon       Run in the background as a daemon"
                    ;;
                    
                respond)
                    echo "Usage: irf respond [OPTIONS]"
                    echo ""
                    echo "Execute response actions for detected incidents."
                    echo ""
                    echo "Options:"
                    echo "  --incident ID     Respond to a specific incident"
                    echo "  --action NAME     Execute a specific action"
                    echo "  --list            List available response actions"
                    ;;
                    
                test)
                    echo "Usage: irf test [COMPONENT]"
                    echo ""
                    echo "Test framework components."
                    echo ""
                    echo "Arguments:"
                    echo "  COMPONENT      Component to test (common, collector, parser, all)"
                    ;;
                    
                *)
                    echo "Unknown command: $1"
                    show_usage
                    ;;
            esac
        fi
        ;;
        
    --version|-v)
        show_version
        ;;
        
    *)
        echo "Unknown command: $COMMAND" >&2
        show_usage
        exit 1
        ;;
esac

exit 0