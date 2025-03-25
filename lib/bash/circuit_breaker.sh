#!/bin/bash
#
# Circuit Breaker implementation for the Incident Response Framework
# Handles fault tolerance for external dependencies

# Prevent multiple includes
if [[ -n "${IRF_CIRCUIT_BREAKER_LOADED:-}" ]]; then
    return 0
fi
export IRF_CIRCUIT_BREAKER_LOADED=1

# Make sure common functions are loaded
if [[ -z "${IRF_COMMON_LOADED:-}" ]]; then
    # shellcheck source=/dev/null
    source "${IRF_ROOT:-$(dirname "$(dirname "$(readlink -f "$0")")")}/lib/bash/common.sh"
fi

# Circuit breaker states
readonly CB_STATE_CLOSED=0   # Working normally
readonly CB_STATE_OPEN=1     # Failing, don't try
readonly CB_STATE_HALF_OPEN=2 # Testing if it's working again

# Circuit breaker configuration
declare -A IRF_CIRCUIT_BREAKERS
declare -A IRF_CIRCUIT_BREAKER_CONFIGS

#
# Function: irf_circuit_breaker_init
# Description: Initialize a circuit breaker
# Arguments:
#   $1 - Circuit breaker name
#   $2 - Failure threshold (default: 3)
#   $3 - Reset timeout in seconds (default: 60)
#   $4 - Half-open timeout in seconds (default: 30)
# Returns:
#   0 if successful
#
irf_circuit_breaker_init() {
    local name="$1"
    local threshold="${2:-3}"
    local reset_timeout="${3:-60}"
    local half_open_timeout="${4:-30}"
    
    # Create or reset circuit breaker
    IRF_CIRCUIT_BREAKERS["${name}.state"]=$CB_STATE_CLOSED
    IRF_CIRCUIT_BREAKERS["${name}.failures"]=0
    IRF_CIRCUIT_BREAKERS["${name}.last_failure"]=0
    IRF_CIRCUIT_BREAKERS["${name}.last_success"]=0
    
    # Store configuration
    IRF_CIRCUIT_BREAKER_CONFIGS["${name}.threshold"]=$threshold
    IRF_CIRCUIT_BREAKER_CONFIGS["${name}.reset_timeout"]=$reset_timeout
    IRF_CIRCUIT_BREAKER_CONFIGS["${name}.half_open_timeout"]=$half_open_timeout
    
    irf_log DEBUG "Initialized circuit breaker: $name"
    return 0
}

#
# Function: irf_circuit_breaker_is_allowed
# Description: Check if a request is allowed through the circuit breaker
# Arguments:
#   $1 - Circuit breaker name
# Returns:
#   0 if allowed, 1 if blocked
#
irf_circuit_breaker_is_allowed() {
    local name="$1"
    local state=${IRF_CIRCUIT_BREAKERS["${name}.state"]:-$CB_STATE_CLOSED}
    local now=$(date +%s)
    
    case $state in
        $CB_STATE_CLOSED)
            # Always allow when closed
            return 0
            ;;
            
        $CB_STATE_OPEN)
            # Check if reset timeout has elapsed
            local last_failure=${IRF_CIRCUIT_BREAKERS["${name}.last_failure"]:-0}
            local reset_timeout=${IRF_CIRCUIT_BREAKER_CONFIGS["${name}.reset_timeout"]:-60}
            
            if (( now - last_failure > reset_timeout )); then
                # Transition to half-open
                IRF_CIRCUIT_BREAKERS["${name}.state"]=$CB_STATE_HALF_OPEN
                irf_log INFO "Circuit breaker $name transitioning to half-open state"
                return 0
            else
                # Still open, block request
                return 1
            fi
            ;;
            
        $CB_STATE_HALF_OPEN)
            # Allow only one test request
            local last_success=${IRF_CIRCUIT_BREAKERS["${name}.last_success"]:-0}
            local half_open_timeout=${IRF_CIRCUIT_BREAKER_CONFIGS["${name}.half_open_timeout"]:-30}
            
            if (( now - last_success > half_open_timeout )); then
                # First request after timeout, allow it
                return 0
            else
                # Recent request succeeded, stay in half-open but rate limit
                return 1
            fi
            ;;
            
        *)
            # Unknown state, assume closed
            IRF_CIRCUIT_BREAKERS["${name}.state"]=$CB_STATE_CLOSED
            return 0
            ;;
    esac
}

#
# Function: irf_circuit_breaker_success
# Description: Record a successful request
# Arguments:
#   $1 - Circuit breaker name
# Returns:
#   0 if successful
#
irf_circuit_breaker_success() {
    local name="$1"
    local state=${IRF_CIRCUIT_BREAKERS["${name}.state"]:-$CB_STATE_CLOSED}
    local now=$(date +%s)
    
    # Record success
    IRF_CIRCUIT_BREAKERS["${name}.last_success"]=$now
    
    # If in half-open state, transition to closed after success
    if (( state == CB_STATE_HALF_OPEN )); then
        IRF_CIRCUIT_BREAKERS["${name}.state"]=$CB_STATE_CLOSED
        IRF_CIRCUIT_BREAKERS["${name}.failures"]=0
        irf_log INFO "Circuit breaker $name closed after successful test request"
    fi
    
    return 0
}

#
# Function: irf_circuit_breaker_failure
# Description: Record a failed request
# Arguments:
#   $1 - Circuit breaker name
# Returns:
#   0 if recorded, 1 if circuit is now open
#
irf_circuit_breaker_failure() {
    local name="$1"
    local state=${IRF_CIRCUIT_BREAKERS["${name}.state"]:-$CB_STATE_CLOSED}
    local failures=${IRF_CIRCUIT_BREAKERS["${name}.failures"]:-0}
    local threshold=${IRF_CIRCUIT_BREAKER_CONFIGS["${name}.threshold"]:-3}
    local now=$(date +%s)
    
    # Record failure
    IRF_CIRCUIT_BREAKERS["${name}.last_failure"]=$now
    
    case $state in
        $CB_STATE_CLOSED)
            # Increment failure counter
            failures=$((failures + 1))
            IRF_CIRCUIT_BREAKERS["${name}.failures"]=$failures
            
            # Check if threshold exceeded
            if (( failures >= threshold )); then
                # Open the circuit
                IRF_CIRCUIT_BREAKERS["${name}.state"]=$CB_STATE_OPEN
                irf_log WARN "Circuit breaker $name opened after $failures failures"
                return 1
            fi
            ;;
            
        $CB_STATE_HALF_OPEN)
            # Test request failed, open circuit again
            IRF_CIRCUIT_BREAKERS["${name}.state"]=$CB_STATE_OPEN
            IRF_CIRCUIT_BREAKERS["${name}.failures"]=$threshold
            irf_log WARN "Circuit breaker $name reopened after failed test request"
            return 1
            ;;
            
        $CB_STATE_OPEN)
            # Already open, just note the failure
            irf_log DEBUG "Circuit breaker $name: failure while open"
            ;;
    esac
    
    return 0
}

#
# Function: irf_with_circuit_breaker
# Description: Execute a command with circuit breaker protection
# Arguments:
#   $1 - Circuit breaker name
#   $2 - Command to execute
#   $3 - Fallback command (optional)
# Returns:
#   Exit code of the command or fallback
#
irf_with_circuit_breaker() {
    local name="$1"
    local command="$2"
    local fallback="$3"
    
    # Initialize circuit breaker if not already done
    if [[ -z "${IRF_CIRCUIT_BREAKERS["${name}.state"]:-}" ]]; then
        irf_circuit_breaker_init "$name"
    fi
    
    # Check if request is allowed
    if irf_circuit_breaker_is_allowed "$name"; then
        # Execute command
        if eval "$command"; then
            # Command succeeded
            irf_circuit_breaker_success "$name"
            return 0
        else
            # Command failed
            local result=$?
            irf_circuit_breaker_failure "$name"
            
            # If fallback provided, use it
            if [[ -n "$fallback" ]]; then
                irf_log INFO "Circuit breaker $name: Executing fallback"
                eval "$fallback"
                return $?
            fi
            
            return $result
        fi
    else
        # Circuit is open, use fallback if provided
        irf_log WARN "Circuit breaker $name is open, request blocked"
        
        if [[ -n "$fallback" ]]; then
            irf_log INFO "Circuit breaker $name: Executing fallback"
            eval "$fallback"
            return $?
        fi
        
        return 1
    fi
}