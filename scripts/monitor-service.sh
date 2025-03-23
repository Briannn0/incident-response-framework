#!/bin/bash
#
# Monitor and auto-restart IRF services
# Run this in background to ensure services stay running

# Get the project root directory
IRF_ROOT=$(dirname "$(dirname "$(readlink -f "$0")")")
source "${IRF_ROOT}/lib/bash/common.sh"

# Load circuit breaker module
source "${IRF_ROOT}/lib/bash/circuit_breaker.sh"

# Check arguments
if [[ $# -lt 1 ]]; then
    echo "Usage: $(basename "$0") [monitor|collector|detector|responder]"
    exit 1
fi

SERVICE="$1"
MAX_RESTARTS=5
CHECK_INTERVAL=60  # Seconds
LOG_FILE="${IRF_LOG_DIR}/monitor_${SERVICE}.log"

# Create log directory if it doesn't exist
mkdir -p "$(dirname "$LOG_FILE")"

# Log with timestamp
log() {
    local level="$1"
    shift
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $*" | tee -a "$LOG_FILE"
}

# Start a service
start_service() {
    local service="$1"
    log INFO "Starting $service service"
    
    # Use circuit breaker to handle startup
    irf_with_circuit_breaker "${service}_start" "${IRF_ROOT}/bin/irf ${service} --daemon" "log ERROR 'Failed to start ${service}, circuit breaker open'"
    
    # Record PID for monitoring
    local pid=$(pgrep -f "${IRF_ROOT}/bin/irf ${service}" | head -1)
    if [[ -n "$pid" ]]; then
        log INFO "$service started with PID $pid"
        echo "$pid" > "${IRF_ROOT}/run/${service}.pid"
        return 0
    else
        log ERROR "Failed to start $service"
        return 1
    fi
}

# Stop a service
stop_service() {
    local service="$1"
    log INFO "Stopping $service service"
    
    # Get PID from file
    local pid_file="${IRF_ROOT}/run/${service}.pid"
    if [[ -f "$pid_file" ]]; then
        local pid=$(cat "$pid_file")
        
        # Check if process exists
        if kill -0 "$pid" 2>/dev/null; then
            # Try graceful shutdown first
            kill "$pid"
            
            # Wait for process to exit
            local timeout=10
            local count=0
            while kill -0 "$pid" 2>/dev/null && [[ $count -lt $timeout ]]; do
                sleep 1
                count=$((count + 1))
            done
            
            # Force kill if still running
            if kill -0 "$pid" 2>/dev/null; then
                log WARN "$service still running after $timeout seconds, sending SIGKILL"
                kill -9 "$pid"
            fi
        fi
        
        rm -f "$pid_file"
    fi
    
    # Double-check no processes are left
    pkill -f "${IRF_ROOT}/bin/irf ${service}" || true
}

# Check service health
check_health() {
    local service="$1"
    
    # Get PID from file
    local pid_file="${IRF_ROOT}/run/${service}.pid"
    if [[ ! -f "$pid_file" ]]; then
        log WARN "$service PID file not found"
        return 1
    fi
    
    local pid=$(cat "$pid_file")
    
    # Check if process exists
    if ! kill -0 "$pid" 2>/dev/null; then
        log WARN "$service process (PID $pid) not running"
        return 1
    fi
    
    # Check resource usage
    local cpu=$(ps -p "$pid" -o %cpu= 2>/dev/null || echo "0")
    local mem=$(ps -p "$pid" -o %mem= 2>/dev/null || echo "0")
    
    # Remove leading/trailing whitespace
    cpu=$(echo "$cpu" | xargs)
    mem=$(echo "$mem" | xargs)
    
    # Convert to numeric values
    cpu=$(echo "$cpu" | sed 's/[^0-9.]//g')
    mem=$(echo "$mem" | sed 's/[^0-9.]//g')
    
    # Check for excessive resource usage
    if (( $(echo "$cpu > 90" | bc -l) )); then
        log WARN "$service CPU usage too high: ${cpu}%"
        return 1
    fi
    
    if (( $(echo "$mem > 90" | bc -l) )); then
        log WARN "$service memory usage too high: ${mem}%"
        return 1
    fi
    
    # Service is healthy
    return 0
}

# Create run directory for PIDs
mkdir -p "${IRF_ROOT}/run"

# Initialize circuit breakers
irf_circuit_breaker_init "${SERVICE}_start" 3 300 60

# Start the service initially
start_service "$SERVICE" || {
    log ERROR "Failed to start $SERVICE initially"
    exit 1
}

# Monitor and restart as needed
restart_count=0
last_restart=0

log INFO "Starting monitoring loop for $SERVICE"

while true; do
    # Check service health
    if ! check_health "$SERVICE"; then
        current_time=$(date +%s)
        
        # Reset counter if last restart was over 10 minutes ago
        if (( current_time - last_restart > 600 )); then
            restart_count=0
        fi
        
        # Check if we're past the restart limit
        if (( restart_count >= MAX_RESTARTS )); then
            log ERROR "$SERVICE has failed $restart_count times, not restarting automatically"
            exit 1
        fi
        
        # Stop and restart the service
        log WARN "$SERVICE is unhealthy, restarting"
        stop_service "$SERVICE"
        sleep 2
        
        if start_service "$SERVICE"; then
            restart_count=$((restart_count + 1))
            last_restart=$current_time
            log INFO "Restarted $SERVICE successfully (attempt $restart_count)"
            
            # Create checkpoint for recovery
            irf_create_checkpoint "${SERVICE}_restart" "count=$restart_count;time=$current_time"
        else
            log ERROR "Failed to restart $SERVICE"
            exit 1
        fi
    else
        # Service is healthy, log periodically
        if (( SECONDS % 300 == 0 )); then  # Every 5 minutes
            log INFO "$SERVICE is running normally"
        fi
    fi
    
    sleep $CHECK_INTERVAL
done