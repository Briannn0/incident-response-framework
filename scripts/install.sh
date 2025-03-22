#!/bin/bash
#
# Incident Response Framework (IRF) - Installation Script
# This script installs the framework and sets up the initial configuration

# Fail on errors
set -e

# Default installation directory
DEFAULT_INSTALL_DIR="/opt/incident-response-framework"
INSTALL_DIR="$DEFAULT_INSTALL_DIR"
DOCKER_INSTALL=false

# Display usage information
show_usage() {
    cat << EOF
Incident Response Framework (IRF) - Installation Script

Usage: $0 [OPTIONS]

Options:
  --prefix DIR    Installation directory (default: $DEFAULT_INSTALL_DIR)
  --docker        Configure for Docker environment
  --help          Display this help message
EOF
}

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefix)
            if [[ -n "$2" ]]; then
                INSTALL_DIR="$2"
                shift 2
            else
                echo "ERROR: Missing argument for --prefix" >&2
                show_usage
                exit 1
            fi
            ;;
            
        --docker)
            DOCKER_INSTALL=true
            shift
            ;;
            
        --help)
            show_usage
            exit 0
            ;;
            
        *)
            echo "ERROR: Unknown option: $1" >&2
            show_usage
            exit 1
            ;;
    esac
done

# Add Docker-specific configuration
if [[ "$DOCKER_INSTALL" == true ]]; then
    echo "Configuring for Docker environment..."
    
    # Create Docker-specific directory structure
    mkdir -p docker/{collector,analyzer,responder}
    
    # Copy Dockerfiles if they don't exist
    for component in collector analyzer responder; do
        if [[ ! -f "docker/$component/Dockerfile" ]]; then
            echo "Creating Dockerfile for $component..."
            cat > "docker/$component/Dockerfile" << EOF
FROM ubuntu:22.04

# Install required dependencies
RUN apt-get update && apt-get install -y \\
    bash \\
    grep \\
    gawk \\
    sed \\
    inotify-tools \\
    && rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /opt/incident-response-framework

# Copy the framework files
COPY . .

# Set permissions
RUN chmod -R 750 /opt/incident-response-framework/bin
RUN chmod -R 640 /opt/incident-response-framework/conf
RUN chmod 750 /opt/incident-response-framework/conf /opt/incident-response-framework/conf/sources /opt/incident-response-framework/conf/rules /opt/incident-response-framework/conf/actions

# Create necessary directories
RUN mkdir -p /opt/incident-response-framework/logs /opt/incident-response-framework/evidence/incidents /opt/incident-response-framework/evidence/archives

# Set environment variables
ENV IRF_ROOT=/opt/incident-response-framework

# Set the entrypoint
ENTRYPOINT ["/opt/incident-response-framework/bin/irf", "$component"]
EOF
        fi
    done
    
    # Create docker-compose.yml if it doesn't exist
    if [[ ! -f "docker/docker-compose.yml" ]]; then
        echo "Creating docker-compose.yml..."
        cat > "docker/docker-compose.yml" << EOF
version: '3'

services:
  collector:
    build:
      context: ..
      dockerfile: docker/collector/Dockerfile
    volumes:
      - /var/log:/var/log:ro
      - shared_evidence:/opt/incident-response-framework/evidence
      - shared_logs:/opt/incident-response-framework/logs
    restart: unless-stopped
    networks:
      - irf-network

  analyzer:
    build:
      context: ..
      dockerfile: docker/analyzer/Dockerfile
    volumes:
      - shared_evidence:/opt/incident-response-framework/evidence
      - shared_logs:/opt/incident-response-framework/logs
    depends_on:
      - collector
    restart: unless-stopped
    networks:
      - irf-network

  responder:
    build:
      context: ..
      dockerfile: docker/responder/Dockerfile
    volumes:
      - shared_evidence:/opt/incident-response-framework/evidence
      - shared_logs:/opt/incident-response-framework/logs
      - /etc/:/etc/:ro
    depends_on:
      - analyzer
    restart: unless-stopped
    networks:
      - irf-network

volumes:
  shared_evidence:
  shared_logs:

networks:
  irf-network:
EOF
    fi
    
    echo "Docker configuration files created successfully!"
fi

# Check for root permissions if installing to system directory
if [[ "$INSTALL_DIR" == "/opt/"* || "$INSTALL_DIR" == "/usr/"* ]] && [[ $EUID -ne 0 ]]; then
    echo "ERROR: Root permissions required for installation in $INSTALL_DIR" >&2
    echo "Please run this script with sudo or as root user." >&2
    exit 1
fi

# Get the directory of this script
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
PROJECT_ROOT=$(dirname "$SCRIPT_DIR")

echo "Installing Incident Response Framework (IRF) to $INSTALL_DIR"

# Create installation directory if it doesn't exist
if [[ ! -d "$INSTALL_DIR" ]]; then
    mkdir -p "$INSTALL_DIR" || {
        echo "ERROR: Failed to create installation directory: $INSTALL_DIR" >&2
        exit 1
    }
    echo "Created installation directory: $INSTALL_DIR"
fi

# Create necessary directories
for dir in "bin" "conf/sources" "conf/rules" "conf/actions" "lib/bash" "lib/python" "logs" "evidence/incidents" "evidence/archives" "modules/collectors" "modules/detectors" "modules/responders"; do
    if [[ ! -d "$INSTALL_DIR/$dir" ]]; then
        mkdir -p "$INSTALL_DIR/$dir" || {
            echo "ERROR: Failed to create directory: $INSTALL_DIR/$dir" >&2
            exit 1
        }
        echo "Created directory: $INSTALL_DIR/$dir"
    fi
done

# Copy executable scripts
echo "Copying executables..."
for script in "$PROJECT_ROOT/bin/"*; do
    if [[ -f "$script" ]]; then
        cp "$script" "$INSTALL_DIR/bin/" || {
            echo "ERROR: Failed to copy executable: $script" >&2
            exit 1
        }
        chmod +x "$INSTALL_DIR/bin/$(basename "$script")" || {
            echo "ERROR: Failed to set executable permissions: $script" >&2
            exit 1
        }
        echo "Installed executable: $(basename "$script")"
    fi
done

# Copy library files
echo "Copying libraries..."
for lib in "$PROJECT_ROOT/lib/bash/"*.sh; do
    if [[ -f "$lib" ]]; then
        cp "$lib" "$INSTALL_DIR/lib/bash/" || {
            echo "ERROR: Failed to copy library: $lib" >&2
            exit 1
        }
        echo "Installed library: $(basename "$lib")"
    fi
done

# Copy configuration files
echo "Copying configuration files..."
for conf in "$PROJECT_ROOT/conf/"*.conf; do
    if [[ -f "$conf" ]]; then
        cp "$conf" "$INSTALL_DIR/conf/" || {
            echo "ERROR: Failed to copy configuration: $conf" >&2
            exit 1
        }
        echo "Installed configuration: $(basename "$conf")"
    fi
done

# Copy source configurations
for source_conf in "$PROJECT_ROOT/conf/sources/"*.conf; do
    if [[ -f "$source_conf" ]]; then
        cp "$source_conf" "$INSTALL_DIR/conf/sources/" || {
            echo "ERROR: Failed to copy source configuration: $source_conf" >&2
            exit 1
        }
        echo "Installed source configuration: $(basename "$source_conf")"
    fi
done

# Set appropriate permissions
echo "Setting permissions..."
chown -R "$(id -u):$(id -g)" "$INSTALL_DIR" || {
    echo "WARNING: Failed to set ownership for $INSTALL_DIR" >&2
}

chmod -R 750 "$INSTALL_DIR/bin" || {
    echo "WARNING: Failed to set permissions for $INSTALL_DIR/bin" >&2
}

chmod -R 640 "$INSTALL_DIR/conf"/* || {
    echo "WARNING: Failed to set permissions for configuration files" >&2
}

chmod 750 "$INSTALL_DIR/conf" "$INSTALL_DIR/conf/sources" "$INSTALL_DIR/conf/rules" "$INSTALL_DIR/conf/actions" || {
    echo "WARNING: Failed to set permissions for configuration directories" >&2
}

# Create symlinks for easier access (if installing to system directory)
if [[ "$INSTALL_DIR" == "/opt/"* || "$INSTALL_DIR" == "/usr/"* ]]; then
    echo "Creating symlinks in /usr/local/bin..."
    
    # Create symlink for the main executable
    ln -sf "$INSTALL_DIR/bin/irf" "/usr/local/bin/irf" || {
        echo "WARNING: Failed to create symlink for irf in /usr/local/bin" >&2
    }
    
    echo "Created symlink: /usr/local/bin/irf -> $INSTALL_DIR/bin/irf"
fi

# Check dependencies
echo "Checking dependencies..."
MISSING=0

for cmd in "grep" "awk" "sed" "bash" "date" "mktemp"; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "WARNING: Required command not found: $cmd" >&2
        MISSING=$((MISSING + 1))
    fi
done

# Check for inotify-tools (optional but recommended)
if ! command -v "inotifywait" &>/dev/null; then
    echo "NOTICE: inotifywait command not found. Real-time log monitoring will be disabled."
    echo "        Install inotify-tools package for real-time monitoring."
fi

# Install Python dependencies if pip3 is available
if command -v pip3 &>/dev/null; then
    pip3 install -r requirements.txt || {
        echo "WARNING: Failed to install Python dependencies" >&2
    }
else
    echo "WARNING: pip3 not found, Python dependencies not installed" >&2
fi

if [[ $MISSING -gt 0 ]]; then
    echo "WARNING: Some required dependencies are missing. The framework may not function correctly." >&2
fi

echo ""
echo "Installation completed successfully!"
echo ""
echo "To use the framework, run:"
echo "  $INSTALL_DIR/bin/irf"
if [[ "$INSTALL_DIR" == "/opt/"* || "$INSTALL_DIR" == "/usr/"* ]]; then
    echo "  or simply: irf"
fi
echo ""
echo "For help and usage information, run:"
echo "  irf help"
echo ""

exit 0