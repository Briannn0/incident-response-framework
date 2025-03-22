# Log Analysis and Incident Response Framework - Installation Guide

## Overview

This document provides detailed instructions for installing the Incident Response Framework (IRF) on Linux systems. The framework can be deployed in three main ways:

1. **Standard Installation**: Direct installation on the host system
2. **Docker Installation**: Deployment using Docker containers
3. **Development Installation**: Setup for development and testing

## Prerequisites

### Standard Installation

- Linux distribution (Ubuntu 18.04+, CentOS 7+, or Debian 10+)
- Bash 4.0 or later
- Standard utilities: grep, awk, sed, date, mktemp
- inotify-tools (for real-time monitoring)
- Python 3.6+ (for advanced analytics modules)
- Root or sudo access for system-wide installation

### Docker Installation

- Docker Engine 19.03+
- Docker Compose 1.25+
- 1GB+ RAM available for containers
- 1GB+ free disk space

### Development Installation

- Git
- Development tools (build-essential on Debian/Ubuntu)
- Python development packages

## System Requirements

- **Minimum**: 1 CPU core, 1GB RAM, 5GB disk space
- **Recommended**: 2+ CPU cores, 4GB+ RAM, 20GB+ disk space
- **Production**: 4+ CPU cores, 8GB+ RAM, 100GB+ disk space (depends on log volume)

## Standard Installation

### 1. Download the Framework

#### Option A: Download the Release Package

```bash
# Create installation directory
sudo mkdir -p /opt/incident-response-framework

# Download the latest release
wget https://github.com/username/incident-response-framework/releases/latest/download/irf.tar.gz

# Extract the package
sudo tar -xzf irf.tar.gz -C /opt/incident-response-framework
```

#### Option B: Clone from Git Repository

```bash
# Clone the repository
git clone https://github.com/username/incident-response-framework.git

# Move to installation directory
sudo mv incident-response-framework /opt/
```

### 2. Run the Installation Script

```bash
# Navigate to the installation directory
cd /opt/incident-response-framework

# Run the installation script
sudo ./scripts/install.sh
```

The installer will:
- Check for dependencies
- Create necessary directories
- Set appropriate permissions
- Create symlinks for easier access

### 3. Configure the Framework

```bash
# Edit the main configuration file
sudo nano /opt/incident-response-framework/conf/main.conf

# Configure log sources
sudo nano /opt/incident-response-framework/conf/sources/auth.conf
sudo nano /opt/incident-response-framework/conf/sources/syslog.conf
```

Customize the configuration files according to your environment. See [configuration.md](./configuration.md) for details.

### 4. Install Python Dependencies (Optional)

If you plan to use the advanced analytics modules:

```bash
# Install Python dependencies
sudo pip3 install -r /opt/incident-response-framework/requirements.txt
```

### 5. Set Up as System Service (Optional)

```bash
# Run the service setup script
sudo /opt/incident-response-framework/scripts/setup-service.sh
```

This will create and enable systemd services for the monitoring daemon.

### 6. Verify Installation

```bash
# Check if the framework is installed correctly
irf --version

# Test the configuration
irf test
```

## Docker Installation

### 1. Download the Framework

```bash
# Clone the repository
git clone https://github.com/username/incident-response-framework.git

# Navigate to the repository
cd incident-response-framework
```

### 2. Configure Docker Environment

```bash
# Prepare the installation for Docker
./scripts/install.sh --docker
```

### 3. Customize Configuration

Edit the Docker configuration files:

```bash
# Edit Docker Compose file if needed
nano docker/docker-compose.yml

# Edit container-specific configurations
nano docker/collector/Dockerfile
nano docker/analyzer/Dockerfile
nano docker/responder/Dockerfile
```

### 4. Build and Start the Containers

```bash
# Build and start the containers
cd docker
docker-compose up -d
```

### 5. Verify Docker Installation

```bash
# Check if containers are running
docker-compose ps

# View logs
docker-compose logs
```

## Development Installation

### 1. Clone the Repository

```bash
# Clone the repository
git clone https://github.com/username/incident-response-framework.git

# Navigate to the repository
cd incident-response-framework
```

### 2. Install Development Dependencies

```bash
# Install development dependencies
./scripts/install-dev-deps.sh
```

### 3. Set Up Development Environment

```bash
# Run with development settings
export IRF_ENV=development
export IRF_ROOT=$(pwd)

# Install in development mode
./scripts/install.sh --prefix $(pwd)/dev-install
```

### 4. Run Tests

```bash
# Run the test suite
./tests/run-tests.sh
```

## Installation Options

The installation script (`scripts/install.sh`) supports several options:

```bash
Usage: install.sh [OPTIONS]

Options:
  --prefix DIR    Installation directory (default: /opt/incident-response-framework)
  --docker        Configure for Docker environment
  --help          Display this help message
```

## Directory Structure After Installation

After installation, the directory structure will look like:

```
/opt/incident-response-framework/
├── bin/                  # Executable scripts
├── conf/                 # Configuration files
│   ├── sources/          # Log source definitions
│   ├── rules/            # Detection rules
│   └── actions/          # Response actions
├── lib/                  # Core libraries
│   ├── bash/             # Bash libraries
│   └── python/           # Python modules
├── logs/                 # Framework logs
├── evidence/             # Evidence preservation
├── modules/              # Pluggable modules
├── scripts/              # Helper scripts
├── tests/                # Test suite
└── docs/                 # Documentation
```

## Upgrading

To upgrade to a newer version:

```bash
# Navigate to the installation directory
cd /opt/incident-response-framework

# Backup configuration files
sudo cp -r conf conf.backup

# Pull latest changes (if installed from git)
sudo git pull

# Or download and extract the latest release package
# sudo tar -xzf irf-new-version.tar.gz -C /opt/incident-response-framework

# Run the upgrade script
sudo ./scripts/upgrade.sh

# Compare and merge configuration changes if needed
sudo diff -r conf.backup conf
```

## Uninstallation

To uninstall the framework:

```bash
# Stop services if running
sudo systemctl stop irf-monitor

# Run uninstallation script
sudo /opt/incident-response-framework/scripts/uninstall.sh

# Remove installation directory
sudo rm -rf /opt/incident-response-framework
```

## Troubleshooting

### Common Installation Issues

1. **Missing Dependencies**

```
ERROR: Required command not found: inotifywait
```

Solution:
```bash
# Debian/Ubuntu
sudo apt-get install inotify-tools

# CentOS/RHEL
sudo yum install inotify-tools
```

2. **Permission Issues**

```
ERROR: Failed to create directory: /opt/incident-response-framework/logs
```

Solution:
```bash
# Ensure you're running as root or with sudo
sudo ./scripts/install.sh
```

3. **Python Module Installation Failures**

```
ERROR: Could not install packages due to an EnvironmentError
```

Solution:
```bash
# Create a virtual environment
python3 -m venv /opt/incident-response-framework/venv
source /opt/incident-response-framework/venv/bin/activate
pip install -r requirements.txt
```

4. **Docker Networking Issues**

```
ERROR: Pool overlaps with other one on this address space
```

Solution:
```bash
# Edit the network configuration in docker-compose.yml
nano docker/docker-compose.yml
# Change the subnet configuration
```

### Installation Logs

The installation process logs to:

```
/opt/incident-response-framework/logs/install.log
```

Check this file for detailed information about any installation issues.

## Additional Resources

- [Configuration Guide](./configuration.md)
- [Usage Guide](./usage.md)
- [Rule Writing Guide](./rule-writing.md)
- [Architecture Overview](./architecture.md)

## Getting Help

If you encounter issues during installation:

1. Check the installation logs
2. Verify system requirements
3. Ensure all dependencies are installed
4. Check for permission issues
5. Consult the troubleshooting section above

For further assistance, please open an issue on GitHub.