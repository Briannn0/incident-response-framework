# Log Analysis and Incident Response Framework - Configuration Guide

## Overview

This document describes the configuration files and options available in the Incident Response Framework (IRF). The framework uses a hierarchical configuration structure with the following components:

- Main configuration (`main.conf`)
- Log source configurations (`conf/sources/*.conf`)
- Detection rules (`conf/rules/*.rules`)
- Response actions (`conf/actions/*.action`)
- Alert settings (`alerts.conf`)

## Configuration Directory Structure

```
conf/
├── main.conf               # Main framework configuration
├── alerts.conf             # Alert notification settings
├── sources/                # Log source definitions
│   ├── auth.conf           # Authentication logs configuration
│   ├── syslog.conf         # System logs configuration
│   ├── apache.conf         # Web server logs configuration
│   └── ...                 # Additional log sources
├── rules/                  # Detection rules
│   ├── brute-force.rules   # Brute force attack detection
│   ├── privilege-esc.rules # Privilege escalation detection
│   ├── malware.rules       # Malware activity detection
│   ├── unauthorized-access.rules # Unauthorized access detection
│   └── ...                 # Additional rule sets
└── actions/                # Response actions
    ├── block-ip.action     # IP blocking configuration
    ├── lock-account.action # Account lockdown configuration
    ├── service-iso.action  # Service isolation procedures
    └── ...                 # Additional response actions
```

## Main Configuration (main.conf)

The `main.conf` file contains core settings that affect the overall behavior of the framework. It is typically located at `/opt/incident-response-framework/conf/main.conf`.

### Example Main Configuration

```bash
# Main configuration file for the Incident Response Framework
# This file contains core settings that affect the overall behavior of the framework

# Framework paths - use environment variables if available, otherwise use defaults
IRF_ROOT=${IRF_ROOT:-"/opt/incident-response-framework"}
IRF_LOG_DIR=${IRF_LOG_DIR:-"${IRF_ROOT}/logs"}
IRF_EVIDENCE_DIR=${IRF_EVIDENCE_DIR:-"${IRF_ROOT}/evidence"}
IRF_CONF_DIR=${IRF_CONF_DIR:-"${IRF_ROOT}/conf"}
IRF_LIB_DIR=${IRF_LIB_DIR:-"${IRF_ROOT}/lib"}

# General settings
ENABLE_MONITORING=${ENABLE_MONITORING:-true}           # Enable real-time monitoring
MONITORING_INTERVAL=${MONITORING_INTERVAL:-60}         # Check interval in seconds for non-real-time monitoring
MAX_LOG_SIZE=${MAX_LOG_SIZE:-104857600}                # 100MB max log size before rotation
MAX_LOG_FILES=${MAX_LOG_FILES:-10}                     # Number of log files to keep in rotation
TIMEZONE=${TIMEZONE:-"UTC"}                            # Timezone for timestamps

# Docker-specific settings
RUNNING_IN_DOCKER=${RUNNING_IN_DOCKER:-false}
DOCKER_LOG_PATH=${DOCKER_LOG_PATH:-"/var/log"}

# Resource limits
MAX_CPU_PERCENT=${MAX_CPU_PERCENT:-80}
MAX_MEMORY_PERCENT=${MAX_MEMORY_PERCENT:-70}

# Feature toggles
ENABLE_REAL_TIME_ALERTS=${ENABLE_REAL_TIME_ALERTS:-true}     # Send alerts in real-time
ENABLE_DAILY_REPORTS=${ENABLE_DAILY_REPORTS:-false}          # Generate daily summary reports
ENABLE_AUTO_RESPONSE=${ENABLE_AUTO_RESPONSE:-false}          # Enable automated response actions

# Logging levels (DEBUG, INFO, WARN, ERROR, CRITICAL)
LOG_LEVEL=${LOG_LEVEL:-"INFO"}                 # Default logging level
ALERT_LOG_LEVEL=${ALERT_LOG_LEVEL:-"WARN"}     # Minimum level to record in alerts log

# Default notification settings
NOTIFICATION_EMAIL=${NOTIFICATION_EMAIL:-"admin@example.com"}  # Email address for alerts (comma-separated for multiple)
NOTIFICATION_SYSLOG=${NOTIFICATION_SYSLOG:-true}              # Send alerts to syslog

# Security settings
ENCRYPT_EVIDENCE=${ENCRYPT_EVIDENCE:-false}           # Encrypt stored evidence files
ENCRYPT_METHOD=${ENCRYPT_METHOD:-"aes-256-cbc"}       # Encryption method if enabled
```

### Main Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `IRF_ROOT` | Base directory for the framework | `/opt/incident-response-framework` |
| `IRF_LOG_DIR` | Directory for framework logs | `${IRF_ROOT}/logs` |
| `IRF_EVIDENCE_DIR` | Directory for evidence preservation | `${IRF_ROOT}/evidence` |
| `IRF_CONF_DIR` | Directory for configuration files | `${IRF_ROOT}/conf` |
| `IRF_LIB_DIR` | Directory for library files | `${IRF_ROOT}/lib` |
| `ENABLE_MONITORING` | Enable real-time log monitoring | `true` |
| `MONITORING_INTERVAL` | Check interval for non-real-time monitoring (seconds) | `60` |
| `MAX_LOG_SIZE` | Maximum log file size before rotation (bytes) | `104857600` (100MB) |
| `MAX_LOG_FILES` | Number of log files to keep in rotation | `10` |
| `TIMEZONE` | Timezone for timestamps | `UTC` |
| `RUNNING_IN_DOCKER` | Whether running in Docker environment | `false` |
| `DOCKER_LOG_PATH` | Path to logs when running in Docker | `/var/log` |
| `MAX_CPU_PERCENT` | Maximum CPU usage percentage | `80` |
| `MAX_MEMORY_PERCENT` | Maximum memory usage percentage | `70` |
| `ENABLE_REAL_TIME_ALERTS` | Send alerts in real-time | `true` |
| `ENABLE_DAILY_REPORTS` | Generate daily summary reports | `false` |
| `ENABLE_AUTO_RESPONSE` | Enable automated response actions | `false` |
| `LOG_LEVEL` | Default logging level | `INFO` |
| `ALERT_LOG_LEVEL` | Minimum level to record in alerts log | `WARN` |
| `NOTIFICATION_EMAIL` | Email address for alerts | `admin@example.com` |
| `NOTIFICATION_SYSLOG` | Send alerts to syslog | `true` |
| `ENCRYPT_EVIDENCE` | Encrypt stored evidence files | `false` |
| `ENCRYPT_METHOD` | Encryption method if enabled | `aes-256-cbc` |

## Log Source Configuration

Log source configurations define how logs are collected and preprocessed from different sources. They are stored in the `conf/sources/` directory.

### Example Log Source Configuration (auth.conf)

```bash
# Authentication logs configuration
# This file defines how auth logs are collected and preprocessed

# Log source details
LOG_TYPE="auth"
LOG_PRIORITY=10               # Priority for processing (lower = higher priority)
ENABLED=true                  # Whether this log source is enabled

# File paths - adjust for your distribution
LOG_FILES="/var/log/auth.log /var/log/secure"  # Space-separated list of log files
LOG_FORMAT="syslog"           # Log format (syslog, json, custom)

# Collection settings
COLLECTION_METHOD="file"      # How to collect logs (file, syslog, journald)
REAL_TIME_MONITORING=true     # Use inotify to monitor in real-time
POLLING_INTERVAL=60           # Fallback polling interval in seconds

# Preprocessing options
FILTER_REGEX=""               # Optional regex to pre-filter logs
EXCLUDE_REGEX=""              # Optional regex to exclude certain log lines
TRANSFORM_SCRIPT=""           # Optional script to transform log entries

# Field extraction for auth logs
TIMESTAMP_FORMAT="%b %d %H:%M:%S"  # Format of timestamp in logs
TIMESTAMP_REGEX="^([A-Za-z]+ [0-9]+ [0-9:]+)"
USERNAME_REGEX="user[=: ]+([^ ]+)"
IP_ADDRESS_REGEX="([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})"
SERVICE_REGEX="([a-zA-Z]+)\[[0-9]+\]"

# Cache settings
MAX_CACHE_SIZE=10000          # Maximum number of entries to keep in memory
CACHE_TTL=3600                # Time in seconds to keep entries in cache
```

### Log Source Configuration Options

| Option | Description | Example |
|--------|-------------|---------|
| `LOG_TYPE` | Identifier for this log source | `auth` |
| `LOG_PRIORITY` | Priority for processing (lower = higher priority) | `10` |
| `ENABLED` | Whether this log source is enabled | `true` |
| `LOG_FILES` | Space-separated list of log files | `/var/log/auth.log /var/log/secure` |
| `LOG_FORMAT` | Log format (syslog, json, custom) | `syslog` |
| `COLLECTION_METHOD` | How to collect logs (file, syslog, journald) | `file` |
| `REAL_TIME_MONITORING` | Use inotify to monitor in real-time | `true` |
| `POLLING_INTERVAL` | Fallback polling interval in seconds | `60` |
| `FILTER_REGEX` | Optional regex to pre-filter logs | `sudo.*authentication` |
| `EXCLUDE_REGEX` | Optional regex to exclude certain log lines | `last message repeated` |
| `TRANSFORM_SCRIPT` | Optional script to transform log entries | `/opt/scripts/transform.sh` |
| `TIMESTAMP_FORMAT` | Format of timestamp in logs | `%b %d %H:%M:%S` |
| `TIMESTAMP_REGEX` | Regex to extract timestamp | `^([A-Za-z]+ [0-9]+ [0-9:]+)` |
| `USERNAME_REGEX` | Regex to extract username | `user[=: ]+([^ ]+)` |
| `IP_ADDRESS_REGEX` | Regex to extract IP address | `([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})` |
| `SERVICE_REGEX` | Regex to extract service name | `([a-zA-Z]+)\[[0-9]+\]` |
| `MAX_CACHE_SIZE` | Maximum number of entries to keep in memory | `10000` |
| `CACHE_TTL` | Time in seconds to keep entries in cache | `3600` |

## Detection Rules

Detection rules define patterns to identify suspicious activity in logs. They are stored in the `conf/rules/` directory with a `.rules` extension.

### Rule File Format

Rule files use a semi-colon separated format:

```
RULE_ID;DESCRIPTION;PATTERN;SEVERITY;FIELDS
```

Where:
- `RULE_ID`: Unique identifier for the rule
- `DESCRIPTION`: Human-readable description
- `PATTERN`: Regex pattern to match
- `SEVERITY`: Alert severity (INFO, LOW, MEDIUM, HIGH, CRITICAL)
- `FIELDS`: Comma-separated list of field indices to apply the pattern to (0-based)

### Example Rule File (brute-force.rules)

```
# Brute Force Attack Detection Rules
# Format: RULE_ID;DESCRIPTION;PATTERN;SEVERITY;FIELDS
#
# Fields reference (0-based index):
# 0 - timestamp
# 1 - source_type
# 2 - source_name
# 3 - log_level
# 4 - username
# 5 - hostname
# 6 - ip_address
# 7 - service
# 8 - process_id
# 9 - message

# SSH Failed Password Attempts
BF-SSH-001;SSH Multiple Failed Password Attempts;Failed\ password;MEDIUM;7,9
BF-SSH-002;SSH Authentication Failure;authentication failure;MEDIUM;9
BF-SSH-003;SSH Invalid User;Invalid user;HIGH;9
BF-SSH-004;SSH Connection Closed by Invalid User;Connection closed by invalid user;HIGH;9

# Failed sudo attempts
BF-SUDO-001;Multiple Failed sudo Password Attempts;authentication failure;HIGH;7,9
BF-SUDO-002;Failed sudo Command Execution;3 incorrect password attempts;HIGH;9

# General Authentication Failures
BF-AUTH-001;Multiple Failed Login Attempts;failed login;MEDIUM;9
BF-AUTH-002;PAM Authentication Failure;pam_unix\(.*\): authentication failure;MEDIUM;9

# Rate-based detection
BF-RATE-001;High Rate of Authentication Failures;authentication failure|Failed password;HIGH;9
```

See [rule-writing.md](./rule-writing.md) for detailed information on creating and testing detection rules.

## Response Actions

Response action configurations define automated responses to security incidents. They are stored in the `conf/actions/` directory with a `.action` extension.

### Example Response Action (block-ip.action)

```bash
# IP Blocking Response Action Configuration

# Action details
ACTION_ID="block-ip"
ACTION_DESCRIPTION="Block malicious IP addresses using iptables"
ENABLED=true

# Execution settings
REQUIRES_ROOT=true
EXECUTION_TIMEOUT=30  # Seconds

# Action parameters
CHAIN_NAME="INPUT"
BLOCK_RULE="-j DROP"
IPV6_SUPPORT=true
PERSISTENT=true
PERSISTENCE_FILE="/etc/iptables/rules.v4"
IPV6_PERSISTENCE_FILE="/etc/iptables/rules.v6"

# Restoration settings
AUTO_RESTORE=false
RESTORE_AFTER=3600  # Seconds

# Validation and safety checks
WHITELIST_IPS="127.0.0.1 192.168.1.1"
VALIDATE_IP=true
CHECK_EXISTING=true
```

## Alert Configuration (alerts.conf)

The alerts configuration defines how security alerts are handled and delivered.

### Example Alert Configuration

```bash
# Alert configuration settings

# Alert delivery methods
EMAIL_ALERTS=true
SYSLOG_ALERTS=true
WEBHOOK_ALERTS=false

# Email settings
SMTP_SERVER="smtp.example.com"
SMTP_PORT=587
SMTP_USE_TLS=true
SMTP_USERNAME="alerts@example.com"
SMTP_PASSWORD="password123"
EMAIL_FROM="alerts@example.com"
EMAIL_TO="admin@example.com,security@example.com"
EMAIL_SUBJECT_PREFIX="[SECURITY ALERT]"

# Syslog settings
SYSLOG_FACILITY="local0"
SYSLOG_PRIORITY="alert"
SYSLOG_TAG="irf"

# Webhook settings
WEBHOOK_URL="https://hooks.example.com/endpoint"
WEBHOOK_METHOD="POST"
WEBHOOK_HEADERS="Content-Type: application/json"
WEBHOOK_TEMPLATE="{\"text\":\"$ALERT_TEXT\",\"severity\":\"$SEVERITY\"}"

# Alert filtering
MIN_SEVERITY="MEDIUM"  # Minimum severity to trigger alerts (INFO, LOW, MEDIUM, HIGH, CRITICAL)
THROTTLE_ALERTS=true
THROTTLE_WINDOW=300  # Seconds
THROTTLE_COUNT=5  # Maximum alerts per window
SUPPRESS_DUPLICATES=true
DUPLICATE_WINDOW=3600  # Seconds

# Alert formatting
INCLUDE_RULE_ID=true
INCLUDE_TIMESTAMP=true
INCLUDE_SOURCE_INFO=true
INCLUDE_RAW_LOG=true
MAX_MESSAGE_LENGTH=1000
```

## Environment Variables

The framework supports configuration via environment variables, which override values in configuration files. The main environment variables are:

| Variable | Description | Default |
|----------|-------------|---------|
| `IRF_ROOT` | Base directory for the framework | `/opt/incident-response-framework` |
| `IRF_LOG_DIR` | Directory for framework logs | `${IRF_ROOT}/logs` |
| `IRF_EVIDENCE_DIR` | Directory for evidence preservation | `${IRF_ROOT}/evidence` |
| `IRF_CONF_DIR` | Directory for configuration files | `${IRF_ROOT}/conf` |
| `IRF_LIB_DIR` | Directory for library files | `${IRF_ROOT}/lib` |
| `IRF_LOG_LEVEL` | Override default logging level | `INFO` |
| `IRF_TIMEZONE` | Override default timezone | `UTC` |
| `IRF_ENABLE_AUTO_RESPONSE` | Override auto-response setting | `false` |
| `IRF_NOTIFICATION_EMAIL` | Override notification email | - |

## Configuration Testing

You can validate your configuration files using the built-in validation tool:

```bash
irf test --config /path/to/config.conf
```

## Applying Configuration Changes

Configuration changes take effect:

1. Immediately for new commands
2. After a restart for running daemons
3. On next poll interval for monitoring processes

To restart the framework after configuration changes:

```bash
systemctl restart irf-monitor
```

## Troubleshooting Configuration Issues

Common configuration issues and solutions:

- **Missing log files**: Check the paths in your log source configurations
- **Permission errors**: Ensure the framework has read access to log files
- **Invalid regex patterns**: Test regex patterns separately before adding them to rules
- **Email alerts not working**: Verify SMTP settings and credentials
- **Real-time monitoring not working**: Check that inotify-tools is installed

For more detailed troubleshooting, check the framework logs in `${IRF_LOG_DIR}/irf.log`.