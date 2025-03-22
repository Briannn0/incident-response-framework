# Log Analysis and Incident Response Framework - Usage Guide

## Overview

This document provides comprehensive instructions on using the Incident Response Framework (IRF) for log collection, analysis, and automated incident response. It covers basic usage, advanced features, and practical examples for common security monitoring tasks.

## Command Structure

The framework uses a unified command structure through the main `irf` executable:

```
irf [COMMAND] [OPTIONS]
```

Available commands:

- `collect` - Collect logs from configured sources
- `parse` - Parse logs into normalized format
- `detect` - Detect incidents from normalized logs
- `monitor` - Start monitoring logs in real-time
- `respond` - Execute response actions for detected incidents
- `analyze` - Perform time-based analysis on security events
- `correlate` - Correlate security events across different log sources
- `baseline` - Create and manage baseline behavior profiles
- `anomaly` - Detect anomalies in security log data
- `test` - Test framework components
- `help` - Display help information

## Basic Usage Examples

### Getting Help

```bash
# Display general help
irf help

# Display help for a specific command
irf help collect
```

### Log Collection

```bash
# Collect logs from all configured sources
irf collect

# Collect logs from a specific source
irf collect --source auth

# Specify output directory
irf collect --output /path/to/collected/logs
```

### Log Parsing

```bash
# Parse logs from a specific source configuration
irf parse /opt/incident-response-framework/conf/sources/auth.conf

# Parse a specific log file
irf parse /opt/incident-response-framework/conf/sources/auth.conf /var/log/auth.log

# Specify output file
irf parse /opt/incident-response-framework/conf/sources/auth.conf /var/log/auth.log /path/to/output.tsv
```

### Threat Detection

```bash
# Detect threats in normalized logs
irf detect --input /path/to/normalized/logs.tsv --output /path/to/alerts.tsv

# Specify rule file
irf detect --input /path/to/normalized/logs.tsv --rules /opt/incident-response-framework/conf/rules/brute-force.rules

# Filter by minimum severity
irf detect --input /path/to/normalized/logs.tsv --min-severity HIGH
```

### Real-time Monitoring

```bash
# Start monitoring all configured sources
irf monitor

# Monitor a specific source
irf monitor --source syslog

# Run as a daemon in the background
irf monitor --daemon
```

### Automated Response

```bash
# List available response actions
irf respond --list

# Execute a specific response action
irf respond --action block-ip --target 192.168.1.100

# Respond to a specific incident
irf respond --incident INC-20230415-001
```

### Event Correlation

```bash
# Correlate events from normalized logs
irf correlate --events /path/to/normalized/logs.tsv --output /path/to/correlated.json

# Specify correlation time window
irf correlate --events /path/to/normalized/logs.tsv --window 3600
```

### Statistical Analysis

```bash
# Analyze events for time-based patterns
irf analyze --data /path/to/normalized/logs.tsv --type frequency

# Analyze with specific time grouping
irf analyze --data /path/to/normalized/logs.tsv --type frequency --groupby 1H
```

### Anomaly Detection

```bash
# Detect anomalies in log data
irf anomaly --data /path/to/normalized/logs.tsv --fields timestamp,ip_address,username

# Specify detection method
irf anomaly --data /path/to/normalized/logs.tsv --fields ip_address,username --method isolation_forest
```

### Baseline Profiling

```bash
# Create a baseline profile
irf baseline create --data /path/to/training/data.tsv

# Detect anomalies by comparing against baseline
irf baseline detect --profile /path/to/baseline/profile.json --data /path/to/current/logs.tsv
```

### Testing Framework Components

```bash
# Test all components
irf test

# Test a specific rule
irf test --rule /opt/incident-response-framework/conf/rules/brute-force.rules

# Generate test data and run tests
irf test --generate
```

## Advanced Usage Scenarios

### Complete Security Monitoring Workflow

```bash
# 1. Collect logs
irf collect --output /tmp/collected_logs

# 2. Parse logs
irf parse /opt/incident-response-framework/conf/sources/auth.conf /tmp/collected_logs/auth.log /tmp/parsed_auth.tsv

# 3. Detect threats
irf detect --input /tmp/parsed_auth.tsv --output /tmp/alerts.tsv

# 4. Correlate events
irf correlate --events /tmp/alerts.tsv --output /tmp/correlated.json

# 5. Analyze patterns
irf analyze --data /tmp/alerts.tsv --output /tmp/analysis

# 6. Execute responses
irf respond --input /tmp/correlated.json
```

### Setting Up Continuous Monitoring

```bash
# Set up as a system service
sudo /opt/incident-response-framework/scripts/setup-service.sh

# Enable and start the service
sudo systemctl enable irf-monitor
sudo systemctl start irf-monitor

# Check service status
sudo systemctl status irf-monitor
```

### Creating a Custom Detection Rule

```bash
# Create a new rule file
cat > /opt/incident-response-framework/conf/rules/custom.rules << EOF
# Custom detection rules
CUSTOM-001;SSH Login from Unusual Country;accepted.*from;MEDIUM;6,9
CUSTOM-002;Access to Sensitive Application;access to app_name;HIGH;9
EOF

# Test the new rules
irf test --rule /opt/incident-response-framework/conf/rules/custom.rules
```

### Automated Response to Brute Force Attacks

```bash
# Set up automated IP blocking
irf respond --setup-action block-ip

# Configure auto-response for brute force
cat > /opt/incident-response-framework/conf/actions/auto-block-brute-force.conf << EOF
RULE_PATTERN=BF-SSH-*
ACTION=block-ip
FIELD=ip_address
THRESHOLD=5
EOF

# Enable auto-response
sudo sed -i 's/ENABLE_AUTO_RESPONSE=false/ENABLE_AUTO_RESPONSE=true/' /opt/incident-response-framework/conf/main.conf

# Restart the monitoring service
sudo systemctl restart irf-monitor
```

## Docker Usage

### Running in Docker Environment

```bash
# Navigate to Docker directory
cd /opt/incident-response-framework/docker

# Start all containers
docker-compose up -d

# Check container status
docker-compose ps

# View logs
docker-compose logs -f
```

### Accessing Docker Services

```bash
# Execute command in collector container
docker-compose exec collector irf collect

# Execute command in analyzer container
docker-compose exec analyzer irf detect --input /opt/incident-response-framework/logs/normalized.tsv

# Execute command in responder container
docker-compose exec responder irf respond --list
```

## Log Formats and Processing

### Normalized Log Format

The framework uses a tab-separated format for normalized logs with the following fields:

| Index | Field | Description |
|-------|-------|-------------|
| 0 | timestamp | Event timestamp |
| 1 | source_type | Type of log source (auth, syslog, etc.) |
| 2 | source_name | Name of the specific log source |
| 3 | log_level | Log severity level |
| 4 | username | User associated with the event |
| 5 | hostname | Host where the event occurred |
| 6 | ip_address | IP address associated with the event |
| 7 | service | Service or application |
| 8 | process_id | Process ID |
| 9 | message | Full log message |

### Log Processing Pipeline

```
Raw Logs → Collection → Parsing → Normalization → Detection → Correlation → Response
```

## Incident Response Workflow

### 1. Initial Detection

```bash
# Monitor logs for suspicious activity
irf monitor

# Alternatively, run periodic detection
irf collect
irf parse /opt/incident-response-framework/conf/sources/auth.conf /tmp/collected_logs/auth.log /tmp/parsed_auth.tsv
irf detect --input /tmp/parsed_auth.tsv --output /tmp/alerts.tsv
```

### 2. Investigation

```bash
# Correlate related events
irf correlate --events /tmp/alerts.tsv --output /tmp/correlated.json

# Analyze patterns
irf analyze --data /tmp/alerts.tsv --type all --output /tmp/analysis
```

### 3. Containment

```bash
# Execute response actions
irf respond --action block-ip --target 192.168.1.100

# Lock compromised account
irf respond --action lock-account --target compromised_user
```

### 4. Evidence Collection

```bash
# Preserve evidence
irf collect --source auth --output /opt/incident-response-framework/evidence/incidents/INC-20230415-001

# Export incident timeline
irf analyze --data /tmp/alerts.tsv --type timeline --output /opt/incident-response-framework/evidence/incidents/INC-20230415-001/timeline.json
```

## Integrating with Other Tools

### SIEM Integration

```bash
# Export alerts to SIEM format
irf detect --input /tmp/parsed_logs.tsv --output /tmp/alerts.json --format json

# Set up automated forwarding
cat > /opt/incident-response-framework/conf/integrations/siem.conf << EOF
ENABLED=true
SIEM_URL=https://siem.example.com/api/events
SIEM_TOKEN=your_api_token
SIEM_FORMAT=json
MIN_SEVERITY=MEDIUM
EOF
```

### Email Notifications

```bash
# Configure email alerts
cat > /opt/incident-response-framework/conf/alerts.conf << EOF
EMAIL_ALERTS=true
SMTP_SERVER=smtp.example.com
SMTP_PORT=587
SMTP_USE_TLS=true
SMTP_USERNAME=alerts@example.com
SMTP_PASSWORD=your_password
EMAIL_FROM=alerts@example.com
EMAIL_TO=security@example.com
EMAIL_SUBJECT_PREFIX=[SECURITY ALERT]
MIN_SEVERITY=HIGH
EOF
```

### Webhook Integration

```bash
# Configure webhook alerts
cat > /opt/incident-response-framework/conf/integrations/webhook.conf << EOF
ENABLED=true
WEBHOOK_URL=https://hooks.slack.com/services/TXXXXX/BXXXXX/XXXXXXXX
WEBHOOK_METHOD=POST
WEBHOOK_HEADERS="Content-Type: application/json"
WEBHOOK_TEMPLATE='{"text":"Security Alert: $ALERT_TEXT","severity":"$SEVERITY"}'
MIN_SEVERITY=HIGH
EOF
```

## Performance Optimization

### Tuning Collection

```bash
# Adjust polling interval
sudo sed -i 's/POLLING_INTERVAL=60/POLLING_INTERVAL=300/' /opt/incident-response-framework/conf/main.conf

# Focus on specific log sources
sudo sed -i 's/ENABLED=true/ENABLED=false/' /opt/incident-response-framework/conf/sources/apache.conf
```

### Optimizing Detection

```bash
# Prioritize important rules
sudo sed -i 's/LOG_PRIORITY=20/LOG_PRIORITY=10/' /opt/incident-response-framework/conf/sources/auth.conf

# Filter low-severity alerts
irf detect --input /tmp/parsed_logs.tsv --min-severity MEDIUM
```

### Resource Usage

```bash
# Set resource limits
sudo sed -i 's/MAX_CPU_PERCENT=80/MAX_CPU_PERCENT=50/' /opt/incident-response-framework/conf/main.conf
sudo sed -i 's/MAX_MEMORY_PERCENT=70/MAX_MEMORY_PERCENT=40/' /opt/incident-response-framework/conf/main.conf
```

## Practical Examples

### SSH Brute Force Detection

```bash
# Collect authentication logs
irf collect --source auth --output /tmp/collected_logs

# Parse logs
irf parse /opt/incident-response-framework/conf/sources/auth.conf /tmp/collected_logs/auth.log /tmp/parsed_auth.tsv

# Detect brute force attempts
irf detect --input /tmp/parsed_auth.tsv --rules /opt/incident-response-framework/conf/rules/brute-force.rules --output /tmp/brute_force_alerts.tsv

# Block attacking IPs
irf respond --input /tmp/brute_force_alerts.tsv --action block-ip
```

### Privileged Account Monitoring

```bash
# Create custom rule for privileged account usage
cat > /opt/incident-response-framework/conf/rules/privileged-accounts.rules << EOF
# Privileged account usage monitoring
PRIV-001;Root Login from Remote IP;root.*accepted.*from;HIGH;4,9
PRIV-002;Privileged Command Execution;sudo.*;MEDIUM;9
PRIV-003;Password Change for Privileged Account;passwd.*root;HIGH;9
EOF

# Monitor logs for privileged account usage
irf monitor --rules /opt/incident-response-framework/conf/rules/privileged-accounts.rules
```

### Malware Detection

```bash
# Collect and parse system logs
irf collect --source syslog --output /tmp/collected_logs
irf parse /opt/incident-response-framework/conf/sources/syslog.conf /tmp/collected_logs/syslog.log /tmp/parsed_syslog.tsv

# Detect malware activity
irf detect --input /tmp/parsed_syslog.tsv --rules /opt/incident-response-framework/conf/rules/malware.rules --output /tmp/malware_alerts.tsv

# Analyze for patterns
irf analyze --data /tmp/malware_alerts.tsv --type all --output /tmp/malware_analysis
```

### Log Anomaly Detection

```bash
# Create baseline from normal activity
irf baseline create --data /path/to/normal/logs.tsv --profile /tmp/baseline.json

# Detect anomalies in current logs
irf baseline detect --profile /tmp/baseline.json --data /path/to/current/logs.tsv --output /tmp/anomalies.json

# Investigate significant anomalies
irf analyze --data /tmp/anomalies.json --type timeline --output /tmp/anomaly_timeline.json
```

## Troubleshooting

### Checking Framework Status

```bash
# Check framework version
irf --version

# Check component status
irf test --component collector
irf test --component detector
```

### Viewing Logs

```bash
# View framework logs
less /opt/incident-response-framework/logs/irf.log

# View alerts log
less /opt/incident-response-framework/logs/alerts.log

# View audit log
less /opt/incident-response-framework/logs/audit.log
```

### Common Issues and Solutions

1. **No logs being collected**
   ```bash
   # Check log source configuration
   cat /opt/incident-response-framework/conf/sources/auth.conf
   
   # Verify file paths and permissions
   ls -la /var/log/auth.log
   ```

2. **No alerts being generated**
   ```bash
   # Test rules against sample logs
   irf test --rule /opt/incident-response-framework/conf/rules/brute-force.rules
   
   # Check minimum severity setting
   grep MIN_SEVERITY /opt/incident-response-framework/conf/main.conf
   ```

3. **Response actions not executing**
   ```bash
   # Check auto-response setting
   grep ENABLE_AUTO_RESPONSE /opt/incident-response-framework/conf/main.conf
   
   # Test response action manually
   irf respond --action block-ip --target 192.168.1.100 --dry-run
   ```

## Maintenance Tasks

### Backing Up Configuration

```bash
# Create a backup of the configuration
tar -czvf irf_config_backup.tar.gz -C /opt/incident-response-framework conf

# Restore from backup
sudo tar -xzvf irf_config_backup.tar.gz -C /opt/incident-response-framework
```

### Updating the Framework

```bash
# Update to latest version
cd /opt/incident-response-framework
sudo git pull

# Run update script
sudo ./scripts/update.sh
```

### Log Rotation

The framework automatically rotates its logs based on the `MAX_LOG_SIZE` and `MAX_LOG_FILES` settings in the main configuration file.

```bash
# View log rotation settings
grep MAX_LOG /opt/incident-response-framework/conf/main.conf

# Manually rotate logs
/opt/incident-response-framework/scripts/rotate-logs.sh
```

## Additional Resources

- [Configuration Guide](./configuration.md)
- [Rule Writing Guide](./rule-writing.md)
- [Architecture Overview](./architecture.md)
- [Installation Guide](./installation.md)

## Command Reference

| Command | Description | Example |
|---------|-------------|---------|
| `irf help` | Display help information | `irf help collect` |
| `irf collect` | Collect logs from sources | `irf collect --source auth` |
| `irf parse` | Parse logs into normalized format | `irf parse conf/sources/auth.conf` |
| `irf detect` | Detect incidents from logs | `irf detect --input logs.tsv` |
| `irf monitor` | Start real-time monitoring | `irf monitor --source syslog` |
| `irf respond` | Execute response actions | `irf respond --action block-ip` |
| `irf analyze` | Perform time-based analysis | `irf analyze --data alerts.tsv` |
| `irf correlate` | Correlate security events | `irf correlate --events alerts.tsv` |
| `irf baseline` | Manage baseline profiles | `irf baseline create --data logs.tsv` |
| `irf anomaly` | Detect anomalies in log data | `irf anomaly --data logs.tsv` |
| `irf test` | Test framework components | `irf test --rule brute-force.rules` |