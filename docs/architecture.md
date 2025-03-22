# Log Analysis and Incident Response Framework - Architecture

## Overview

The Incident Response Framework (IRF) is a modular bash-based system designed to automate log collection, analysis, and incident response for Linux systems. This document outlines the framework's architecture, key components, data flow, and design principles.

## Architecture Diagram

```
                                   ┌─────────────────┐
                                   │                 │
                              ┌───▶│  Alert Manager  │───┐
                              │    │                 │   │
                              │    └─────────────────┘   │
                              │                          ▼
┌─────────────┐    ┌─────────┴──────┐    ┌───────────────────────┐
│             │    │                │    │                       │
│ Log Sources │──▶│ Log Collector  │──▶│   Response Automation  │
│             │    │                │    │                       │
└─────────────┘    └─────────┬──────┘    └───────────┬───────────┘
                             │                       │
                             ▼                       │
                   ┌─────────────────┐               │
                   │                 │               │
                   │  Parser Engine  │               │
                   │                 │               │
                   └────────┬────────┘               │
                            │                        │
                            ▼                        │
                   ┌─────────────────┐               │
                   │                 │               │
                   │ Detection Engine│───────────────┘
                   │                 │
                   └────────┬────────┘
                            │
                            ▼
                   ┌─────────────────┐
                   │                 │
                   │Correlation Engine│
                   │                 │
                   └────────┬────────┘
                            │
                            ▼
                   ┌─────────────────┐
                   │                 │
                   │Evidence Preserv.│
                   │                 │
                   └─────────────────┘
```

## Core Components

### 1. Log Collector (`bin/irf-collector`)

The Log Collector gathers logs from various sources defined in the `conf/sources/` directory. It supports:

- File-based logs (auth.log, syslog, apache logs, etc.)
- Real-time monitoring using inotify
- Various collection methods (file, syslog, journald)

The collector normalizes and structures the collected logs for further processing.

### 2. Parser Engine (`lib/bash/parser.sh`)

The Parser Engine processes raw log data into a standardized format. Key features:

- Converts various log formats (syslog, JSON, custom) into tab-separated normalized records
- Extracts key fields (timestamp, source, user, IP address, message, etc.)
- Handles field extraction using regex patterns defined in source configurations

### 3. Detection Engine (`lib/bash/detector.sh`)

The Detection Engine identifies suspicious patterns in normalized logs using rule-based pattern matching:

- Processes log entries against detection rules
- Rules defined in `conf/rules/` directory
- Supports regex patterns with severity classifications
- Generates alerts for matching patterns

### 4. Correlation Engine (`lib/python/correlator.py`)

The Correlation Engine connects related events across different log sources:

- Time-based correlation
- IP-based correlation
- Attack chain identification
- Statistical analysis

### 5. Alert Manager

The Alert Manager handles notification based on detection and correlation results:

- Email notifications
- Syslog forwarding
- Severity-based filtering
- Alert aggregation

### 6. Response Automation (`lib/bash/responder.sh`)

The Response Automation module takes predefined actions to contain threats:

- IP blocking via iptables
- Account lockdown
- Service isolation
- Configurable response actions in `conf/actions/`

### 7. Evidence Preservation

The Evidence Preservation module secures forensic data for investigation:

- Timestamps and records all actions
- Maintains chain of custody
- Preserves original logs
- Creates incident records

### 8. Reporting Module

The Reporting Module generates incident summaries and statistics:

- Per-incident reports
- Summary statistics
- Timeline visualization
- Evidence documentation

## Data Flow

1. **Collection**: Logs are gathered from configured sources
2. **Parsing**: Raw logs are normalized into a standard format
3. **Detection**: Normalized logs are analyzed against detection rules
4. **Correlation**: Related events are linked across log sources
5. **Alerting**: Administrators are notified of detected threats
6. **Response**: Automated actions are taken to contain threats
7. **Preservation**: Evidence is secured for investigation
8. **Reporting**: Incident summaries are generated

## Directory Structure

```
incident-response-framework/
├── bin/                  # Executable scripts
│   ├── irf               # Main executable wrapper
│   ├── irf-collector     # Log collection utility
│   ├── irf-monitor       # Monitoring daemon
│   └── irf-respond       # Response execution utility
│
├── conf/                 # Configuration files
│   ├── sources/          # Log source definitions
│   ├── rules/            # Detection rules
│   ├── actions/          # Response actions
│   ├── main.conf         # Main configuration file
│   └── alerts.conf       # Alert configuration settings
│
├── lib/                  # Core libraries
│   ├── bash/             # Bash libraries
│   │   ├── collector.sh  # Log collection module
│   │   ├── parser.sh     # Log parsing utilities
│   │   ├── detector.sh   # Rule-based detection engine
│   │   ├── responder.sh  # Automated response handler
│   │   ├── logger.sh     # Logging utilities
│   │   └── common.sh     # Common functions
│   │
│   └── python/           # Python modules
│       ├── correlator.py # Advanced event correlation
│       ├── analyzer.py   # Statistical analysis module
│       ├── visualizer.py # Data visualization utilities
│       ├── ml_detector.py # Machine learning detection
│       └── threat_intel.py # Threat intelligence integration
│
├── logs/                 # Framework logs
│
├── evidence/             # Evidence preservation
│   ├── incidents/        # Organized by incident ID
│   └── archives/         # Long-term storage
│
├── modules/              # Pluggable modules
│
├── docker/               # Docker configuration
│
├── tests/                # Test suite
│
└── docs/                 # Documentation
```

## Extension Points

The framework is designed with modularity and extensibility in mind:

1. **Log Sources**: Add new log sources by creating configuration files in `conf/sources/`
2. **Detection Rules**: Add new detection patterns in `conf/rules/`
3. **Response Actions**: Define new automated responses in `conf/actions/`
4. **Python Modules**: Extend analytics capabilities with custom Python modules
5. **Custom Modules**: Add specialized functionality in the `modules/` directory

## Security Considerations

1. **Least Privilege**: Framework operates with minimal required permissions
2. **Secure Defaults**: Conservative default configurations
3. **Evidence Integrity**: Checksums and timestamps for forensic data
4. **Audit Trail**: Full logging of all framework actions
5. **Input Validation**: Sanitization of all inputs

## Docker Support

The framework can be deployed as a containerized application:

- Collector container: Gathers and processes logs
- Analyzer container: Performs detection and correlation
- Responder container: Executes response actions

## References

- The IRF configuration guide: [configuration.md](./configuration.md)
- Installation instructions: [installation.md](./installation.md)
- Rule writing guide: [rule-writing.md](./rule-writing.md)
- Usage examples: [usage.md](./usage.md)