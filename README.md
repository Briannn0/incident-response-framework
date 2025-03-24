# Incident Response Framework (IRF)

A comprehensive bash-based framework that automates log collection, analysis, and incident response for Linux systems. IRF detects security threats in real-time, alerts administrators, and provides automated response options to contain threats.


## Features

- **Log Collection**: Gather logs from multiple sources (auth.log, syslog, apache, etc.)
- **Log Parsing**: Normalize and structure log data for efficient analysis
- **Real-time Monitoring**: Watch log files for suspicious activity using inotify
- **Pattern Detection**: Identify security threats using customizable rule sets
- **Event Correlation**: Link related events across different log sources
- **Automated Response**: Configure predefined actions to contain threats
- **Evidence Preservation**: Secure forensic data for investigation
- **Statistical Analysis**: Detect anomalies and unusual patterns in log data
- **Modular Architecture**: Easily extendable with plugins and custom rules
- **Docker Support**: Run in containerized environments with provided Dockerfiles

## Architecture

The framework consists of several core modules working together:

- **Log Collector**: Gathers logs from configured sources
- **Parser Engine**: Normalizes and structures log data
- **Detection Engine**: Identifies suspicious patterns using rules
- **Correlation Engine**: Connects related events across logs
- **Alert Manager**: Notifies administrators based on threat severity
- **Response Automation**: Takes actions to contain threats
- **Evidence Preservation**: Secures data for investigation
- **Reporting Module**: Generates incident summaries

## Installation

### Prerequisites

- Bash 4.0 or later
- Standard Linux utilities (grep, awk, sed)
- inotify-tools (for real-time monitoring)
- Python 3.x (for advanced analysis modules)

### Basic Installation

```bash
# Clone the repository
git clone https://github.com/Briannn0/incident-response-framework.git
cd incident-response-framework

# Run the installation script
./scripts/install.sh

# Verify the installation
irf --version
```

### Docker Installation

```bash
# Clone the repository
git clone https://github.com/Briannn0/incident-response-framework.git
cd incident-response-framework

# Build and run with Docker Compose
cd docker
docker-compose up -d
```

## Getting Started

### Basic Usage

```bash
# Collect logs from all configured sources
irf collect

# Parse logs from a specific source
irf parse /opt/incident-response-framework/conf/sources/auth.conf

# Start monitoring logs in real-time
irf monitor

# Run rule-based detection on collected logs
irf detect --input /path/to/normalized/logs.tsv --output /path/to/alerts.tsv

# Test detection rules against sample data
irf test --rule conf/rules/brute-force.rules --generate
```

### Advanced Usage

```bash
# Correlate events across different log sources
irf correlate --events /path/to/alerts.tsv --window 3600

# Perform statistical analysis on log data
irf analyze --data /path/to/normalized/logs.tsv --type frequency

# Create baseline profiles for anomaly detection
irf baseline create --data /path/to/training/data.tsv

# Detect anomalies by comparing against baselines
irf anomaly --data /path/to/current/logs.tsv --fields "ip_address,username,service"
```

## Configuration

The framework's behavior is controlled by configuration files in the `conf/` directory:

- **main.conf**: Core settings that affect the overall behavior
- **sources/**: Configurations for different log sources
- **rules/**: Detection rules for identifying suspicious patterns
- **actions/**: Automated response configurations

### Example Configuration

```bash
# Add a new log source
cat > conf/sources/nginx.conf << EOF
# Nginx logs configuration
LOG_TYPE="nginx"
LOG_PRIORITY=30
ENABLED=true
LOG_FILES="/var/log/nginx/access.log /var/log/nginx/error.log"
LOG_FORMAT="custom"
COLLECTION_METHOD="file"
REAL_TIME_MONITORING=true
EOF

# Create a custom detection rule
cat > conf/rules/web-attacks.rules << EOF
# Web Attack Detection Rules
WEB-001;SQL Injection Attempt;SELECT.*FROM|UNION.*SELECT|INSERT.*INTO;HIGH;9
WEB-002;XSS Attempt;<script>|javascript:|alert\(|onclick=;HIGH;9
WEB-003;Path Traversal;\.\.\/|\.\.%2f|etc\/passwd;HIGH;9
EOF
```

## Project Structure

```
incident-response-framework/
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

## Development Roadmap

The framework is being developed in phases:

1. **Foundation** (Completed): Core structure, log collection, basic parsing
2. **Detection** (In Progress): Pattern matching, rule creation for common attacks
3. **Analysis & Correlation** (Planned): Link related events, anomaly detection
4. **Response & Reporting** (Planned): Alerting, automated containment, documentation

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Thanks to all the open-source projects that inspired this framework
- Special thanks to the security community for sharing knowledge