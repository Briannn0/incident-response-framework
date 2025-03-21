# Incident Response Framework (IRF)

A bash-based framework that automates log collection, analysis, and incident response for Linux systems. The framework is designed to detect security threats, alert administrators, and provide automated response options.

## Features

- **Log Collection**: Gather logs from multiple sources (auth.log, syslog, etc.)
- **Log Parsing**: Normalize and structure log data for analysis
- **Real-time Monitoring**: Watch log files for suspicious activity using inotify
- **Modular Architecture**: Easily extendable with plugins and custom rules
- **Evidence Preservation**: Secure forensic data for investigation
- **Automated Response**: Configure predefined actions to contain threats

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

## Installation

### Prerequisites

- Bash 4.0 or later
- Standard Linux utilities (grep, awk, sed)
- inotify-tools (optional, for real-time monitoring)

### Basic Installation

1. Clone the repository:
   git clone https://github.com/yourusername/incident-response-framework.git
   cd incident-response-framework


2. Run the installation script:
   ./scripts/install.sh

3. Verify the installation:
   irf --version


## Getting Started

### Basic Usage

1. Collect logs from all configured sources:
   irf collect

2. Parse logs from a specific source:
   irf parse /opt/incident-response-framework/conf/sources/auth.conf

3. Start monitoring logs in real-time:
   irf monitor

### Configuration

The framework's behavior is controlled by configuration files in the `conf/` directory:

- **main.conf**: Core settings that affect the overall behavior
- **sources/**: Configurations for different log sources
- **rules/**: Detection rules for identifying suspicious patterns
- **actions/**: Automated response configurations

## Development Roadmap

The framework is being developed in phases:

1. **Foundation** (Current): Core structure, log collection, basic parsing
2. **Detection**: Pattern matching, rule creation for common attacks
3. **Analysis & Correlation**: Link related events, anomaly detection
4. **Response & Reporting**: Alerting, automated containment, documentation

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Thanks to all the open-source projects that inspired this framework
- Special thanks to the security community for sharing knowledge