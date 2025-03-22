# Log Analysis and Incident Response Framework - Rule Writing Guide

## Overview

This document provides a comprehensive guide to writing, testing, and managing detection rules for the Incident Response Framework (IRF). Detection rules are the core component that enables the framework to identify security threats in log data.

## Rule File Structure

Detection rules are stored in the `conf/rules/` directory with a `.rules` extension. Each rule file contains a set of related rules for a specific type of threat, such as:

- `brute-force.rules` - Brute force attack detection
- `privilege-esc.rules` - Privilege escalation detection
- `malware.rules` - Malware activity detection
- `unauthorized-access.rules` - Unauthorized access detection

## Rule Format

Rules use a semi-colon separated format:

```
RULE_ID;DESCRIPTION;PATTERN;SEVERITY;FIELDS
```

Where:
- `RULE_ID`: Unique identifier for the rule (e.g., `BF-SSH-001`)
- `DESCRIPTION`: Human-readable description of what the rule detects
- `PATTERN`: Regular expression pattern to match
- `SEVERITY`: Alert severity level (INFO, LOW, MEDIUM, HIGH, CRITICAL)
- `FIELDS`: Comma-separated list of field indices to apply the pattern to (0-based)

### Field Reference

When writing rules, refer to these field indices:

```
0 - timestamp
1 - source_type
2 - source_name
3 - log_level
4 - username
5 - hostname
6 - ip_address
7 - service
8 - process_id
9 - message
```

## Rule Examples

### SSH Brute Force Detection

```
# SSH Failed Password Attempts
BF-SSH-001;SSH Multiple Failed Password Attempts;Failed\ password;MEDIUM;7,9
```

This rule:
- Has ID `BF-SSH-001`
- Detects SSH failed password attempts
- Looks for the pattern `Failed password`
- Has MEDIUM severity
- Checks fields 7 (service) and 9 (message)

### Privilege Escalation Detection

```
# Sudo configuration change
PE-SUDO-003;Sudo Configuration Change;sudoers changed;HIGH;9
```

This rule:
- Has ID `PE-SUDO-003`
- Detects changes to sudo configuration
- Looks for the pattern `sudoers changed`
- Has HIGH severity
- Checks field 9 (message)

### Malware Detection

```
# Base64 encoded script execution
MW-PROC-001;Base64 Encoded Execution;(echo|printf).*\|.*base64.*\|.*bash;HIGH;9
```

This rule:
- Has ID `MW-PROC-001`
- Detects base64 encoded script execution
- Looks for patterns of encoding/decoding and piping to bash
- Has HIGH severity
- Checks field 9 (message)

## Rule Naming Convention

Rule IDs should follow this format:

```
[CATEGORY]-[SUBCATEGORY]-[NUMBER]
```

Where:
- `CATEGORY`: 2-3 letter code for the threat category (e.g., BF for Brute Force)
- `SUBCATEGORY`: 2-4 letter code for the subcategory (e.g., SSH for SSH-related)
- `NUMBER`: 3-digit sequential number (e.g., 001, 002)

### Common Category Prefixes

- `BF` - Brute Force attacks
- `PE` - Privilege Escalation
- `MW` - Malware activity
- `UA` - Unauthorized Access
- `DL` - Data Leakage
- `FW` - Firewall events
- `IDS` - Intrusion Detection
- `AV` - Antivirus
- `TI` - Threat Intelligence

## Writing Effective Rules

### Pattern Writing Guidelines

1. **Start Simple**: Begin with simple patterns and refine them
2. **Escape Special Characters**: Use backslashes to escape regex special characters
3. **Use Character Classes**: For more flexible matching (e.g., `[0-9]` for digits)
4. **Allow for Variations**: Account for minor variations in log formats
5. **Test Thoroughly**: Test against both positive and negative examples

### Common Regex Patterns

| Pattern | Description | Example |
|---------|-------------|---------|
| `\d+` | One or more digits | `Failed password \d+ times` |
| `\S+` | One or more non-whitespace characters | `user=\S+` |
| `[a-zA-Z]+` | One or more letters | `status: [a-zA-Z]+` |
| `[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}` | IPv4 address | `from ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})` |
| `\b(word1\|word2\|word3)\b` | Word alternatives | `\b(failed\|invalid\|error)\b` |

### Performance Considerations

1. **Avoid Excessive Backtracking**: Complex regex patterns can cause performance issues
2. **Limit Wildcard Usage**: Use `.*` sparingly, especially in the middle of patterns
3. **Target Specific Fields**: Use the FIELDS parameter to limit pattern matching to relevant fields
4. **Optimize Rule Order**: Put more specific or common rules first
5. **Consider Rule Granularity**: Balance between specific and general rules

## Testing Rules

### Using the Rule Testing Utility

The framework includes a utility for testing rules:

```bash
# Test a specific rule against sample log data
irf test --rule conf/rules/brute-force.rules --log tests/sample-logs/auth.log

# Generate sample test data and test rules
irf test --rule conf/rules/brute-force.rules --generate

# Test all rules against all sample logs
irf test --all
```

### Sample Rule Testing Script

```bash
#!/bin/bash

# Path to your rules directory
RULES_DIR="/opt/incident-response-framework/conf/rules"

# Path to sample logs directory
LOGS_DIR="/opt/incident-response-framework/tests/sample-logs"

# Create temporary directory for outputs
TEMP_DIR=$(mktemp -d)

# Test each rule file against sample logs
for rule_file in "$RULES_DIR"/*.rules; do
    rule_name=$(basename "$rule_file")
    echo "Testing $rule_name..."
    
    # Run against each sample log
    for log_file in "$LOGS_DIR"/*.log; do
        log_name=$(basename "$log_file")
        echo "  Against $log_name..."
        
        # Run test and capture output
        output_file="$TEMP_DIR/${rule_name}_${log_name}.txt"
        irf test --rule "$rule_file" --log "$log_file" > "$output_file"
        
        # Check results
        matches=$(grep -c "Detected" "$output_file")
        echo "  Found $matches matches"
    done
done

# Clean up
rm -rf "$TEMP_DIR"
```

## Rule Management

### Organizing Rules

1. **Group by Threat Type**: Keep related rules in the same file
2. **Document File Purpose**: Include a header comment explaining the rule file's purpose
3. **Use Categories**: Create subdirectories for large rule sets if needed
4. **Document Field Reference**: Include the field reference as a comment in each file
5. **Track Rule Changes**: Use version comments for tracking changes

### Rule Customization

Rules can be customized for your environment:

1. **Tune Severity Levels**: Adjust based on your security policy
2. **Add Environment-Specific Patterns**: Include patterns for your custom applications
3. **Exclude False Positives**: Add patterns to exclude known false positives
4. **Add Context to Descriptions**: Include organization-specific information

### Rule Versioning

It's recommended to include version information in rule files:

```
# Rule file: brute-force.rules
# Version: 1.2
# Last updated: 2023-04-15
# Author: Security Team
#
# Changelog:
# 1.2 - Added rule BF-SSH-005 for SSH key-based authentication failures
# 1.1 - Enhanced BF-SSH-001 pattern to reduce false positives
# 1.0 - Initial version
```

## Advanced Rule Techniques

### Correlation Rules

Create rules that detect patterns across multiple log entries:

```
# Correlation Rule for Failed Login Followed by Successful Login
CR-LOGIN-001;Failed then Successful Login;failed.*login.*followed by successful;HIGH;9
```

### Context-Aware Rules

Use the framework's context tracking to create stateful rules:

```
# Detect login outside normal hours
CA-LOGIN-001;Login Outside Business Hours;accepted;MEDIUM;0,9
```

### Rate-Based Rules

Detect unusually high rates of specific events:

```
# High rate of authentication failures
RB-AUTH-001;High Rate of Authentication Failures;authentication failure;HIGH;9
```

### Baseline Deviation Rules

Detect deviations from baseline behavior:

```
# Unusual login location
BD-LOGIN-001;Login from Unusual Location;accepted.*from;MEDIUM;6,9
```

## Generating Rules

### Manual Rule Generation

1. Review logs for patterns of interest
2. Create a rule with a unique ID and descriptive name
3. Develop the regex pattern and test against sample logs
4. Assign appropriate severity and fields
5. Document the rule's purpose and expected matches

### Automated Rule Generation

The framework includes utilities for generating rules from logs:

```bash
# Generate rule suggestions from a log file
irf analyze --data /var/log/auth.log --suggest-rules > suggested_rules.txt

# Generate rules from threat intelligence feeds
irf threat-intel --update-rules
```

## Common Rule Patterns

### Authentication Failures

```
# SSH Authentication Failure
BF-SSH-002;SSH Authentication Failure;authentication failure;MEDIUM;9

# Failed sudo Authentication
BF-SUDO-001;Multiple Failed sudo Password Attempts;authentication failure;HIGH;7,9

# General Authentication Failure
BF-AUTH-002;PAM Authentication Failure;pam_unix\(.*\): authentication failure;MEDIUM;9
```

### Suspicious Commands

```
# Reverse Shell Attempt
MW-PROC-004;Reverse Shell Pattern;(bash|nc|python|perl).*-e;HIGH;9

# Command Execution in Writable Directory
MW-PROC-002;Suspicious Command in Temp Directory;/tmp/[^[:space:]]+;MEDIUM;9

# Base64 Encoded Command
MW-PROC-001;Base64 Encoded Execution;(echo|printf).*\|.*base64.*\|.*bash;HIGH;9
```

### Privilege Escalation

```
# User Added to Sudo Group
PE-USER-001;User Added to Admin Group;usermod.*wheel|usermod.*admin|usermod.*root;HIGH;9

# Sudo Configuration Change
PE-SUDO-003;Sudo Configuration Change;sudoers changed;HIGH;9

# Critical File Permission Change
PE-PERM-001;Critical File Permission Change;chmod.*(/etc/passwd|/etc/shadow|/etc/sudoers);HIGH;9
```

### Unauthorized Access

```
# Access to Sensitive Files
UA-FILE-001;Sensitive File Access Attempt;/etc/(passwd|shadow|sudoers);HIGH;9

# SSH Root Login
UA-SSH-003;SSH Root Login Attempt;root;HIGH;4,9

# Login from External IP
UA-SSH-004;SSH Login from External IP Range;accepted.*from;MEDIUM;6,9
```

## Troubleshooting Rules

### Common Rule Issues

1. **Too Many False Positives**: Pattern is too general
   - Solution: Make the pattern more specific or add context
   
2. **Missed Detections**: Pattern is too specific
   - Solution: Generalize the pattern or create multiple rules
   
3. **Performance Issues**: Complex pattern causing slowdowns
   - Solution: Simplify pattern or split into multiple rules
   
4. **Regex Syntax Errors**: Invalid regex pattern
   - Solution: Test and validate regex patterns separately

### Debugging Rules

Use the framework's debug mode to troubleshoot rules:

```bash
# Enable debug mode for rule testing
irf test --rule conf/rules/brute-force.rules --log tests/sample-logs/auth.log --debug

# Test a specific pattern against a log line
irf test --pattern "Failed password" --text "Apr 15 08:30:15 server sshd[1234]: Failed password for user from 192.168.1.100"
```

## Rule Maintenance

### Regular Review Process

1. **Periodic Review**: Schedule regular reviews of all rules
2. **False Positive Analysis**: Review alerts to identify false positive triggers
3. **Missed Detection Analysis**: Review logs for attacks that weren't detected
4. **Performance Monitoring**: Check rule execution times
5. **Rule Updates**: Update rules based on new threats and attack techniques

### Sharing and Importing Rules

Rules can be shared and imported:

```bash
# Export rules to a package
irf rules --export myorg-rules.tar.gz

# Import rules from a package
irf rules --import myorg-rules.tar.gz
```

## Best Practices

1. **Start with Core Threats**: Focus on common attacks first
2. **Layer Your Detection**: Use multiple rules to detect different aspects of attacks
3. **Test Before Deployment**: Always test rules in a non-production environment
4. **Document Your Rules**: Maintain clear documentation for each rule
5. **Review and Update**: Regularly review and update rules based on new threats
6. **Minimize False Positives**: Balance between detection and noise
7. **Use Meaningful IDs**: Create clear, categorized rule IDs
8. **Share Knowledge**: Contribute rules back to the community

## Conclusion

Effective rule writing is key to successful security monitoring with the Incident Response Framework. By following this guide, you can create, test, and maintain rules that detect security threats while minimizing false positives.

## References

- [Configuration Guide](./configuration.md)
- [Usage Guide](./usage.md)
- [Architecture Overview](./architecture.md)
- [Regular Expression Reference](https://www.regular-expressions.info/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)