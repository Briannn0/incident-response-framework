# Security Policy

## Supported Versions

Currently, the Incident Response Framework (IRF) is in active development. Security updates will be applied to the latest development version.

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

We take the security of the Incident Response Framework seriously. If you believe you've found a security vulnerability, please follow these steps:

1. **Do Not Disclose Publicly**: Please do not disclose the vulnerability publicly until we've had a chance to address it.

2. **Email Details**: Send an email to daotuananhnguyen@gmail.com with detailed information about the vulnerability:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if available)

3. **Response Timeline**:
   - Initial response within 48 hours acknowledging receipt
   - Assessment of vulnerability within 7 days
   - Discussion of fix and timeline within 14 days
   - Public disclosure after the fix is implemented

## Security Best Practices for Deployment

When deploying IRF in your environment, consider these security best practices:

1. **Least Privilege**: Run the framework with the minimum privileges required. Avoid running as root except where absolutely necessary.

2. **Container Isolation**: When using Docker, ensure proper container isolation and security configurations are in place.

3. **Configuration Security**: Protect configuration files that may contain sensitive information, especially:
   - `conf/main.conf`
   - `conf/actions/` directory 

4. **Network Access**: Restrict network access to IRF components, especially for response automation components that may modify firewall rules or system configurations.

5. **Regular Updates**: Keep the framework updated with the latest security patches.

6. **Evidence Protection**: Secure the `evidence/` directory to prevent tampering with forensic data.

7. **Audit Logging**: Enable comprehensive audit logging to track framework activities.

## Security Features

IRF includes several security features to ensure its own integrity:

1. **Input Validation**: Sanitization of log inputs to prevent injection attacks
2. **Path Traversal Prevention**: Checks to prevent directory traversal in file paths
3. **Secure Permissions**: Default installation uses restrictive file permissions
4. **Evidence Integrity**: Options for checksumming and verifying evidence files

## Contributing Security Improvements

Security improvements are always welcome. If you'd like to contribute security enhancements:

1. Follow the standard contribution process outlined in the README
2. For security-specific changes, clearly describe the security impact in your pull request
3. Consider adding tests that verify the security behavior

Thank you for helping improve the security of the Incident Response Framework!