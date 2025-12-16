# TailOpsMCP Configuration Examples

## Overview

This directory contains working configuration examples for the TailOpsMCP control plane gateway architecture. These examples demonstrate common deployment scenarios and provide practical templates for real-world use cases.

## Example Categories

### 1. Basic Gateway Setup
- Single gateway with minimal target configuration
- Basic authentication and security settings
- Essential environment variables

### 2. Multi-Target Infrastructure
- Multiple target systems with different capabilities
- Production vs development environment separation
- Cross-target operation examples

### 3. Security-Focused Deployment
- Enhanced security configurations
- Approval gates and audit logging
- Target-specific security constraints

### 4. Development Environment
- Development-specific capabilities
- Testing and staging configurations
- Local development workflows

## Example Files

### [`basic-gateway.yaml`](basic-gateway.yaml)
Minimal gateway configuration for getting started

### [`multi-target-infrastructure.yaml`](multi-target-infrastructure.yaml)
Complete infrastructure with web servers, databases, and monitoring

### [`security-focused.yaml`](security-focused.yaml)
Production-ready security configuration with approval gates

### [`development-environment.yaml`](development-environment.yaml)
Development environment with permissive access for testing

## Usage Instructions

1. **Copy the example file** to your configuration directory
2. **Update target-specific settings** (hostnames, credentials, etc.)
3. **Set environment variables** as specified in each example
4. **Test connectivity** to all targets
5. **Deploy the gateway** using the configuration

## Environment Variables Reference

Each example includes required environment variables. Common variables include:

- `SYSTEMMANAGER_AUTH_MODE`: Authentication mode (oauth/token)
- `SYSTEMMANAGER_TARGETS_CONFIG`: Path to targets.yaml
- `SYSTEMMANAGER_SHARED_SECRET`: Shared secret for token auth
- `SYSTEMMANAGER_AUTH_SERVER`: OAuth server URL
- Target-specific SSH keys and credentials

## Testing and Validation

After configuring, test your setup:

```bash
# Test target connectivity
python -c "from src.services.target_registry import TargetRegistry; tr = TargetRegistry(); tr.test_all_connectivity()"

# Verify configuration
python -c "from src.services.target_registry import TargetRegistry; tr = TargetRegistry(); print('Configuration valid:', tr.validate_configuration())"
```

## Security Considerations

- Never commit actual credentials to version control
- Use environment variables for sensitive information
- Regularly rotate SSH keys and tokens
- Monitor audit logs for suspicious activity
- Follow the security best practices guide

## Troubleshooting

If you encounter issues:

1. Check target connectivity manually
2. Verify environment variables are set correctly
3. Review gateway logs for error messages
4. Test individual target connections
5. Consult the troubleshooting guide

## Contributing

If you have additional configuration examples or improvements, please contribute by:

1. Creating a new example file with clear documentation
2. Testing the configuration thoroughly
3. Following the existing format and structure
4. Submitting a pull request

---

*Last updated: $(date)*
