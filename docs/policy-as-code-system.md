"""
README for Policy-as-Code + Auditing System

This system implements a comprehensive Policy-as-Code framework with deny-by-default
security, operation allowlists, and structured audit logging for the Gateway Fleet Orchestrator.
"""

# Policy-as-Code + Auditing System

## Overview

The Policy-as-Code + Auditing system provides a security-first approach to fleet management
with explicit allowlists, deny-by-default enforcement, and comprehensive audit logging.

## Key Features

### Security-First Design
- **Deny-by-default**: All operations are denied unless explicitly permitted
- **Operation allowlists**: Control what operations can be performed (not raw commands)
- **Structured audit logging**: JSON lines format with result hashing and duration tracking
- **Credential path references**: Never store secrets in configuration files

### Policy Configuration
- **YAML/JSON configuration**: Human-readable policy definitions
- **Target-based rules**: Different policies per server role/tag
- **Parameter validation**: Type and constraint validation for all operations
- **Operation tiers**: Observe/Control/Admin levels with approval requirements

### Audit Capabilities
- **Structured logging**: JSON lines format for easy parsing and analysis
- **Result integrity**: SHA-256 hashing of operation results
- **Performance tracking**: Operation duration in milliseconds
- **Log rotation**: Automatic rotation with configurable size and count limits
- **Search capabilities**: Filter audit logs by time, actor, target, operation, etc.

## Configuration Files

### Policy Configuration (`policy.yaml`)

```yaml
targets:
  - id: "web-prod-01"
    host: "web01.production.example.com"
    tags: ["web", "production"]
    roles: ["webserver"]
    connection_method: "ssh"
    credential_path: "/path/to/credentials.key"
    capabilities: ["container:write", "system:read"]

rules:
  - name: "default_deny"
    description: "Default deny rule"
    target_pattern: ".*"
    allowed_operations: []  # Deny all by default
    required_capabilities: []
    parameter_constraints: {}
    operation_tier: "observe"

  - name: "web_server_operations"
    description: "Web server operations"
    target_pattern: "web-.*"
    allowed_operations: ["status", "start_container", "stop_container"]
    required_capabilities: ["container:write"]
    parameter_constraints:
      container_name:
        type: "string"
        max_length: 256
    operation_tier: "control"
```

### Credentials References (`credentials.yaml`)

```yaml
credentials:
  - target_id: "web-prod-01"
    credential_path: "/etc/systemmanager/credentials/web-prod-01.key"
    description: "SSH private key for web-prod-01"
```

**Security Note**: Never store actual secrets in configuration files. Only reference paths to credential files.

## Usage

### Basic Integration

```python
from src.services.policy_integration import policy_as_code_integration

# Check if operation is allowed
allowed = policy_as_code_integration.policy_manager.is_operation_allowed(
    "web-prod-01", "start_container"
)

# Get all allowed operations for a target
allowed_ops = policy_as_code_integration.get_allowed_operations("web-prod-01")

# Authorize and execute an operation
result = await policy_as_code_integration.execute_remote_operation(
    actor="gateway-client",
    target_id="web-prod-01",
    operation="start_container",
    parameters={"container_name": "nginx"}
)
```

### Audit Log Search

```python
# Search audit logs
entries = policy_as_code_integration.search_audit_logs(
    start_time=datetime.now() - timedelta(hours=24),
    target="web-prod-01",
    operation="start_container",
    authorized=True
)

# Get audit statistics
stats = policy_as_code_integration.get_audit_statistics()
```

## Security Considerations

### Credential Management
- Store credential files with restricted permissions (600)
- Use encrypted storage for credential files in production
- Rotate credentials regularly
- Monitor credential file access

### Audit Log Security
- Store audit logs in secure, append-only locations
- Encrypt audit logs in transit and at rest
- Implement log integrity verification
- Regular log analysis for security incidents

### Policy Design Principles
- **Least privilege**: Grant minimum necessary permissions
- **Separation of duties**: Different roles for different operations
- **Approval workflows**: Require approval for high-risk operations
- **Regular review**: Periodically review and update policies

## Example Configurations

See the `examples/` directory for complete configuration examples:

- `policy-as-code-config.yaml`: Complete production configuration
- `security-focused-policy.yaml`: High-security environment configuration
- `credentials-references.yaml`: Credential path references example

## Testing

Run the policy system tests:

```bash
pytest tests/test_policy_as_code.py -v
```

## Integration with Existing Systems

The Policy-as-Code system integrates seamlessly with:
- Existing PolicyGate for backward compatibility
- Target registry for capability validation
- Audit logging system for comprehensive tracking
- Authentication middleware for user authorization

## Monitoring and Alerting

Monitor the system using:
- Audit log statistics for operational insights
- Policy decision metrics for security posture
- Operation success rates for system health
- Authorization failure alerts for security incidents

## Troubleshooting

### Common Issues

1. **Operation denied**: Check if the operation is in the allowlist for the target
2. **Parameter validation failed**: Verify parameter types and constraints
3. **Target not found**: Ensure target is registered in the configuration
4. **Credential access denied**: Check credential file permissions and existence

### Debug Mode

Enable debug logging for detailed policy decision information:

```python
import logging
logging.getLogger("src.services.policy_as_code").setLevel(logging.DEBUG)
```

## Contributing

When extending the policy system:
- Follow the security-first design principles
- Add comprehensive tests for new functionality
- Update documentation for new features
- Review policy configurations for security implications
