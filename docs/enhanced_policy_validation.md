# Enhanced Policy Configuration with Input Validation (Control Plane Gateway)

This configuration file demonstrates the enhanced policy system with comprehensive input validation
and allowlisting capabilities for the TailOpsMCP control plane gateway.

## Configuration Structure (Gateway Architecture)

### Global Settings (Gateway-Wide)
```yaml
default_validation_mode: "strict"  # strict, warn, or permissive
enable_dry_run: true
maintenance_windows: []
lockout_periods: []
gateway_id: "gateway-001"  # Unique identifier for this gateway
```

### Policy Rules (Target-Specific)
Each rule defines:
- **name**: Unique identifier for the rule
- **description**: Human-readable description
- **target_pattern**: Regex pattern for target matching (supports target IDs)
- **allowed_operations**: List of permitted operations
- **required_capabilities**: Required scopes/capabilities
- **parameter_constraints**: Enhanced validation rules with target context
- **operation_tier**: Operation tier (observe/control/admin)
- **requires_approval**: Whether approval is required
- **dry_run_supported**: Whether dry-run is supported
- **target_constraints**: Target-specific limitations and requirements

## Enhanced Parameter Constraints (Multi-Target)

Parameter constraints now support:
- **validation_type**: Specific validation type (service_name, container_name, etc.) with target context
- **allowlist_source**: Discovery tool to populate allowed values across all targets
- **pattern**: Regex pattern for validation
- **min/max**: Range validation for numeric values
- **min_length/max_length**: Length validation for strings
- **target_specific**: Whether validation rules vary by target

## Example Configuration (Gateway Context)

```yaml
default_validation_mode: "strict"
enable_dry_run: true
gateway_id: "gateway-001"

rules:
  - name: "docker_container_operations"
    description: "Docker container management with enhanced validation across targets"
    target_pattern: ".*"
    allowed_operations:
      - "start"
      - "stop"
      - "restart"
      - "inspect"
    required_capabilities:
      - "container:write"
    parameter_constraints:
      container_name:
        type: "string"
        max_length: 256
        validation_type: "container_name"
        allowlist_source: "list_containers"
        pattern: "^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$"
      timeout:
        type: "int"
        min: 1
        max: 300
        validation_type: "timeout"
    operation_tier: "control"
    requires_approval: false
    dry_run_supported: true

  - name: "stack_operations"
    description: "Docker Compose stack management with enhanced validation"
    target_pattern: ".*"
    allowed_operations:
      - "deploy"
      - "pull"
      - "restart"
    required_capabilities:
      - "stack:write"
    parameter_constraints:
      stack_name:
        type: "string"
        max_length: 64
        validation_type: "stack_name"
        allowlist_source: "list_stacks"
        pattern: "^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$"
      timeout:
        type: "int"
        min: 1
        max: 600
        validation_type: "timeout"
    operation_tier: "control"
    requires_approval: false
    dry_run_supported: true

  - name: "service_operations"
    description: "System service management with enhanced validation"
    target_pattern: ".*"
    allowed_operations:
      - "restart"
      - "status"
    required_capabilities:
      - "system:write"
    parameter_constraints:
      service_name:
        type: "string"
        max_length: 64
        validation_type: "service_name"
        allowlist_source: "list_services"
        pattern: "^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$"
      timeout:
        type: "int"
        min: 1
        max: 300
        validation_type: "timeout"
    operation_tier: "control"
    requires_approval: false
    dry_run_supported: true

  - name: "file_operations"
    description: "File system operations with enhanced validation"
    target_pattern: ".*"
    allowed_operations:
      - "read"
      - "list"
    required_capabilities:
      - "file:read"
    parameter_constraints:
      path:
        type: "string"
        max_length: 1024
        validation_type: "file_path"
        pattern: "^[a-zA-Z0-9./_-]+$"
    operation_tier: "observe"
    requires_approval: false
    dry_run_supported: true

  - name: "network_operations"
    description: "Network operations with enhanced validation"
    target_pattern: ".*"
    allowed_operations:
      - "test"
      - "scan"
    required_capabilities:
      - "network:read"
    parameter_constraints:
      host:
        type: "string"
        max_length: 253
        validation_type: "hostname"
        pattern: "^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
      port:
        type: "int"
        min: 1
        max: 65535
        validation_type: "port_number"
    operation_tier: "observe"
    requires_approval: false
    dry_run_supported: true

  - name: "admin_operations"
    description: "Administrative operations requiring approval"
    target_pattern: ".*"
    allowed_operations:
      - "shutdown"
      - "reboot"
      - "update"
    required_capabilities:
      - "system:admin"
    parameter_constraints:
      reason:
        type: "string"
        max_length: 500
        validation_type: "string"
    operation_tier: "admin"
    requires_approval: true
    dry_run_supported: false
```

## Validation Types

Supported validation types:
- **service_name**: Validates against service allowlist
- **container_name**: Validates against container allowlist
- **stack_name**: Validates against stack allowlist
- **file_path**: Validates file paths with traversal protection
- **port_number**: Validates port numbers (1-65535)
- **timeout**: Validates timeout values (1-3600)
- **output_limit**: Validates output limits (1-10485760)
- **hostname**: Validates hostname format
- **ip_address**: Validates IP address format
- **url**: Validates URL format

## Allowlist Sources

Supported discovery tools for populating allowlists:
- **list_services**: Discovers available system services
- **list_containers**: Discovers running Docker containers
- **list_stacks**: Discovers Docker Compose stacks
- **list_ports**: Discovers open network ports

## Security Features

### Command Injection Prevention
- All parameters are validated against strict patterns
- File paths are checked for directory traversal attempts
- Hostnames and URLs are validated for proper format
- Numeric values are range-checked

### Typo Hazard Prevention
- Service/container/stack names are validated against allowlists
- Only existing, discovered resources can be targeted
- Dynamic allowlist population with caching (5-minute TTL)

### Audit Logging
- All validation decisions are logged for compliance
- Parameter values are sanitized for sensitive data
- Validation errors are tracked and reported

## Usage

### Environment Variables
```bash
# Policy configuration file
SYSTEMMANAGER_POLICY_CONFIG=/etc/systemmanager/policy.yaml

# Validation mode (strict, warn, permissive)
SYSTEMMANAGER_POLICY_MODE=strict

# Enable dry-run mode
SYSTEMMANAGER_ENABLE_DRY_RUN=true
```

### Python Integration
```python
from src.services.enhanced_policy_config import get_enhanced_policy_config

# Load enhanced configuration
config = get_enhanced_policy_config("/path/to/policy.yaml")

# Use with PolicyGate
from src.services.policy_gate import PolicyGate
policy_gate = PolicyGate(target_registry, audit_logger)
policy_gate.policy_config = config
```

## Benefits

1. **Enhanced Security**: Prevents command injection and typo hazards
2. **Dynamic Validation**: Allowlists are populated from current system state
3. **Comprehensive Coverage**: Validates all common parameter types
4. **Performance**: Caching system prevents repeated discovery calls
5. **Auditability**: All validation decisions are logged for compliance
6. **Flexibility**: Configurable validation modes (strict, warn, permissive)

This enhanced policy system provides defense-in-depth security controls while maintaining operational flexibility and performance.
