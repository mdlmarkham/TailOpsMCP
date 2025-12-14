# Policy-Driven Execution System

## Overview

The Policy-Driven Execution System is a comprehensive security framework that replaces free-text remote commands with structured, capability-driven operations. This system provides defense-in-depth security controls through policy enforcement, capability validation, and audit logging.

## Key Features

### 1. Capability-Driven Operations
- **Structured Operations**: Replace free-text commands with typed, validated operations
- **Parameter Validation**: Comprehensive parameter validation with type checking and constraints
- **Capability Registry**: Centralized registry of supported operations per backend
- **Timeout Management**: Automatic timeout handling based on operation type

### 2. Policy Engine
- **Deny-by-Default Security**: Conservative security posture with explicit allow rules
- **Role-Based Access Control**: Different permissions based on target roles (production, development, staging)
- **Time-Based Restrictions**: Restrict operations by time, date, and maintenance windows
- **Policy Inheritance**: Gateway policies cascade to target roles
- **Policy Versioning**: Track policy changes with rollback capabilities

### 3. Execution Backends
- **Pluggable Architecture**: Support for multiple execution backends
- **SSH/Tailscale Backend**: Secure remote execution via SSH with optional Tailscale integration
- **Local Backend**: Local execution for gateway operations
- **Docker Backend**: Docker container management (extensible)
- **Proxmox Backend**: Proxmox VE VM/container management (extensible)

### 4. Comprehensive Audit
- **Operation Logging**: Detailed audit trail for all operations
- **Policy Decision Tracking**: Log policy evaluation decisions and reasons
- **Correlation IDs**: Trace operations across the system
- **Security Event Correlation**: Link security events to operations

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   MCP Tools     │    │ Capability       │    │ Policy Engine   │
│                 │    │ Executor         │    │                 │
│ - execute_*     │◄──►│                  │◄──►│ - evaluate()    │
│ - simulate()    │    │ - validate()     │    │ - enforce()     │
│ - validate()    │    │ - execute()      │    │ - audit()       │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │                        │
                                ▼                        ▼
                       ┌──────────────────┐    ┌─────────────────┐
                       │ Execution        │    │ Policy Config   │
                       │ Backends         │    │                 │
                       │                  │    │ - YAML/JSON     │
                       │ - SSH/Tailscale  │    │ - Validation    │
                       │ - Local          │    │ - Versioning    │
                       │ - Docker         │    │ - History       │
                       │ - Proxmox        │    │                 │
                       └──────────────────┘    └─────────────────┘
```

## Core Components

### Policy Models (`src/models/policy_models.py`)
- **PolicyConfig**: Main policy configuration container
- **PolicyRule**: Individual rule definitions
- **CapabilityOperation**: Capability-driven operation definitions
- **PolicyContext**: Context for policy evaluation
- **PolicyEvaluation**: Results of policy evaluation

### Policy Engine (`src/services/policy_engine.py`)
- **PolicyEngine**: Main policy evaluation engine
- **Policy Evaluation**: Comprehensive policy decision logic
- **Policy Management**: Configuration updates and rollback
- **Caching**: Performance optimization for policy evaluation

### Capability Executor (`src/services/capability_executor.py`)
- **CapabilityExecutor**: Main orchestration engine
- **CapabilityValidator**: Parameter validation and schema enforcement
- **Operation Creation**: Helper functions for common operations
- **Result Processing**: Standardized execution result handling

### Execution Backends (`src/services/`)
- **RemoteExecutionBackend**: Abstract base for all backends
- **SSHTailscaleBackend**: SSH/Tailscale remote execution
- **LocalExecutionBackend**: Local gateway operations
- **DockerBackend**: Docker container management
- **ProxmoxBackend**: Proxmox VE management

### MCP Tools (`src/tools/capability_tools.py`)
- **CapabilityTools**: High-level operation tools
- **PolicyManagementTools**: Policy configuration and management
- **Validation Tools**: Parameter and configuration validation
- **Simulation Tools**: Dry-run and scenario testing

## Supported Operations

### Service Operations
- `service_restart`: Restart system services
- `service_start`: Start system services
- `service_stop`: Stop system services
- `service_status`: Check service status

### Container Operations
- `container_create`: Create new containers
- `container_delete`: Delete containers
- `container_start`: Start containers
- `container_stop`: Stop containers
- `container_restart`: Restart containers
- `container_inspect`: Inspect container configuration

### Stack Operations
- `stack_deploy`: Deploy application stacks
- `stack_remove`: Remove application stacks
- `stack_update`: Update application stacks

### Backup Operations
- `backup_create`: Create backups
- `backup_restore`: Restore from backups
- `backup_list`: List available backups
- `backup_delete`: Delete backups

### Snapshot Operations
- `snapshot_create`: Create snapshots
- `snapshot_delete`: Delete snapshots
- `snapshot_restore`: Restore from snapshots
- `snapshot_list`: List snapshots

### File Operations
- `file_read`: Read file contents
- `file_write`: Write file contents
- `file_delete`: Delete files
- `file_copy`: Copy files

### Network Operations
- `network_scan`: Network scanning
- `network_test`: Network connectivity testing
- `network_status`: Network status information

### Package Operations
- `package_update`: Update packages
- `package_install`: Install packages
- `package_remove`: Remove packages
- `package_list`: List installed packages

## Policy Configuration

### Basic Structure
```yaml
policies:
  version: "v2"
  name: "Policy Name"
  description: "Policy description"
  deny_by_default: true
  enable_dry_run: true
  require_approval_for_admin: true
  
  global_policies:
    - name: "rule_name"
      description: "Rule description"
      enabled: true
      operations: [op1, op2]
      target_roles: [role1, role2]
      allowed: true
      requires_approval: false
      parameter_constraints:
        param_name:
          type: "string"
          required: true
          max_length: 64
          pattern: "^[a-zA-Z0-9]+$"
  
  role_policies:
    production:
      - # Production-specific rules
    development:
      - # Development-specific rules
  
  emergency_policies:
    - # Emergency override rules
```

### Policy Rules

#### Operation Types
- **Service Operations**: `service_restart`, `service_start`, `service_stop`, `service_status`
- **Container Operations**: `container_create`, `container_delete`, `container_start`, `container_stop`, `container_restart`, `container_inspect`
- **Stack Operations**: `stack_deploy`, `stack_remove`, `stack_update`
- **Backup Operations**: `backup_create`, `backup_restore`, `backup_list`, `backup_delete`
- **Snapshot Operations**: `snapshot_create`, `snapshot_delete`, `snapshot_restore`, `snapshot_list`
- **File Operations**: `file_read`, `file_write`, `file_delete`, `file_copy`
- **Network Operations**: `network_scan`, `network_test`, `network_status`
- **Package Operations**: `package_update`, `package_install`, `package_remove`, `package_list`

#### Target Roles
- **gateway**: Gateway system itself
- **production**: Production environment targets
- **development**: Development environment targets
- **staging**: Staging environment targets
- **testing**: Testing environment targets
- **maintenance**: Maintenance mode targets

#### Parameter Constraints
```yaml
parameter_constraints:
  service_name:
    type: "string"
    required: true
    max_length: 64
    pattern: "^[a-zA-Z0-9][a-zA-Z0-9_-]*$"
  timeout:
    type: "int"
    required: false
    min: 1
    max: 300
    default: 60
  container_name:
    type: "string"
    required: true
    max_length: 64
    allowlist_source: "list_containers"  # Dynamic validation
```

#### Time Restrictions
```yaml
time_restrictions:
  - start_time: "08:00"
    end_time: "18:00"
    days_of_week: [1,2,3,4,5]  # Monday-Friday
    timezone: "UTC"
```

## Usage Examples

### Basic Operation Execution
```python
from src.tools.capability_tools import capability_tools

# Execute a service restart
result = await capability_tools.execute_service_restart(
    service_name="nginx",
    target_id="prod-web-01",
    requested_by="admin@company.com",
    timeout=60
)

print(f"Operation result: {result}")
```

### Policy Simulation
```python
# Simulate an operation with policy checks
simulation = await capability_tools.simulate_operation(
    operation_type="container_delete",
    target_id="dev-test-01",
    requested_by="developer@company.com",
    parameters={
        "container_name": "test-container",
        "force": False
    },
    target_role="development"
)

print(f"Policy decision: {simulation['policy_evaluation']['decision']}")
```

### Policy Management
```python
from src.tools.capability_tools import policy_management_tools

# Get current policy status
status = await policy_management_tools.get_policy_status()

# List allowed operations for production
allowed = await policy_management_tools.list_allowed_operations(
    target_role="production",
    user_id="admin@company.com"
)

print(f"Allowed operations: {allowed['allowed_operations']}")
```

### Parameter Validation
```python
# Validate operation parameters
validation = await capability_tools.validate_operation_parameters(
    operation_type="service_restart",
    parameters={
        "service_name": "nginx",
        "timeout": 60
    }
)

if validation['valid']:
    print("Parameters are valid")
else:
    print(f"Validation errors: {validation['errors']}")
```

## Security Features

### 1. Input Validation
- **Type Checking**: Validate parameter types against schemas
- **Length Limits**: Enforce maximum lengths for string parameters
- **Pattern Matching**: Use regex patterns for string validation
- **Range Validation**: Enforce min/max values for numeric parameters
- **Allowlist Validation**: Dynamic validation against system state

### 2. Path Traversal Protection
- File operations enforce safe path patterns
- Prevent `../` traversal attempts
- Restrict access to system directories
- Validate file paths against allowed patterns

### 3. Command Injection Prevention
- Capability-driven operations eliminate shell command construction
- Parameter sanitization for all inputs
- No direct shell execution from user input
- Structured operation parameters only

### 4. Network Security
- SSH with strict host key verification
- Tailscale integration for secure remote access
- Connection timeout and retry controls
- Cipher selection for SSH security

### 5. Audit and Monitoring
- Comprehensive operation logging
- Policy decision audit trails
- Failed operation tracking
- Security event correlation
- Correlation ID tracking for traceability

## Configuration

### Environment Variables
- `SYSTEMMANAGER_POLICY_CONFIG`: Path to policy configuration file
- `SYSTEMMANAGER_POLICY_MODE`: Policy validation mode (strict, permissive)
- `SYSTEMMANAGER_ENABLE_DRY_RUN`: Enable dry-run mode globally
- `SYSTEMMANAGER_AUDIT_LEVEL`: Audit logging level

### Policy Configuration Files
- `config/policy-examples/production-security-focused.yaml`: Production security policy
- `config/policy-examples/development-flexible.yaml`: Development flexible policy

## Integration

### With Existing Systems
- **Fleet Inventory**: Uses inventory metadata for policy decisions
- **Security Scanner**: Integrates with security validation systems
- **Audit Logger**: Comprehensive audit trail integration
- **MCP Server**: Full integration with MCP tool framework

### With Authentication
- **User Identity**: Uses authenticated user context for policy decisions
- **Role-Based Access**: Maps user roles to policy permissions
- **Session Management**: Maintains security context across operations

## Deployment

### 1. Policy Configuration
```bash
# Copy example policy configuration
cp config/policy-examples/production-security-focused.yaml /etc/systemmanager/policy.yaml

# Customize for your environment
vim /etc/systemmanager/policy.yaml
```

### 2. Initialize Policy Engine
```python
from src.services.policy_engine import PolicyEngine
from src.utils.audit import AuditLogger

audit_logger = AuditLogger()
policy_engine = PolicyEngine(
    config_path="/etc/systemmanager/policy.yaml",
    audit_logger=audit_logger
)
```

### 3. Setup Capability Executor
```python
from src.services.capability_executor import CapabilityExecutor
from src.services.execution_factory import execution_backend_factory

capability_executor = CapabilityExecutor(
    policy_engine=policy_engine,
    execution_factory=execution_backend_factory,
    audit_logger=audit_logger
)
```

### 4. Initialize MCP Tools
```python
from src.tools.capability_tools import initialize_capability_tools

initialize_capability_tools(
    capability_executor=capability_executor,
    policy_engine=policy_engine,
    audit_logger=audit_logger
)
```

## Monitoring and Observability

### Key Metrics
- Policy evaluation decisions (allow/deny/require_approval)
- Operation success/failure rates
- Backend execution times
- Policy cache hit rates
- Audit log volume

### Health Checks
- Policy configuration validity
- Backend connectivity
- Execution success rates
- Audit system availability

### Alerting
- Policy configuration errors
- High denial rates
- Execution failures
- Security violations

## Best Practices

### 1. Policy Design
- Start with deny-by-default posture
- Use specific rather than generic rules
- Implement time-based restrictions for sensitive operations
- Regular policy review and updates

### 2. Security
- Validate all parameters before execution
- Use dry-run mode for testing
- Monitor audit logs regularly
- Implement proper user authentication

### 3. Operations
- Test policy changes in development first
- Use simulation tools for validation
- Maintain backup policy configurations
- Document policy change rationale

### 4. Maintenance
- Regular policy validation
- Backend health monitoring
- Audit log rotation
- Performance optimization

## Troubleshooting

### Common Issues

#### Policy Configuration Errors
```python
# Validate policy configuration
validation = await policy_management_tools.validate_policy_config(config_data)
if not validation['valid']:
    print(f"Errors: {validation['errors']}")
```

#### Operation Denials
```python
# Check why operation was denied
simulation = await capability_tools.simulate_operation(...)
print(f"Policy reason: {simulation['policy_evaluation']['reason']}")
```

#### Backend Connectivity
```python
# Test backend connectivity
backend_factory = execution_backend_factory
test_results = await backend_factory.test_all_backends()
for backend_type, result in test_results.items():
    print(f"{backend_type}: {result.status}")
```

## Future Enhancements

### Planned Features
- **Machine Learning Policy Optimization**: ML-based policy recommendation
- **Advanced Approval Workflows**: Multi-step approval processes
- **Policy Templates**: Pre-built policy templates for common scenarios
- **Real-time Policy Updates**: Dynamic policy updates without restart
- **Enhanced Analytics**: Advanced policy analytics and reporting

### Extensibility
- **Custom Backends**: Plugin architecture for new execution backends
- **Custom Operations**: Extension points for domain-specific operations
- **Policy Extensions**: Custom policy evaluation logic
- **Integration APIs**: APIs for third-party system integration

## Conclusion

The Policy-Driven Execution System provides a robust, secure foundation for remote operations in the TailOpsMCP ecosystem. By replacing free-text commands with structured, policy-enforced capabilities, it significantly improves security while maintaining operational flexibility.

The system's modular architecture, comprehensive audit trail, and policy-driven approach make it suitable for enterprise deployments requiring strict security controls and compliance tracking.