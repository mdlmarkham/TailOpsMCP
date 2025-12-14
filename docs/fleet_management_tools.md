"""Documentation for fleet management tools in Gateway mode."""

# Fleet Management Tools for Gateway Mode

This document describes the new MCP tools for Gateway mode that expose high-level fleet management capabilities to the LLM. These tools are policy-gated and provide safe, structured operations.

## Overview

The fleet management tools enable centralized management of distributed infrastructure through a gateway system. All operations are policy-gated through the Policy-as-Code system and provide safe, structured operations without exposing arbitrary remote execution capabilities to the LLM.

## Available Tools

### 1. fleet_discover()

Run discovery and return summary of fleet nodes, services, and containers.

**Parameters:**
- `targets` (Optional[List[str]]): Specific targets to discover (all if None)
- `force_refresh` (bool): Force fresh discovery even if cached data exists
- `format` (Literal["json", "toon"]): Response format (default: "toon")

**Returns:** Summary of discovered entities in TOON or JSON format

**Policy Tier:** OBSERVE

### 2. fleet_inventory_get()

Return latest fleet inventory snapshot with comprehensive node, service, and container information.

**Parameters:**
- `format` (Literal["json", "toon"]): Response format (default: "toon")

**Returns:** Latest inventory data in TOON or JSON format

**Policy Tier:** OBSERVE

### 3. fleet_node_health(node_id)

Get health summary and last events for a specific node.

**Parameters:**
- `node_id` (str): ID of the node to check

**Returns:** Health status, last seen timestamp, and recent events

**Policy Tier:** OBSERVE

### 4. fleet_operation_plan(op_name, targets, params)

Create an operation plan for fleet-wide operations (returns plan without execution).

**Parameters:**
- `op_name` (str): Operation name (update_packages, restart_service, etc.)
- `targets` (List[str]): List of target node IDs
- `parameters` (Dict[str, Any]): Operation-specific parameters

**Returns:** Operation plan with estimated impact and plan ID

**Policy Tier:** CONTROL (planning phase)

### 5. fleet_operation_execute(plan_id)

Execute a previously created operation plan.

**Parameters:**
- `plan_id` (str): ID of the operation plan to execute

**Returns:** Execution results for each target

**Policy Tier:** CONTROL/ADMIN (execution phase)

## Supported Operations

### Safe Operations (Policy-Gated)

1. **update_packages** - Safe package updates with apt
   - Parameters: `update_only`, `upgrade`, `packages`
   - Risk Level: Low
   - Timeout: 30 minutes

2. **restart_service** - Safe service restart with systemd
   - Parameters: `service`
   - Risk Level: Medium
   - Timeout: 5 minutes

3. **docker_compose_pull_up** - GitOps-style stack update
   - Parameters: `stack`, `detach`
   - Risk Level: Medium
   - Timeout: 15 minutes

4. **snapshot_or_backup** - Snapshot or backup operation
   - Parameters: `type`, `target`
   - Risk Level: Low
   - Timeout: 60 minutes

5. **restore** - Restore operation (admin-only)
   - Parameters: `backup_id`, `target`
   - Risk Level: High
   - Requires Approval: Yes
   - Timeout: 60 minutes

## Policy Integration

All fleet management tools integrate with the Policy-as-Code system:

- **Operation Authorization**: Each tool call is authorized through the policy gate
- **Target Validation**: Operations are validated against allowed targets
- **Parameter Validation**: Operation parameters are validated for safety
- **Role-Based Access**: Different roles (fleet_operator, fleet_admin) have different permissions
- **Audit Logging**: All operations are logged for security and compliance

## Security Features

### Policy Gating
- Deny-by-default security model
- Explicit allowlists for operations and targets
- Role-based access control
- Parameter validation and sanitization

### Safe Execution
- No arbitrary remote execution exposed to LLM
- Predefined safe operation patterns
- Timeout limits on all operations
- Impact estimation before execution

### Audit and Compliance
- Comprehensive audit logging
- Operation tracking and reporting
- Security event monitoring
- Compliance with security policies

## Integration Points

### Target Registry
- Integrates with existing TargetRegistry system
- Supports both local and remote targets
- Dynamic target discovery and management

### Executor System
- Uses unified executor interface
- Supports multiple connection methods (SSH, Docker, Tailscale)
- Consistent execution patterns across targets

### Discovery System
- Leverages existing discovery pipelines
- Supports Proxmox, Docker, and custom discovery
- Real-time inventory updates

## Usage Examples

### Basic Fleet Discovery
```python
# Discover all nodes in the fleet
result = await fleet_discover()

# Discover specific targets with force refresh
result = await fleet_discover(
    targets=["node1", "node2"],
    force_refresh=True,
    format="json"
)
```

### Node Health Monitoring
```python
# Check health of a specific node
result = await fleet_node_health("web-server-01")
```

### Safe Package Updates
```python
# Plan package update operation
plan = await fleet_operation_plan(
    op_name="update_packages",
    targets=["web-server-01", "db-server-01"],
    parameters={"update_only": True, "upgrade": False}
)

# Execute the plan
result = await fleet_operation_execute(plan["plan_id"])
```

### Service Management
```python
# Plan service restart
plan = await fleet_operation_plan(
    op_name="restart_service",
    targets=["web-server-01"],
    parameters={"service": "nginx"}
)

# Execute the restart
result = await fleet_operation_execute(plan["plan_id"])
```

## Configuration

### Policy Configuration
Fleet management policies are defined in `config/fleet_management_policy.yaml`:

```yaml
version: "1.0"
policy_name: "fleet_management"

operations:
  fleet_discover:
    tier: observe
    allowed_targets: ["gateway"]
    
  update_packages:
    tier: control
    allowed_targets: ["*"]
    parameters:
      update_only: [true, false]
      upgrade: [true, false]

roles:
  fleet_operator:
    allowed_operations:
      - fleet_discover
      - update_packages
      - restart_service
```

### Gateway Mode Configuration
Enable gateway mode by setting environment variable:
```bash
export SYSTEMMANAGER_OPERATION_MODE=gateway
```

## Testing

Run the test suite to verify fleet management tools:
```bash
pytest tests/test_fleet_tools.py -v
```

## Security Considerations

- All operations require explicit policy authorization
- No arbitrary command execution is exposed
- Operations are limited to predefined safe patterns
- Comprehensive audit logging tracks all activities
- Role-based access control prevents unauthorized operations

## Troubleshooting

### Common Issues

1. **"Operation only available in gateway mode"**
   - Ensure `SYSTEMMANAGER_OPERATION_MODE=gateway` is set
   - Verify gateway mode detection is working

2. **Policy authorization failures**
   - Check policy configuration file
   - Verify role assignments and operation permissions
   - Review audit logs for authorization details

3. **Target connection failures**
   - Verify target configuration in TargetRegistry
   - Check network connectivity to targets
   - Validate credentials and connection methods

## Future Enhancements

- Additional safe operation types
- Enhanced impact analysis and risk assessment
- Integration with more infrastructure platforms
- Advanced scheduling and orchestration features
- Improved monitoring and alerting capabilities