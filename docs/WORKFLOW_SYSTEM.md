# TailOpsMCP Workflow System

## Overview

The TailOpsMCP Workflow System provides comprehensive orchestration capabilities for common operational tasks, transforming brittle scripts into reliable, governed workflows with proper safety controls.

## Key Features

### 🔄 Workflow Orchestration
- **Blueprint-based workflows**: Define reusable workflow templates
- **Step-by-step execution**: Orchestrate complex operational procedures
- **Dependency management**: Handle step dependencies and execution order
- **Retry policies**: Automatic retry with exponential backoff

### 🛡️ Safety & Governance
- **Rollback capabilities**: Automatic rollback on failure
- **Approval workflows**: Human-in-the-loop for critical operations
- **Policy enforcement**: Integration with existing policy system
- **Compliance validation**: Built-in compliance checking

### ⏰ Scheduling & Automation
- **Recurring workflows**: Cron-based scheduling
- **Event-driven execution**: Trigger workflows from events
- **Resource reservation**: Prevent conflicts during execution
- **Failure handling**: Automatic recovery and escalation

### 📊 Monitoring & Observability
- **Real-time execution tracking**: Monitor workflow progress
- **Comprehensive metrics**: Performance and success tracking
- **Event integration**: Full observability through event system
- **Audit trails**: Complete execution history

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Workflow System Architecture             │
├─────────────────────────────────────────────────────────────┤
│  MCP Tools Layer                                           │
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐ │
│  │ List Workflows  │ │ Execute Workflow│ │ Manage Approvals│ │
│  └─────────────────┘ └─────────────────┘ └─────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│  Service Layer                                             │
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐ │
│  │ Workflow Engine │ │   Scheduler     │ │   Approval Sys  │ │
│  └─────────────────┘ └─────────────────┘ └─────────────────┘ │
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐ │
│  │   Governance    │ │   Integration   │ │   Blueprints    │ │
│  └─────────────────┘ └─────────────────┘ └─────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│  Data Models                                               │
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐ │
│  │ Workflow Models │ │ Execution Models│ │  Approval Models│ │
│  └─────────────────┘ └─────────────────┘ └─────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│  Integration Layer                                         │
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐ │
│  │ Policy Engine   │ │ Fleet Inventory │ │  Event System   │ │
│  └─────────────────┘ └─────────────────┘ └─────────────────┘ │
│  ┌─────────────────┐ ┌─────────────────┐                     │
│  │  Capability Exec│ │   Audit Logger  │                     │
│  └─────────────────┘ └─────────────────┘                     │
└─────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Workflow Models (`src/models/workflow_models.py`)
- **WorkflowBlueprint**: Defines workflow templates with steps, parameters, and policies
- **WorkflowExecution**: Tracks individual workflow execution instances
- **WorkflowStep**: Individual steps within workflows
- **Approval System**: Handles workflow approvals and governance

### 2. Workflow Engine (`src/services/workflow_engine.py`)
- **Execution Orchestration**: Coordinates step execution
- **Rollback Management**: Handles failure recovery
- **Error Handling**: Comprehensive error management
- **Event Emission**: Real-time status updates

### 3. Workflow Scheduler (`src/services/workflow_scheduler.py`)
- **Cron Scheduling**: Recurring workflow execution
- **Schedule Management**: Create, update, cancel schedules
- **Execution Triggering**: Automatic workflow launching
- **Time Zone Support**: Global time zone handling

### 4. Approval System (`src/services/workflow_approval.py`)
- **Approval Requests**: Manage approval workflows
- **Governance Rules**: Enforce compliance policies
- **Audit Tracking**: Complete approval history
- **Escalation Management**: Handle approval timeouts

### 5. Integration Layer (`src/services/workflow_integration.py`)
- **Policy Integration**: Work with existing policy engine
- **Inventory Integration**: Target fleet management
- **Event Integration**: Emit workflow events
- **Capability Integration**: Execute through capability system

## Built-in Workflow Blueprints

### Environment Provisioning
```python
workflow = EnvironmentProvisioningWorkflow(
    environment_name="production-api",
    container_count=5,
    service_type="api"
)
```

**Features:**
- Resource allocation with approval
- Container creation and configuration
- Service deployment
- Network configuration
- Health validation
- Initial backup creation

### Fleet Backup Orchestration
```python
workflow = BackupOrchestrationWorkflow(
    backup_retention_days=30,
    backup_compression=True
)
```

**Features:**
- Automatic target discovery
- Backup space validation
- Snapshot creation
- Data backup
- Integrity verification
- Automated cleanup

### Safe Container Upgrade
```python
workflow = SafeUpgradeWorkflow(
    upgrade_type="rolling",
    maintenance_window="off-hours"
)
```

**Features:**
- Pre-upgrade snapshots
- Rolling/blue-green/canary strategies
- Comprehensive testing
- Performance validation
- Automatic rollback on failure

### Disaster Recovery
```python
workflow = DisasterRecoveryWorkflow(
    recovery_type="full",
    validation_level="comprehensive"
)
```

**Features:**
- Backup validation
- Environment preparation
- Data restoration
- Configuration recovery
- Health validation
- Functionality testing

## Usage Examples

### Basic Workflow Execution
```python
# List available workflows
workflows = await list_workflows()

# Get workflow details
details = await get_workflow_details("environment_provisioning")

# Execute workflow
result = await execute_workflow(
    workflow_name="environment_provisioning",
    parameters={
        "environment_name": "staging-api",
        "container_count": 3,
        "service_type": "api"
    },
    created_by="user@example.com"
)

# Monitor execution
status = await get_workflow_status(result["execution_id"])
```

### Workflow Scheduling
```python
# Schedule daily backup
schedule = await schedule_workflow(
    workflow_name="fleet_backup_orchestration",
    schedule={
        "cron_expression": "0 2 * * *",  # Daily at 2 AM
        "timezone": "UTC",
        "parameters": {"backup_retention_days": 30}
    }
)

# List scheduled workflows
schedules = await list_scheduled_workflows()

# Get upcoming executions
upcoming = await get_upcoming_executions(hours_ahead=24)
```

### Approval Management
```python
# Request approval
approval = await request_workflow_approval(
    execution_id="exec-123",
    step_id="allocate_resources",
    approver="operations_manager",
    comment="Need approval for resource allocation"
)

# Approve step
await approve_workflow_step(
    approval_id=approval["approval_id"],
    approver="operations_manager",
    comment="Approved for production deployment"
)

# Get pending approvals
pending = await get_pending_approvals("operations_manager")
```

## Configuration

### Workflow YAML Configuration
```yaml
workflows:
  custom_workflow:
    name: "Custom Workflow"
    description: "Custom operational workflow"
    category: "provisioning"
    version: "1.0.0"

    parameters:
      environment_name:
        type: "string"
        required: true
        description: "Environment name"

      container_count:
        type: "integer"
        required: true
        default: 3
        validation:
          min: 1
          max: 100

    steps:
      - id: "validate"
        name: "Validate Prerequisites"
        type: "validation"
        timeout_minutes: 5

      - id: "provision"
        name: "Provision Environment"
        type: "container_operations"
        timeout_minutes: 30
        dependencies: ["validate"]

    rollback_plan:
      enabled: true
      actions:
        - id: "cleanup"
          name: "Cleanup Resources"
          type: "container_operations"
          timeout_minutes: 15
```

### Database Schema
The workflow system uses SQLite for persistence with the following tables:
- `workflow_blueprints`: Store workflow definitions
- `workflow_executions`: Track execution instances
- `workflow_schedules`: Manage recurring schedules
- `workflow_approvals`: Handle approval requests
- `workflow_events`: Audit trail and monitoring
- `workflow_metrics`: Performance tracking

## Integration with Existing Systems

### Policy Engine Integration
```python
# Validate workflow against policies
policy_result = await validate_workflow_policies(
    blueprint=workflow,
    user="user@example.com"
)

if not policy_result["allowed"]:
    print(f"Policy violations: {policy_result['violations']}")
```

### Fleet Inventory Integration
```python
# Get compatible targets
targets = await get_workflow_targets(
    blueprint=workflow,
    parameters=parameters
)

# Validate target compatibility
compatibility = await validate_target_compatibility(
    targets=targets,
    blueprint=workflow
)
```

### Event System Integration
```python
# Workflow events are automatically emitted
event = SystemEvent(
    event_type=EventType.WORKFLOW,
    severity=EventSeverity.INFO,
    data={
        "execution_id": execution_id,
        "event_type": "step_completed",
        "details": {...}
    }
)
```

## Best Practices

### 1. Workflow Design
- Keep workflows focused and modular
- Use clear, descriptive step names
- Define proper dependencies between steps
- Include comprehensive error handling
- Plan for rollback scenarios

### 2. Parameter Management
- Use parameter validation
- Provide sensible defaults
- Document all parameters clearly
- Use appropriate parameter types
- Consider sensitive parameter handling

### 3. Approval Workflows
- Require approvals for critical operations
- Define clear approval criteria
- Set appropriate timeout periods
- Use role-based approver assignments
- Document approval processes

### 4. Error Handling
- Implement comprehensive retry policies
- Plan for rollback scenarios
- Use appropriate timeout values
- Provide detailed error messages
- Log all significant events

### 5. Monitoring and Observability
- Monitor workflow execution metrics
- Set up alerts for failures
- Track approval response times
- Monitor resource usage
- Maintain audit trails

## Security Considerations

### Access Control
- Workflow execution requires proper authentication
- Approval workflows enforce separation of duties
- Policy engine validates all operations
- Audit logging tracks all actions

### Data Protection
- Sensitive parameters are encrypted
- Workflow execution contexts are isolated
- Backup data is protected
- Access logs are maintained

### Compliance
- Built-in compliance validation
- Governance rule enforcement
- Approval trail requirements
- Change management processes

## Troubleshooting

### Common Issues

#### Workflow Execution Fails
1. Check workflow parameters are valid
2. Verify target availability and compatibility
3. Review policy validation results
4. Check approval requirements
5. Examine step execution logs

#### Approval Not Granted
1. Verify approver has necessary permissions
2. Check approval timeout settings
3. Review approval criteria
4. Ensure proper escalation rules

#### Schedule Not Triggering
1. Validate cron expression syntax
2. Check schedule is enabled
3. Verify next_run time is set correctly
4. Review scheduler logs for errors

#### Rollback Failure
1. Check rollback action definitions
2. Verify resource availability for rollback
3. Review rollback dependencies
4. Examine rollback action logs

### Debug Mode
Enable debug logging:
```python
import logging
logging.getLogger("workflow_engine").setLevel(logging.DEBUG)
logging.getLogger("workflow_scheduler").setLevel(logging.DEBUG)
logging.getLogger("workflow_approval").setLevel(logging.DEBUG)
```

### Monitoring
Monitor key metrics:
- Workflow execution success rate
- Average execution time
- Approval response times
- Rollback frequency
- Resource utilization

## Future Enhancements

### Planned Features
- Visual workflow designer
- Advanced scheduling options
- Machine learning-based optimization
- Cross-environment workflows
- Workflow templates marketplace
- Advanced analytics and reporting

### Extensibility
The workflow system is designed for extensibility:
- Custom step types
- Integration plugins
- External trigger systems
- Custom approval workflows
- Extended governance rules

## Support and Contribution

### Getting Help
- Review this documentation
- Check the examples in `examples/workflow_examples.py`
- Examine the test scenarios
- Review logs for error details

### Contributing
1. Follow the existing code patterns
2. Add comprehensive tests
3. Update documentation
4. Ensure backward compatibility
5. Follow security best practices

---

The TailOpsMCP Workflow System transforms operational automation from brittle scripts into robust, governed workflows that ensure reliability, safety, and compliance across your infrastructure operations.
