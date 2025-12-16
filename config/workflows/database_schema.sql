"""
Database Schema for TailOpsMCP Workflow System.

Provides SQL schema definitions for persisting workflow blueprints,
executions, schedules, and approvals.
"""

# Workflow Blueprints Table
CREATE TABLE workflow_blueprints (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    category TEXT NOT NULL,
    version TEXT NOT NULL,
    config TEXT NOT NULL, -- JSON configuration
    parameters TEXT, -- JSON parameter definitions
    steps TEXT, -- JSON step definitions
    approvals TEXT, -- JSON approval requirements
    rollback_plan TEXT, -- JSON rollback plan
    estimated_duration_seconds INTEGER,
    resource_requirements TEXT, -- JSON resource requirements
    tags TEXT, -- JSON array of tags
    owner TEXT,
    documentation TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CHECK (category IN ('provisioning', 'backup', 'upgrade', 'recovery', 'maintenance', 'monitoring', 'security', 'deployment', 'scaling', 'compliance')),
    CHECK (length(name) > 0),
    CHECK (length(version) > 0)
);

# Workflow Executions Table
CREATE TABLE workflow_executions (
    id TEXT PRIMARY KEY,
    blueprint_id TEXT NOT NULL,
    blueprint_name TEXT NOT NULL,
    parameters TEXT NOT NULL, -- JSON execution parameters
    status TEXT NOT NULL,
    current_step TEXT,
    step_results TEXT, -- JSON step results
    approvals TEXT, -- JSON approval records
    start_time DATETIME NOT NULL,
    end_time DATETIME,
    created_by TEXT,
    context TEXT, -- JSON execution context
    rollback_executed BOOLEAN DEFAULT FALSE,
    error_message TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    -- Foreign Keys
    FOREIGN KEY (blueprint_id) REFERENCES workflow_blueprints(id) ON DELETE CASCADE,

    -- Constraints
    CHECK (status IN ('pending', 'running', 'paused', 'completed', 'failed', 'cancelled', 'rolling_back', 'rolled_back', 'waiting_approval')),
    CHECK (start_time <= end_time OR end_time IS NULL)
);

# Workflow Step Results Table (Normalized)
CREATE TABLE workflow_step_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    execution_id TEXT NOT NULL,
    step_id TEXT NOT NULL,
    step_name TEXT NOT NULL,
    success BOOLEAN NOT NULL,
    message TEXT,
    data TEXT, -- JSON step data
    execution_time_seconds INTEGER,
    started_at DATETIME,
    completed_at DATETIME,
    retry_count INTEGER DEFAULT 0,
    logs TEXT, -- JSON array of log entries
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    -- Foreign Keys
    FOREIGN KEY (execution_id) REFERENCES workflow_executions(id) ON DELETE CASCADE,

    -- Unique constraint
    UNIQUE (execution_id, step_id)
);

# Workflow Schedules Table
CREATE TABLE workflow_schedules (
    id TEXT PRIMARY KEY,
    blueprint_id TEXT NOT NULL,
    blueprint_name TEXT NOT NULL,
    schedule_expression TEXT NOT NULL,
    timezone TEXT DEFAULT 'UTC',
    enabled BOOLEAN DEFAULT TRUE,
    next_run DATETIME,
    last_run DATETIME,
    parameters TEXT, -- JSON schedule parameters
    created_by TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    -- Foreign Keys
    FOREIGN KEY (blueprint_id) REFERENCES workflow_blueprints(id) ON DELETE CASCADE,

    -- Constraints
    CHECK (enabled IN (0, 1)),
    CHECK (timezone IS NOT NULL)
);

# Workflow Approvals Table
CREATE TABLE workflow_approvals (
    id TEXT PRIMARY KEY,
    execution_id TEXT NOT NULL,
    step_id TEXT NOT NULL,
    step_name TEXT,
    approver TEXT NOT NULL,
    status TEXT NOT NULL,
    comment TEXT,
    requested_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    responded_at DATETIME,
    expires_at DATETIME,

    -- Foreign Keys
    FOREIGN KEY (execution_id) REFERENCES workflow_executions(id) ON DELETE CASCADE,

    -- Constraints
    CHECK (status IN ('pending', 'approved', 'rejected', 'expired')),
    CHECK (responded_at IS NULL OR requested_at <= responded_at)
);

# Workflow Events Table (For audit and monitoring)
CREATE TABLE workflow_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    execution_id TEXT,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    source TEXT NOT NULL,
    category TEXT NOT NULL,
    timestamp DATETIME NOT NULL,
    data TEXT, -- JSON event data
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    -- Foreign Keys
    FOREIGN KEY (execution_id) REFERENCES workflow_executions(id) ON DELETE CASCADE,

    -- Constraints
    CHECK (severity IN ('info', 'warning', 'error', 'critical')),
    CHECK (category IN ('workflow', 'step', 'approval', 'policy', 'system', 'alert'))
);

# Workflow Metrics Table (For performance tracking)
CREATE TABLE workflow_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    execution_id TEXT NOT NULL,
    blueprint_name TEXT NOT NULL,
    status TEXT NOT NULL,
    total_steps INTEGER NOT NULL,
    completed_steps INTEGER NOT NULL,
    failed_steps INTEGER NOT NULL,
    total_execution_time_seconds INTEGER,
    approval_count INTEGER DEFAULT 0,
    rollback_count INTEGER DEFAULT 0,
    start_time DATETIME NOT NULL,
    end_time DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    -- Foreign Keys
    FOREIGN KEY (execution_id) REFERENCES workflow_executions(id) ON DELETE CASCADE,

    -- Constraints
    CHECK (total_steps >= 0),
    CHECK (completed_steps >= 0),
    CHECK (failed_steps >= 0),
    CHECK (completed_steps + failed_steps <= total_steps),
    CHECK (status IN ('pending', 'running', 'paused', 'completed', 'failed', 'cancelled', 'rolling_back', 'rolled_back', 'waiting_approval'))
);

# Workflow Governance Rules Table
CREATE TABLE workflow_governance_rules (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    policy_type TEXT NOT NULL,
    enabled BOOLEAN DEFAULT TRUE,
    conditions TEXT, -- JSON rule conditions
    actions TEXT, -- JSON rule actions
    severity TEXT DEFAULT 'medium',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CHECK (policy_type IN ('security_validation', 'resource_limit', 'time_window', 'user_permission', 'change_approval', 'compliance_check')),
    CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    CHECK (enabled IN (0, 1))
);

# Workflow Compliance Results Table
CREATE TABLE workflow_compliance_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    blueprint_id TEXT NOT NULL,
    compliance_standard TEXT NOT NULL,
    compliant BOOLEAN NOT NULL,
    violations TEXT, -- JSON array of violations
    warnings TEXT, -- JSON array of warnings
    recommendations TEXT, -- JSON array of recommendations
    checked_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    -- Foreign Keys
    FOREIGN KEY (blueprint_id) REFERENCES workflow_blueprints(id) ON DELETE CASCADE
);

# Indexes for Performance
CREATE INDEX idx_workflow_executions_status ON workflow_executions(status);
CREATE INDEX idx_workflow_executions_blueprint ON workflow_executions(blueprint_id);
CREATE INDEX idx_workflow_executions_created_at ON workflow_executions(created_at);
CREATE INDEX idx_workflow_executions_created_by ON workflow_executions(created_by);

CREATE INDEX idx_workflow_schedules_enabled ON workflow_schedules(enabled);
CREATE INDEX idx_workflow_schedules_next_run ON workflow_schedules(next_run);
CREATE INDEX idx_workflow_schedules_blueprint ON workflow_schedules(blueprint_id);

CREATE INDEX idx_workflow_approvals_status ON workflow_approvals(status);
CREATE INDEX idx_workflow_approvals_execution ON workflow_approvals(execution_id);
CREATE INDEX idx_workflow_approvals_approver ON workflow_approvals(approver);

CREATE INDEX idx_workflow_events_execution ON workflow_events(execution_id);
CREATE INDEX idx_workflow_events_timestamp ON workflow_events(timestamp);
CREATE INDEX idx_workflow_events_type ON workflow_events(event_type);

CREATE INDEX idx_workflow_metrics_execution ON workflow_metrics(execution_id);
CREATE INDEX idx_workflow_metrics_status ON workflow_metrics(status);
CREATE INDEX idx_workflow_metrics_blueprint ON workflow_metrics(blueprint_name);

# Triggers for Updated Timestamps
CREATE TRIGGER update_workflow_blueprints_timestamp
    AFTER UPDATE ON workflow_blueprints
    BEGIN
        UPDATE workflow_blueprints SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
    END;

CREATE TRIGGER update_workflow_executions_timestamp
    AFTER UPDATE ON workflow_executions
    BEGIN
        UPDATE workflow_executions SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
    END;

CREATE TRIGGER update_workflow_schedules_timestamp
    AFTER UPDATE ON workflow_schedules
    BEGIN
        UPDATE workflow_schedules SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
    END;

CREATE TRIGGER update_workflow_governance_rules_timestamp
    AFTER UPDATE ON workflow_governance_rules
    BEGIN
        UPDATE workflow_governance_rules SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
    END;

# Views for Common Queries
CREATE VIEW workflow_execution_summary AS
SELECT
    we.id as execution_id,
    we.blueprint_name,
    we.status,
    we.created_by,
    we.start_time,
    we.end_time,
    CASE
        WHEN we.end_time IS NULL THEN (julianday('now') - julianday(we.start_time)) * 24 * 60
        ELSE (julianday(we.end_time) - julianday(we.start_time)) * 24 * 60
    END as execution_time_minutes,
    wm.total_steps,
    wm.completed_steps,
    wm.failed_steps,
    wm.approval_count,
    wm.rollback_count
FROM workflow_executions we
LEFT JOIN workflow_metrics wm ON we.id = wm.execution_id;

CREATE VIEW workflow_schedule_summary AS
SELECT
    ws.id as schedule_id,
    ws.blueprint_name,
    ws.schedule_expression,
    ws.timezone,
    ws.enabled,
    ws.next_run,
    ws.last_run,
    wb.category,
    wb.owner,
    wb.tags
FROM workflow_schedules ws
JOIN workflow_blueprints wb ON ws.blueprint_id = wb.id;

CREATE VIEW pending_approvals_summary AS
SELECT
    wa.id as approval_id,
    wa.execution_id,
    wa.step_id,
    wa.approver,
    wa.status,
    wa.requested_at,
    wa.expires_at,
    we.blueprint_name,
    we.created_by as execution_creator
FROM workflow_approvals wa
JOIN workflow_executions we ON wa.execution_id = we.id
WHERE wa.status = 'pending';

# Sample Data Insertion Functions

-- Insert default governance rules
INSERT OR REPLACE INTO workflow_governance_rules (id, name, description, policy_type, enabled, conditions, actions, severity) VALUES
('security_validation', 'Security Validation', 'Validate security requirements for workflow execution', 'security_validation', TRUE,
 '{"require_security_check": true, "validate_user_permissions": true, "check_resource_access": true}',
 '["block_execution", "log_violation"]', 'high'),

('resource_limit', 'Resource Limit', 'Enforce resource usage limits', 'resource_limit', TRUE,
 '{"max_cpu_percent": 80, "max_memory_percent": 85, "max_disk_usage": "90%"}',
 '["request_approval", "limit_resources"]', 'medium'),

('time_window', 'Time Window Restriction', 'Restrict execution to approved time windows', 'time_window', TRUE,
 '{"allowed_hours": ["09:00-17:00"], "timezone": "UTC", "require_weekend_approval": true}',
 '["request_approval", "delay_execution"]', 'medium'),

('change_approval', 'Change Approval', 'Require approval for production changes', 'change_approval', TRUE,
 '{"environments": ["production", "staging"], "change_types": ["deployment", "configuration", "upgrade"]}',
 '["require_approval", "log_change"]', 'high');

-- Sample workflow blueprint (for testing)
INSERT OR REPLACE INTO workflow_blueprints (
    id, name, description, category, version, config, parameters, steps, rollback_plan, estimated_duration_seconds, tags, owner
) VALUES (
    'sample_provisioning',
    'Sample Environment Provisioning',
    'Sample workflow for environment provisioning',
    'provisioning',
    '1.0.0',
    '{"documentation": "Sample workflow for testing"}',
    '{"environment_name": {"type": "string", "required": true}, "container_count": {"type": "integer", "default": 3}}',
    '[{"id": "validate", "name": "Validate", "type": "validation", "timeout": 300}]',
    '{"enabled": true, "actions": []}',
    3600,
    '["sample", "testing"]',
    'test_user'
);
