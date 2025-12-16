-- Enhanced Security Database Schema for TailOpsMCP
-- This schema supports comprehensive security and identity controls
-- Compatible with standard SQL databases

-- Security audit logs table
CREATE TABLE security_audit_logs (
    id VARCHAR(255) PRIMARY KEY,
    operation_id VARCHAR(255) NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    initiator_type VARCHAR(50) NOT NULL,
    initiator_identity TEXT, -- JSON
    operation_type VARCHAR(100) NOT NULL,
    target_resources TEXT NOT NULL, -- JSON
    operation_parameters TEXT, -- JSON
    risk_level VARCHAR(20) NOT NULL,
    outcome VARCHAR(50) NOT NULL,
    outcome_details TEXT, -- JSON
    correlation_id VARCHAR(255),
    session_id VARCHAR(255),
    source_ip VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- User identities table
CREATE TABLE user_identities (
    user_id VARCHAR(255) PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    email VARCHAR(255),
    groups TEXT, -- JSON array
    roles TEXT, -- JSON array
    permissions TEXT, -- JSON array
    authentication_method VARCHAR(50) NOT NULL,
    risk_profile VARCHAR(50) DEFAULT 'standard',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    login_count INTEGER DEFAULT 0,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP,
    active BOOLEAN DEFAULT TRUE
);

-- User sessions table
CREATE TABLE user_sessions (
    session_token VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    identity_context TEXT NOT NULL, -- JSON
    created_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    last_accessed TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMP,
    revocation_reason VARCHAR(255),
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at_ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES user_identities(user_id)
);

-- Identity events table
CREATE TABLE identity_events (
    event_id VARCHAR(255) PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    identity_data TEXT NOT NULL, -- JSON
    event_details TEXT, -- JSON
    source_ip VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Policy decisions table
CREATE TABLE policy_decisions (
    decision_id VARCHAR(255) PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL,
    policy_name VARCHAR(255) NOT NULL,
    decision VARCHAR(50) NOT NULL,
    reason TEXT NOT NULL,
    policy_context TEXT, -- JSON
    enforcement_details TEXT, -- JSON
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Security violations table
CREATE TABLE security_violations (
    violation_id VARCHAR(255) PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL,
    violation_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    description TEXT NOT NULL,
    affected_resources TEXT, -- JSON array
    implicated_identities TEXT, -- JSON array
    violation_details TEXT, -- JSON
    automated_response TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Access attempts table
CREATE TABLE access_attempts (
    attempt_id VARCHAR(255) PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL,
    identity_data TEXT NOT NULL, -- JSON
    resource_data TEXT NOT NULL, -- JSON
    action VARCHAR(100) NOT NULL,
    decision VARCHAR(50) NOT NULL,
    decision_reason TEXT,
    risk_score DECIMAL(5,4),
    enforcement_details TEXT, -- JSON
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Security alerts table
CREATE TABLE security_alerts (
    alert_id VARCHAR(255) PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL,
    severity VARCHAR(20) NOT NULL,
    alert_type VARCHAR(100) NOT NULL,
    description TEXT NOT NULL,
    affected_resources TEXT, -- JSON array
    implicated_identities TEXT, -- JSON array
    status VARCHAR(50) NOT NULL,
    assigned_to VARCHAR(255),
    resolved_at TIMESTAMP,
    resolution_details TEXT,
    recommended_actions TEXT, -- JSON array
    automated_response TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- OIDC tokens table
CREATE TABLE oidc_tokens (
    token_id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    issuer VARCHAR(255) NOT NULL,
    audience VARCHAR(255) NOT NULL,
    token_claims TEXT NOT NULL, -- JSON
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES user_identities(user_id)
);

-- Compliance assessments table
CREATE TABLE compliance_assessments (
    assessment_id VARCHAR(255) PRIMARY KEY,
    standard VARCHAR(50) NOT NULL,
    assessment_date TIMESTAMP NOT NULL,
    compliance_score DECIMAL(5,2) NOT NULL,
    violations TEXT, -- JSON array of violations
    recommendations TEXT, -- JSON array of recommendations
    evidence_artifacts TEXT, -- JSON array of artifact references
    next_assessment TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Security configuration table
CREATE TABLE security_configuration (
    config_id VARCHAR(255) PRIMARY KEY,
    config_key VARCHAR(255) NOT NULL UNIQUE,
    config_value TEXT NOT NULL, -- JSON
    config_type VARCHAR(50) NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(255),
    updated_by VARCHAR(255)
);

-- Threat intelligence table
CREATE TABLE threat_intelligence (
    threat_id VARCHAR(255) PRIMARY KEY,
    threat_type VARCHAR(100) NOT NULL,
    indicator TEXT NOT NULL,
    confidence_score DECIMAL(5,4),
    severity VARCHAR(20) NOT NULL,
    first_seen TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL,
    source VARCHAR(255),
    description TEXT,
    mitigation TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Security metrics table
CREATE TABLE security_metrics (
    metric_id VARCHAR(255) PRIMARY KEY,
    metric_name VARCHAR(255) NOT NULL,
    metric_value DECIMAL(15,6) NOT NULL,
    metric_type VARCHAR(100) NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    dimensions TEXT, -- JSON object for dimensional data
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Access control rules table
CREATE TABLE access_control_rules (
    rule_id VARCHAR(255) PRIMARY KEY,
    rule_name VARCHAR(255) NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    action VARCHAR(100) NOT NULL,
    conditions TEXT, -- JSON object
    decision VARCHAR(50) NOT NULL,
    priority INTEGER NOT NULL,
    description TEXT,
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Data retention policies table
CREATE TABLE data_retention_policies (
    policy_id VARCHAR(255) PRIMARY KEY,
    data_type VARCHAR(100) NOT NULL,
    retention_period_days INTEGER NOT NULL,
    action_on_expiry VARCHAR(50) NOT NULL,
    description TEXT,
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Security incidents table
CREATE TABLE security_incidents (
    incident_id VARCHAR(255) PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL,
    status VARCHAR(50) NOT NULL,
    affected_systems TEXT, -- JSON array
    affected_users TEXT, -- JSON array
    incident_type VARCHAR(100) NOT NULL,
    detection_method VARCHAR(255),
    assigned_to VARCHAR(255),
    resolved_at TIMESTAMP,
    resolution_summary TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for better query performance
CREATE INDEX idx_operation_correlation ON security_audit_logs(correlation_id);
CREATE INDEX idx_initiator_type ON security_audit_logs(initiator_type);
CREATE INDEX idx_operation_type ON security_audit_logs(operation_type);
CREATE INDEX idx_risk_level ON security_audit_logs(risk_level);
CREATE INDEX idx_timestamp ON security_audit_logs(timestamp);

CREATE INDEX idx_username ON user_identities(username);
CREATE INDEX idx_email ON user_identities(email);
CREATE INDEX idx_auth_method ON user_identities(authentication_method);
CREATE INDEX idx_active ON user_identities(active);
CREATE INDEX idx_last_login ON user_identities(last_login);

CREATE INDEX idx_sessions_user_id ON user_sessions(user_id);
CREATE INDEX idx_sessions_expires ON user_sessions(expires_at);
CREATE INDEX idx_sessions_revoked ON user_sessions(revoked_at);

CREATE INDEX idx_identity_events_timestamp ON identity_events(timestamp);
CREATE INDEX idx_identity_events_type ON identity_events(event_type);

CREATE INDEX idx_policy_decisions_timestamp ON policy_decisions(timestamp);
CREATE INDEX idx_policy_name ON policy_decisions(policy_name);
CREATE INDEX idx_decision ON policy_decisions(decision);

CREATE INDEX idx_violations_timestamp ON security_violations(timestamp);
CREATE INDEX idx_violations_severity ON security_violations(severity);
CREATE INDEX idx_violations_type ON security_violations(violation_type);

CREATE INDEX idx_access_attempts_timestamp ON access_attempts(timestamp);
CREATE INDEX idx_access_attempts_action ON access_attempts(action);
CREATE INDEX idx_access_attempts_decision ON access_attempts(decision);

CREATE INDEX idx_security_alerts_timestamp ON security_alerts(timestamp);
CREATE INDEX idx_security_alerts_severity ON security_alerts(severity);
CREATE INDEX idx_security_alerts_type ON security_alerts(alert_type);
CREATE INDEX idx_security_alerts_status ON security_alerts(status);
CREATE INDEX idx_security_alerts_assigned ON security_alerts(assigned_to);

CREATE INDEX idx_oidc_tokens_user ON oidc_tokens(user_id);
CREATE INDEX idx_oidc_tokens_issuer ON oidc_tokens(issuer);
CREATE INDEX idx_oidc_tokens_expires ON oidc_tokens(expires_at);

CREATE INDEX idx_compliance_standard ON compliance_assessments(standard);
CREATE INDEX idx_compliance_date ON compliance_assessments(assessment_date);
CREATE INDEX idx_compliance_score ON compliance_assessments(compliance_score);

CREATE INDEX idx_security_config_key ON security_configuration(config_key);
CREATE INDEX idx_security_config_type ON security_configuration(config_type);

CREATE INDEX idx_threat_intelligence_type ON threat_intelligence(threat_type);
CREATE INDEX idx_threat_intelligence_severity ON threat_intelligence(severity);
CREATE INDEX idx_threat_intelligence_indicator ON threat_intelligence(indicator);
CREATE INDEX idx_threat_intelligence_confidence ON threat_intelligence(confidence_score);

CREATE INDEX idx_security_metrics_name ON security_metrics(metric_name);
CREATE INDEX idx_security_metrics_type ON security_metrics(metric_type);
CREATE INDEX idx_security_metrics_timestamp ON security_metrics(timestamp);

CREATE INDEX idx_access_rules_type ON access_control_rules(resource_type);
CREATE INDEX idx_access_rules_action ON access_control_rules(action);
CREATE INDEX idx_access_rules_priority ON access_control_rules(priority);
CREATE INDEX idx_access_rules_enabled ON access_control_rules(enabled);

CREATE INDEX idx_retention_policies_type ON data_retention_policies(data_type);
CREATE INDEX idx_retention_policies_enabled ON data_retention_policies(enabled);

CREATE INDEX idx_security_incidents_severity ON security_incidents(severity);
CREATE INDEX idx_security_incidents_status ON security_incidents(status);
CREATE INDEX idx_security_incidents_type ON security_incidents(incident_type);
CREATE INDEX idx_security_incidents_created ON security_incidents(created_at);

-- Insert default security configuration
INSERT INTO security_configuration (config_key, config_value, config_type, description) VALUES
('audit_logging_enabled', 'true', 'boolean', 'Enable comprehensive audit logging'),
('session_timeout_hours', '1', 'integer', 'Session timeout in hours'),
('max_concurrent_sessions', '3', 'integer', 'Maximum concurrent sessions per user'),
('mfa_required_roles', '["admin", "security", "operations"]', 'json', 'Roles requiring multi-factor authentication'),
('brute_force_threshold', '5', 'integer', 'Failed login attempts before blocking'),
('data_retention_days', '2555', 'integer', 'Data retention period in days (7 years)'),
('compliance_standards', '["SOC2", "ISO27001"]', 'json', 'Enabled compliance standards'),
('threat_detection_enabled', 'true', 'boolean', 'Enable real-time threat detection'),
('automated_response_enabled', 'false', 'boolean', 'Enable automated security responses'),
('separation_of_duties_enabled', 'true', 'boolean', 'Enable separation of duties checks');

-- Insert default access control rules
INSERT INTO access_control_rules (rule_name, resource_type, action, conditions, decision, priority, description) VALUES
('Admin system access', 'SYSTEM', 'admin', '{"user_roles": ["admin"], "mfa_required": true}', 'allow', 10, 'Administrators can perform system administration'),
('Security audit access', 'AUDIT', 'read', '{"user_roles": ["security", "admin"], "resource_sensitivity": ["internal", "confidential", "restricted"]}', 'allow', 20, 'Security team can read audit logs'),
('Operations target access', 'TARGET', 'manage', '{"user_roles": ["operations", "admin"], "time_restrictions": {"allowed_hours": [8,9,10,11,12,13,14,15,16,17], "allowed_days": [0,1,2,3,4]}}', 'conditional', 30, 'Operations team can manage targets during business hours'),
('Public read access', 'DATA', 'read', '{"resource_sensitivity": ["public"]}', 'allow', 90, 'Anyone can read public data'),
('Default deny', 'SYSTEM', '*', '{}', 'deny', 100, 'Default deny all access');

-- Insert default data retention policies
INSERT INTO data_retention_policies (data_type, retention_period_days, action_on_expiry, description) VALUES
('audit_logs', 2555, 'archive', 'Audit logs retention - 7 years'),
('security_events', 2555, 'archive', 'Security events retention - 7 years'),
('user_sessions', 30, 'delete', 'User session data retention - 30 days'),
('security_alerts', 365, 'archive', 'Security alerts retention - 1 year'),
('compliance_reports', 2555, 'archive', 'Compliance reports retention - 7 years'),
('threat_intelligence', 90, 'delete', 'Threat intelligence data retention - 90 days');
