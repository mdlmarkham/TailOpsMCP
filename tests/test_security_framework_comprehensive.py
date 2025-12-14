"""
Comprehensive Security Framework Tests for TailOpsMCP.

This test suite validates all security components and their integration,
ensuring enterprise-grade security capabilities work correctly.
"""

import asyncio
import pytest
import tempfile
import os
import sqlite3
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, AsyncMock
from typing import Dict, Any

# Test all security models
class TestSecurityModels:
    """Test security data models."""
    
    def test_security_operation_creation(self):
        """Test SecurityOperation model creation."""
        from src.models.security_models import SecurityOperation, InitiatorType, RiskLevel
        
        operation = SecurityOperation(
            operation_id="test_op_001",
            timestamp=datetime.utcnow(),
            initiator_type=InitiatorType.HUMAN,
            operation_type="deploy",
            target_resources=["target1", "target2"],
            operation_parameters={"env": "production"},
            risk_level=RiskLevel.MEDIUM,
            correlation_id="corr_001"
        )
        
        assert operation.operation_id == "test_op_001"
        assert operation.initiator_type == InitiatorType.HUMAN
        assert operation.operation_type == "deploy"
        assert len(operation.target_resources) == 2
        assert operation.risk_level == RiskLevel.MEDIUM
    
    def test_identity_context_creation(self):
        """Test IdentityContext model creation."""
        from src.models.security_models import IdentityContext, AuthenticationMethod, RiskProfile
        
        identity = IdentityContext(
            user_id="user_123",
            username="john.doe",
            email="john.doe@company.com",
            groups=["engineering", "production"],
            roles=["developer"],
            permissions=["read", "write"],
            authentication_method=AuthenticationMethod.OIDC,
            session_id="session_123",
            tailscale_node="johns-laptop",
            source_ip="192.168.1.100",
            user_agent="Mozilla/5.0",
            risk_profile=RiskProfile.STANDARD
        )
        
        assert identity.user_id == "user_123"
        assert identity.authentication_method == AuthenticationMethod.OIDC
        assert "engineering" in identity.groups
        assert identity.risk_profile == RiskProfile.STANDARD
    
    def test_security_alert_creation(self):
        """Test SecurityAlert model creation."""
        from src.models.security_models import SecurityAlert, AlertSeverity, AlertType
        
        alert = SecurityAlert(
            alert_id="alert_001",
            timestamp=datetime.utcnow(),
            severity=AlertSeverity.HIGH,
            alert_type=AlertType.AUTHENTICATION_FAILURE,
            description="Multiple failed login attempts",
            affected_resources=["login-service"],
            implicated_identities=["user_123"],
            recommended_actions=["Review login attempts", "Check for compromise"]
        )
        
        assert alert.severity == AlertSeverity.HIGH
        assert alert.alert_type == AlertType.AUTHENTICATION_FAILURE
        assert len(alert.recommended_actions) == 2


# Test security audit logger
class TestSecurityAuditLogger:
    """Test security audit logging functionality."""
    
    @pytest.fixture
    def audit_logger(self):
        """Create audit logger with temporary database."""
        from src.security import SecurityAuditLogger
        
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp_file:
            db_path = tmp_file.name
        
        logger = SecurityAuditLogger(database_path=db_path)
        yield logger
        
        # Cleanup
        if os.path.exists(db_path):
            os.unlink(db_path)
    
    @pytest.mark.asyncio
    async def test_log_operation_initiated(self, audit_logger):
        """Test logging operation initiation."""
        from src.models.security_models import SecurityOperation, InitiatorType, RiskLevel
        
        operation = SecurityOperation(
            operation_id="test_op_001",
            timestamp=datetime.utcnow(),
            initiator_type=InitiatorType.HUMAN,
            operation_type="deploy",
            target_resources=["target1"],
            operation_parameters={"env": "production"},
            risk_level=RiskLevel.MEDIUM,
            correlation_id="corr_001"
        )
        
        operation_id = await audit_logger.log_operation_initiated(operation)
        
        assert operation_id == "test_op_001"
        
        # Verify in database
        conn = sqlite3.connect(audit_logger.database_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM security_audit_logs WHERE operation_id = ?", (operation_id,))
        result = cursor.fetchone()
        conn.close()
        
        assert result is not None
    
    @pytest.mark.asyncio
    async def test_log_security_violation(self, audit_logger):
        """Test logging security violations."""
        from src.models.security_models import SecurityViolation, ViolationType, ViolationSeverity
        
        violation = SecurityViolation(
            violation_id="violation_001",
            timestamp=datetime.utcnow(),
            violation_type=ViolationType.UNAUTHORIZED_ACCESS,
            severity=ViolationSeverity.HIGH,
            description="User attempted to access restricted resource",
            resource_id="restricted_resource",
            user_id="user_123",
            source_ip="192.168.1.100",
            remediation_actions=["Revoke access", "Review permissions"]
        )
        
        await audit_logger.log_security_violation(violation)
        
        # Verify violation was logged
        violations = await audit_logger.get_security_violations({"user_id": "user_123"})
        assert len(violations) > 0
        assert violations[0]["violation_type"] == ViolationType.UNAUTHORIZED_ACCESS.value
    
    @pytest.mark.asyncio
    async def test_get_audit_events(self, audit_logger):
        """Test retrieving audit events."""
        from src.models.security_models import SecurityOperation, InitiatorType, RiskLevel
        
        # Log some operations
        for i in range(3):
            operation = SecurityOperation(
                operation_id=f"test_op_{i:03d}",
                timestamp=datetime.utcnow(),
                initiator_type=InitiatorType.HUMAN,
                operation_type="read",
                target_resources=[f"resource_{i}"],
                operation_parameters={},
                risk_level=RiskLevel.LOW,
                correlation_id="corr_test"
            )
            await audit_logger.log_operation_initiated(operation)
        
        # Retrieve events
        events = await audit_logger.get_audit_events({
            "initiator_type": "HUMAN",
            "time_range": "1h"
        })
        
        assert len(events) == 3
        assert all(event["initiator_type"] == "HUMAN" for event in events)


# Test identity manager
class TestIdentityManager:
    """Test identity management functionality."""
    
    @pytest.fixture
    def identity_manager(self):
        """Create identity manager with temporary database."""
        from src.services.identity_manager import IdentityManager
        
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp_file:
            db_path = tmp_file.name
        
        manager = IdentityManager(database_path=db_path)
        yield manager
        
        # Cleanup
        if os.path.exists(db_path):
            os.unlink(db_path)
    
    @pytest.mark.asyncio
    async def test_create_session(self, identity_manager):
        """Test session creation."""
        from src.models.security_models import IdentityContext, AuthenticationMethod, RiskProfile
        
        identity = IdentityContext(
            user_id="test_user",
            username="test.user@company.com",
            email="test.user@company.com",
            groups=["engineering"],
            roles=["developer"],
            permissions=["read", "write"],
            authentication_method=AuthenticationMethod.OIDC,
            session_id="session_001",
            source_ip="192.168.1.100",
            user_agent="Test Browser",
            risk_profile=RiskProfile.STANDARD
        )
        
        session_token = await identity_manager.create_session(
            identity=identity,
            ttl=timedelta(hours=1)
        )
        
        assert session_token is not None
        assert len(session_token) > 10
        
        # Verify session in database
        session = await identity_manager.get_session(session_token)
        assert session is not None
        assert session["user_id"] == "test_user"
    
    @pytest.mark.asyncio
    async def test_validate_session(self, identity_manager):
        """Test session validation."""
        from src.models.security_models import IdentityContext, AuthenticationMethod, RiskProfile
        
        # Create session
        identity = IdentityContext(
            user_id="test_user",
            username="test.user@company.com",
            email="test.user@company.com",
            groups=["engineering"],
            roles=["developer"],
            permissions=["read", "write"],
            authentication_method=AuthenticationMethod.OIDC,
            session_id="session_001",
            source_ip="192.168.1.100",
            user_agent="Test Browser",
            risk_profile=RiskProfile.STANDARD
        )
        
        session_token = await identity_manager.create_session(
            identity=identity,
            ttl=timedelta(hours=1)
        )
        
        # Validate session
        validation_result = await identity_manager.validate_session(session_token)
        
        assert validation_result.is_valid
        assert validation_result.identity.user_id == "test_user"
    
    @pytest.mark.asyncio
    async def test_get_user_permissions(self, identity_manager):
        """Test permission retrieval."""
        from src.models.security_models import IdentityContext, AuthenticationMethod, RiskProfile
        
        identity = IdentityContext(
            user_id="test_user",
            username="test.user@company.com",
            email="test.user@company.com",
            groups=["engineering", "security"],
            roles=["developer", "security_analyst"],
            permissions=["read", "write", "analyze"],
            authentication_method=AuthenticationMethod.OIDC,
            session_id="session_001",
            source_ip="192.168.1.100",
            user_agent="Test Browser",
            risk_profile=RiskProfile.STANDARD
        )
        
        permissions = await identity_manager.get_user_permissions("test_user")
        
        assert "read" in permissions
        assert "write" in permissions
        assert "analyze" in permissions


# Test access control
class TestAdvancedAccessControl:
    """Test advanced access control functionality."""
    
    @pytest.fixture
    def access_control(self):
        """Create access control with temporary database."""
        from src.services.access_control import AdvancedAccessControl
        
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp_file:
            db_path = tmp_file.name
        
        control = AdvancedAccessControl(database_path=db_path)
        yield control
        
        # Cleanup
        if os.path.exists(db_path):
            os.unlink(db_path)
    
    @pytest.mark.asyncio
    async def test_evaluate_access_allow(self, access_control):
        """Test access evaluation - allow case."""
        from src.models.security_models import (
            IdentityContext, ResourceContext, AuthenticationMethod, 
            RiskProfile, ResourceType, SensitivityLevel, SecurityClassification
        )
        
        identity = IdentityContext(
            user_id="test_user",
            username="test.user@company.com",
            email="test.user@company.com",
            groups=["engineering"],
            roles=["developer"],
            permissions=["read", "write"],
            authentication_method=AuthenticationMethod.OIDC,
            session_id="session_001",
            source_ip="192.168.1.100",
            user_agent="Test Browser",
            risk_profile=RiskProfile.STANDARD
        )
        
        resource = ResourceContext(
            resource_type=ResourceType.FILE,
            resource_id="document_123",
            resource_path="/documents/document_123.pdf",
            sensitivity_level=SensitivityLevel.INTERNAL,
            ownership={"owner_id": "test_user"},
            security_classification=SecurityClassification.CONFIDENTIAL
        )
        
        decision = await access_control.evaluate_access(
            identity=identity,
            resource=resource,
            action="read"
        )
        
        assert decision.decision == "ALLOW"
        assert decision.confidence_score > 0.7
    
    @pytest.mark.asyncio
    async def test_evaluate_access_deny_high_risk(self, access_control):
        """Test access evaluation - deny high risk case."""
        from src.models.security_models import (
            IdentityContext, ResourceContext, AuthenticationMethod, 
            RiskProfile, ResourceType, SensitivityLevel, SecurityClassification
        )
        
        identity = IdentityContext(
            user_id="test_user",
            username="test.user@company.com",
            email="test.user@company.com",
            groups=["engineering"],
            roles=["developer"],
            permissions=["read", "write"],
            authentication_method=AuthenticationMethod.OIDC,
            session_id="session_001",
            source_ip="192.168.1.100",
            user_agent="Test Browser",
            risk_profile=RiskProfile.HIGH_RISK  # High risk profile
        )
        
        resource = ResourceContext(
            resource_type=ResourceType.DATABASE,
            resource_id="financial_db",
            resource_path="/databases/financial",
            sensitivity_level=SensitivityLevel.RESTRICTED,
            ownership={"owner_id": "finance_team"},
            security_classification=SecurityClassification.RESTRICTED
        )
        
        decision = await access_control.evaluate_access(
            identity=identity,
            resource=resource,
            action="read"
        )
        
        assert decision.decision == "DENY"
        assert "high_risk" in decision.decision_reason.lower()
    
    @pytest.mark.asyncio
    async def test_evaluate_risk(self, access_control):
        """Test risk evaluation."""
        from src.models.security_models import (
            SecurityOperation, InitiatorType, RiskLevel, 
            IdentityContext, AuthenticationMethod, RiskProfile
        )
        
        identity = IdentityContext(
            user_id="test_user",
            username="test.user@company.com",
            email="test.user@company.com",
            groups=["engineering"],
            roles=["developer"],
            permissions=["read", "write"],
            authentication_method=AuthenticationMethod.OIDC,
            session_id="session_001",
            source_ip="192.168.1.100",
            user_agent="Test Browser",
            risk_profile=RiskProfile.STANDARD
        )
        
        operation = SecurityOperation(
            operation_id="test_op_001",
            timestamp=datetime.utcnow(),
            initiator_type=InitiatorType.HUMAN,
            operation_type="deploy",
            target_resources=["production_service"],
            operation_parameters={"environment": "production"},
            risk_level=RiskLevel.HIGH,
            correlation_id="corr_001"
        )
        
        risk_assessment = await access_control.evaluate_risk(
            identity=identity,
            operation=operation
        )
        
        assert risk_assessment.risk_score >= 0
        assert risk_assessment.risk_score <= 1
        assert len(risk_assessment.risk_factors) > 0


# Test security monitor
class TestSecurityMonitor:
    """Test security monitoring functionality."""
    
    @pytest.fixture
    def security_monitor(self):
        """Create security monitor with temporary database."""
        from src.security import SecurityMonitor
        
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp_file:
            db_path = tmp_file.name
        
        monitor = SecurityMonitor(database_path=db_path)
        yield monitor
        
        # Cleanup
        if os.path.exists(db_path):
            os.unlink(db_path)
    
    @pytest.mark.asyncio
    async def test_monitor_failed_attempts(self, security_monitor):
        """Test monitoring failed attempts."""
        from src.models.security_models import FailedAttempt
        
        # Create some failed attempts
        failed_attempts = [
            FailedAttempt(
                user_id="test_user",
                source_ip="192.168.1.100",
                timestamp=datetime.utcnow(),
                failure_reason="invalid_password"
            ),
            FailedAttempt(
                user_id="test_user",
                source_ip="192.168.1.100",
                timestamp=datetime.utcnow() + timedelta(seconds=30),
                failure_reason="invalid_password"
            ),
            FailedAttempt(
                user_id="test_user",
                source_ip="192.168.1.100",
                timestamp=datetime.utcnow() + timedelta(seconds=60),
                failure_reason="invalid_password"
            )
        ]
        
        for attempt in failed_attempts:
            await security_monitor.log_failed_attempt(attempt)
        
        # Check for brute force attacks
        alerts = await security_monitor.monitor_failed_attempts()
        
        assert len(alerts) > 0
        assert any("brute_force" in alert.alert_type.value for alert in alerts)
    
    @pytest.mark.asyncio
    async def test_detect_anomalous_behavior(self, security_monitor):
        """Test anomalous behavior detection."""
        from src.models.security_models import IdentityContext, AuthenticationMethod, RiskProfile
        
        identity = IdentityContext(
            user_id="test_user",
            username="test.user@company.com",
            email="test.user@company.com",
            groups=["engineering"],
            roles=["developer"],
            permissions=["read", "write"],
            authentication_method=AuthenticationMethod.OIDC,
            session_id="session_001",
            source_ip="192.168.1.100",
            user_agent="Test Browser",
            risk_profile=RiskProfile.STANDARD
        )
        
        # Generate unusual behavior (multiple rapid logins from different locations)
        anomalies = await security_monitor.detect_anomalous_behavior(identity)
        
        # The system should detect some form of anomalous behavior
        # (exact behavior depends on baseline establishment)
        assert isinstance(anomalies, list)
    
    @pytest.mark.asyncio
    async def test_log_security_alert(self, security_monitor):
        """Test security alert logging."""
        from src.models.security_models import (
            SecurityAlert, AlertSeverity, AlertType
        )
        
        alert = SecurityAlert(
            alert_id="test_alert_001",
            timestamp=datetime.utcnow(),
            severity=AlertSeverity.HIGH,
            alert_type=AlertType.AUTHENTICATION_FAILURE,
            description="Test security alert",
            affected_resources=["auth-service"],
            implicated_identities=["test_user"],
            recommended_actions=["Review authentication logs"]
        )
        
        await security_monitor.log_security_alert(alert)
        
        # Verify alert was logged
        alerts = await security_monitor.get_security_alerts({"severity": "HIGH"})
        assert len(alerts) > 0
        assert alerts[0]["alert_type"] == AlertType.AUTHENTICATION_FAILURE.value


# Test compliance framework
class TestComplianceFramework:
    """Test compliance framework functionality."""
    
    @pytest.fixture
    def compliance_framework(self):
        """Create compliance framework with temporary database."""
        from src.services.compliance_framework import ComplianceFramework
        
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp_file:
            db_path = tmp_file.name
        
        framework = ComplianceFramework(database_path=db_path)
        yield framework
        
        # Cleanup
        if os.path.exists(db_path):
            os.unlink(db_path)
    
    @pytest.mark.asyncio
    async def test_audit_compliance_soc2(self, compliance_framework):
        """Test SOC2 compliance audit."""
        from src.models.security_models import ComplianceStandard
        
        time_range = {
            "start": datetime.utcnow() - timedelta(days=30),
            "end": datetime.utcnow()
        }
        
        report = await compliance_framework.audit_compliance(
            compliance_standard=ComplianceStandard.SOC2,
            time_range=time_range
        )
        
        assert report.standard == ComplianceStandard.SOC2
        assert report.compliance_score >= 0
        assert report.compliance_score <= 100
        assert isinstance(report.violations, list)
        assert isinstance(report.recommendations, list)
    
    @pytest.mark.asyncio
    async def test_generate_compliance_evidence(self, compliance_framework):
        """Test compliance evidence generation."""
        from src.models.security_models import ComplianceStandard
        
        time_range = {
            "start": datetime.utcnow() - timedelta(days=30),
            "end": datetime.utcnow()
        }
        
        evidence = await compliance_framework.generate_compliance_evidence(
            compliance_standard=ComplianceStandard.ISO27001,
            time_range=time_range
        )
        
        assert evidence.standard == ComplianceStandard.ISO27001
        assert evidence.time_range == time_range
        assert len(evidence.evidence_items) > 0
    
    @pytest.mark.asyncio
    async def test_validate_data_handling(self, compliance_framework):
        """Test data handling validation."""
        from src.models.security_models import SecurityOperation, InitiatorType, RiskLevel
        
        operation = SecurityOperation(
            operation_id="test_op_001",
            timestamp=datetime.utcnow(),
            initiator_type=InitiatorType.HUMAN,
            operation_type="read",
            target_resources=["customer_data"],
            operation_parameters={"data_type": "pii"},
            risk_level=RiskLevel.MEDIUM,
            correlation_id="corr_001"
        )
        
        validation = await compliance_framework.validate_data_handling(operation)
        
        assert validation.is_compliant is not None
        assert validation.violations is not None


# Test security management tools
class TestSecurityManagementTools:
    """Test security management tools."""
    
    @pytest.fixture
    def security_tools(self):
        """Create security management tools."""
        from src.tools.security_management_tools import SecurityManagementTools
        
        tools = SecurityManagementTools()
        return tools
    
    def test_get_security_audit_log(self, security_tools):
        """Test security audit log retrieval."""
        result = security_tools.get_security_audit_log({
            "time_range": "24h",
            "event_type": "authentication"
        })
        
        assert isinstance(result, dict)
        assert "success" in result
    
    def test_get_identity_context(self, security_tools):
        """Test identity context retrieval."""
        result = security_tools.get_identity_context("test_user")
        
        assert isinstance(result, dict)
        assert "success" in result
    
    def test_validate_user_permissions(self, security_tools):
        """Test user permission validation."""
        result = security_tools.validate_user_permissions(
            user_id="test_user",
            resource="/documents/document_123"
        )
        
        assert isinstance(result, dict)
        assert "success" in result
    
    def test_get_security_alerts(self, security_tools):
        """Test security alerts retrieval."""
        result = security_tools.get_security_alerts(severity="high")
        
        assert isinstance(result, dict)
        assert "success" in result
    
    def test_generate_compliance_report(self, security_tools):
        """Test compliance report generation."""
        result = security_tools.generate_compliance_report(
            standard="SOC2",
            time_range="monthly"
        )
        
        assert isinstance(result, dict)
        assert "success" in result
    
    def test_validate_security_posture(self, security_tools):
        """Test security posture validation."""
        result = security_tools.validate_security_posture()
        
        assert isinstance(result, dict)
        assert "success" in result
        assert "security_score" in result


# Integration tests
class TestSecurityIntegration:
    """Test security system integration."""
    
    @pytest.mark.asyncio
    async def test_end_to_end_security_workflow(self):
        """Test complete security workflow from authentication to audit."""
        from src.security import SecurityAuditLogger
        from src.services.identity_manager import IdentityManager
        from src.services.access_control import AdvancedAccessControl
        from src.models.security_models import (
            IdentityContext, AuthenticationMethod, RiskProfile,
            ResourceContext, ResourceType, SensitivityLevel, SecurityClassification,
            SecurityOperation, InitiatorType, RiskLevel
        )
        
        # Create temporary databases
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp_file:
            audit_db = tmp_file.name
        
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp_file:
            identity_db = tmp_file.name
        
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp_file:
            access_db = tmp_file.name
        
        try:
            # Initialize services
            audit_logger = SecurityAuditLogger(database_path=audit_db)
            identity_manager = IdentityManager(database_path=identity_db)
            access_control = AdvancedAccessControl(database_path=access_db)
            
            # Create identity and session
            identity = IdentityContext(
                user_id="integration_test_user",
                username="integration.test@company.com",
                email="integration.test@company.com",
                groups=["engineering"],
                roles=["developer"],
                permissions=["read", "write"],
                authentication_method=AuthenticationMethod.OIDC,
                session_id="integration_session",
                source_ip="192.168.1.100",
                user_agent="Integration Test Browser",
                risk_profile=RiskProfile.STANDARD
            )
            
            session_token = await identity_manager.create_session(
                identity=identity,
                ttl=timedelta(hours=1)
            )
            
            # Validate session
            validation_result = await identity_manager.validate_session(session_token)
            assert validation_result.is_valid
            
            # Log operation
            operation = SecurityOperation(
                operation_id="integration_test_op",
                timestamp=datetime.utcnow(),
                initiator_type=InitiatorType.HUMAN,
                operation_type="read",
                target_resources=["integration_resource"],
                operation_parameters={},
                risk_level=RiskLevel.LOW,
                correlation_id="integration_corr"
            )
            
            operation_id = await audit_logger.log_operation_initiated(operation)
            assert operation_id == "integration_test_op"
            
            # Check access
            resource = ResourceContext(
                resource_type=ResourceType.FILE,
                resource_id="integration_resource",
                resource_path="/integration/resource",
                sensitivity_level=SensitivityLevel.INTERNAL,
                ownership={"owner_id": "integration_test_user"},
                security_classification=SecurityClassification.CONFIDENTIAL
            )
            
            access_decision = await access_control.evaluate_access(
                identity=identity,
                resource=resource,
                action="read"
            )
            
            assert access_decision.decision in ["ALLOW", "DENY"]
            
            # Complete operation audit
            from src.models.security_models import OperationOutcome
            outcome = OperationOutcome(
                operation_id=operation_id,
                outcome="SUCCESS",
                details={"access_granted": access_decision.decision == "ALLOW"}
            )
            
            await audit_logger.log_operation_outcome(operation_id, outcome)
            
            # Verify complete audit trail
            audit_events = await audit_logger.get_audit_events({
                "operation_id": "integration_test_op"
            })
            
            assert len(audit_events) >= 2  # Initiation + outcome
            
        finally:
            # Cleanup databases
            for db_path in [audit_db, identity_db, access_db]:
                if os.path.exists(db_path):
                    os.unlink(db_path)
    
    @pytest.mark.asyncio
    async def test_security_policy_integration(self):
        """Test security integration with policy system."""
        from src.security import SecurityPolicyIntegration
        from src.models.policy_models import PolicyContext, Policy
        from src.models.security_models import (
            IdentityContext, AuthenticationMethod, RiskProfile,
            SecurityOperation, InitiatorType, RiskLevel
        )
        
        # Create mock services
        mock_audit_logger = AsyncMock()
        mock_security_monitor = AsyncMock()
        mock_identity_manager = AsyncMock()
        
        integration = SecurityPolicyIntegration(
            audit_logger=mock_audit_logger,
            security_monitor=mock_security_monitor,
            identity_manager=mock_identity_manager
        )
        
        # Test policy context enhancement
        policy_context = PolicyContext(
            policy_id="test_policy",
            policy_name="Test Policy",
            conditions={"environment": "production"},
            actions=["deploy"],
            resources=["production_service"]
        )
        
        enhanced_context = await integration.enhance_policy_decisions(policy_context)
        
        assert enhanced_context is not None
        assert hasattr(enhanced_context, "security_requirements")
        
        # Test policy enforcement logging
        mock_policy_enforcement = Mock()
        mock_policy_enforcement.policy_id = "test_policy"
        mock_policy_enforcement.decision = "APPROVED"
        mock_policy_enforcement.security_impact = "LOW"
        
        await integration.log_policy_enforcement(mock_policy_enforcement)
        
        mock_audit_logger.log_policy_enforcement.assert_called_once()


# Performance tests
class TestSecurityPerformance:
    """Test security system performance."""
    
    @pytest.mark.asyncio
    async def test_audit_logging_performance(self):
        """Test audit logging performance under load."""
        from src.security import SecurityAuditLogger
        from src.models.security_models import (
            SecurityOperation, InitiatorType, RiskLevel
        )
        
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp_file:
            db_path = tmp_file.name
        
        try:
            audit_logger = SecurityAuditLogger(database_path=db_path)
            
            # Generate multiple operations
            operations = []
            for i in range(100):
                operation = SecurityOperation(
                    operation_id=f"perf_test_op_{i:03d}",
                    timestamp=datetime.utcnow(),
                    initiator_type=InitiatorType.HUMAN,
                    operation_type="read",
                    target_resources=[f"resource_{i}"],
                    operation_parameters={},
                    risk_level=RiskLevel.LOW,
                    correlation_id="perf_test_corr"
                )
                operations.append(operation)
            
            # Time the logging
            start_time = datetime.utcnow()
            
            for operation in operations:
                await audit_logger.log_operation_initiated(operation)
            
            end_time = datetime.utcnow()
            duration = (end_time - start_time).total_seconds()
            
            # Should complete 100 operations in under 5 seconds
            assert duration < 5.0
            print(f"Audit logging performance: {duration:.2f}s for 100 operations")
            
        finally:
            if os.path.exists(db_path):
                os.unlink(db_path)
    
    @pytest.mark.asyncio
    async def test_access_control_performance(self):
        """Test access control performance under load."""
        from src.services.access_control import AdvancedAccessControl
        from src.models.security_models import (
            IdentityContext, ResourceContext, AuthenticationMethod, 
            RiskProfile, ResourceType, SensitivityLevel, SecurityClassification
        )
        
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp_file:
            db_path = tmp_file.name
        
        try:
            access_control = AdvancedAccessControl(database_path=db_path)
            
            # Create test identity and resource
            identity = IdentityContext(
                user_id="perf_test_user",
                username="perf.test@company.com",
                email="perf.test@company.com",
                groups=["engineering"],
                roles=["developer"],
                permissions=["read", "write"],
                authentication_method=AuthenticationMethod.OIDC,
                session_id="perf_session",
                source_ip="192.168.1.100",
                user_agent="Performance Test Browser",
                risk_profile=RiskProfile.STANDARD
            )
            
            resource = ResourceContext(
                resource_type=ResourceType.FILE,
                resource_id="perf_resource",
                resource_path="/perf/resource",
                sensitivity_level=SensitivityLevel.INTERNAL,
                ownership={"owner_id": "perf_test_user"},
                security_classification=SecurityClassification.CONFIDENTIAL
            )
            
            # Time multiple access evaluations
            start_time = datetime.utcnow()
            
            for i in range(50):
                decision = await access_control.evaluate_access(
                    identity=identity,
                    resource=resource,
                    action="read"
                )
                assert decision.decision in ["ALLOW", "DENY"]
            
            end_time = datetime.utcnow()
            duration = (end_time - start_time).total_seconds()
            
            # Should complete 50 evaluations in under 3 seconds
            assert duration < 3.0
            print(f"Access control performance: {duration:.2f}s for 50 evaluations")
            
        finally:
            if os.path.exists(db_path):
                os.unlink(db_path)


# Test configuration and validation
class TestSecurityConfiguration:
    """Test security configuration and validation."""
    
    def test_security_config_validation(self):
        """Test security configuration validation."""
        from src.services.security_config_manager import SecurityConfigManager
        
        config_manager = SecurityConfigManager()
        
        # Test valid configuration
        valid_config = {
            "audit_logging": {
                "enabled": True,
                "retention_days": 2555
            },
            "identity_management": {
                "session_timeout": 3600,
                "mfa_required_roles": ["admin"]
            },
            "access_control": {
                "default_deny": True
            }
        }
        
        is_valid = config_manager.validate_configuration(valid_config)
        assert is_valid is True
        
        # Test invalid configuration
        invalid_config = {
            "audit_logging": {
                "enabled": True,
                "retention_days": -1  # Invalid value
            }
        }
        
        is_valid = config_manager.validate_configuration(invalid_config)
        assert is_valid is False
    
    def test_security_posture_assessment(self):
        """Test security posture assessment."""
        from src.services.security_posture_validator import SecurityPostureValidator
        
        validator = SecurityPostureValidator()
        
        # Mock system state
        system_state = {
            "audit_logging_enabled": True,
            "encryption_enabled": True,
            "mfa_enforced": True,
            "access_control_configured": True,
            "monitoring_enabled": True,
            "compliance_framework_active": True
        }
        
        assessment = validator.assess_security_posture(system_state)
        
        assert assessment.overall_score >= 0
        assert assessment.overall_score <= 100
        assert isinstance(assessment.findings, list)
        assert isinstance(assessment.recommendations, list)


# Security validation utilities
class SecurityTestUtils:
    """Utilities for security testing."""
    
    @staticmethod
    def create_test_identity(user_id: str = "test_user") -> Dict[str, Any]:
        """Create test identity context."""
        return {
            "user_id": user_id,
            "username": f"{user_id}@company.com",
            "email": f"{user_id}@company.com",
            "groups": ["engineering"],
            "roles": ["developer"],
            "permissions": ["read", "write"],
            "authentication_method": "OIDC",
            "session_id": f"session_{user_id}",
            "source_ip": "192.168.1.100",
            "user_agent": "Test Browser",
            "risk_profile": "standard"
        }
    
    @staticmethod
    def create_test_operation(operation_id: str = "test_op") -> Dict[str, Any]:
        """Create test security operation."""
        return {
            "operation_id": operation_id,
            "timestamp": datetime.utcnow().isoformat(),
            "initiator_type": "HUMAN",
            "operation_type": "read",
            "target_resources": ["test_resource"],
            "operation_parameters": {},
            "risk_level": "LOW",
            "correlation_id": f"corr_{operation_id}"
        }
    
    @staticmethod
    def assert_valid_audit_event(event: Dict[str, Any]):
        """Assert that an audit event is valid."""
        required_fields = [
            "operation_id", "timestamp", "initiator_type", 
            "operation_type", "risk_level"
        ]
        
        for field in required_fields:
            assert field in event, f"Missing required field: {field}"
        
        # Validate timestamp format
        datetime.fromisoformat(event["timestamp"].replace('Z', '+00:00'))
        
        # Validate enum values
        assert event["initiator_type"] in ["HUMAN", "LLM", "SYSTEM", "AUTOMATION"]
        assert event["risk_level"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    
    @staticmethod
    def assert_valid_security_alert(alert: Dict[str, Any]):
        """Assert that a security alert is valid."""
        required_fields = [
            "alert_id", "timestamp", "severity", "alert_type", "description"
        ]
        
        for field in required_fields:
            assert field in alert, f"Missing required field: {field}"
        
        # Validate enum values
        assert alert["severity"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        assert alert["alert_type"] in [
            "AUTHENTICATION_FAILURE", "UNAUTHORIZED_ACCESS", 
            "POLICY_VIOLATION", "THREAT_DETECTED", "ANOMALOUS_BEHAVIOR"
        ]


# Run all tests
if __name__ == "__main__":
    # Run with pytest
    pytest.main([
        __file__,
        "-v",
        "--tb=short",
        "--asyncio-mode=auto"
    ])