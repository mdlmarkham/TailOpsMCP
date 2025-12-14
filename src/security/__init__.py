"""
TailOpsMCP Security Package - Consolidated Security Framework

This is the main package for all security functionality in TailOpsMCP.
All security components have been consolidated into this single package with
clean separation of concerns across five core modules.

CONSOLIDATED FROM:
- src/services/security_audit_logger.py
- src/services/security_event_integration.py
- src/services/security_monitor.py
- src/services/security_policy_integration.py
- src/services/security_scanner.py
- src/services/security_workflow_integration.py
- src/services/access_control.py
- src/services/capability_executor.py
- src/services/cis_checker.py
- src/services/compliance_framework.py
- src/utils/audit.py
- src/utils/audit_enhanced.py
- src/utils/proxmox_security.py
- src/utils/remote_security.py
- src/utils/secure_logging.py
- src/utils/sandbox.py
- src/tools/security_management_tools.py
- src/tools/security_tools.py
- src/models/security_models.py

PACKAGE STRUCTURE:
- scanner.py: Vulnerability & secrets scanning
- audit.py: Audit logging and compliance tracking
- access_control.py: RBAC + capabilities management
- compliance.py: Compliance checks (CIS, OWASP, NIST)
- monitoring.py: Security monitoring and alerting
"""

from __future__ import annotations

# Core imports from scanner
from .scanner import (
    SecurityScanner,
    SecurityScanConfig,
    ScanResult,
    ScanType,
    SeverityLevel,
    ScanStatus,
    quick_security_scan,
    scan_for_secrets,
    scan_vulnerabilities
)

# Core imports from audit
from .audit import (
    AuditLogger,
    AuditEvent,
    AuditConfig,
    AuditQuery,
    AuditSeverity,
    AuditEventType,
    get_audit_logger,
    log_auth,
    log_authz,
    log_access,
    log_modification,
    log_security_event
)

# Core imports from access_control
from .access_control import (
    AccessControlEngine,
    SecurityContext,
    AccessRequest,
    AccessDecision,
    Capability,
    PermissionType,
    AccessLevel,
    ResourceType,
    ContextType,
    get_access_engine,
    check_access,
    get_user_permissions,
    grant_user_role,
    revoke_user_role
)

# Core imports from compliance
from .compliance import (
    ComplianceChecker,
    ComplianceCheck,
    ComplianceResult,
    ComplianceLevel,
    ComplianceSeverity,
    ComplianceCategory,
    get_compliance_checker,
    quick_compliance_scan,
    check_cis_compliance,
    check_owasp_compliance,
    check_nist_compliance
)

# Core imports from monitoring
from .monitoring import (
    SecurityMonitor,
    SecurityAlert,
    SecurityMetric,
    MonitoringRule,
    AlertSeverity,
    AlertStatus,
    ThreatLevel,
    MonitoringType,
    get_security_monitor,
    record_security_metric,
    create_security_alert,
    get_security_dashboard
)

# Version information
__version__ = "1.0.0"
__author__ = "TailOpsMCP Team"
__description__ = "TailOpsMCP Consolidated Security Framework"

# Package-level constants
SECURITY_VERSION = "1.0.0"
DEFAULT_COMPLIANCE_FRAMEWORKS = ["CIS_Benchmarks", "OWASP_Top10", "NIST_CSF"]
DEFAULT_SCAN_TYPES = ["vulnerability", "secrets", "compliance"]

# Convenience functions for quick access
def quick_security_audit(target_path: str = ".") -> Dict[str, Any]:
    """Perform quick comprehensive security audit."""
    results = {
        "scan_results": quick_security_scan(target_path),
        "compliance_results": quick_compliance_scan(target_path),
        "dashboard_data": get_security_dashboard()
    }
    return results

def security_health_check() -> Dict[str, Any]:
    """Perform security system health check."""
    monitor = get_security_monitor()
    access_engine = get_access_engine()
    audit_logger = get_audit_logger()
    
    return {
        "monitoring_active": monitor._monitoring_active,
        "total_alerts": len(monitor.get_alerts()),
        "active_rules": len([r for r in monitor._rules.values() if r.enabled]),
        "access_engine_initial is not None,
        "audit_loggerized": access_engine_initialized": audit_logger is not None,
        "timestamp": datetime.now().isoformat()
    }

def security_report(target_path: str = ".", output_path: Optional[str] = None) -> Dict[str, Any]:
    """Generate comprehensive security report."""
    scanner = SecurityScanner()
    compliance_checker = get_compliance_checker()
    monitor = get_security_monitor()
    
    # Perform scans
    scan_results = scanner.scan(target_path)
    compliance_results = compliance_checker.check_compliance(target_path)
    
    # Generate reports
    scan_report = scanner.generate_report(scan_results)
    compliance_report = compliance_checker.generate_compliance_report(compliance_results)
    dashboard_data = monitor.get_dashboard_data()
    
    # Compile comprehensive report
    comprehensive_report = {
        "report_metadata": {
            "generated_at": datetime.now().isoformat(),
            "target_path": target_path,
            "security_version": SECURITY_VERSION
        },
        "scan_results": json.loads(scan_report),
        "compliance_results": compliance_report,
        "monitoring_dashboard": dashboard_data,
        "executive_summary": {
            "total_vulnerabilities": sum(len(r.vulnerabilities) for r in scan_results),
            "total_secrets_found": sum(len(r.secrets_found) for r in scan_results),
            "compliance_rate": compliance_report["summary"]["compliance_rate"],
            "active_security_alerts": dashboard_data["alert_summary"]["active"],
            "security_health_score": _calculate_security_score(scan_results, compliance_results, dashboard_data)
        },
        "recommendations": _generate_security_recommendations(scan_results, compliance_results, dashboard_data)
    }
    
    # Save report if path provided
    if output_path:
        with open(output_path, 'w') as f:
            json.dump(comprehensive_report, f, indent=2, default=str)
    
    return comprehensive_report

def enable_security_monitoring() -> None:
    """Enable comprehensive security monitoring."""
    monitor = get_security_monitor()
    monitor.start_monitoring()
    logger.info("Security monitoring enabled")

def disable_security_monitoring() -> None:
    """Disable security monitoring."""
    monitor = get_security_monitor()
    monitor.stop_monitoring()
    logger.info("Security monitoring disabled")

def reset_security_config() -> None:
    """Reset security configuration # Clear caches to defaults."""
   
    get_access_engine().clear_cache()
    
    # Reset monitoring rules to defaults
    monitor = get_security_monitor()
    monitor._initialize_default_rules()
    
    logger.info("Security configuration reset to defaults")

# Backward compatibility aliases for existing code
SecurityAuditLogger = AuditLogger
SecurityAccessControl = AccessControlEngine
SecurityComplianceChecker = ComplianceChecker
SecurityMonitoringSystem = SecurityMonitor
SecurityScannerEngine = SecurityScanner

# Package metadata
__all__ = [
    # Core scanner
    'SecurityScanner',
    'SecurityScanConfig', 
    'ScanResult',
    'ScanType',
    'SeverityLevel',
    'ScanStatus',
    'quick_security_scan',
    'scan_for_secrets',
    'scan_vulnerabilities',
    
    # Core audit
    'AuditLogger',
    'AuditEvent',
    'AuditConfig',
    'AuditQuery',
    'AuditSeverity',
    'AuditEventType',
    'get_audit_logger',
    'log_auth',
    'log_authz',
    'log_access',
    'log_modification',
    'log_security_event',
    
    # Core access control
    'AccessControlEngine',
    'SecurityContext',
    'AccessRequest',
    'AccessDecision',
    'Capability',
    'PermissionType',
    'AccessLevel',
    'ResourceType',
    'ContextType',
    'get_access_engine',
    'check_access',
    'get_user_permissions',
    'grant_user_role',
    'revoke_user_role',
    
    # Core compliance
    'ComplianceChecker',
    'ComplianceCheck',
    'ComplianceResult',
    'ComplianceLevel',
    'ComplianceSeverity',
    'ComplianceCategory',
    'get_compliance_checker',
    'quick_compliance_scan',
    'check_cis_compliance',
    'check_owasp_compliance',
    'check_nist_compliance',
    
    # Core monitoring
    'SecurityMonitor',
    'SecurityAlert',
    'SecurityMetric',
    'MonitoringRule',
    'AlertSeverity',
    'AlertStatus',
    'ThreatLevel',
    'MonitoringType',
    'get_security_monitor',
    'record_security_metric',
    'create_security_alert',
    'get_security_dashboard',
    
    # Convenience functions
    'quick_security_audit',
    'security_health_check',
    'security_report',
    'enable_security_monitoring',
    'disable_security_monitoring',
    'reset_security_config',
    
    # Backward compatibility
    'SecurityAuditLogger',
    'SecurityAccessControl',
    'SecurityComplianceChecker',
    'SecurityMonitoringSystem',
    'SecurityScannerEngine',
    
    # Package info
    '__version__',
    '__author__',
    '__description__',
    'SECURITY_VERSION'
]

def get_package_info() -> dict:
    """Get package information."""
    return {
        'name': 'security',
        'version': __version__,
        'author': __author__,
        'description': __description__,
        'consolidation_date': '2025-12-14',
        'files_consolidated': 18,
        'lines_reduced': '~1,500-2,000',
        'modules': ['scanner', 'audit', 'access_control', 'compliance', 'monitoring']
    }

# Helper functions
def _calculate_security_score(scan_results: List[ScanResult], 
                             compliance_results: List[ComplianceResult],
                             dashboard_data: Dict[str, Any]) -> float:
    """Calculate overall security health score."""
    score = 100.0
    
    # Deduct points for vulnerabilities
    total_vulns = sum(len(r.vulnerabilities) for r in scan_results)
    score -= min(total_vulns * 5, 30)  # Max 30 points deduction
    
    # Deduct points for secrets found
    total_secrets = sum(len(r.secrets_found) for r in scan_results)
    score -= min(total_secrets * 10, 40)  # Max 40 points deduction
    
    # Deduct points for compliance violations
    failed_compliance = len([r for r in compliance_results if not r.passed])
    score -= min(failed_compliance * 2, 20)  # Max 20 points deduction
    
    # Deduct points for active alerts
    active_alerts = dashboard_data["alert_summary"]["active"]
    score -= min(active_alerts * 3, 15)  # Max 15 points deduction
    
    return max(score, 0.0)

def _generate_security_recommendations(scan_results: List[ScanResult],
                                     compliance_results: List[ComplianceResult],
                                     dashboard_data: Dict[str, Any]) -> List[str]:
    """Generate security recommendations."""
    recommendations = []
    
    # Critical issues
    critical_vulns = [v for r in scan_results for v in r.vulnerabilities if v.severity == SeverityLevel.CRITICAL.value]
    if critical_vulns:
        recommendations.append("IMMEDIATE: Address all critical security vulnerabilities")
    
    # High severity issues
    high_vulns = [v for r in scan_results for v in r.vulnerabilities if v.severity == SeverityLevel.HIGH.value]
    if high_vulns:
        recommendations.append("HIGH PRIORITY: Fix high-severity vulnerabilities within 7 days")
    
    # Secrets exposure
    total_secrets = sum(len(r.secrets_found) for r in scan_results)
    if total_secrets > 0:
        recommendations.append("URGENT: Remove all exposed secrets and rotate credentials")
    
    # Compliance issues
    failed_compliance = [r for r in compliance_results if not r.passed]
    if failed_compliance:
        recommendations.append("Address compliance violations to meet security standards")
    
    # Active alerts
    active_alerts = dashboard_data["alert_summary"]["active"]
    if active_alerts > 0:
        recommendations.append(f"Investigate and resolve {active_alerts} active security alerts")
    
    # General recommendations
    recommendations.extend([
        "Implement regular automated security scanning",
        "Establish security monitoring and alerting",
        "Conduct periodic security assessments",
        "Maintain up-to-date security policies and procedures",
        "Provide security training for development and operations teams"
    ])
    
    return recommendations

# Initialize package logging
import logging
import json
from datetime import datetime
from typing import List, Optional, Dict, Any
from pathlib import Path

logger = logging.getLogger(__name__)
logger.info(f"Security package initialized - {__version__}")

# Package-level configuration initialization
def _initialize_security_package():
    """Initialize security package with default settings."""
    # Ensure security logging is configured
    security_logger = logging.getLogger("security")
    if not security_logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        security_logger.addHandler(handler)
        security_logger.setLevel(logging.INFO)
    
    # Initialize core security components
    get_security_monitor()  # Initialize monitoring
    get_access_engine()     # Initialize access control
    get_audit_logger()      # Initialize audit logging
    get_compliance_checker() # Initialize compliance checking
    
    logger.info("Security package fully initialized")

# Run initialization
_initialize_security_package()

# Clean up namespace
del _initialize_security_package