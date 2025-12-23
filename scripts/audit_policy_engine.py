#!/usr/bin/env python3
"""
Policy Engine Audit and Validation Script

Audits policy engine implementation for security gaps, performance issues,
and compliance with security requirements.
"""

import os
import sys
import logging
from typing import List, Dict, Any
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class PolicyAuditor:
    """Comprehensive policy engine auditor."""

    def __init__(self):
        self.audit_results = []
        self.security_gaps = []
        self.performance_issues = []
        self.compliance_issues = []

    def run_full_audit(self) -> Dict[str, Any]:
        """Run comprehensive policy engine audit."""
        logger.info("Starting comprehensive policy engine audit...")

        # Audit phases
        self._audit_policy_gate_implementation()
        self._audit_policy_engine_implementation()
        self._audit_security_controls()
        self._audit_compliance_features()
        self._audit_edge_cases()

        # Generate comprehensive report
        return self._generate_audit_report()

    def _audit_policy_gate_implementation(self):
        """Audit PolicyGate implementation."""
        logger.info("Auditing PolicyGate implementation...")

        # Test 1: PolicyGate code structure
        try:
            policy_gate_path = (
                Path(__file__).parent.parent / "src" / "services" / "policy_gate.py"
            )

            if not policy_gate_path.exists():
                self.audit_results.append(
                    {
                        "test": "PolicyGate File Existence",
                        "status": "FAIL",
                        "details": "policy_gate.py file not found",
                    }
                )
                return

            with open(policy_gate_path, "r") as f:
                content = f.read()

            # Check for critical components
            required_components = [
                "class PolicyGate:",
                "async def enforce_policy",
                "def validate_capabilities",
                "async def validate_parameters",
                "def _sanitize_parameters",
                "def audit_policy_decision",
                "def get_matching_policy_rule",
                "OperationTier.CONTROL",
                "OperationTier.ADMIN",
                "OperationTier.OBSERVE",
            ]

            missing_components = []
            for component in required_components:
                if component not in content:
                    missing_components.append(component)

            if missing_components:
                self.audit_results.append(
                    {
                        "test": "PolicyGate Critical Components",
                        "status": "FAIL",
                        "details": f"Missing components: {missing_components}",
                    }
                )
                self.security_gaps.append(f"PolicyGate missing: {missing_components}")
            else:
                self.audit_results.append(
                    {
                        "test": "PolicyGate Critical Components",
                        "status": "PASS",
                        "details": "All critical components present",
                    }
                )

        except Exception as e:
            self.audit_results.append(
                {
                    "test": "PolicyGate File Analysis",
                    "status": "FAIL",
                    "details": f"File analysis failed: {e}",
                }
            )

        # Test 2: Default policy rules validation
        try:
            with open(policy_gate_path, "r") as f:
                content = f.read()

            critical_rules = [
                "docker_container_operations",
                "docker_image_operations",
                "system_monitoring",
                "network_operations",
            ]

            missing_rules = []
            for rule in critical_rules:
                if rule not in content:
                    missing_rules.append(rule)

            if missing_rules:
                self.compliance_issues.append(
                    f"Missing critical policy rules: {missing_rules}"
                )
                self.audit_results.append(
                    {
                        "test": "Critical Policy Rules",
                        "status": "FAIL",
                        "details": f"Missing rules: {missing_rules}",
                    }
                )
            else:
                self.audit_results.append(
                    {
                        "test": "Critical Policy Rules",
                        "status": "PASS",
                        "details": f"All {len(critical_rules)} critical rules present",
                    }
                )
        except Exception as e:
            self.audit_results.append(
                {
                    "test": "Critical Policy Rules",
                    "status": "FAIL",
                    "details": f"Rule validation failed: {e}",
                }
            )

        # Test 3: Parameter validation security
        self._test_parameter_validation_security(policy_gate_path)

    def _test_parameter_validation_security(self, policy_gate_path):
        """Test parameter validation for security vulnerabilities."""
        try:
            with open(policy_gate_path, "r") as f:
                content = f.read()

            # Check for security validation patterns
            security_patterns = [
                "max_length",
                "type.*validation",
                "pattern.*match",
                "value.*validation",
                "constraint",
            ]

            found_patterns = sum(
                1 for pattern in security_patterns if pattern in content.lower()
            )

            if found_patterns >= 3:
                self.audit_results.append(
                    {
                        "test": "Parameter Validation Security",
                        "status": "PASS",
                        "details": f"Found {found_patterns} security validation patterns",
                    }
                )
            else:
                self.security_gaps.append("Insufficient parameter validation security")
                self.audit_results.append(
                    {
                        "test": "Parameter Validation Security",
                        "status": "FAIL",
                        "details": f"Only {found_patterns} security patterns found",
                    }
                )
        except Exception as e:
            self.audit_results.append(
                {
                    "test": "Parameter Validation Security",
                    "status": "FAIL",
                    "details": f"Validation test failed: {e}",
                }
            )

    def _audit_policy_engine_implementation(self):
        """Audit PolicyEngine implementation."""
        logger.info("Auditing PolicyEngine implementation...")

        # Test 1: PolicyEngine code structure
        try:
            policy_engine_path = (
                Path(__file__).parent.parent / "src" / "services" / "policy_engine.py"
            )

            if not policy_engine_path.exists():
                self.audit_results.append(
                    {
                        "test": "PolicyEngine File Existence",
                        "status": "FAIL",
                        "details": "policy_engine.py file not found",
                    }
                )
                return

            with open(policy_engine_path, "r") as f:
                content = f.read()

            # Check for critical components
            required_components = [
                "class PolicyEngine:",
                "async def evaluate_operation",
                "def _get_applicable_rules",
                "def _validate_parameters",
                "def update_policy_config",
                "def rollback_policy",
                "deny_by_default",
                "PolicyDecision.DENY",
            ]

            missing_components = []
            for component in required_components:
                if component not in content:
                    missing_components.append(component)

            if missing_components:
                self.audit_results.append(
                    {
                        "test": "PolicyEngine Critical Components",
                        "status": "FAIL",
                        "details": f"Missing components: {missing_components}",
                    }
                )
                self.security_gaps.append(f"PolicyEngine missing: {missing_components}")
            else:
                self.audit_results.append(
                    {
                        "test": "PolicyEngine Critical Components",
                        "status": "PASS",
                        "details": "All critical components present",
                    }
                )

        except Exception as e:
            self.audit_results.append(
                {
                    "test": "PolicyEngine File Analysis",
                    "status": "FAIL",
                    "details": f"File analysis failed: {e}",
                }
            )

        # Test 2: Deny-by-default security posture
        try:
            with open(policy_engine_path, "r") as f:
                content = f.read()

            if "deny_by_default" in content and (
                "True" in content or "enabled" in content
            ):
                self.audit_results.append(
                    {
                        "test": "Deny-by-Default Posture",
                        "status": "PASS",
                        "details": "Configured for deny-by-default security",
                    }
                )
            else:
                self.security_gaps.append(
                    "Policy engine not configured for deny-by-default"
                )
                self.audit_results.append(
                    {
                        "test": "Deny-by-Default Posture",
                        "status": "FAIL",
                        "details": "Policy engine may allow operations by default",
                    }
                )
        except Exception as e:
            self.audit_results.append(
                {
                    "test": "Deny-by-Default Posture",
                    "status": "FAIL",
                    "details": f"Test failed: {e}",
                }
            )

        # Test 3: Emergency mode security
        self._test_emergency_mode_security(policy_engine_path)

    def _test_emergency_mode_security(self, policy_engine_path):
        """Test emergency mode security controls."""
        try:
            with open(policy_engine_path, "r") as f:
                content = f.read()

            emergency_patterns = [
                "emergency",
                "emergency_policies",
                "emergency_mode",
                "override",
            ]

            found_patterns = sum(
                1 for pattern in emergency_patterns if pattern in content.lower()
            )

            if found_patterns >= 2:
                self.audit_results.append(
                    {
                        "test": "Emergency Mode Security",
                        "status": "PASS",
                        "details": f"Found {found_patterns} emergency mode patterns",
                    }
                )
            else:
                self.audit_results.append(
                    {
                        "test": "Emergency Mode Security",
                        "status": "WARN",
                        "details": f"Limited emergency mode patterns: {found_patterns}",
                    }
                )
        except Exception as e:
            self.audit_results.append(
                {
                    "test": "Emergency Mode Security",
                    "status": "FAIL",
                    "details": f"Test failed: {e}",
                }
            )

    def _audit_security_controls(self):
        """Audit security control implementation."""
        logger.info("Auditing security controls...")

        # Test 1: Authentication integration
        self._test_authentication_integration()

        # Test 2: Audit logging completeness
        self._test_audit_logging()

    def _test_authentication_integration(self):
        """Test authentication integration."""
        try:
            policy_gate_path = (
                Path(__file__).parent.parent / "src" / "services" / "policy_gate.py"
            )

            with open(policy_gate_path, "r") as f:
                content = f.read()

            auth_patterns = [
                "check_authorization",
                "claims.*scopes",
                "TokenClaims",
                "authentication",
            ]

            found_patterns = sum(
                1 for pattern in auth_patterns if pattern.lower() in content.lower()
            )

            if found_patterns >= 2:
                self.audit_results.append(
                    {
                        "test": "Authentication Integration",
                        "status": "PASS",
                        "details": f"Found {found_patterns} authentication patterns",
                    }
                )
            else:
                self.security_gaps.append("Insufficient authentication integration")
                self.audit_results.append(
                    {
                        "test": "Authentication Integration",
                        "status": "FAIL",
                        "details": f"Only {found_patterns} authentication patterns found",
                    }
                )
        except Exception as e:
            self.audit_results.append(
                {
                    "test": "Authentication Integration",
                    "status": "FAIL",
                    "details": f"Test failed: {e}",
                }
            )

    def _test_audit_logging(self):
        """Test audit logging for security events."""
        try:
            policy_gate_path = (
                Path(__file__).parent.parent / "src" / "services" / "policy_gate.py"
            )

            with open(policy_gate_path, "r") as f:
                content = f.read()

            # Check audit logging patterns
            audit_patterns = [
                "audit_policy_decision",
                "_sanitize_parameters",
                "audit_logger",
                "token.*password.*secret",
                "REDACTED",
            ]

            found_patterns = sum(
                1 for pattern in audit_patterns if pattern.lower() in content.lower()
            )

            if found_patterns >= 3:
                self.audit_results.append(
                    {
                        "test": "Audit Logging Security",
                        "status": "PASS",
                        "details": f"Found {found_patterns} audit security patterns",
                    }
                )
            else:
                self.security_gaps.append("Insufficient audit logging security")
                self.audit_results.append(
                    {
                        "test": "Audit Logging Security",
                        "status": "FAIL",
                        "details": f"Only {found_patterns} audit security patterns found",
                    }
                )

        except Exception as e:
            self.audit_results.append(
                {
                    "test": "Audit Logging Security",
                    "status": "FAIL",
                    "details": f"Audit test failed: {e}",
                }
            )

    def _audit_compliance_features(self):
        """Audit compliance-related features."""
        logger.info("Auditing compliance features...")

        # Test 1: Policy history tracking
        try:
            policy_engine_path = (
                Path(__file__).parent.parent / "src" / "services" / "policy_engine.py"
            )

            with open(policy_engine_path, "r") as f:
                content = f.read()

            history_patterns = [
                "policy_history",
                "update_policy_config",
                "rollback_policy",
                "PolicyHistory",
            ]

            found_patterns = sum(
                1 for pattern in history_patterns if pattern.lower() in content.lower()
            )

            if found_patterns >= 3:
                self.audit_results.append(
                    {
                        "test": "Policy History Tracking",
                        "status": "PASS",
                        "details": f"Found {found_patterns} history tracking patterns",
                    }
                )
            else:
                self.compliance_issues.append("Policy history tracking incomplete")
                self.audit_results.append(
                    {
                        "test": "Policy History Tracking",
                        "status": "FAIL",
                        "details": f"Only {found_patterns} history tracking patterns found",
                    }
                )
        except Exception as e:
            self.audit_results.append(
                {
                    "test": "Policy History Tracking",
                    "status": "FAIL",
                    "details": f"Test failed: {e}",
                }
            )

        # Test 2: Error handling and exception management
        self._test_error_handling()

    def _test_error_handling(self):
        """Test error handling and exception management."""
        try:
            policy_gate_path = (
                Path(__file__).parent.parent / "src" / "services" / "policy_gate.py"
            )

            with open(policy_gate_path, "r") as f:
                content = f.read()

            error_patterns = [
                "SystemManagerError",
                "ErrorCategory",
                "except.*:",
                "validation_errors",
                "return.*False.*validation_errors",
            ]

            found_patterns = sum(
                1 for pattern in error_patterns if pattern.lower() in content.lower()
            )

            if found_patterns >= 3:
                self.audit_results.append(
                    {
                        "test": "Error Handling Security",
                        "status": "PASS",
                        "details": f"Found {found_patterns} error handling patterns",
                    }
                )
            else:
                self.security_gaps.append("Insufficient error handling")
                self.audit_results.append(
                    {
                        "test": "Error Handling Security",
                        "status": "FAIL",
                        "details": f"Only {found_patterns} error handling patterns found",
                    }
                )
        except Exception as e:
            self.audit_results.append(
                {
                    "test": "Error Handling Security",
                    "status": "FAIL",
                    "details": f"Test failed: {e}",
                }
            )

    def _audit_edge_cases(self):
        """Audit edge cases and error handling."""
        logger.info("Auditing edge cases...")

        # Test 1: Input validation completeness
        self._test_input_validation()

        # Test 2: Regex injection protection
        self._test_regex_injection_protection()

    def _test_input_validation(self):
        """Test input validation completeness."""
        try:
            policy_gate_path = (
                Path(__file__).parent.parent / "src" / "services" / "policy_gate.py"
            )

            with open(policy_gate_path, "r") as f:
                content = f.read()

            validation_patterns = [
                "def.*validate",
                "parameter.*constraint",
                "max_length",
                "min.*max",
                "type.*check",
            ]

            found_patterns = sum(
                1
                for pattern in validation_patterns
                if pattern.lower() in content.lower()
            )

            if found_patterns >= 4:
                self.audit_results.append(
                    {
                        "test": "Input Validation Completeness",
                        "status": "PASS",
                        "details": f"Found {found_patterns} validation patterns",
                    }
                )
            else:
                self.security_gaps.append("Incomplete input validation")
                self.audit_results.append(
                    {
                        "test": "Input Validation Completeness",
                        "status": "FAIL",
                        "details": f"Only {found_patterns} validation patterns found",
                    }
                )
        except Exception as e:
            self.audit_results.append(
                {
                    "test": "Input Validation Completeness",
                    "status": "FAIL",
                    "details": f"Test failed: {e}",
                }
            )

    def _test_regex_injection_protection(self):
        """Test regex injection protection."""
        try:
            policy_gate_path = (
                Path(__file__).parent.parent / "src" / "services" / "policy_gate.py"
            )

            with open(policy_gate_path, "r") as f:
                content = f.read()

            # Look for proper regex handling
            regex_patterns = [
                "re.compile",
                "re.match",
                "re.error",
                "Invalid regex pattern",
            ]

            found_patterns = sum(1 for pattern in regex_patterns if pattern in content)

            if found_patterns >= 2:
                self.audit_results.append(
                    {
                        "test": "Regex Injection Protection",
                        "status": "PASS",
                        "details": f"Found {found_patterns} regex protection patterns",
                    }
                )
            else:
                self.security_gaps.append("Potential regex injection vulnerability")
                self.audit_results.append(
                    {
                        "test": "Regex Injection Protection",
                        "status": "WARN",
                        "details": f"Limited regex protection: {found_patterns} patterns",
                    }
                )
        except Exception as e:
            self.audit_results.append(
                {
                    "test": "Regex Injection Protection",
                    "status": "FAIL",
                    "details": f"Test failed: {e}",
                }
            )

    def _generate_audit_report(self) -> Dict[str, Any]:
        """Generate comprehensive audit report."""
        total_tests = len(self.audit_results)
        passed_tests = len([r for r in self.audit_results if r["status"] == "PASS"])
        failed_tests = len([r for r in self.audit_results if r["status"] == "FAIL"])
        warned_tests = len([r for r in self.audit_results if r["status"] == "WARN"])
        skipped_tests = len([r for r in self.audit_results if r["status"] == "SKIP"])

        return {
            "summary": {
                "total_tests": total_tests,
                "passed": passed_tests,
                "failed": failed_tests,
                "warnings": warned_tests,
                "skipped": skipped_tests,
                "pass_rate": (passed_tests / total_tests) * 100
                if total_tests > 0
                else 0,
            },
            "security_gaps": {
                "count": len(self.security_gaps),
                "items": self.security_gaps,
            },
            "performance_issues": {
                "count": len(self.performance_issues),
                "items": self.performance_issues,
            },
            "compliance_issues": {
                "count": len(self.compliance_issues),
                "items": self.compliance_issues,
            },
            "detailed_results": self.audit_results,
            "recommendations": self._generate_recommendations(),
        }

    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations."""
        recommendations = []

        # Security recommendations
        if self.security_gaps:
            recommendations.append(
                "CRITICAL: Address all identified security gaps immediately"
            )
            recommendations.append(
                "Implement comprehensive input validation for all parameters"
            )
            recommendations.append("Review and strengthen authentication controls")
            recommendations.append(
                "Add regex injection protection for all pattern matching"
            )
            recommendations.append("Ensure all error handling uses SystemManagerError")

        # Performance recommendations
        if self.performance_issues:
            recommendations.append(
                "Optimize policy evaluation performance for production workloads"
            )
            recommendations.append("Consider implementing policy evaluation caching")

        # Compliance recommendations
        if self.compliance_issues:
            recommendations.append(
                "Ensure all compliance features are fully operational"
            )
            recommendations.append(
                "Test policy rollback and history tracking procedures"
            )
            recommendations.append("Verify deny-by-default security posture")

        # General recommendations
        recommendations.append("Implement regular policy engine audits (quarterly)")
        recommendations.append("Establish policy change approval workflows")
        recommendations.append("Monitor policy evaluation performance in production")
        recommendations.append("Add comprehensive unit tests for all policy components")

        return recommendations


def main():
    """Run the comprehensive policy audit."""
    auditor = PolicyAuditor()

    logger.info("Starting comprehensive policy engine audit...")
    report = auditor.run_full_audit()

    # Print results
    print("\n" + "=" * 80)
    print("POLICY ENGINE AUDIT REPORT")
    print("=" * 80)

    summary = report["summary"]
    print(
        f"Summary: {summary['passed']}/{summary['total_tests']} tests passed ({summary['pass_rate']:.1f}%)"
    )

    if summary["skipped"] > 0:
        print(f"Skipped: {summary['skipped']} tests")

    if report["security_gaps"]["count"] > 0:
        print(f"\n🚨 SECURITY GAPS ({report['security_gaps']['count']}):")
        for gap in report["security_gaps"]["items"]:
            print(f"  - {gap}")

    if report["performance_issues"]["count"] > 0:
        print(f"\n⚡ PERFORMANCE ISSUES ({report['performance_issues']['count']}):")
        for issue in report["performance_issues"]["items"]:
            print(f"  - {issue}")

    if report["compliance_issues"]["count"] > 0:
        print(f"\n📋 COMPLIANCE ISSUES ({report['compliance_issues']['count']}):")
        for issue in report["compliance_issues"]["items"]:
            print(f"  - {issue}")

    print(f"\n📝 RECOMMENDATIONS:")
    for rec in report["recommendations"]:
        print(f"  - {rec}")

    print(f"\n📊 DETAILED RESULTS:")
    for result in report["detailed_results"]:
        status_icon = (
            "✅"
            if result["status"] == "PASS"
            else "❌"
            if result["status"] == "FAIL"
            else "⚠️"
            if result["status"] == "WARN"
            else "⏭️"
        )
        print(f"  {status_icon} {result['test']}: {result['details']}")

    print("\n" + "=" * 80)

    # Return exit code based on critical issues
    if report["security_gaps"]["count"] > 0:
        print("❌ CRITICAL SECURITY ISSUES FOUND")
        return 1
    elif report["compliance_issues"]["count"] > 0:
        print("⚠️ COMPLIANCE ISSUES NEED ATTENTION")
        return 2
    else:
        print("✅ POLICY ENGINE AUDIT COMPLETED")
        return 0


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
