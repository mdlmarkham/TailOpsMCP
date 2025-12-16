"""
Security Compliance Module - Consolidated Compliance Framework

This module provides comprehensive compliance checking including:
- CIS (Center for Internet Security) benchmarks
- NIST Cybersecurity Framework compliance
- OWASP Top 10 security guidelines
- Custom compliance policies and frameworks
- Compliance reporting and remediation guidance

CONSOLIDATED FROM:
- src/services/cis_checker.py
- src/services/compliance_framework.py
"""

from __future__ import annotations

import json
import re
import yaml
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field
import logging

from ..models.security_models import ComplianceStatus, ComplianceFramework

logger = logging.getLogger(__name__)


# Compliance Framework Enums
class ComplianceLevel(Enum):
    """Compliance requirement levels."""

    MANDATORY = "mandatory"
    RECOMMENDED = "recommended"
    OPTIONAL = "optional"


class ComplianceSeverity(Enum):
    """Severity levels for compliance violations."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ComplianceCategory(Enum):
    """Categories of compliance requirements."""

    ACCESS_CONTROL = "access_control"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    AUDIT_LOGGING = "audit_logging"
    DATA_PROTECTION = "data_protection"
    NETWORK_SECURITY = "network_security"
    SYSTEM_SECURITY = "system_security"
    CONFIGURATION_MANAGEMENT = "configuration_management"
    INCIDENT_RESPONSE = "incident_response"
    BUSINESS_CONTINUITY = "business_continuity"
    VULNERABILITY_MANAGEMENT = "vulnerability_management"
    THIRD_PARTY_RISK = "third_party_risk"


@dataclass
class ComplianceCheck:
    """Individual compliance check definition."""

    # Identification
    check_id: str
    name: str
    description: str
    category: ComplianceCategory
    framework: ComplianceFramework

    # Requirements
    requirement: str
    compliance_level: ComplianceLevel
    severity: ComplianceSeverity

    # Implementation details
    check_type: str = "config"  # config, file, process, network, etc.
    target_patterns: List[str] = field(default_factory=list)
    forbidden_patterns: List[str] = field(default_factory=list)
    required_values: Dict[str, Any] = field(default_factory=dict)
    forbidden_values: Dict[str, Any] = field(default_factory=dict)

    # Remediation
    remediation_guide: str = ""
    remediation_commands: List[str] = field(default_factory=list)
    remediation_files: List[str] = field(default_factory=list)

    # Dependencies
    prerequisites: List[str] = field(default_factory=list)
    related_checks: List[str] = field(default_factory=list)

    # Metadata
    version: str = "1.0"
    last_updated: datetime = field(default_factory=datetime.now)
    tags: Set[str] = field(default_factory=set)


@dataclass
class ComplianceResult:
    """Result of compliance check execution."""

    # Check information
    check_id: str
    check_name: str
    framework: ComplianceFramework
    category: ComplianceCategory

    # Execution details
    executed_at: datetime = field(default_factory=datetime.now)
    duration_seconds: float = 0.0
    target_path: str = ""

    # Result status
    status: ComplianceStatus = ComplianceStatus.UNKNOWN
    passed: bool = False
    compliance_level: ComplianceLevel = ComplianceLevel.RECOMMENDED
    severity: ComplianceSeverity = ComplianceSeverity.LOW

    # Findings
    evidence: List[str] = field(default_factory=list)
    violations: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

    # Context
    check_details: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None
    warnings: List[str] = field(default_factory=list)

    # Remediation
    remediation_required: bool = False
    remediation_steps: List[str] = field(default_factory=list)
    estimated_effort: str = "low"  # low, medium, high


class ComplianceChecker:
    """Comprehensive compliance checking engine."""

    def __init__(self):
        self._checks: Dict[str, ComplianceCheck] = {}
        self._frameworks: Dict[str, ComplianceFramework] = {}
        self._categories: Dict[str, ComplianceCategory] = {}

        # Initialize built-in frameworks and checks
        self._initialize_frameworks()
        self._initialize_cis_benchmarks()
        self._initialize_nist_framework()
        self._initialize_owasp_checks()

    def _initialize_frameworks(self) -> None:
        """Initialize compliance frameworks."""
        frameworks = [
            ComplianceFramework(
                name="CIS_Benchmarks",
                version="1.0",
                description="Center for Internet Security Benchmarks",
                categories=list(ComplianceCategory),
            ),
            ComplianceFramework(
                name="NIST_CSF",
                version="1.1",
                description="NIST Cybersecurity Framework",
                categories=list(ComplianceCategory),
            ),
            ComplianceFramework(
                name="OWASP_Top10",
                version="2021",
                description="OWASP Top 10 Security Risks",
                categories={
                    ComplianceCategory.AUTHENTICATION,
                    ComplianceCategory.AUTHORIZATION,
                    ComplianceCategory.DATA_PROTECTION,
                    ComplianceCategory.VULNERABILITY_MANAGEMENT,
                },
            ),
        ]

        for framework in frameworks:
            self._frameworks[framework.name] = framework

    def _initialize_cis_benchmarks(self) -> None:
        """Initialize CIS benchmark compliance checks."""
        cis_checks = [
            ComplianceCheck(
                check_id="CIS-1.1.1",
                name="Ensure passwords are complex",
                description="Passwords should meet complexity requirements",
                category=ComplianceCategory.AUTHENTICATION,
                framework=self._frameworks["CIS_Benchmarks"],
                requirement="All user passwords must meet complexity requirements",
                compliance_level=ComplianceLevel.MANDATORY,
                severity=ComplianceSeverity.HIGH,
                check_type="config",
                target_patterns=["*/auth/*", "*/security/*"],
                forbidden_patterns=["password_policy.*=.*none", "min_length.*=.*0"],
            ),
            ComplianceCheck(
                check_id="CIS-1.1.2",
                name="Ensure password expiration is configured",
                description="Passwords should expire after reasonable period",
                category=ComplianceCategory.AUTHENTICATION,
                framework=self._frameworks["CIS_Benchmarks"],
                requirement="Password expiration policy must be configured",
                compliance_level=ComplianceLevel.MANDATORY,
                severity=ComplianceSeverity.MEDIUM,
                check_type="config",
                target_patterns=["*/auth/*", "*/security/*"],
                required_values={"password_expiration_days": "> 0"},
            ),
            ComplianceCheck(
                check_id="CIS-2.1.1",
                name="Ensure logging is enabled",
                description="System logging must be enabled",
                category=ComplianceCategory.AUDIT_LOGGING,
                framework=self._frameworks["CIS_Benchmarks"],
                requirement="Logging must be enabled for security events",
                compliance_level=ComplianceLevel.MANDATORY,
                severity=ComplianceSeverity.HIGH,
                check_type="config",
                target_patterns=["*/logging/*", "*/audit/*"],
                required_values={"logging_enabled": True},
            ),
            ComplianceCheck(
                check_id="CIS-3.1.1",
                name="Ensure network segmentation",
                description="Network should be properly segmented",
                category=ComplianceCategory.NETWORK_SECURITY,
                framework=self._frameworks["CIS_Benchmarks"],
                requirement="Network should be properly segmented",
                compliance_level=ComplianceLevel.RECOMMENDED,
                severity=ComplianceSeverity.MEDIUM,
                check_type="config",
                target_patterns=["*/network/*", "*/firewall/*"],
            ),
            ComplianceCheck(
                check_id="CIS-4.1.1",
                name="Ensure vulnerability scanning",
                description="Regular vulnerability scanning should be performed",
                category=ComplianceCategory.VULNERABILITY_MANAGEMENT,
                framework=self._frameworks["CIS_Benchmarks"],
                requirement="Vulnerability scanning must be performed regularly",
                compliance_level=ComplianceLevel.MANDATORY,
                severity=ComplianceSeverity.HIGH,
                check_type="process",
                required_values={"vulnerability_scan_frequency": "> 30"},
            ),
        ]

        for check in cis_checks:
            self._checks[check.check_id] = check

    def _initialize_nist_framework(self) -> None:
        """Initialize NIST Cybersecurity Framework checks."""
        nist_checks = [
            ComplianceCheck(
                check_id="NIST-IDENTIFY-1",
                name="Asset inventory management",
                description="Maintain comprehensive asset inventory",
                category=ComplianceCategory.CONFIGURATION_MANAGEMENT,
                framework=self._frameworks["NIST_CSF"],
                requirement="Organizations must maintain accurate asset inventory",
                compliance_level=ComplianceLevel.MANDATORY,
                severity=ComplianceSeverity.HIGH,
                check_type="config",
                target_patterns=["*/inventory/*", "*/assets/*"],
            ),
            ComplianceCheck(
                check_id="NIST-PROTECT-1",
                name="Access control management",
                description="Implement robust access control",
                category=ComplianceCategory.ACCESS_CONTROL,
                framework=self._frameworks["NIST_CSF"],
                requirement="Access controls must be properly implemented",
                compliance_level=ComplianceLevel.MANDATORY,
                severity=ComplianceSeverity.CRITICAL,
                check_type="config",
                target_patterns=["*/access/*", "*/auth/*"],
                required_values={"access_control_enabled": True},
            ),
            ComplianceCheck(
                check_id="NIST-DETECT-1",
                name="Security monitoring",
                description="Implement continuous security monitoring",
                category=ComplianceCategory.SYSTEM_SECURITY,
                framework=self._frameworks["NIST_CSF"],
                requirement="Continuous security monitoring must be implemented",
                compliance_level=ComplianceLevel.MANDATORY,
                severity=ComplianceSeverity.HIGH,
                check_type="process",
                required_values={"monitoring_enabled": True},
            ),
        ]

        for check in nist_checks:
            self._checks[check.check_id] = check

    def _initialize_owasp_checks(self) -> None:
        """Initialize OWASP Top 10 compliance checks."""
        owasp_checks = [
            ComplianceCheck(
                check_id="OWASP-A01-2021",
                name="Broken Access Control",
                description="Ensure proper access control implementation",
                category=ComplianceCategory.AUTHORIZATION,
                framework=self._frameworks["OWASP_Top10"],
                requirement="Broken access control must be prevented",
                compliance_level=ComplianceLevel.MANDATORY,
                severity=ComplianceSeverity.CRITICAL,
                check_type="code",
                target_patterns=["*.py", "*.js", "*.java", "*.php"],
                forbidden_patterns=["if.*user.*is.*admin.*return.*true"],
            ),
            ComplianceCheck(
                check_id="OWASP-A02-2021",
                name="Cryptographic Failures",
                description="Ensure proper use of cryptography",
                category=ComplianceCategory.DATA_PROTECTION,
                framework=self._frameworks["OWASP_Top10"],
                requirement="Cryptographic failures must be prevented",
                compliance_level=ComplianceLevel.MANDATORY,
                severity=ComplianceSeverity.CRITICAL,
                check_type="code",
                target_patterns=["*.py", "*.js", "*.java", "*.php"],
                forbidden_patterns=["md5", "sha1", "des", "rc4"],
            ),
            ComplianceCheck(
                check_id="OWASP-A03-2021",
                name="Injection Vulnerabilities",
                description="Prevent SQL injection and other injection attacks",
                category=ComplianceCategory.VULNERABILITY_MANAGEMENT,
                framework=self._frameworks["OWASP_Top10"],
                requirement="Injection vulnerabilities must be prevented",
                compliance_level=ComplianceLevel.MANDATORY,
                severity=ComplianceSeverity.CRITICAL,
                check_type="code",
                target_patterns=["*.py", "*.js", "*.java", "*.php"],
                forbidden_patterns=["execute.*\\+.*user", "query.*\\+.*input"],
            ),
        ]

        for check in owasp_checks:
            self._checks[check.check_id] = check

    def check_compliance(
        self,
        target_path: str,
        framework: Optional[str] = None,
        categories: Optional[Set[ComplianceCategory]] = None,
    ) -> List[ComplianceResult]:
        """Run compliance checks on target."""
        results = []

        # Select checks to run
        checks_to_run = self._select_checks(framework, categories)

        logger.info(f"Running {len(checks_to_run)} compliance checks on {target_path}")

        for check in checks_to_run:
            try:
                result = self._execute_check(check, target_path)
                results.append(result)

                status = "PASS" if result.passed else "FAIL"
                logger.info(f"Check {check.check_id}: {status}")

            except Exception as e:
                logger.error(f"Error executing check {check.check_id}: {e}")
                error_result = ComplianceResult(
                    check_id=check.check_id,
                    check_name=check.name,
                    framework=check.framework,
                    category=check.category,
                    status=ComplianceStatus.ERROR,
                    passed=False,
                    error_message=str(e),
                )
                results.append(error_result)

        return results

    def _select_checks(
        self,
        framework: Optional[str] = None,
        categories: Optional[Set[ComplianceCategory]] = None,
    ) -> List[ComplianceCheck]:
        """Select checks to run based on criteria."""
        selected_checks = []

        for check in self._checks.values():
            # Filter by framework
            if framework and check.framework.name != framework:
                continue

            # Filter by categories
            if categories and check.category not in categories:
                continue

            selected_checks.append(check)

        return selected_checks

    def _execute_check(
        self, check: ComplianceCheck, target_path: str
    ) -> ComplianceResult:
        """Execute individual compliance check."""
        start_time = datetime.now()

        result = ComplianceResult(
            check_id=check.check_id,
            check_name=check.name,
            framework=check.framework,
            category=check.category,
            compliance_level=check.compliance_level,
            severity=check.severity,
            target_path=target_path,
        )

        try:
            # Execute based on check type
            if check.check_type == "config":
                self._check_config_compliance(check, target_path, result)
            elif check.check_type == "file":
                self._check_file_compliance(check, target_path, result)
            elif check.check_type == "code":
                self._check_code_compliance(check, target_path, result)
            elif check.check_type == "process":
                self._check_process_compliance(check, target_path, result)
            else:
                result.status = ComplianceStatus.UNKNOWN
                result.error_message = f"Unknown check type: {check.check_type}"

            # Calculate duration
            result.duration_seconds = (datetime.now() - start_time).total_seconds()

            # Determine final status
            if result.violations:
                result.status = ComplianceStatus.NON_COMPLIANT
                result.passed = False
                result.remediation_required = True
            else:
                result.status = ComplianceStatus.COMPLIANT
                result.passed = True

        except Exception as e:
            result.status = ComplianceStatus.ERROR
            result.error_message = str(e)
            result.duration_seconds = (datetime.now() - start_time).total_seconds()

        return result

    def _check_config_compliance(
        self, check: ComplianceCheck, target_path: str, result: ComplianceResult
    ) -> None:
        """Check configuration file compliance."""
        config_files = self._find_config_files(target_path, check.target_patterns)

        violations = []
        evidence = []

        for config_file in config_files:
            try:
                with open(config_file, "r") as f:
                    content = f.read()

                # Check for forbidden patterns
                for pattern in check.forbidden_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        violations.append(
                            f"Found forbidden pattern '{pattern}' in {config_file}"
                        )
                        evidence.append(f"File: {config_file}")

                # Check for required values
                for key, expected_value in check.required_values.items():
                    if key in content:
                        if isinstance(
                            expected_value, str
                        ) and expected_value.startswith(">"):
                            # Numeric comparison
                            actual_value = self._extract_numeric_value(content, key)
                            threshold = float(expected_value[1:])
                            if actual_value and actual_value <= threshold:
                                violations.append(
                                    f"Value for {key} ({actual_value}) below required threshold ({threshold})"
                                )
                        elif (
                            expected_value is True
                            and expected_value not in content.lower()
                        ):
                            violations.append(
                                f"Required configuration {key} not found or disabled"
                            )
                        elif (
                            expected_value is False
                            and expected_value in content.lower()
                        ):
                            violations.append(
                                f"Configuration {key} should be disabled but is enabled"
                            )
                    else:
                        violations.append(f"Required configuration {key} not found")

            except Exception as e:
                violations.append(f"Error reading config file {config_file}: {e}")

        if config_files:
            evidence.append(f"Checked {len(config_files)} configuration files")
        else:
            violations.append("No configuration files found matching patterns")

        result.violations = violations
        result.evidence = evidence

    def _check_file_compliance(
        self, check: ComplianceCheck, target_path: str, result: ComplianceResult
    ) -> None:
        """Check file-based compliance."""
        files = self._find_files(target_path, check.target_patterns)

        violations = []
        evidence = []

        for file_path in files:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                # Check for forbidden patterns
                for pattern in check.forbidden_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        violations.append(
                            f"Found forbidden pattern '{pattern}' in {file_path}"
                        )

            except Exception as e:
                violations.append(f"Error reading file {file_path}: {e}")

        if files:
            evidence.append(f"Checked {len(files)} files")
        else:
            violations.append("No files found matching patterns")

        result.violations = violations
        result.evidence = evidence

    def _check_code_compliance(
        self, check: ComplianceCheck, target_path: str, result: ComplianceResult
    ) -> None:
        """Check code-based compliance."""
        code_files = self._find_code_files(target_path, check.target_patterns)

        violations = []
        evidence = []

        for code_file in code_files:
            try:
                with open(code_file, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                # Check for forbidden patterns
                for pattern in check.forbidden_patterns:
                    matches = re.finditer(
                        pattern, content, re.IGNORECASE | re.MULTILINE
                    )
                    for match in matches:
                        line_number = content[: match.start()].count("\n") + 1
                        violations.append(
                            f"Found forbidden pattern '{pattern}' in {code_file}:{line_number}"
                        )
                        evidence.append(f"File: {code_file}, Line: {line_number}")

                # Check for security anti-patterns
                if check.check_id.startswith("OWASP"):
                    security_violations = self._check_owasp_patterns(content, code_file)
                    violations.extend(security_violations)

            except Exception as e:
                violations.append(f"Error reading code file {code_file}: {e}")

        if code_files:
            evidence.append(f"Checked {len(code_files)} code files")
        else:
            violations.append("No code files found matching patterns")

        result.violations = violations
        result.evidence = evidence

    def _check_process_compliance(
        self, check: ComplianceCheck, target_path: str, result: ComplianceResult
    ) -> None:
        """Check process-based compliance."""
        violations = []
        evidence = []

        # Check for running processes
        try:
            import psutil

            # Check for security monitoring processes
            if "monitoring" in check.name.lower():
                monitoring_processes = []
                for proc in psutil.process_iter(["pid", "name", "cmdline"]):
                    try:
                        if any(
                            term in proc.info["name"].lower()
                            for term in ["audit", "monitor", "security"]
                        ):
                            monitoring_processes.append(proc.info["name"])
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                if not monitoring_processes:
                    violations.append("No security monitoring processes found")
                else:
                    evidence.append(
                        f"Found monitoring processes: {', '.join(monitoring_processes)}"
                    )

            # Check for vulnerability scanning processes
            elif "vulnerability" in check.name.lower():
                vuln_processes = []
                for proc in psutil.process_iter(["pid", "name", "cmdline"]):
                    try:
                        if any(
                            term in proc.info["name"].lower()
                            for term in ["nmap", "nessus", "openvas", "scanner"]
                        ):
                            vuln_processes.append(proc.info["name"])
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                if not vuln_processes:
                    violations.append("No vulnerability scanning processes found")
                else:
                    evidence.append(
                        f"Found vulnerability scanning processes: {', '.join(vuln_processes)}"
                    )

        except ImportError:
            violations.append("psutil not available for process checking")
        except Exception as e:
            violations.append(f"Error checking processes: {e}")

        result.violations = violations
        result.evidence = evidence

    def _check_owasp_patterns(self, content: str, file_path: str) -> List[str]:
        """Check for OWASP-specific security patterns."""
        violations = []

        # A01: Broken Access Control
        if "A01-2021" in file_path or "access" in file_path.lower():
            # Check for broken access control patterns
            patterns = [
                r"if\s*\(\s*user\s*\.\s*is_admin\s*\)\s*return\s*true",
                r"role\s*==\s*['\"]admin['\"]",
                r"permission\s*==\s*['\"]admin['\"]",
            ]

            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    violations.append(f"Potential broken access control in {file_path}")

        # A02: Cryptographic Failures
        if "A02-2021" in file_path or "crypto" in file_path.lower():
            # Check for weak cryptographic algorithms
            weak_algos = ["md5", "sha1", "des", "rc4", "weak"]
            for algo in weak_algos:
                if re.search(rf"\b{algo}\b", content, re.IGNORECASE):
                    violations.append(
                        f"Weak cryptographic algorithm '{algo}' in {file_path}"
                    )

        # A03: Injection Vulnerabilities
        if "A03-2021" in file_path or "sql" in file_path.lower():
            # Check for SQL injection patterns
            sql_patterns = [
                r"execute\s*\(\s*['\"].*\+.*['\"]",
                r"query\s*\(\s*['\"].*\+.*['\"]",
                r"cursor\.execute\s*\(\s*f?['\"].*\+",
            ]

            for pattern in sql_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    violations.append(f"Potential SQL injection in {file_path}")

        return violations

    def _find_config_files(self, target_path: str, patterns: List[str]) -> List[str]:
        """Find configuration files matching patterns."""
        files = []
        target_path = Path(target_path)

        for pattern in patterns:
            files.extend(target_path.rglob(pattern))

        return [str(f) for f in files if f.is_file()]

    def _find_files(self, target_path: str, patterns: List[str]) -> List[str]:
        """Find files matching patterns."""
        files = []
        target_path = Path(target_path)

        for pattern in patterns:
            files.extend(target_path.rglob(pattern))

        return [str(f) for f in files if f.is_file()]

    def _find_code_files(self, target_path: str, patterns: List[str]) -> List[str]:
        """Find code files matching patterns."""
        code_extensions = {
            ".py",
            ".js",
            ".ts",
            ".java",
            ".php",
            ".cpp",
            ".c",
            ".go",
            ".rs",
        }
        files = []
        target_path = Path(target_path)

        for pattern in patterns:
            matching_files = target_path.rglob(pattern)
            for file_path in matching_files:
                if file_path.is_file() and file_path.suffix.lower() in code_extensions:
                    files.append(str(file_path))

        return files

    def _extract_numeric_value(self, content: str, key: str) -> Optional[float]:
        """Extract numeric value from content."""
        # Simple regex to find numeric values
        pattern = rf"{key}\s*[:=]\s*(\d+(?:\.\d+)?)"
        match = re.search(pattern, content, re.IGNORECASE)

        if match:
            try:
                return float(match.group(1))
            except ValueError:
                pass

        return None

    def generate_compliance_report(
        self, results: List[ComplianceResult], output_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """Generate comprehensive compliance report."""
        report_data = {
            "report_metadata": {
                "generated_at": datetime.now().isoformat(),
                "total_checks": len(results),
                "frameworks_checked": list(set(r.framework.name for r in results)),
            },
            "summary": {
                "passed": len([r for r in results if r.passed]),
                "failed": len(
                    [
                        r
                        for r in results
                        if not r.passed and r.status != ComplianceStatus.ERROR
                    ]
                ),
                "errors": len(
                    [r for r in results if r.status == ComplianceStatus.ERROR]
                ),
                "compliance_rate": len([r for r in results if r.passed]) / len(results)
                if results
                else 0,
            },
            "compliance_by_framework": {},
            "compliance_by_category": {},
            "violations": [],
            "recommendations": [],
        }

        # Group results by framework
        for framework in set(r.framework.name for r in results):
            framework_results = [r for r in results if r.framework.name == framework]
            report_data["compliance_by_framework"][framework] = {
                "total": len(framework_results),
                "passed": len([r for r in framework_results if r.passed]),
                "compliance_rate": len([r for r in framework_results if r.passed])
                / len(framework_results),
            }

        # Group results by category
        for category in set(r.category for r in results):
            category_results = [r for r in results if r.category == category]
            report_data["compliance_by_category"][category.value] = {
                "total": len(category_results),
                "passed": len([r for r in category_results if r.passed]),
                "compliance_rate": len([r for r in category_results if r.passed])
                / len(category_results),
            }

        # Collect violations
        for result in results:
            if not result.passed and result.violations:
                violation_data = {
                    "check_id": result.check_id,
                    "check_name": result.check_name,
                    "framework": result.framework.name,
                    "category": result.category.value,
                    "severity": result.severity.value,
                    "violations": result.violations,
                    "remediation_required": result.remediation_required,
                }
                report_data["violations"].append(violation_data)

        # Generate recommendations
        recommendations = self._generate_recommendations(results)
        report_data["recommendations"] = recommendations

        # Save report if path provided
        if output_path:
            if output_path.endswith(".yaml") or output_path.endswith(".yml"):
                with open(output_path, "w") as f:
                    yaml.dump(report_data, f, default_flow_style=False, indent=2)
            else:
                with open(output_path, "w") as f:
                    json.dump(report_data, f, indent=2, default=str)

        return report_data

    def _generate_recommendations(self, results: List[ComplianceResult]) -> List[str]:
        """Generate compliance recommendations."""
        recommendations = []

        # Analyze critical violations
        critical_violations = [
            r
            for r in results
            if r.severity == ComplianceSeverity.CRITICAL and not r.passed
        ]
        if critical_violations:
            recommendations.append(
                "URGENT: Address all critical compliance violations immediately"
            )

        # Analyze high severity violations
        high_violations = [
            r for r in results if r.severity == ComplianceSeverity.HIGH and not r.passed
        ]
        if high_violations:
            recommendations.append(
                "HIGH PRIORITY: Address high-severity compliance issues within 7 days"
            )

        # Framework-specific recommendations
        cis_results = [r for r in results if r.framework.name == "CIS_Benchmarks"]
        if cis_results:
            failed_cis = [r for r in cis_results if not r.passed]
            if failed_cis:
                recommendations.append(
                    "Implement CIS benchmark controls for security hardening"
                )

        owasp_results = [r for r in results if r.framework.name == "OWASP_Top10"]
        if owasp_results:
            failed_owasp = [r for r in owasp_results if not r.passed]
            if failed_owasp:
                recommendations.append(
                    "Address OWASP Top 10 security risks to prevent common attacks"
                )

        # General recommendations
        recommendations.extend(
            [
                "Establish regular compliance monitoring and reporting",
                "Implement automated compliance checking in CI/CD pipeline",
                "Conduct periodic security assessments and penetration testing",
                "Provide security training for development and operations teams",
                "Maintain updated security documentation and procedures",
            ]
        )

        return recommendations


# Global compliance checker instance
_compliance_checker = None


def get_compliance_checker() -> ComplianceChecker:
    """Get global compliance checker instance."""
    global _compliance_checker
    if _compliance_checker is None:
        _compliance_checker = ComplianceChecker()
    return _compliance_checker


# Convenience functions
def quick_compliance_scan(
    target_path: str = ".", framework: str = "CIS_Benchmarks"
) -> Dict[str, Any]:
    """Perform quick compliance scan."""
    checker = get_compliance_checker()
    results = checker.check_compliance(target_path, framework)
    return checker.generate_compliance_report(results)


def check_cis_compliance(target_path: str) -> Dict[str, Any]:
    """Check CIS benchmark compliance."""
    return quick_compliance_scan(target_path, "CIS_Benchmarks")


def check_owasp_compliance(target_path: str) -> Dict[str, Any]:
    """Check OWASP Top 10 compliance."""
    return quick_compliance_scan(target_path, "OWASP_Top10")


def check_nist_compliance(target_path: str) -> Dict[str, Any]:
    """Check NIST framework compliance."""
    return quick_compliance_scan(target_path, "NIST_CSF")


# Export main classes and functions
__all__ = [
    "ComplianceChecker",
    "ComplianceCheck",
    "ComplianceResult",
    "ComplianceLevel",
    "ComplianceSeverity",
    "ComplianceCategory",
    "get_compliance_checker",
    "quick_compliance_scan",
    "check_cis_compliance",
    "check_owasp_compliance",
    "check_nist_compliance",
]
