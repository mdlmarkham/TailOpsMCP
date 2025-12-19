#!/usr/bin/env python3
"""
TailOpsMCP Security Scanner CLI

A comprehensive security scanning tool that utilizes the existing security scanner
from src.security.scanner to perform various types of security assessments.

Usage:
    python scripts/scan.py [OPTIONS] [TARGET_PATH]

Examples:
    # Quick security scan
    python scripts/scan.py --quick

    # Full security scan with report
    python scripts/scan.py --full --output security-report.json

    # Scan for secrets only
    python scripts/scan.py --secrets --output secrets-report.json

    # Vulnerability scan
    python scripts/scan.py --vulnerabilities --output vulns-report.json

    # Interactive scan
    python scripts/scan.py --interactive
"""

import argparse
import json
import sys
import os
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Set, Dict, Any

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# Import yaml with fallback
try:
    import yaml
except ImportError:
    yaml = None

from security.scanner import SecurityScanner, SecurityScanConfig, ScanResult, ScanType


class SecurityScanCLI:
    """Command-line interface for security scanning."""

    def __init__(self):
        self.scanner = SecurityScanner()
        self.config = SecurityScanConfig()

    def run_scan(
        self,
        target_path: str = ".",
        scan_types: Optional[Set[ScanType]] = None,
        output_file: Optional[str] = None,
        output_format: str = "json",
        verbose: bool = False,
    ) -> int:
        """Run security scan with specified parameters."""
        target_path = os.path.abspath(target_path)

        if not os.path.exists(target_path):
            print(f"❌ Error: Target path '{target_path}' does not exist")
            return 1

        if verbose:
            print(f"🔍 Starting security scan of: {target_path}")
            print(f"📋 Scan types: {scan_types or self.config.scan_types}")
            print(f"💾 Output format: {output_format}")
            print("-" * 60)

        try:
            # Perform the scan
            results = self.scanner.scan(target_path, scan_types)

            if verbose:
                print(
                    f"✅ Scan completed in {sum(r.duration_seconds or 0 for r in results):.2f}s"
                )

            # Generate report
            report = self._generate_report(results, target_path)

            # Save to file if specified
            if output_file:
                self._save_report(report, output_file, output_format)
                if verbose:
                    print(f"📄 Report saved to: {output_file}")

            # Display summary
            self._display_summary(results, verbose)

            # Return exit code based on findings
            return self._get_exit_code(results)

        except Exception as e:
            print(f"❌ Error during scan: {e}")
            if verbose:
                import traceback

                traceback.print_exc()
            return 1

    def _generate_report(
        self, results: List[ScanResult], target_path: str
    ) -> Dict[str, Any]:
        """Generate comprehensive report from scan results."""
        report = {
            "scan_info": {
                "target_path": target_path,
                "scan_time": datetime.now().isoformat(),
                "total_scans": len(results),
                "scanner_version": "1.0.0",
            },
            "summary": {
                "total_files_scanned": sum(r.files_scanned for r in results),
                "total_lines_scanned": sum(r.lines_scanned for r in results),
                "total_issues": sum(r.issues_found for r in results),
                "risk_score": self._calculate_risk_score(results),
            },
            "scan_results": [],
            "recommendations": [],
        }

        # Add individual scan results
        for result in results:
            scan_data = {
                "scan_id": result.scan_id,
                "scan_type": result.scan_type.value,
                "status": result.status.value,
                "duration_seconds": result.duration_seconds,
                "files_scanned": result.files_scanned,
                "lines_scanned": result.lines_scanned,
                "issues_found": result.issues_found,
                "vulnerabilities": [
                    self._serialize_vulnerability(v) for v in result.vulnerabilities
                ],
                "secrets_found": result.secrets_found,
                "compliance_issues": result.compliance_issues,
                "policy_violations": result.policy_violations,
            }
            report["scan_results"].append(scan_data)

        # Add recommendations
        report["recommendations"] = self._generate_recommendations(results)

        return report

    def _serialize_vulnerability(self, vuln) -> Dict[str, Any]:
        """Serialize vulnerability object to dictionary."""
        if hasattr(vuln, "__dict__"):
            return {
                "id": getattr(vuln, "id", "Unknown"),
                "title": getattr(vuln, "title", "Unknown"),
                "description": getattr(vuln, "description", "Unknown"),
                "severity": getattr(vuln, "severity", "Unknown"),
                "affected_component": getattr(vuln, "affected_component", "Unknown"),
                "file_path": getattr(vuln, "file_path", "Unknown"),
                "line_number": getattr(vuln, "line_number", 0),
            }
        return {"error": "Unable to serialize vulnerability"}

    def _calculate_risk_score(self, results: List[ScanResult]) -> float:
        """Calculate overall risk score based on scan results."""
        if not results:
            return 0.0

        total_score = 0.0
        max_score = 0.0

        for result in results:
            # Calculate score based on issues found
            vuln_score = (
                len([v for v in result.vulnerabilities if v.severity == "critical"])
                * 10
            )
            vuln_score += (
                len([v for v in result.vulnerabilities if v.severity == "high"]) * 5
            )
            vuln_score += (
                len([v for v in result.vulnerabilities if v.severity == "medium"]) * 2
            )
            vuln_score += (
                len([v for v in result.vulnerabilities if v.severity == "low"]) * 1
            )

            secret_score = len(result.secrets_found) * 8
            compliance_score = len(result.compliance_issues) * 3

            result_score = vuln_score + secret_score + compliance_score
            total_score += result_score
            max_score += 100  # Maximum possible score per scan

        return min(100.0, (total_score / max_score) * 100) if max_score > 0 else 0.0

    def _generate_recommendations(self, results: List[ScanResult]) -> List[str]:
        """Generate recommendations based on scan results."""
        recommendations = []

        # Analyze vulnerabilities
        critical_vulns = sum(
            1 for r in results for v in r.vulnerabilities if v.severity == "critical"
        )
        high_vulns = sum(
            1 for r in results for v in r.vulnerabilities if v.severity == "high"
        )
        total_secrets = sum(len(r.secrets_found) for r in results)
        total_compliance = sum(len(r.compliance_issues) for r in results)

        if critical_vulns > 0:
            recommendations.append(
                f"🚨 CRITICAL: Address {critical_vulns} critical vulnerabilities immediately"
            )

        if high_vulns > 0:
            recommendations.append(
                f"⚠️  HIGH: Address {high_vulns} high-severity vulnerabilities within 7 days"
            )

        if total_secrets > 0:
            recommendations.append(
                f"🔐 URGENT: Remove {total_secrets} exposed secrets and rotate credentials"
            )

        if total_compliance > 0:
            recommendations.append(
                f"📋 COMPLIANCE: Address {total_compliance} compliance issues"
            )

        # General recommendations
        if not recommendations:
            recommendations.append(
                "✅ No critical issues found. Maintain good security practices."
            )

        recommendations.extend(
            [
                "📈 Implement regular security scanning in CI/CD pipeline",
                "🔍 Establish security monitoring and alerting",
                "🚨 Create incident response procedures",
                "📚 Conduct regular security training for development team",
                "🔄 Review and update security policies quarterly",
            ]
        )

        return recommendations

    def _save_report(
        self, report: Dict[str, Any], output_file: str, output_format: str
    ):
        """Save report to file in specified format."""
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if output_format.lower() == "yaml" or output_file.endswith((".yaml", ".yml")):
            if yaml is not None:
                with open(output_path, "w") as f:
                    yaml.dump(report, f, default_flow_style=False, indent=2)
            else:
                # Fallback to JSON if yaml is not available
                output_path = output_path.with_suffix(".json")
                with open(output_path, "w") as f:
                    json.dump(report, f, indent=2, default=str)
                print("YAML not available, saved as JSON instead", "WARNING")
        else:
            with open(output_path, "w") as f:
                json.dump(report, f, indent=2, default=str)

    def _display_summary(self, results: List[ScanResult], verbose: bool = False):
        """Display scan summary."""
        if not verbose:
            print("\n📊 Security Scan Summary")
            print("=" * 40)

        total_issues = sum(r.issues_found for r in results)
        total_files = sum(r.files_scanned for r in results)

        print(f"📁 Files scanned: {total_files}")
        print(f"⚠️  Issues found: {total_issues}")

        if total_issues > 0:
            print("🔍 Issues by type:")

            # Count issues by type
            secrets_count = sum(len(r.secrets_found) for r in results)
            vuln_count = sum(len(r.vulnerabilities) for r in results)
            compliance_count = sum(len(r.compliance_issues) for r in results)

            if secrets_count > 0:
                print(f"   🔐 Secrets: {secrets_count}")
            if vuln_count > 0:
                print(f"   🐛 Vulnerabilities: {vuln_count}")
            if compliance_count > 0:
                print(f"   📋 Compliance: {compliance_count}")
        else:
            print("✅ No issues found!")

    def _get_exit_code(self, results: List[ScanResult]) -> int:
        """Determine exit code based on scan results."""
        critical_issues = sum(
            len([v for v in r.vulnerabilities if v.severity == "critical"])
            for r in results
        )

        if critical_issues > 0:
            return 2  # Critical issues found

        high_issues = sum(
            len([v for v in r.vulnerabilities if v.severity == "high"]) for r in results
        )

        if high_issues > 0 or sum(len(r.secrets_found) for r in results) > 0:
            return 1  # High priority issues found

        return 0  # No issues found

    def interactive_scan(self):
        """Run interactive security scan."""
        print("🔍 TailOpsMCP Interactive Security Scanner")
        print("=" * 50)

        # Get target path
        target = input("Enter target path (default: current directory): ").strip()
        if not target:
            target = "."

        # Get scan types
        print("\nAvailable scan types:")
        print("1. Quick scan (vulnerabilities + secrets)")
        print("2. Full scan (all types)")
        print("3. Secrets only")
        print("4. Vulnerabilities only")
        print("5. Compliance only")

        choice = input("\nSelect scan type (1-5, default: 1): ").strip()

        scan_types = None
        if choice == "2":
            scan_types = {
                ScanType.VULNERABILITY,
                ScanType.SECRETS,
                ScanType.COMPLIANCE,
                ScanType.POLICY,
                ScanType.INFRASTRUCTURE,
            }
        elif choice == "3":
            scan_types = {ScanType.SECRETS}
        elif choice == "4":
            scan_types = {ScanType.VULNERABILITY}
        elif choice == "5":
            scan_types = {ScanType.COMPLIANCE}
        # Default is choice "1" or any other input

        # Get output options
        save_report = input("\nSave detailed report? (y/N): ").strip().lower() == "y"
        output_file = None
        output_format = "json"

        if save_report:
            output_file = input(
                "Enter output file path (default: security-report.json): "
            ).strip()
            if not output_file:
                output_file = "security-report.json"

        print(f"\n🚀 Starting scan of '{target}'...")
        return self.run_scan(
            target, scan_types, output_file, output_format, verbose=True
        )


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="TailOpsMCP Security Scanner - Comprehensive security assessment tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --quick                    # Quick security scan
  %(prog)s --full                     # Full security scan
  %(prog)s --secrets --output report.json  # Secrets scan with output
  %(prog)s --vulnerabilities --verbose    # Verbose vulnerability scan
  %(prog)s --interactive              # Interactive scan mode
        """,
    )

    parser.add_argument(
        "target_path",
        nargs="?",
        default=".",
        help="Path to scan (default: current directory)",
    )

    # Scan type options
    scan_group = parser.add_argument_group("Scan Types")
    scan_group.add_argument(
        "--quick", action="store_true", help="Quick scan (vulnerabilities and secrets)"
    )
    scan_group.add_argument(
        "--full", action="store_true", help="Full comprehensive scan"
    )
    scan_group.add_argument(
        "--secrets",
        action="store_true",
        help="Scan for exposed secrets and credentials",
    )
    scan_group.add_argument(
        "--vulnerabilities", action="store_true", help="Scan for known vulnerabilities"
    )
    scan_group.add_argument(
        "--compliance", action="store_true", help="Scan for compliance violations"
    )
    scan_group.add_argument(
        "--interactive", action="store_true", help="Run in interactive mode"
    )

    # Output options
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument("--output", "-o", help="Output file for detailed report")
    output_group.add_argument(
        "--format",
        choices=["json", "yaml"],
        default="json",
        help="Output format (default: json)",
    )
    output_group.add_argument(
        "--verbose", "-v", action="store_true", help="Verbose output"
    )
    output_group.add_argument(
        "--quiet", "-q", action="store_true", help="Quiet mode (minimal output)"
    )

    args = parser.parse_args()

    # Handle interactive mode
    if args.interactive:
        cli = SecurityScanCLI()
        return cli.interactive_scan()

    # Determine scan types
    scan_types = None
    if args.full:
        scan_types = {
            ScanType.VULNERABILITY,
            ScanType.SECRETS,
            ScanType.COMPLIANCE,
            ScanType.POLICY,
            ScanType.INFRASTRUCTURE,
            ScanType.CONTAINER,
            ScanType.NETWORK,
        }
    elif args.secrets:
        scan_types = {ScanType.SECRETS}
    elif args.vulnerabilities:
        scan_types = {ScanType.VULNERABILITY}
    elif args.compliance:
        scan_types = {ScanType.COMPLIANCE}
    # Default to quick scan if no specific type chosen

    # Initialize and run scanner
    cli = SecurityScanCLI()
    exit_code = cli.run_scan(
        target_path=args.target_path,
        scan_types=scan_types,
        output_file=args.output,
        output_format=args.format,
        verbose=args.verbose and not args.quiet,
    )

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
