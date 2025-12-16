#!/usr/bin/env python3
"""
TailOpsMCP Quality Checks Runner

A comprehensive script that runs all quality assurance tools and generates reports.
This script orchestrates the execution of various quality tools and provides
a unified interface for running all quality checks.

Usage:
    python scripts/run_quality_checks.py [OPTIONS]

Examples:
    # Run all quality checks
    python scripts/run_quality_checks.py --all

    # Run only linting and formatting
    python scripts/run_quality_checks.py --lint --format

    # Run with detailed output
    python scripts/run_quality_checks.py --all --verbose

    # Generate reports
    python scripts/run_quality_checks.py --all --report-dir reports/
"""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import shutil

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))


class QualityCheckRunner:
    """Orchestrates all quality assurance tools."""

    def __init__(self, verbose: bool = False, report_dir: Optional[str] = None):
        self.verbose = verbose
        self.report_dir = Path(report_dir) if report_dir else Path("quality-reports")
        self.report_dir.mkdir(exist_ok=True)
        self.results: Dict[str, Any] = {}
        self.start_time = datetime.now()

    def log(self, message: str, level: str = "INFO"):
        """Log message with optional verbosity."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        if self.verbose or level in ["ERROR", "SUCCESS"]:
            print(f"[{timestamp}] {level}: {message}")

    def run_command(self, command: List[str], check: bool = True) -> Tuple[bool, str, str]:
        """Run a command and return success, stdout, stderr."""
        try:
            self.log(f"Running: {' '.join(command)}")
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=check
            )
            return True, result.stdout, result.stderr
        except subprocess.CalledProcessError as e:
            self.log(f"Command failed: {' '.join(command)}", "ERROR")
            return False, e.stdout, e.stderr
        except FileNotFoundError:
            self.log(f"Command not found: {command[0]}", "ERROR")
            return False, "", f"Command not found: {command[0]}"

    def run_linting(self) -> Dict[str, Any]:
        """Run ruff linting."""
        self.log("Starting linting checks...")
        start_time = time.time()
        
        success, stdout, stderr = self.run_command([
            "ruff", "check", "src", "tests", "--output-format=json"
        ])
        
        duration = time.time() - start_time
        
        # Parse results
        issues = []
        if success and stdout.strip():
            try:
                issues = json.loads(stdout)
            except json.JSONDecodeError:
                self.log("Failed to parse lint output", "ERROR")
        
        result = {
            "tool": "ruff",
            "success": success,
            "duration": duration,
            "issues_found": len(issues),
            "issues": issues,
            "stdout": stdout,
            "stderr": stderr
        }
        
        self.results["linting"] = result
        self.log(f"Linting completed: {len(issues)} issues found", "SUCCESS" if not issues else "WARNING")
        return result

    def run_formatting(self) -> Dict[str, Any]:
        """Run code formatting checks."""
        self.log("Starting formatting checks...")
        start_time = time.time()
        
        # Check if code is properly formatted
        success, stdout, stderr = self.run_command([
            "ruff", "format", "--check", "src", "tests"
        ], check=False)
        
        duration = time.time() - start_time
        
        # Count files that need formatting
        unformatted_count = 0
        if not success and "would reformat" in stdout:
            unformatted_count = stdout.count("would reformat")
        
        result = {
            "tool": "ruff-format",
            "success": success,
            "duration": duration,
            "files_need_formatting": unformatted_count,
            "stdout": stdout,
            "stderr": stderr
        }
        
        self.results["formatting"] = result
        self.log(f"Formatting check completed: {unformatted_count} files need formatting", 
                "SUCCESS" if success else "WARNING")
        return result

    def run_type_checking(self) -> Dict[str, Any]:
        """Run mypy type checking."""
        self.log("Starting type checking...")
        start_time = time.time()
        
        success, stdout, stderr = self.run_command([
            "mypy", "src", "--ignore-missing-imports", 
            "--show-error-codes", "--pretty"
        ], check=False)
        
        duration = time.time() - start_time
        
        # Parse type errors
        type_errors = []
        if stdout.strip():
            for line in stdout.split('\n'):
                if ': error:' in line:
                    type_errors.append(line.strip())
        
        result = {
            "tool": "mypy",
            "success": success,
            "duration": duration,
            "type_errors": type_errors,
            "error_count": len(type_errors),
            "stdout": stdout,
            "stderr": stderr
        }
        
        self.results["type_checking"] = result
        self.log(f"Type checking completed: {len(type_errors)} type errors found", 
                "SUCCESS" if not type_errors else "WARNING")
        return result

    def run_security_checks(self) -> Dict[str, Any]:
        """Run security scans using bandit and safety."""
        self.log("Starting security checks...")
        start_time = time.time()
        
        results = {
            "bandit": {},
            "safety": {}
        }
        
        # Run bandit
        bandit_success, bandit_stdout, bandit_stderr = self.run_command([
            "bandit", "-r", "src", "-f", "json"
        ], check=False)
        
        results["bandit"] = {
            "success": bandit_success,
            "issues_found": 0,
            "stdout": bandit_stdout,
            "stderr": bandit_stderr
        }
        
        if bandit_stdout.strip():
            try:
                bandit_results = json.loads(bandit_stdout)
                results["bandit"]["issues_found"] = len(bandit_results.get("results", []))
            except json.JSONDecodeError:
                self.log("Failed to parse bandit output", "ERROR")
        
        # Run safety
        safety_success, safety_stdout, safety_stderr = self.run_command([
            "safety", "check", "--json"
        ], check=False)
        
        results["safety"] = {
            "success": safety_success,
            "vulnerabilities_found": 0,
            "stdout": safety_stdout,
            "stderr": safety_stderr
        }
        
        if safety_stdout.strip():
            try:
                safety_results = json.loads(safety_stdout)
                results["safety"]["vulnerabilities_found"] = len(safety_results)
            except json.JSONDecodeError:
                self.log("Failed to parse safety output", "ERROR")
        
        duration = time.time() - start_time
        
        total_issues = results["bandit"]["issues_found"] + results["safety"]["vulnerabilities_found"]
        
        result = {
            "tool": "security",
            "success": total_issues == 0,
            "duration": duration,
            "bandit_issues": results["bandit"]["issues_found"],
            "safety_vulnerabilities": results["safety"]["vulnerabilities_found"],
            "total_issues": total_issues,
            "details": results
        }
        
        self.results["security"] = result
        self.log(f"Security checks completed: {total_issues} issues found", 
                "SUCCESS" if total_issues == 0 else "WARNING")
        return result

    def run_complexity_analysis(self) -> Dict[str, Any]:
        """Run complexity analysis using radon."""
        self.log("Starting complexity analysis...")
        start_time = time.time()
        
        # Cyclomatic complexity
        cc_success, cc_stdout, cc_stderr = self.run_command([
            "radon", "cc", "src", "--json"
        ], check=False)
        
        # Maintainability index
        mi_success, mi_stdout, mi_stderr = self.run_command([
            "radon", "mi", "src", "--json"
        ], check=False)
        
        duration = time.time() - start_time
        
        # Parse results
        complexity_data = {}
        if cc_stdout.strip():
            try:
                complexity_data["cyclomatic"] = json.loads(cc_stdout)
            except json.JSONDecodeError:
                self.log("Failed to parse complexity output", "ERROR")
        
        if mi_stdout.strip():
            try:
                complexity_data["maintainability"] = json.loads(mi_stdout)
            except json.JSONDecodeError:
                self.log("Failed to parse maintainability output", "ERROR")
        
        # Calculate metrics
        high_complexity_files = 0
        if "cyclomatic" in complexity_data:
            for file_path, file_data in complexity_data["cyclomatic"].items():
                for func_data in file_data.get("functions", []):
                    if func_data.get("rank", "A") in ["D", "E", "F"]:
                        high_complexity_files += 1
        
        result = {
            "tool": "radon",
            "success": high_complexity_files == 0,
            "duration": duration,
            "high_complexity_functions": high_complexity_files,
            "complexity_data": complexity_data,
            "stdout": cc_stdout + mi_stdout,
            "stderr": cc_stderr + mi_stderr
        }
        
        self.results["complexity"] = result
        self.log(f"Complexity analysis completed: {high_complexity_files} high-complexity functions found",
                "SUCCESS" if high_complexity_files == 0 else "WARNING")
        return result

    def run_tests(self) -> Dict[str, Any]:
        """Run tests with pytest."""
        self.log("Starting tests...")
        start_time = time.time()
        
        # Create test report directory
        test_report_dir = self.report_dir / "tests"
        test_report_dir.mkdir(exist_ok=True)
        
        success, stdout, stderr = self.run_command([
            "pytest", "tests/", "--tb=short", 
            "--cov=src", "--cov-report=html:" + str(test_report_dir / "htmlcov"),
            "--cov-report=json:" + str(test_report_dir / "coverage.json"),
            "--cov-report=term-missing",
            "--junitxml=" + str(test_report_dir / "junit.xml")
        ], check=False)
        
        duration = time.time() - start_time
        
        # Parse test results
        tests_passed = 0
        tests_failed = 0
        tests_skipped = 0
        coverage_percent = 0.0
        
        # Try to parse coverage from stdout
        if "===" in stdout and "passed" in stdout:
            for line in stdout.split('\n'):
                if "passed" in line and "===" in line:
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part == "passed":
                            tests_passed = int(parts[i-1]) if i > 0 else 0
                        elif part == "failed":
                            tests_failed = int(parts[i-1]) if i > 0 else 0
                        elif part == "skipped":
                            tests_skipped = int(parts[i-1]) if i > 0 else 0
        
        # Read coverage from JSON file
        coverage_file = test_report_dir / "coverage.json"
        if coverage_file.exists():
            try:
                with open(coverage_file) as f:
                    coverage_data = json.load(f)
                    coverage_percent = coverage_data.get("totals", {}).get("percent_covered", 0.0)
            except Exception as e:
                self.log(f"Failed to read coverage data: {e}", "WARNING")
        
        result = {
            "tool": "pytest",
            "success": success,
            "duration": duration,
            "tests_passed": tests_passed,
            "tests_failed": tests_failed,
            "tests_skipped": tests_skipped,
            "total_tests": tests_passed + tests_failed + tests_skipped,
            "coverage_percent": coverage_percent,
            "stdout": stdout,
            "stderr": stderr
        }
        
        self.results["tests"] = result
        self.log(f"Tests completed: {tests_passed} passed, {tests_failed} failed, {tests_skipped} skipped",
                "SUCCESS" if success else "ERROR")
        self.log(f"Coverage: {coverage_percent:.1f}%")
        return result

    def run_all_checks(self) -> Dict[str, Any]:
        """Run all quality checks."""
        self.log("Starting comprehensive quality checks...")
        
        # Run all checks
        self.run_linting()
        self.run_formatting()
        self.run_type_checking()
        self.run_security_checks()
        self.run_complexity_analysis()
        self.run_tests()
        
        # Calculate summary
        total_duration = (datetime.now() - self.start_time).total_seconds()
        
        summary = {
            "start_time": self.start_time.isoformat(),
            "end_time": datetime.now().isoformat(),
            "total_duration": total_duration,
            "checks_run": len(self.results),
            "overall_success": all(
                result.get("success", False) for result in self.results.values()
            ),
            "results": self.results
        }
        
        self.log(f"All quality checks completed in {total_duration:.2f}s", "SUCCESS")
        return summary

    def generate_report(self, output_file: Optional[str] = None) -> str:
        """Generate comprehensive report."""
        report = {
            "project": "TailOpsMCP",
            "report_time": datetime.now().isoformat(),
            "summary": self.results
        }
        
        # Add overall metrics
        total_issues = sum(
            result.get("issues_found", 0) for result in self.results.values()
        )
        total_errors = sum(
            result.get("error_count", 0) for result in self.results.values()
        )
        total_security_issues = sum(
            result.get("total_issues", 0) for result in self.results.values()
            if result.get("tool") == "security"
        )
        
        report["metrics"] = {
            "total_issues_found": total_issues,
            "total_type_errors": total_errors,
            "total_security_issues": total_security_issues,
            "overall_score": self._calculate_overall_score()
        }
        
        # Save to file if specified
        if output_file:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            self.log(f"Report saved to: {output_path}")
        
        return json.dumps(report, indent=2, default=str)

    def _calculate_overall_score(self) -> float:
        """Calculate overall quality score."""
        scores = []
        
        # Linting score
        if "linting" in self.results:
            lint_issues = self.results["linting"].get("issues_found", 0)
            lint_score = max(0, 100 - (lint_issues * 5))  # 5 points per issue
            scores.append(lint_score)
        
        # Formatting score
        if "formatting" in self.results:
            format_issues = self.results["formatting"].get("files_need_formatting", 0)
            format_score = 100 if format_issues == 0 else max(0, 100 - (format_issues * 10))
            scores.append(format_score)
        
        # Type checking score
        if "type_checking" in self.results:
            type_errors = self.results["type_checking"].get("error_count", 0)
            type_score = max(0, 100 - (type_errors * 10))
            scores.append(type_score)
        
        # Security score
        if "security" in self.results:
            security_issues = self.results["security"].get("total_issues", 0)
            security_score = max(0, 100 - (security_issues * 20))  # Security issues have high impact
            scores.append(security_score)
        
        # Test score
        if "tests" in self.results:
            tests_passed = self.results["tests"].get("tests_passed", 0)
            total_tests = self.results["tests"].get("total_tests", 1)
            test_score = (tests_passed / total_tests) * 100 if total_tests > 0 else 0
            scores.append(test_score)
        
        return sum(scores) / len(scores) if scores else 0.0

    def print_summary(self):
        """Print a human-readable summary."""
        print("\n" + "="*60)
        print("📊 QUALITY CHECKS SUMMARY")
        print("="*60)
        
        for check_name, result in self.results.items():
            status = "✅ PASS" if result.get("success", False) else "❌ FAIL"
            duration = result.get("duration", 0)
            
            print(f"\n{check_name.upper()}: {status}")
            print(f"  Duration: {duration:.2f}s")
            
            # Add specific metrics
            if check_name == "linting":
                issues = result.get("issues_found", 0)
                print(f"  Issues found: {issues}")
            elif check_name == "formatting":
                files = result.get("files_need_formatting", 0)
                print(f"  Files need formatting: {files}")
            elif check_name == "type_checking":
                errors = result.get("error_count", 0)
                print(f"  Type errors: {errors}")
            elif check_name == "security":
                total = result.get("total_issues", 0)
                bandit = result.get("bandit_issues", 0)
                safety = result.get("safety_vulnerabilities", 0)
                print(f"  Total security issues: {total}")
                print(f"    - Bandit: {bandit}")
                print(f"    - Safety: {safety}")
            elif check_name == "tests":
                passed = result.get("tests_passed", 0)
                failed = result.get("tests_failed", 0)
                skipped = result.get("tests_skipped", 0)
                coverage = result.get("coverage_percent", 0)
                print(f"  Tests: {passed} passed, {failed} failed, {skipped} skipped")
                print(f"  Coverage: {coverage:.1f}%")
        
        # Overall score
        overall_score = self._calculate_overall_score()
        print(f"\n🏆 OVERALL QUALITY SCORE: {overall_score:.1f}/100")
        
        if overall_score >= 90:
            print("🎉 Excellent code quality!")
        elif overall_score >= 75:
            print("👍 Good code quality with room for improvement")
        elif overall_score >= 60:
            print("⚠️  Code quality needs attention")
        else:
            print("🚨 Code quality requires immediate attention")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="TailOpsMCP Quality Checks Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --all                    # Run all quality checks
  %(prog)s --lint --format          # Run only linting and formatting
  %(prog)s --all --verbose          # Run all checks with verbose output
  %(prog)s --all --report-dir reports/  # Generate reports in custom directory
        """
    )
    
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run all quality checks (default)"
    )
    
    parser.add_argument(
        "--lint",
        action="store_true",
        help="Run linting checks"
    )
    
    parser.add_argument(
        "--format",
        action="store_true",
        help="Run formatting checks"
    )
    
    parser.add_argument(
        "--typecheck",
        action="store_true",
        help="Run type checking"
    )
    
    parser.add_argument(
        "--security",
        action="store_true",
        help="Run security checks"
    )
    
    parser.add_argument(
        "--complexity",
        action="store_true",
        help="Run complexity analysis"
    )
    
    parser.add_argument(
        "--tests",
        action="store_true",
        help="Run tests"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output"
    )
    
    parser.add_argument(
        "--report-dir",
        help="Directory to save reports (default: quality-reports)"
    )
    
    parser.add_argument(
        "--output", "-o",
        help="Output file for comprehensive report"
    )
    
    parser.add_argument(
        "--no-summary",
        action="store_true",
        help="Skip printing summary"
    )
    
    args = parser.parse_args()
    
    # Determine which checks to run
    run_all = args.all or not any([args.lint, args.format, args.typecheck, 
                                   args.security, args.complexity, args.tests])
    
    runner = QualityCheckRunner(verbose=args.verbose, report_dir=args.report_dir)
    
    if run_all:
        summary = runner.run_all_checks()
    else:
        # Run specific checks
        if args.lint:
            runner.run_linting()
        if args.format:
            runner.run_formatting()
        if args.typecheck:
            runner.run_type_checking()
        if args.security:
            runner.run_security_checks()
        if args.complexity:
            runner.run_complexity_analysis()
        if args.tests:
            runner.run_tests()
        
        summary = {"results": runner.results}
    
    # Generate report
    if args.output or args.verbose:
        report = runner.generate_report(args.output)
        if args.verbose:
            print("\n" + "="*60)
            print("📄 DETAILED REPORT")
            print("="*60)
            print(report)
    
    # Print summary unless disabled
    if not args.no_summary:
        runner.print_summary()
    
    # Return exit code based on results
    overall_success = all(
        result.get("success", False) for result in runner.results.values()
    )
    
    return 0 if overall_success else 1


if __name__ == "__main__":
    sys.exit(main())