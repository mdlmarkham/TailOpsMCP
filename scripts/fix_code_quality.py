#!/usr/bin/env python3
"""
TailOpsMCP Code Quality Auto-Fixer

A comprehensive script that automatically fixes common code quality issues
using various tools like ruff, isort, and other formatters.

Usage:
    python scripts/fix_code_quality.py [OPTIONS]

Examples:
    # Auto-fix all issues
    python scripts/fix_code_quality.py --all

    # Fix only import sorting and formatting
    python scripts/fix_code_quality.py --imports --format

    # Preview changes without applying them
    python scripts/fix_code_quality.py --all --dry-run

    # Fix specific issues only
    python scripts/fix_code_quality.py --lint --imports
"""

import argparse
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


class CodeQualityFixer:
    """Automatically fixes code quality issues."""

    def __init__(self, dry_run: bool = False, verbose: bool = False):
        self.dry_run = dry_run
        self.verbose = verbose
        self.fixes_applied: List[str] = []
        self.fixes_failed: List[str] = []
        self.start_time = datetime.now()

    def log(self, message: str, level: str = "INFO"):
        """Log message with optional verbosity."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        if self.verbose or level in ["SUCCESS", "ERROR", "WARNING"]:
            prefix = "🔧" if level == "INFO" else "✅" if level == "SUCCESS" else "❌" if level == "ERROR" else "⚠️"
            print(f"[{timestamp}] {prefix} {message}")

    def run_command(self, command: List[str], check: bool = True) -> Tuple[bool, str, str]:
        """Run a command and return success, stdout, stderr."""
        try:
            self.log(f"Running: {' '.join(command)}")
            if self.dry_run:
                self.log("DRY RUN: Command would be executed", "WARNING")
                return True, "", ""
            
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

    def fix_linting_issues(self) -> Dict[str, Any]:
        """Fix linting issues using ruff."""
        self.log("Fixing linting issues...")
        start_time = time.time()
        
        success, stdout, stderr = self.run_command([
            "ruff", "check", "--fix", "src", "tests"
        ], check=False)
        
        duration = time.time() - start_time
        
        if success:
            self.fixes_applied.append("ruff-lint")
            self.log("Linting issues fixed successfully", "SUCCESS")
        else:
            self.fixes_failed.append("ruff-lint")
            self.log("Failed to fix linting issues", "ERROR")
        
        return {
            "tool": "ruff-lint",
            "success": success,
            "duration": duration,
            "stdout": stdout,
            "stderr": stderr
        }

    def fix_formatting(self) -> Dict[str, Any]:
        """Fix code formatting using ruff format."""
        self.log("Fixing code formatting...")
        start_time = time.time()
        
        success, stdout, stderr = self.run_command([
            "ruff", "format", "src", "tests"
        ], check=False)
        
        duration = time.time() - start_time
        
        if success:
            self.fixes_applied.append("ruff-format")
            self.log("Code formatting fixed successfully", "SUCCESS")
        else:
            self.fixes_failed.append("ruff-format")
            self.log("Failed to fix formatting", "ERROR")
        
        return {
            "tool": "ruff-format",
            "success": success,
            "duration": duration,
            "stdout": stdout,
            "stderr": stderr
        }

    def fix_import_sorting(self) -> Dict[str, Any]:
        """Fix import sorting using isort."""
        self.log("Fixing import sorting...")
        start_time = time.time()
        
        success, stdout, stderr = self.run_command([
            "isort", "--profile", "black", "src", "tests"
        ], check=False)
        
        duration = time.time() - start_time
        
        if success:
            self.fixes_applied.append("isort")
            self.log("Import sorting fixed successfully", "SUCCESS")
        else:
            self.fixes_failed.append("isort")
            self.log("Failed to fix import sorting", "ERROR")
        
        return {
            "tool": "isort",
            "success": success,
            "duration": duration,
            "stdout": stdout,
            "stderr": stderr
        }

    def fix_docstrings(self) -> Dict[str, Any]:
        """Add missing docstrings using ruff."""
        self.log("Checking and fixing docstrings...")
        start_time = time.time()
        
        success, stdout, stderr = self.run_command([
            "ruff", "check", "--select", "D", "--fix", "src", "tests"
        ], check=False)
        
        duration = time.time() - start_time
        
        if success:
            self.fixes_applied.append("docstrings")
            self.log("Docstrings fixed successfully", "SUCCESS")
        else:
            self.fixes_failed.append("docstrings")
            self.log("Failed to fix docstrings", "ERROR")
        
        return {
            "tool": "docstrings",
            "success": success,
            "duration": duration,
            "stdout": stdout,
            "stderr": stderr
        }

    def fix_type_annotations(self) -> Dict[str, Any]:
        """Fix missing type annotations using ruff."""
        self.log("Checking and fixing type annotations...")
        start_time = time.time()
        
        success, stdout, stderr = self.run_command([
            "ruff", "check", "--select", "ANN", "--fix", "src", "tests"
        ], check=False)
        
        duration = time.time() - start_time
        
        if success:
            self.fixes_applied.append("type-annotations")
            self.log("Type annotations fixed successfully", "SUCCESS")
        else:
            self.fixes_failed.append("type-annotations")
            self.log("Failed to fix type annotations", "ERROR")
        
        return {
            "tool": "type-annotations",
            "success": success,
            "duration": duration,
            "stdout": stdout,
            "stderr": stderr
        }

    def fix_security_issues(self) -> Dict[str, Any]:
        """Fix security-related issues using ruff."""
        self.log("Checking and fixing security issues...")
        start_time = time.time()
        
        success, stdout, stderr = self.run_command([
            "ruff", "check", "--select", "S", "--fix", "src", "tests"
        ], check=False)
        
        duration = time.time() - start_time
        
        if success:
            self.fixes_applied.append("security")
            self.log("Security issues fixed successfully", "SUCCESS")
        else:
            self.fixes_failed.append("security")
            self.log("Failed to fix security issues", "ERROR")
        
        return {
            "tool": "security",
            "success": success,
            "duration": duration,
            "stdout": stdout,
            "stderr": stderr
        }

    def fix_performance_issues(self) -> Dict[str, Any]:
        """Fix performance-related issues using ruff."""
        self.log("Checking and fixing performance issues...")
        start_time = time.time()
        
        success, stdout, stderr = self.run_command([
            "ruff", "check", "--select", "PERF", "--fix", "src", "tests"
        ], check=False)
        
        duration = time.time() - start_time
        
        if success:
            self.fixes_applied.append("performance")
            self.log("Performance issues fixed successfully", "SUCCESS")
        else:
            self.fixes_failed.append("performance")
            self.log("Failed to fix performance issues", "ERROR")
        
        return {
            "tool": "performance",
            "success": success,
            "duration": duration,
            "stdout": stdout,
            "stderr": stderr
        }

    def fix_complexity_issues(self) -> Dict[str, Any]:
        """Fix complexity-related issues using ruff."""
        self.log("Checking and fixing complexity issues...")
        start_time = time.time()
        
        success, stdout, stderr = self.run_command([
            "ruff", "check", "--select", "C90", "--fix", "src", "tests"
        ], check=False)
        
        duration = time.time() - start_time
        
        if success:
            self.fixes_applied.append("complexity")
            self.log("Complexity issues fixed successfully", "SUCCESS")
        else:
            self.fixes_failed.append("complexity")
            self.log("Failed to fix complexity issues", "ERROR")
        
        return {
            "tool": "complexity",
            "success": success,
            "duration": duration,
            "stdout": stdout,
            "stderr": stderr
        }

    def run_all_fixes(self) -> Dict[str, Any]:
        """Run all automatic fixes."""
        self.log("Starting comprehensive code quality fixes...")
        
        results = {}
        
        # Run fixes in logical order
        results["imports"] = self.fix_import_sorting()
        results["formatting"] = self.fix_formatting()
        results["linting"] = self.fix_linting_issues()
        results["type_annotations"] = self.fix_type_annotations()
        results["docstrings"] = self.fix_docstrings()
        results["security"] = self.fix_security_issues()
        results["performance"] = self.fix_performance_issues()
        results["complexity"] = self.fix_complexity_issues()
        
        # Calculate summary
        total_duration = (datetime.now() - self.start_time).total_seconds()
        
        summary = {
            "start_time": self.start_time.isoformat(),
            "end_time": datetime.now().isoformat(),
            "total_duration": total_duration,
            "dry_run": self.dry_run,
            "fixes_applied": len(self.fixes_applied),
            "fixes_failed": len(self.fixes_failed),
            "results": results
        }
        
        self.log(f"All fixes completed in {total_duration:.2f}s")
        return summary

    def create_backup(self) -> Optional[str]:
        """Create backup of source code before making changes."""
        if self.dry_run:
            return None
        
        backup_dir = Path("code-backup") / datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_dir.mkdir(parents=True, exist_ok=True)
        
        self.log("Creating backup...")
        
        try:
            if os.path.exists("src"):
                shutil.copytree("src", backup_dir / "src")
            if os.path.exists("tests"):
                shutil.copytree("tests", backup_dir / "tests")
            
            self.log(f"Backup created at: {backup_dir}", "SUCCESS")
            return str(backup_dir)
        except Exception as e:
            self.log(f"Failed to create backup: {e}", "ERROR")
            return None

    def verify_fixes(self) -> Dict[str, Any]:
        """Verify that fixes were applied successfully."""
        self.log("Verifying fixes...")
        
        verification_results = {}
        
        # Check if code is now properly formatted
        format_success, format_output, _ = self.run_command([
            "ruff", "format", "--check", "src", "tests"
        ], check=False)
        
        verification_results["formatting"] = {
            "is_formatted": format_success,
            "output": format_output
        }
        
        # Check if linting issues are resolved
        lint_success, lint_output, _ = self.run_command([
            "ruff", "check", "src", "tests"
        ], check=False)
        
        verification_results["linting"] = {
            "no_issues": lint_success,
            "output": lint_output
        }
        
        # Check import sorting
        import_success, import_output, _ = self.run_command([
            "isort", "--check-only", "--diff", "src", "tests"
        ], check=False)
        
        verification_results["imports"] = {
            "is_sorted": import_success,
            "output": import_output
        }
        
        return verification_results

    def print_summary(self):
        """Print a human-readable summary."""
        print("\n" + "="*60)
        print("🔧 CODE QUALITY FIX SUMMARY")
        print("="*60)
        
        if self.dry_run:
            print("⚠️  DRY RUN MODE - No changes were actually applied")
            print()
        
        if self.fixes_applied:
            print("✅ FIXES APPLIED:")
            for fix in self.fixes_applied:
                print(f"   • {fix.replace('-', ' ').title()}")
            print()
        
        if self.fixes_failed:
            print("❌ FIXES FAILED:")
            for fix in self.fixes_failed:
                print(f"   • {fix.replace('-', ' ').title()}")
            print()
        
        total_duration = (datetime.now() - self.start_time).total_seconds()
        print(f"⏱️  Total time: {total_duration:.2f}s")
        
        if not self.dry_run and self.fixes_applied:
            print("\n📝 NEXT STEPS:")
            print("1. Review the changes made to your code")
            print("2. Run tests to ensure everything still works: make test")
            print("3. Run quality checks to verify improvements: make quality")
            print("4. Consider committing changes if satisfied")
        
        if not self.dry_run and self.fixes_failed:
            print("\n🔧 MANUAL FIXES NEEDED:")
            print("Some issues couldn't be fixed automatically.")
            print("Please review the output above and fix manually.")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="TailOpsMCP Code Quality Auto-Fixer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --all                    # Fix all auto-fixable issues
  %(prog)s --imports --format       # Fix imports and formatting only
  %(prog)s --all --dry-run          # Preview changes without applying
  %(prog)s --lint --security        # Fix linting and security issues
        """
    )
    
    parser.add_argument(
        "--all",
        action="store_true",
        help="Fix all auto-fixable issues (default)"
    )
    
    parser.add_argument(
        "--imports",
        action="store_true",
        help="Fix import sorting and organization"
    )
    
    parser.add_argument(
        "--format",
        action="store_true",
        help="Fix code formatting"
    )
    
    parser.add_argument(
        "--lint",
        action="store_true",
        help="Fix linting issues"
    )
    
    parser.add_argument(
        "--type-annotations",
        action="store_true",
        help="Fix missing type annotations"
    )
    
    parser.add_argument(
        "--docstrings",
        action="store_true",
        help="Fix missing docstrings"
    )
    
    parser.add_argument(
        "--security",
        action="store_true",
        help="Fix security-related issues"
    )
    
    parser.add_argument(
        "--performance",
        action="store_true",
        help="Fix performance-related issues"
    )
    
    parser.add_argument(
        "--complexity",
        action="store_true",
        help="Fix complexity-related issues"
    )
    
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview changes without applying them"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output"
    )
    
    parser.add_argument(
        "--no-backup",
        action="store_true",
        help="Skip creating backup before making changes"
    )
    
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Skip verification after applying fixes"
    )
    
    args = parser.parse_args()
    
    # Determine which fixes to run
    run_all = args.all or not any([
        args.imports, args.format, args.lint, args.type_annotations,
        args.docstrings, args.security, args.performance, args.complexity
    ])
    
    fixer = CodeQualityFixer(dry_run=args.dry_run, verbose=args.verbose)
    
    # Create backup if not in dry run and not disabled
    backup_path = None
    if not args.dry_run and not args.no_backup:
        backup_path = fixer.create_backup()
    
    # Run fixes
    if run_all:
        summary = fixer.run_all_fixes()
    else:
        # Run specific fixes
        summary = {"results": {}}
        if args.imports:
            summary["results"]["imports"] = fixer.fix_import_sorting()
        if args.format:
            summary["results"]["formatting"] = fixer.fix_formatting()
        if args.lint:
            summary["results"]["linting"] = fixer.fix_linting_issues()
        if args.type_annotations:
            summary["results"]["type_annotations"] = fixer.fix_type_annotations()
        if args.docstrings:
            summary["results"]["docstrings"] = fixer.fix_docstrings()
        if args.security:
            summary["results"]["security"] = fixer.fix_security_issues()
        if args.performance:
            summary["results"]["performance"] = fixer.fix_performance_issues()
        if args.complexity:
            summary["results"]["complexity"] = fixer.fix_complexity_issues()
    
    # Verify fixes if not in dry run and not disabled
    if not args.dry_run and not args.no_verify:
        verification = fixer.verify_fixes()
        summary["verification"] = verification
        
        if args.verbose:
            print("\n" + "="*60)
            print("🔍 VERIFICATION RESULTS")
            print("="*60)
            for tool, result in verification.items():
                status = "✅" if result.get(f"is_{tool}" if tool != "linting" else "no_issues", False) else "❌"
                print(f"{tool.title()}: {status}")
    
    # Print summary
    fixer.print_summary()
    
    # Return exit code based on results
    if args.dry_run:
        return 0  # Dry run always succeeds
    
    return 0 if len(fixer.fixes_failed) == 0 else 1


if __name__ == "__main__":
    sys.exit(main())