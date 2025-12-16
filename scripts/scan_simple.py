#!/usr/bin/env python3
"""
TailOpsMCP Security Scanner CLI (Simplified Version)

A simplified security scanning tool that provides basic functionality
without complex dependencies on the security framework.

Usage:
    python scripts/scan.py [OPTIONS] [TARGET_PATH]

Examples:
    # Quick security scan
    python scripts/scan.py --quick

    # Full security scan with report
    python scripts/scan.py --full --output security-report.json

    # Scan for secrets only
    python scripts/scan.py --secrets --output secrets-report.json
"""

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any
import hashlib

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))


class SimpleSecurityScanner:
    """Simplified security scanner for basic functionality."""

    def __init__(self):
        self.findings = []
        
    def scan_for_secrets(self, target_path: str) -> List[Dict[str, Any]]:
        """Scan for exposed secrets in files."""
        secrets_patterns = [
            (r'password\s*=\s*["\']([^"\']+)["\']', 'password'),
            (r'secret\s*=\s*["\']([^"\']+)["\']', 'secret'),
            (r'api_key\s*=\s*["\']([^"\']+)["\']', 'api_key'),
            (r'token\s*=\s*["\']([^"\']+)["\']', 'token'),
            (r'aws_access_key_id\s*=\s*["\']([^"\']+)["\']', 'aws_access_key'),
            (r'aws_secret_access_key\s*=\s*["\']([^"\']+)["\']', 'aws_secret_key'),
        ]
        
        findings = []
        
        for file_path in self._find_files(target_path):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    for line_num, line in enumerate(content.split('\n'), 1):
                        for pattern, secret_type in secrets_patterns:
                            matches = re.finditer(pattern, line, re.IGNORECASE)
                            for match in matches:
                                findings.append({
                                    'type': 'secret',
                                    'secret_type': secret_type,
                                    'file': file_path,
                                    'line': line_num,
                                    'content': line.strip(),
                                    'match': match.group(1)[:10] + '...' if len(match.group(1)) > 10 else match.group(1)
                                })
            except Exception as e:
                print(f"Warning: Could not read {file_path}: {e}")
                
        return findings

    def scan_with_bandit(self, target_path: str) -> List[Dict[str, Any]]:
        """Run bandit security scanner."""
        try:
            result = subprocess.run([
                'bandit', '-r', target_path, '-f', 'json'
            ], capture_output=True, text=True, timeout=60)
            
            if result.stdout.strip():
                try:
                    bandit_data = json.loads(result.stdout)
                    return bandit_data.get('results', [])
                except json.JSONDecodeError:
                    return []
            return []
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []

    def scan_with_safety(self, target_path: str) -> List[Dict[str, Any]]:
        """Run safety vulnerability scanner."""
        try:
            result = subprocess.run([
                'safety', 'check', '--json'
            ], capture_output=True, text=True, timeout=60)
            
            if result.stdout.strip():
                try:
                    safety_data = json.loads(result.stdout)
                    return safety_data
                except json.JSONDecodeError:
                    return []
            return []
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []

    def _find_files(self, target_path: str) -> List[str]:
        """Find Python files to scan."""
        files = []
        target = Path(target_path)
        
        for ext in ['*.py', '*.txt', '*.md', '*.yml', '*.yaml', '*.json']:
            files.extend(target.rglob(ext))
            
        return [str(f) for f in files if f.is_file()]

    def generate_report(self, findings: Dict[str, Any], output_file: Optional[str] = None) -> str:
        """Generate security report."""
        report = {
            "scan_info": {
                "target_path": findings.get("target_path", "."),
                "scan_time": datetime.now().isoformat(),
                "scanner_version": "simplified-1.0.0"
            },
            "summary": {
                "total_files_scanned": len(findings.get("files_scanned", [])),
                "secrets_found": len(findings.get("secrets", [])),
                "bandit_issues": len(findings.get("bandit_issues", [])),
                "safety_vulnerabilities": len(findings.get("safety_issues", [])),
                "total_issues": len(findings.get("secrets", [])) + len(findings.get("bandit_issues", [])) + len(findings.get("safety_issues", []))
            },
            "findings": findings
        }
        
        if output_file:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2, default=str)
                
        return json.dumps(report, indent=2, default=str)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="TailOpsMCP Simplified Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "target_path",
        nargs="?",
        default=".",
        help="Path to scan (default: current directory)"
    )
    
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Quick scan (secrets + basic checks)"
    )
    
    parser.add_argument(
        "--secrets",
        action="store_true",
        help="Scan for exposed secrets only"
    )
    
    parser.add_argument(
        "--full",
        action="store_true",
        help="Full scan with bandit and safety"
    )
    
    parser.add_argument(
        "--output", "-o",
        help="Output file for report"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output"
    )
    
    args = parser.parse_args()
    
    # Check if target path exists
    target_path = os.path.abspath(args.target_path)
    if not os.path.exists(target_path):
        print(f"❌ Error: Target path '{target_path}' does not exist")
        return 1
    
    print(f"🔍 Scanning: {target_path}")
    
    scanner = SimpleSecurityScanner()
    findings = {
        "target_path": target_path,
        "files_scanned": scanner._find_files(target_path)
    }
    
    try:
        # Run scans based on arguments
        if args.secrets or args.quick or args.full:
            if args.verbose:
                print("Scanning for secrets...")
            findings["secrets"] = scanner.scan_for_secrets(target_path)
            print(f"Found {len(findings['secrets'])} potential secrets")
        
        if args.full:
            if args.verbose:
                print("Running bandit scan...")
            findings["bandit_issues"] = scanner.scan_with_bandit(target_path)
            print(f"Found {len(findings['bandit_issues'])} bandit issues")
            
            if args.verbose:
                print("Running safety scan...")
            findings["safety_issues"] = scanner.scan_with_safety(target_path)
            print(f"Found {len(findings['safety_issues'])} safety issues")
        
        # Generate and save report
        report = scanner.generate_report(findings, args.output)
        
        # Print summary
        total_issues = findings["summary"]["total_issues"]
        print(f"\n📊 Scan Summary:")
        print(f"Files scanned: {len(findings['files_scanned'])}")
        print(f"Total issues found: {total_issues}")
        
        if total_issues == 0:
            print("✅ No security issues found!")
        else:
            print("⚠️  Security issues detected!")
            
        if args.verbose:
            print("\n" + "="*60)
            print("📄 DETAILED REPORT")
            print("="*60)
            print(report)
        
        return 0 if total_issues == 0 else 1
        
    except KeyboardInterrupt:
        print("\n⚠️ Scan interrupted by user")
        return 1
    except Exception as e:
        print(f"❌ Error during scan: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())