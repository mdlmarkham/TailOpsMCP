#!/usr/bin/env python3
"""
Enhanced Security Scanner Capabilities

Adds comprehensive threat coverage to the security scanner including:
- Runtime security monitoring
- API security scanning  
- Database security checks
- Filesystem security validation
- Malware detection
- Threat intelligence integration
"""

import os
import re
import logging
from pathlib import Path
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


class EnhancedScannerMixin:
    """Mixin class to add enhanced scanning capabilities to SecurityScanner."""
    
    def _scan_runtime(self, target_path: str, result) -> None:
        """Scan for runtime security issues."""
        logger.info("Scanning runtime security...")
        
        # Check for runtime configuration issues
        runtime_files = self.find_runtime_files(target_path)
        
        for runtime_file in runtime_files:
            try:
                with open(runtime_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Check for suspicious runtime configurations
                suspicious_patterns = [
                    (r'exec.*\(', 'Arbitrary code execution capability'),
                    (r'shell_exec', 'Shell execution capability'),
                    (r'eval\s*\(', 'Code evaluation capability'),
                    (r'system\s*\(', 'System command execution'),
                    (r'subprocess\.call', 'Process execution without shell'),
                    (r'os\.system', 'Direct system command execution'),
                    (r'timeout.*=.*0', 'No timeout protection'),
                    (r'resource_limits.*none', 'No resource limits'),
                ]
                
                for pattern, description in suspicious_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        result.compliance_issues.append({
                            'type': 'runtime_security',
                            'severity': 'HIGH',
                            'description': f'Runtime security issue: {description}',
                            'file_path': runtime_file,
                            'remediation': 'Review runtime configuration and implement proper security controls'
                        })
                        
            except Exception as e:
                logger.warning(f"Error scanning runtime file {runtime_file}: {e}")

    def _scan_api_security(self, target_path: str, result) -> None:
        """Scan API security configurations."""
        logger.info("Scanning API security...")
        
        # Find API configuration files
        api_files = self.find_api_files(target_path)
        
        for api_file in api_files:
            try:
                with open(api_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Check for API security issues
                security_patterns = [
                    (r'auth.*=.*false', 'Authentication disabled'),
                    (r'clock_rate.*none', 'No rate limiting'),
                    (r'cors.*\*', 'CORS wildcard policy'),
                    (r'allow_origins.*\*\*', 'CORS permissive policy'),
                    (r'tls.*=.*false', 'TLS disabled'),
                    (r'api_key.*=.*""', 'Empty API key'),
                    (r'secret.*=.*""', 'Empty secret'),
                    (r'admin.*=.*true', 'Global admin access'),
                ]
                
                for pattern, description in security_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        result.compliance_issues.append({
                            'type': 'api_security',
                            'severity': 'HIGH',
                            'description': f'API security issue: {description}',
                            'file_path': api_file,
                            'remediation': 'Implement proper API security controls'
                        })
                        
            except Exception as e:
                logger.warning(f"Error scanning API file {api_file}: {e}")

    def _scan_database_security(self, target_path: str, result) -> None:
        """Scan database security configurations."""
        logger.info("Scanning database security...")
        
        # Find database configuration files
        db_files = self.find_database_files(target_path)
        
        for db_file in db_files:
            try:
                with open(db_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Check for database security issues
                security_patterns = [
                    (r'password.*=.*""', 'Empty database password'),
                    (r'encrypt.*=.*false', 'Database encryption disabled'),
                    (r'ssl.*=.*false', 'SSL/TLS disabled'),
                    (r'root.*password.*=.*"123456"', 'Weak root password'),
                    (r'grant.*all.*privileges', 'Excessive database privileges'),
                    (r'create.*user.*.* Identified.*by.*""', 'User without password'),
                    (r'max_connections.*=.*unlimited', 'Unlimited connections'),
                    (r'local_infile.*=.*1', 'Local file loading enabled'),
                ]
                
                for pattern, description in security_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        result.compliance_issues.append({
                            'type': 'database_security',
                            'severity': 'HIGH',
                            'description': f'Database security issue: {description}',
                            'file_path': db_file,
                            'remediation': 'Implement proper database security controls'
                        })
                        
            except Exception as e:
                logger.warning(f"Error scanning database file {db_file}: {e}")

    def _scan_filesystem_security(self, target_path: str, result) -> None:
        """Scan filesystem security configurations."""
        logger.info("Scanning filesystem security...")
        
        # Check for sensitive files with improper permissions
        sensitive_files = self.find_sensitive_files(target_path)
        
        for file_path in sensitive_files:
            try:
                stat_info = os.stat(file_path)
                permissions = oct(stat_info.st_mode)[-3:]
                
                # Check for world-writable sensitive files
                if permissions[2] in ['6', '7']:  # World writable
                    result.compliance_issues.append({
                        'type': 'filesystem_security',
                        'severity': 'HIGH',
                        'description': f'Sensitive file with world-writable permissions',
                        'file_path': file_path,
                        'remediation': 'Remove world-write permissions'
                    })
                
                # Check for group-writable configurations
                if file_path.endswith('.conf') or file_path.endswith('.config'):
                    if permissions[1] in ['6', '7']:  # Group writable
                        result.compliance_issues.append({
                            'type': 'filesystem_security',
                            'severity': 'MEDIUM',
                            'description': f'Configuration file with group-writable permissions',
                            'file_path': file_path,
                            'remediation': 'Restrict file permissions for configuration files'
                        })
                        
            except Exception as e:
                logger.warning(f"Error checking permissions for {file_path}: {e}")

    def _scan_malware(self, target_path: str, result) -> None:
        """Scan for malware indicators."""
        logger.info("Scanning for malware indicators...")
        
        # Scan for suspicious patterns in executable files
        suspicious_patterns = [
            r'\x90\x90\x90\x90\x90\x90',  # NOP sled
            r'eval.*base64_decode',      # Base64 encoded eval
            r'preg_replace.*\/e',        # PHP eval pattern
            r'shell_exec.*\$.*',         # Shell command execution
            r'powershell.*-enc',         # Encoded PowerShell
            r'cmd.*\/c',                 # Command prompt execution
            r'wget.*http.*\|.*sh',      # Download and execute
            r'curl.*http.*\|.*bash',     # Download and execute (curl)
        ]
        
        for root, dirs, files in os.walk(target_path):
            for file in files:
                file_path = os.path.join(root, file)
                
                # Skip binary files that are too large
                if os.path.getsize(file_path) > 1024 * 1024:  # 1MB limit
                    continue
                    
                try:
                    with open(file_path, 'rb') as f:
                        content = f.read()
                    
                    # Check for malware patterns
                    file_content_str = content.decode('utf-8', errors='ignore')
                    for pattern in suspicious_patterns:
                        if re.search(pattern, file_content_str, re.IGNORECASE):
                            result.compliance_issues.append({
                                'type': 'malware',
                                'severity': 'CRITICAL',
                                'description': f'Potential malware pattern detected',
                                'file_path': file_path,
                                'remediation': 'Isolate file and conduct thorough malware analysis'
                            })
                            break
                            
                except Exception as e:
                    logger.warning(f"Error scanning file {file_path}: {e}")

    def _scan_threat_intelligence(self, target_path: str, result) -> None:
        """Scan using threat intelligence indicators."""
        logger.info("Scanning with threat intelligence...")
        
        # Known malicious IPs and domains
        known_bad_patterns = [
            r'192\.168\.1\.[0-9]+.*malicious',  # Example malicious IP range
            r'evil\.example\.com',              # Example malicious domain
            r'malware\.dll',                    # Known malware file
            r'backdoor\.exe',                  # Known backdoor
        ]
        
        for root, dirs, files in os.walk(target_path):
            for file in files:
                file_path = os.path.join(root, file)
                
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    # Check against threat intelligence patterns
                    for pattern in known_bad_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            result.compliance_issues.append({
                                'type': 'threat_intelligence',
                                'severity': 'CRITICAL',
                                'description': f'Threat intelligence indicator detected',
                                'file_path': file_path,
                                'remediation': 'Investigate potential security threat immediately'
                            })
                            break
                            
                except Exception as e:
                    logger.warning(f"Error scanning file {file_path}: {e}")

    # Enhanced helper methods for new scan types
    def find_runtime_files(self, target_path: str) -> List[str]:
        """Find runtime configuration files."""
        patterns = [
            "*.service",           # Systemd service files
            "daemon.conf",         # Daemon configurations
            "runtime.yaml",        # Runtime configurations
            "worker*.py",          # Worker processes
            "server*.conf",        # Server configurations
            "supervisor.conf",     # Supervisor configurations
        ]
        
        files = []
        for pattern in patterns:
            files.extend(Path(target_path).rglob(pattern))
        
        return [str(f) for f in files]

    def find_api_files(self, target_path: str) -> List[str]:
        """Find API configuration files."""
        patterns = [
            "*api*.yaml",          # API configurations
            "*api*.json",          # API configurations
            "*api*.conf",          # API configurations
            "openapi.yaml",        # OpenAPI specifications
            "swagger.yaml",        # Swagger definitions
            "*server*.py",         # API server files
            "*routes*.py",         # API route files
        ]
        
        files = []
        for pattern in patterns:
            files.extend(Path(target_path).rglob(pattern))
        
        return [str(f) for f in files]

    def find_database_files(self, target_path: str) -> List[str]:
        """Find database configuration files."""
        patterns = [
            "*database*.conf",     # Database configurations
            "*db*.yaml",           # Database YAML configs
            "*db*.json",           # Database JSON configs
            "my.cnf",              # MySQL config
            "postgresql.conf",      # PostgreSQL config
            "redis.conf",          # Redis config
            "mongod.conf",         # MongoDB config
        ]
        
        files = []
        for pattern in patterns:
            files.extend(Path(target_path).rglob(pattern))
        
        return [str(f) for f in files]

    def find_sensitive_files(self, target_path: str) -> List[str]:
        """Find sensitive files that should have restricted permissions."""
        sensitive_patterns = [
            "*.key",              # Private keys
            "*.pem",              # Certificate files
            "*password*",         # Password files
            "*secret*",           # Secret files
            "*credentials*",      # Credential files
            "*config*.conf",      # Configuration files
            "*config*.yaml",      # Configuration files
            "*.env",              # Environment files
            "*.sh",               # Shell scripts
            "/etc/ssh/*",         # SSH configurations
        ]
        
        files = []
        for pattern in sensitive_patterns:
            files.extend(Path(target_path).rglob(pattern))
        
        return [str(f) for f in files if os.path.isfile(str(f)))]


# Enhanced Security Scanner Class
class EnhancedSecurityScanner(EnhancedScannerMixin):
    """Enhanced security scanner with comprehensive threat coverage."""
    
    def __init__(self, config=None):
        # Initialize base scanner (would be imported from main module)
        self.config = config
        
    def scan_enhanced_types(self, target_path: str, scan_type: str, result) -> None:
        """Dispatch enhanced scan methods."""
        scan_method_map = {
            'runtime': self._scan_runtime,
            'api_security': self._scan_api_security,
            'database_security': self._scan_database_security,
            'filesystem_security': self._scan_filesystem_security,
            'malware': self._scan_malware,
            'threat_intelligence': self._scan_threat_intelligence,
        }
        
        if scan_type in scan_method_map:
            scan_method_map[scan_type](target_path, result)
        else:
            raise ValueError(f"Unknown enhanced scan type: {scan_type}")


# Test the enhanced scanner
def test_enhanced_scanner():
    """Test enhanced security scanner capabilities."""
    from ..scanner import SecurityScanConfig, ScanResult, ScanStatus, ScanType
    from datetime import datetime
    
    print("🔍 Testing Enhanced Security Scanner...")
    
    # Test on project directory
    target_path = "/home/mdlmarkham/projects/Personal/TailOpsMCP"
    
    scanner = EnhancedSecurityScanner()
    
    # Test each enhanced scan type
    enhanced_scan_types = [
        'runtime',
        'api_security', 
        'database_security',
        'filesystem_security',
        'malware',
        'threat_intelligence'
    ]
    
    for scan_type in enhanced_scan_types:
        print(f"\n📡 Testing {scan_type.upper()} scan...")
        
        # Create mock result
        class MockResult:
            def __init__(self):
                self.compliance_issues = []
        
        result = MockResult()
        
        try:
            scanner.scan_enhanced_types(target_path, scan_type, result)
            issues_found = len(result.compliance_issues)
            print(f"   ✅ {scan_type}: {issues_found} issues found")
            
            if issues_found > 0:
                for issue in result.compliance_issues[:3]:  # Show first 3 issues
                    print(f"      - {issue.get('description', 'Unknown')}")
                    
        except Exception as e:
            print(f"   ❌ {scan_type}: Error - {e}")
    
    print("\n🎯 Enhanced Security Scanner Tests Complete!")


if __name__ == "__main__":
    test_enhanced_scanner()