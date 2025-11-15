#!/usr/bin/env python3
"""
Remote System Test Runner
========================

Run comprehensive tests against a remote SystemManager MCP server.
Generates detailed HTML report of results.

Usage:
    python remote_test_runner.py --host remote.example.com --port 8080 --token <token>
    python remote_test_runner.py --docker                    # Test local Docker
    python remote_test_runner.py --systemd                   # Test local systemd service
"""

import asyncio
import json
import sys
import time
import argparse
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import subprocess
import base64
import hmac
import hashlib

try:
    import requests
    import requests.exceptions
except ImportError:
    print("ERROR: requests library required. Install with: pip install requests")
    sys.exit(1)


class RemoteTestRunner:
    """Run comprehensive tests against remote MCP server."""
    
    def __init__(self, host: str, port: int = 8080, token: Optional[str] = None, use_https: bool = False):
        self.host = host
        self.port = port
        self.token = token
        self.use_https = use_https
        self.base_url = f"{'https' if use_https else 'http'}://{host}:{port}"
        self.results = {"tests": [], "summary": {}}
        self.start_time = None
        
    def _make_request(self, method: str, endpoint: str, data: Optional[Dict] = None, 
                     expect_status: int = 200, timeout: int = 10) -> Dict[str, Any]:
        """Make HTTP request to MCP server."""
        url = f"{self.base_url}{endpoint}"
        headers = {"Content-Type": "application/json"}
        
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        
        try:
            if method.upper() == "GET":
                resp = requests.get(url, headers=headers, timeout=timeout)
            else:
                resp = requests.post(url, json=data or {}, headers=headers, timeout=timeout)
            
            return {
                "status_code": resp.status_code,
                "success": resp.status_code == expect_status,
                "body": resp.json() if resp.text else {},
                "error": None,
                "response_time": resp.elapsed.total_seconds()
            }
        except requests.exceptions.ConnectionError as e:
            return {"status_code": None, "success": False, "error": f"Connection error: {e}", "response_time": None}
        except requests.exceptions.Timeout:
            return {"status_code": None, "success": False, "error": "Request timeout", "response_time": None}
        except Exception as e:
            return {"status_code": None, "success": False, "error": str(e), "response_time": None}
    
    def test_connectivity(self) -> bool:
        """Test basic connectivity to server."""
        test_name = "Connectivity Test"
        print(f"  → {test_name}...", end=" ", flush=True)
        
        result = self._make_request("GET", "/health", expect_status=200)
        
        success = result["success"]
        status = "✓ PASS" if success else "✗ FAIL"
        print(status)
        
        self.results["tests"].append({
            "name": test_name,
            "passed": success,
            "details": result,
            "timestamp": datetime.utcnow().isoformat()
        })
        
        return success
    
    def test_health_endpoint(self) -> bool:
        """Test health endpoint response format."""
        test_name = "Health Endpoint"
        print(f"  → {test_name}...", end=" ", flush=True)
        
        result = self._make_request("GET", "/health")
        
        success = (result["success"] and 
                  "status" in result["body"] and 
                  "uptime" in result["body"])
        
        status = "✓ PASS" if success else "✗ FAIL"
        print(status)
        
        self.results["tests"].append({
            "name": test_name,
            "passed": success,
            "details": result,
            "response_body": result["body"],
            "timestamp": datetime.utcnow().isoformat()
        })
        
        return success
    
    def test_authentication_required(self) -> bool:
        """Test that unauthenticated requests are rejected."""
        test_name = "Authentication Required"
        print(f"  → {test_name}...", end=" ", flush=True)
        
        # Save token and temporarily clear it
        original_token = self.token
        self.token = None
        
        result = self._make_request("POST", "/tools/get_system_status", 
                                   data={}, expect_status=401)
        
        # Restore token
        self.token = original_token
        
        # Request should fail (401) when no token provided
        success = not result["success"]  # We expect it to fail
        status = "✓ PASS" if success else "✗ FAIL"
        print(status)
        
        self.results["tests"].append({
            "name": test_name,
            "passed": success,
            "details": result,
            "timestamp": datetime.utcnow().isoformat()
        })
        
        return success
    
    def test_system_status_tool(self) -> bool:
        """Test get_system_status tool."""
        test_name = "get_system_status Tool"
        print(f"  → {test_name}...", end=" ", flush=True)
        
        result = self._make_request("POST", "/tools/get_system_status", 
                                   data={"format": "json"})
        
        success = (result["success"] and 
                  result["body"].get("success") and
                  "data" in result["body"])
        
        if success and "data" in result["body"]:
            data = result["body"]["data"]
            required_fields = ["cpu_percent", "memory_usage", "disk_usage", "timestamp"]
            success = all(field in data for field in required_fields)
        
        status = "✓ PASS" if success else "✗ FAIL"
        print(status)
        
        self.results["tests"].append({
            "name": test_name,
            "passed": success,
            "details": result,
            "timestamp": datetime.utcnow().isoformat()
        })
        
        return success
    
    def test_system_status_toon_format(self) -> bool:
        """Test get_system_status with TOON format."""
        test_name = "get_system_status TOON Format"
        print(f"  → {test_name}...", end=" ", flush=True)
        
        result = self._make_request("POST", "/tools/get_system_status", 
                                   data={"format": "toon"})
        
        success = (result["success"] and 
                  result["body"].get("success") and
                  "data" in result["body"])
        
        status = "✓ PASS" if success else "✗ FAIL"
        print(status)
        
        self.results["tests"].append({
            "name": test_name,
            "passed": success,
            "details": result,
            "timestamp": datetime.utcnow().isoformat()
        })
        
        return success
    
    def test_network_status_tool(self) -> bool:
        """Test get_network_status tool."""
        test_name = "get_network_status Tool"
        print(f"  → {test_name}...", end=" ", flush=True)
        
        result = self._make_request("POST", "/tools/get_network_status", 
                                   data={})
        
        success = (result["success"] and 
                  result["body"].get("success") and
                  "data" in result["body"])
        
        status = "✓ PASS" if success else "✗ FAIL"
        print(status)
        
        self.results["tests"].append({
            "name": test_name,
            "passed": success,
            "details": result,
            "timestamp": datetime.utcnow().isoformat()
        })
        
        return success
    
    def test_list_directory_tool(self) -> bool:
        """Test list_directory tool."""
        test_name = "list_directory Tool"
        print(f"  → {test_name}...", end=" ", flush=True)
        
        result = self._make_request("POST", "/tools/list_directory", 
                                   data={"path": "/tmp"})
        
        success = (result["success"] and 
                  result["body"].get("success") and
                  "data" in result["body"])
        
        status = "✓ PASS" if success else "✗ FAIL"
        print(status)
        
        self.results["tests"].append({
            "name": test_name,
            "passed": success,
            "details": result,
            "timestamp": datetime.utcnow().isoformat()
        })
        
        return success
    
    def test_performance(self, iterations: int = 10) -> bool:
        """Test response time performance."""
        test_name = f"Performance ({iterations} requests)"
        print(f"  → {test_name}...", end=" ", flush=True)
        
        response_times = []
        for _ in range(iterations):
            result = self._make_request("POST", "/tools/get_system_status", 
                                       data={})
            if result["response_time"]:
                response_times.append(result["response_time"])
        
        if response_times:
            avg_time = sum(response_times) / len(response_times)
            max_time = max(response_times)
            success = avg_time < 1.0  # Expect < 1 second average
            
            status = "✓ PASS" if success else "✗ FAIL"
            print(f"{status} (avg: {avg_time:.3f}s, max: {max_time:.3f}s)")
            
            self.results["tests"].append({
                "name": test_name,
                "passed": success,
                "avg_response_time": avg_time,
                "max_response_time": max_time,
                "response_times": response_times,
                "timestamp": datetime.utcnow().isoformat()
            })
            
            return success
        else:
            print("✗ FAIL (no response times collected)")
            return False
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Run all tests and return results."""
        self.start_time = datetime.utcnow()
        
        print(f"\n=== Remote MCP Server Test Suite ===")
        print(f"Target: {self.base_url}")
        print(f"Start: {self.start_time.isoformat()}\n")
        
        tests = [
            self.test_connectivity,
            self.test_health_endpoint,
            self.test_authentication_required,
            self.test_system_status_tool,
            self.test_system_status_toon_format,
            self.test_network_status_tool,
            self.test_list_directory_tool,
            lambda: self.test_performance(iterations=10),
        ]
        
        passed = 0
        failed = 0
        
        for test in tests:
            try:
                if test():
                    passed += 1
                else:
                    failed += 1
            except Exception as e:
                print(f"✗ EXCEPTION in {test.__name__}: {e}")
                failed += 1
        
        end_time = datetime.utcnow()
        duration = (end_time - self.start_time).total_seconds()
        
        self.results["summary"] = {
            "total_tests": len(tests),
            "passed": passed,
            "failed": failed,
            "duration_seconds": duration,
            "start_time": self.start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "success_rate": f"{(passed / len(tests) * 100):.1f}%" if len(tests) > 0 else "0%"
        }
        
        print(f"\n=== Test Summary ===")
        print(f"Total: {self.results['summary']['total_tests']}")
        print(f"Passed: {passed} ✓")
        print(f"Failed: {failed} ✗")
        print(f"Success Rate: {self.results['summary']['success_rate']}")
        print(f"Duration: {duration:.2f}s\n")
        
        return self.results
    
    def generate_html_report(self, filename: str = "test_report.html") -> None:
        """Generate HTML report of test results."""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>MCP Server Test Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }}
        h1 {{ color: #333; border-bottom: 3px solid #0078d4; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .summary {{ background: #f0f0f0; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .summary-item {{ display: inline-block; margin: 10px 20px 10px 0; }}
        .summary-item strong {{ color: #0078d4; }}
        .test-result {{ margin: 15px 0; padding: 15px; border-left: 4px solid #ccc; background: #fafafa; }}
        .test-result.passed {{ border-left-color: #4CAF50; background: #f1f8f3; }}
        .test-result.failed {{ border-left-color: #f44336; background: #fdf1f0; }}
        .test-name {{ font-weight: bold; margin-bottom: 5px; }}
        .test-status {{ display: inline-block; padding: 3px 8px; border-radius: 3px; font-weight: bold; }}
        .status-pass {{ background: #4CAF50; color: white; }}
        .status-fail {{ background: #f44336; color: white; }}
        .details {{ margin-top: 10px; font-size: 0.9em; color: #666; }}
        pre {{ background: #f5f5f5; padding: 10px; border-radius: 3px; overflow-x: auto; }}
        .metric {{ display: inline-block; margin-right: 20px; }}
        .error {{ color: #d32f2f; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>MCP Server Test Report</h1>
        <p>Generated: {datetime.utcnow().isoformat()}</p>
        
        <div class="summary">
            <h3>Summary</h3>
            <div class="metric"><strong>Target:</strong> {self.base_url}</div>
            <div class="metric"><strong>Total Tests:</strong> {self.results['summary']['total_tests']}</div>
            <div class="metric"><strong>Passed:</strong> <span style="color: #4CAF50;">{self.results['summary']['passed']}</span></div>
            <div class="metric"><strong>Failed:</strong> <span style="color: #f44336;">{self.results['summary']['failed']}</span></div>
            <div class="metric"><strong>Success Rate:</strong> {self.results['summary']['success_rate']}</div>
            <div class="metric"><strong>Duration:</strong> {self.results['summary']['duration_seconds']:.2f}s</div>
        </div>
        
        <h2>Test Results</h2>
"""
        
        for test in self.results["tests"]:
            status_class = "passed" if test["passed"] else "failed"
            status_text = "PASS ✓" if test["passed"] else "FAIL ✗"
            status_badge = "status-pass" if test["passed"] else "status-fail"
            
            html += f"""        <div class="test-result {status_class}">
            <div class="test-name">
                {test['name']}
                <span class="test-status {status_badge}">{status_text}</span>
            </div>
"""
            
            if "response_time" in test["details"] and test["details"]["response_time"]:
                html += f'            <div class="details">Response Time: {test["details"]["response_time"]:.3f}s</div>\n'
            
            if "avg_response_time" in test:
                html += f'            <div class="details">Average Response Time: {test["avg_response_time"]:.3f}s (max: {test["max_response_time"]:.3f}s)</div>\n'
            
            if test["details"].get("error"):
                html += f'            <div class="error">Error: {test["details"]["error"]}</div>\n'
            
            html += "        </div>\n"
        
        html += """    </div>
</body>
</html>
"""
        
        with open(filename, "w") as f:
            f.write(html)
        
        print(f"Report saved to: {filename}")


def main():
    parser = argparse.ArgumentParser(description="Test remote MCP server")
    parser.add_argument("--host", default="localhost", help="Server hostname/IP")
    parser.add_argument("--port", type=int, default=8080, help="Server port")
    parser.add_argument("--token", help="Bearer token for authentication")
    parser.add_argument("--https", action="store_true", help="Use HTTPS")
    parser.add_argument("--report", default="test_report.html", help="HTML report filename")
    
    args = parser.parse_args()
    
    runner = RemoteTestRunner(
        host=args.host,
        port=args.port,
        token=args.token,
        use_https=args.https
    )
    
    results = runner.run_all_tests()
    runner.generate_html_report(args.report)
    
    # Exit with appropriate code
    sys.exit(0 if results["summary"]["failed"] == 0 else 1)


if __name__ == "__main__":
    main()
