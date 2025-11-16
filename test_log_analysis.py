"""
Test Intelligent Log Analysis with Sampling
"""

import asyncio
import sys
from src.services.log_analyzer import LogAnalyzer


# Sample problematic logs for testing
SAMPLE_LOGS = {
    "nginx_oom": """
2024-11-15T10:23:45.123Z [INFO] Starting nginx web server
2024-11-15T10:23:46.234Z [INFO] Listening on port 80
2024-11-15T10:25:12.456Z [WARNING] High memory usage detected: 1.8GB
2024-11-15T10:26:45.678Z [ERROR] Memory allocation failed
2024-11-15T10:26:45.789Z [CRITICAL] Out of memory: Cannot allocate 256MB
2024-11-15T10:26:45.890Z [ERROR] Worker process crashed
2024-11-15T10:26:46.001Z [INFO] Attempting to restart worker
2024-11-15T10:26:46.112Z [CRITICAL] OOM killer terminated process
2024-11-15T10:26:47.223Z [ERROR] Container exiting with code 137
""",
    "database_connection": """
2024-11-15T10:30:00.000Z [INFO] PostgreSQL database starting
2024-11-15T10:30:01.111Z [INFO] Initialization complete
2024-11-15T10:35:23.456Z [ERROR] Connection refused on port 5432
2024-11-15T10:35:23.567Z [ERROR] ECONNREFUSED 127.0.0.1:5432
2024-11-15T10:35:24.678Z [WARNING] Retrying connection (attempt 1/3)
2024-11-15T10:35:29.789Z [ERROR] Connection timeout after 5s
2024-11-15T10:35:29.890Z [ERROR] Failed to connect to database
2024-11-15T10:35:30.001Z [CRITICAL] Application startup failed
""",
    "permission_denied": """
2024-11-15T10:40:00.000Z [INFO] Application starting
2024-11-15T10:40:01.111Z [ERROR] EACCES: permission denied, open '/data/config.json'
2024-11-15T10:40:01.222Z [ERROR] Failed to read configuration file
2024-11-15T10:40:02.333Z [WARNING] Using default configuration
2024-11-15T10:40:05.444Z [ERROR] EACCES: permission denied, mkdir '/var/log/app'
2024-11-15T10:40:05.555Z [ERROR] Cannot create log directory
2024-11-15T10:40:06.666Z [CRITICAL] Application cannot continue without logging
""",
    "healthy": """
2024-11-15T11:00:00.000Z [INFO] Application starting
2024-11-15T11:00:01.111Z [INFO] Database connection established
2024-11-15T11:00:02.222Z [INFO] Cache initialized
2024-11-15T11:00:03.333Z [INFO] API server listening on port 3000
2024-11-15T11:00:10.444Z [INFO] Processed request: GET /health - 200 OK
2024-11-15T11:00:15.555Z [INFO] Processed request: GET /api/users - 200 OK
2024-11-15T11:00:20.666Z [INFO] Background job completed successfully
"""
}


async def test_basic_analysis():
    """Test basic pattern-based analysis (without AI)."""
    print("=" * 80)
    print("TEST 1: Basic Pattern-Based Analysis (No AI)")
    print("=" * 80)
    
    analyzer = LogAnalyzer(mcp_client=None)
    
    for scenario, logs in SAMPLE_LOGS.items():
        print(f"\n--- Analyzing: {scenario} ---")
        result = await analyzer.analyze_container_logs(
            container_name=f"test-{scenario}",
            logs=logs
        )
        
        if result["success"]:
            analysis = result["analysis"]
            print(f"Summary: {analysis['summary']}")
            print(f"Stats: {analysis['stats']}")
            
            if analysis['errors']:
                print(f"Errors found: {len(analysis['errors'])}")
                for error in analysis['errors'][:3]:
                    print(f"  - [{error['severity']}] Line {error['line_number']}: {error['message'][:80]}")
            
            if analysis.get('root_cause'):
                print(f"Root Cause: {analysis['root_cause']}")
            
            if analysis.get('recommendations'):
                print("Recommendations:")
                for rec in analysis['recommendations'][:3]:
                    print(f"  • {rec}")
        else:
            print(f"Analysis failed: {result.get('error')}")
        
        print()


async def test_with_ai_simulation():
    """Test with simulated AI response."""
    print("=" * 80)
    print("TEST 2: AI-Enhanced Analysis (Simulated)")
    print("=" * 80)
    print("Note: This simulates AI analysis without actual LLM calls")
    print()
    
    # Create a mock MCP client
    class MockMCPClient:
        async def create_message(self, messages, max_tokens=2000):
            """Simulate AI response."""
            prompt = messages[0]["content"]
            
            # Simple simulation based on log content
            if "Out of memory" in prompt or "OOM" in prompt:
                response_text = """{
  "summary": "Container experiencing critical memory exhaustion leading to OOM killer termination",
  "errors": [
    {"severity": "CRITICAL", "message": "Out of memory: Cannot allocate 256MB", "line_number": 5},
    {"severity": "CRITICAL", "message": "OOM killer terminated process", "line_number": 8},
    {"severity": "ERROR", "message": "Container exiting with code 137", "line_number": 9}
  ],
  "root_cause": "Memory leak or insufficient memory allocation. Exit code 137 indicates OOM killer intervention.",
  "performance_issues": [
    "Memory usage spiked to 1.8GB before failure",
    "Worker process crashed due to allocation failure",
    "Container terminated by kernel OOM killer"
  ],
  "recommendations": [
    "Increase container memory limit to at least 2.5GB",
    "Investigate memory leak in application code",
    "Add memory monitoring and alerts at 80% threshold",
    "Consider implementing memory-efficient caching strategies"
  ]
}"""
            elif "Connection refused" in prompt or "ECONNREFUSED" in prompt:
                response_text = """{
  "summary": "Database connection failures preventing application startup",
  "errors": [
    {"severity": "ERROR", "message": "Connection refused on port 5432", "line_number": 3},
    {"severity": "ERROR", "message": "ECONNREFUSED 127.0.0.1:5432", "line_number": 4},
    {"severity": "CRITICAL", "message": "Application startup failed", "line_number": 8}
  ],
  "root_cause": "PostgreSQL service not running or not accessible on expected port 5432",
  "performance_issues": [
    "5-second connection timeout indicates service unavailability",
    "Application unable to proceed without database connectivity"
  ],
  "recommendations": [
    "Verify PostgreSQL container is running: docker ps | grep postgres",
    "Check Docker network connectivity between containers",
    "Ensure database service starts before application container",
    "Add health checks and proper service dependencies in docker-compose.yml"
  ]
}"""
            elif "permission denied" in prompt or "EACCES" in prompt:
                response_text = """{
  "summary": "Multiple file permission errors preventing application initialization",
  "errors": [
    {"severity": "ERROR", "message": "EACCES: permission denied, open '/data/config.json'", "line_number": 2},
    {"severity": "ERROR", "message": "EACCES: permission denied, mkdir '/var/log/app'", "line_number": 5},
    {"severity": "CRITICAL", "message": "Application cannot continue without logging", "line_number": 7}
  ],
  "root_cause": "Container process lacks necessary file system permissions for mounted volumes",
  "performance_issues": [],
  "recommendations": [
    "Check volume mount permissions: ls -la /data /var/log",
    "Ensure container user matches host volume ownership",
    "Add USER directive in Dockerfile or update docker-compose.yml",
    "Consider using named volumes with proper permissions"
  ]
}"""
            else:
                response_text = """{
  "summary": "Application running normally with no critical issues detected",
  "errors": [],
  "root_cause": null,
  "performance_issues": [],
  "recommendations": [
    "System appears healthy - continue monitoring",
    "Consider adding structured logging for better observability"
  ]
}"""
            
            class Response:
                def __init__(self, text):
                    self.content = [type('obj', (object,), {'text': text})]
            
            return Response(response_text)
    
    analyzer = LogAnalyzer(mcp_client=MockMCPClient())
    
    for scenario, logs in SAMPLE_LOGS.items():
        print(f"\n--- AI Analysis: {scenario} ---")
        result = await analyzer.analyze_container_logs(
            container_name=f"test-{scenario}",
            logs=logs
        )
        
        if result["success"]:
            analysis = result["analysis"]
            print(f"\n📊 Summary:")
            print(f"   {analysis['summary']}")
            
            if analysis.get('errors'):
                print(f"\n❌ Errors ({len(analysis['errors'])}):")
                for error in analysis['errors'][:3]:
                    print(f"   [{error['severity']}] {error['message']}")
            
            if analysis.get('root_cause'):
                print(f"\n🔍 Root Cause:")
                print(f"   {analysis['root_cause']}")
            
            if analysis.get('performance_issues'):
                print(f"\n⚠️  Performance Issues:")
                for issue in analysis['performance_issues']:
                    print(f"   • {issue}")
            
            if analysis.get('recommendations'):
                print(f"\n💡 Recommendations:")
                for rec in analysis['recommendations']:
                    print(f"   • {rec}")
            
            print(f"\n📈 Stats: {analysis['stats']}")
        else:
            print(f"Analysis failed: {result.get('error')}")
        
        print()


async def main():
    """Run all tests."""
    print("\n" + "=" * 80)
    print("INTELLIGENT LOG ANALYSIS - TEST SUITE")
    print("=" * 80)
    print()
    
    await test_basic_analysis()
    print("\n\n")
    await test_with_ai_simulation()
    
    print("\n" + "=" * 80)
    print("TESTS COMPLETE")
    print("=" * 80)
    print("\nNext Steps:")
    print("1. Deploy the updated server to enable real AI analysis")
    print("2. Use the 'analyze_container_logs' tool from VS Code")
    print("3. Compare basic vs AI-enhanced analysis results")
    print()


if __name__ == "__main__":
    asyncio.run(main())
