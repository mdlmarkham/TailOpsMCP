# Intelligent Log Analysis with AI Sampling (Control Plane Gateway)

## Overview

The TailOpsMCP control plane gateway includes **intelligent log analysis** powered by AI sampling across all managed targets. This feature transforms raw container logs from multiple systems into actionable insights, automatically identifying issues, determining root causes, and providing specific recommendations across your entire infrastructure.

## What is MCP Sampling? (Gateway Context)

**Sampling** allows the MCP server to make LLM calls back to the client, enabling AI-powered analysis within server-side tools. In the control plane gateway architecture, this creates a powerful feedback loop where:

1. Client (VS Code/Copilot) calls server tool through the gateway
2. Gateway retrieves data from multiple targets across the infrastructure (e.g., container logs from web servers, databases, etc.)
3. Gateway uses sampling to ask the LLM to analyze the aggregated data
4. Gateway returns AI-enhanced insights to the client with cross-system context

## Features (Multi-Target Analysis)

### 🔍 Intelligent Analysis Across Targets
- **Cross-System Error Detection**: Identifies errors, warnings, and critical issues across all managed systems
- **Distributed Root Cause Analysis**: Determines why problems occurred with multi-system context
- **Performance Insights**: Detects memory leaks, timeouts, and resource issues across the infrastructure
- **Contextual Understanding**: Analyzes logs in context of the application and target environment

### 💡 Actionable Recommendations (Gateway-Specific)
- Specific commands to run for diagnosis across multiple targets
- Configuration changes to prevent issues with target-specific considerations
- Best practices for container orchestration across the infrastructure
- Docker Compose improvements with multi-target deployment patterns

### 🎯 Dual-Mode Operation (Gateway Enhanced)
1. **AI-Enhanced Mode**: Uses LLM sampling for deep analysis across all targets (when available)
2. **Basic Mode**: Falls back to pattern matching with target-specific rules if sampling unavailable

## New MCP Tools (Gateway Interface)

### `analyze_container_logs` (Multi-Target)

Intelligently analyze Docker container logs across multiple targets to identify issues and provide recommendations.

**Parameters:**
- `name_or_id` (required): Container name or ID to analyze
- `target` (optional): Target ID or "all" for all targets (default: current target)
- `lines` (optional, default: 200): Number of recent log lines to analyze
- `context` (optional): Specific context or question about the logs
- `use_ai` (optional, default: true): Enable AI analysis if available

**Returns:**
```json
{
  "success": true,
  "target": "web-server-01",
  "container": "nginx-web",
  "analyzed_at": "2024-11-15T10:30:00.000Z",
  "analysis": {
    "summary": "Container experiencing critical memory exhaustion...",
    "errors": [
      {
        "severity": "CRITICAL",
        "message": "Out of memory: Cannot allocate 256MB",
        "line_number": 5
      }
    ],
    "root_cause": "Memory leak or insufficient memory allocation...",
    "performance_issues": [
      "Memory usage spiked to 1.8GB before failure"
    ],
    "recommendations": [
      "Increase container memory limit to at least 2.5GB",
      "Investigate memory leak in application code"
    ],
    "stats": {
      "total_lines": 200,
      "error_count": 5,
      "warning_count": 3,
      "critical_count": 2
    }
  }
}
```

## Usage Examples

### From VS Code with GitHub Copilot

```
User: "Why did my nginx container crash?"

Copilot: [calls analyze_container_logs tool]

Result:
📊 Analysis Summary:
Container experiencing critical memory exhaustion leading to OOM killer termination

🔍 Root Cause:
Memory leak or insufficient memory allocation. Exit code 137 indicates OOM killer
intervention.

💡 Recommendations:
• Increase container memory limit to at least 2.5GB
• Investigate memory leak in application code
• Add memory monitoring and alerts at 80% threshold
```

### Programmatic Usage

```python
from src.services.log_analyzer import LogAnalyzer

# Create analyzer with MCP client for AI sampling
analyzer = LogAnalyzer(mcp_client=your_mcp_client)

# Analyze logs
result = await analyzer.analyze_container_logs(
    container_name="web-app",
    logs=raw_logs,
    context="application keeps restarting"
)

print(result['analysis']['summary'])
print(result['analysis']['recommendations'])
```

## Comparison: Basic vs AI-Enhanced Analysis

### Basic Pattern Matching
```
Summary: Found 5 errors and 1 warnings in 10 log lines
Root Cause: Memory exhaustion - container may need increased memory limits
Recommendations:
  • Increase container memory limits in docker-compose.yml
  • Review application memory usage and optimize if needed
```

### AI-Enhanced Analysis
```
Summary: Container experiencing critical memory exhaustion leading to OOM killer
         termination with exit code 137

Root Cause: Memory leak or insufficient memory allocation. The progressive increase
            from 1.8GB to failure point indicates a leak rather than a spike. Exit
            code 137 confirms OOM killer intervention.

Performance Issues:
  • Memory usage spiked from normal 200MB to 1.8GB in 3 minutes
  • Worker process crashed attempting 256MB allocation
  • Container terminated by kernel OOM killer (SIGKILL)

Recommendations:
  • Increase container memory limit to at least 2.5GB (--memory=2.5g)
  • Investigate memory leak in application code, particularly in worker processes
  • Add memory monitoring with alerts at 80% threshold
  • Consider implementing memory-efficient caching strategies
  • Review nginx worker_processes and worker_connections settings
```

## Deployment

### 1. Update Server Code

The code is already integrated. Simply restart your TailOpsMCP server:

```bash
ssh dev1.tailf9480.ts.net
cd /opt/systemmanager
git pull
sudo systemctl restart systemmanager-mcp
```

### 2. Client Configuration

The MCP client configuration already supports sampling - no changes needed:

```json
{
  "Dev1-TailOpsMCP": {
    "type": "sse",
    "url": "http://dev1.tailf9480.ts.net:8080/sse",
    "headers": {
      "Authorization": "Bearer YOUR_TOKEN"
    }
  }
}
```

### 3. Verify Deployment

```bash
# Check logs for sampling capability
ssh dev1.tailf9480.ts.net "tail -f /opt/systemmanager/logs/mcp_server.log"

# Should see:
# [INFO] Starting TailOpsMCP Server on http://0.0.0.0:8080
# [INFO] Intelligent log analysis with AI sampling enabled
```

## Testing

Run the test suite to verify functionality:

```bash
python test_log_analysis.py
```

This tests:
- ✅ Basic pattern-based analysis (no AI)
- ✅ AI-enhanced analysis (simulated)
- ✅ Multiple error scenarios (OOM, connection, permissions)
- ✅ Healthy container detection

## Security Considerations

The `analyze_container_logs` tool requires the following scopes:
- `readonly` or `docker` - to read container logs
- Standard authentication applies

No sensitive data is sent to the LLM - logs are truncated to the most recent lines and can be filtered.

## Performance

- **Basic Analysis**: < 100ms (pattern matching only)
- **AI Analysis**: 1-5 seconds (includes LLM sampling call)
- **Memory**: Minimal overhead (logs are streamed, not stored)
- **Caching**: Container status cached for 5 seconds

## Common Use Cases

### 1. Container Crash Investigation
```
analyze_container_logs(
    name_or_id="crashed-app",
    lines=500,
    context="why did this container crash?"
)
```

### 2. Performance Debugging
```
analyze_container_logs(
    name_or_id="slow-api",
    lines=1000,
    context="application response times are slow"
)
```

### 3. Startup Failures
```
analyze_container_logs(
    name_or_id="failing-service",
    lines=100,
    context="container won't start properly"
)
```

### 4. Regular Health Checks
```
analyze_container_logs(
    name_or_id="production-web",
    lines=200,
    context="routine health check"
)
```

## Architecture

```
┌─────────────────────────────────────────────────┐
│ VS Code / GitHub Copilot (Client)              │
│                                                 │
│  User: "Why did nginx crash?"                  │
└────────────────┬────────────────────────────────┘
                 │
                 │ MCP Tool Call
                 │ analyze_container_logs(name_or_id="nginx")
                 ▼
┌─────────────────────────────────────────────────┐
│ TailOpsMCP Server                         │
│                                                 │
│  ┌─────────────────────────────────────────┐   │
│  │ 1. Fetch container logs (Docker API)   │   │
│  └─────────────────┬───────────────────────┘   │
│                    │                            │
│  ┌─────────────────▼───────────────────────┐   │
│  │ 2. Build analysis prompt                │   │
│  │    - Format logs                        │   │
│  │    - Add context                        │   │
│  └─────────────────┬───────────────────────┘   │
│                    │                            │
│  ┌─────────────────▼───────────────────────┐   │
│  │ 3. MCP Sampling (create_message)        │   │
│  │    - Send prompt to LLM                 │◄──┼─── AI calls back to client
│  │    - Receive AI analysis                │   │    via sampling
│  └─────────────────┬───────────────────────┘   │
│                    │                            │
│  ┌─────────────────▼───────────────────────┐   │
│  │ 4. Parse & enhance response             │   │
│  │    - Extract JSON analysis              │   │
│  │    - Add statistics                     │   │
│  └─────────────────┬───────────────────────┘   │
│                    │                            │
└────────────────────┼────────────────────────────┘
                     │
                     │ Return enhanced analysis
                     ▼
┌─────────────────────────────────────────────────┐
│ VS Code / GitHub Copilot                        │
│                                                 │
│  📊 Summary: OOM killer terminated container   │
│  🔍 Root Cause: Memory leak in worker process  │
│  💡 Recommendations:                            │
│     • Increase memory to 2.5GB                 │
│     • Investigate worker process memory usage  │
└─────────────────────────────────────────────────┘
```

## Future Enhancements

Potential improvements with sampling:

1. **Multi-Container Analysis**: Correlate logs across related containers
2. **Trend Detection**: Analyze historical patterns over time
3. **Automated Remediation**: Generate docker-compose patches
4. **Custom Playbooks**: Learn from past fixes and suggest known solutions
5. **Integration with Monitoring**: Combine logs with metrics for deeper insights

## Troubleshooting

### AI Analysis Not Working

If you see basic analysis instead of AI-enhanced:

1. **Check FastMCP version**: Ensure `fastmcp>=1.0.0`
2. **Verify sampling support**: Check server logs for sampling initialization
3. **Test with simulation**: Run `python test_log_analysis.py`
4. **Check client support**: Ensure VS Code MCP client supports sampling

### Fallback Mode

The tool automatically falls back to basic pattern matching if:
- MCP client doesn't support sampling
- AI analysis fails or times out
- Network issues prevent sampling calls

This ensures the tool always provides value, even without AI.

## Related Documentation

- [MCP Sampling Specification](https://modelcontextprotocol.io/docs/concepts/sampling)
- [FastMCP Documentation](https://github.com/jlowin/fastmcp)
- [TailOpsMCP Quick Reference](../QUICK_REFERENCE.md)
- [Security Configuration](./SECURITY.md)
