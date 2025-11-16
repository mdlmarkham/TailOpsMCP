"""
Intelligent Log Analysis Service using MCP Sampling
"""

import logging
import re
from typing import Dict, List, Optional, Any
from datetime import datetime

logger = logging.getLogger(__name__)


class LogAnalyzer:
    """Service for intelligent analysis of logs using AI sampling."""
    
    def __init__(self, mcp_client=None):
        """Initialize log analyzer with optional MCP client for sampling.
        
        Args:
            mcp_client: MCP client instance that supports sampling (create_message)
        """
        self.mcp_client = mcp_client
        
    async def analyze_container_logs(
        self,
        container_name: str,
        logs: str,
        context: Optional[str] = None
    ) -> Dict[str, Any]:
        """Analyze container logs using AI to extract insights.
        
        Args:
            container_name: Name of the container
            logs: Raw log content
            context: Optional context about what to look for
            
        Returns:
            Dictionary with analysis results including:
            - summary: High-level summary of log contents
            - errors: Detected errors with severity
            - warnings: Detected warnings
            - insights: AI-generated insights
            - recommendations: Suggested actions
        """
        if not self.mcp_client:
            # Fallback to basic analysis without AI
            return self._basic_analysis(container_name, logs)
        
        try:
            # Build analysis prompt
            prompt = self._build_analysis_prompt(container_name, logs, context)
            
            # Use MCP sampling to get AI analysis
            response = await self.mcp_client.create_message(
                messages=[{
                    "role": "user",
                    "content": prompt
                }],
                max_tokens=2000
            )
            
            # Parse AI response
            analysis = self._parse_ai_response(response)
            
            # Add basic stats
            analysis["stats"] = self._extract_stats(logs)
            
            return {
                "success": True,
                "container": container_name,
                "analyzed_at": datetime.now().isoformat(),
                "analysis": analysis
            }
            
        except Exception as e:
            logger.error(f"AI analysis failed: {e}, falling back to basic analysis")
            return self._basic_analysis(container_name, logs)
    
    def _build_analysis_prompt(
        self,
        container_name: str,
        logs: str,
        context: Optional[str] = None
    ) -> str:
        """Build prompt for AI log analysis."""
        
        prompt = f"""Analyze these Docker container logs and provide insights:

Container: {container_name}
Log Lines: {len(logs.splitlines())}

Logs:
```
{logs[-5000:]}  # Last 5000 chars to avoid token limits
```

Please provide:
1. **Summary**: Brief overview of what's happening in the logs
2. **Errors**: List any errors found with severity (CRITICAL/ERROR/WARNING)
3. **Root Cause**: If errors exist, identify the likely root cause
4. **Performance Issues**: Any performance concerns (memory, CPU, timeouts)
5. **Recommendations**: Specific actionable recommendations to fix issues

"""
        
        if context:
            prompt += f"\nSpecific Context: {context}\n"
        
        prompt += """
Format your response as JSON:
{
  "summary": "brief summary",
  "errors": [{"severity": "ERROR", "message": "...", "line_number": 123}],
  "root_cause": "identified root cause or null",
  "performance_issues": ["issue1", "issue2"],
  "recommendations": ["action1", "action2"]
}
"""
        
        return prompt
    
    def _parse_ai_response(self, response: Any) -> Dict[str, Any]:
        """Parse AI response into structured analysis."""
        import json
        
        try:
            # Extract content from MCP response
            content = response.content[0].text if hasattr(response, 'content') else str(response)
            
            # Try to parse as JSON
            # Look for JSON block in response
            json_match = re.search(r'\{[\s\S]*\}', content)
            if json_match:
                return json.loads(json_match.group(0))
            
            # Fallback: structure the text response
            return {
                "summary": content[:500],
                "errors": [],
                "root_cause": None,
                "performance_issues": [],
                "recommendations": []
            }
            
        except Exception as e:
            logger.error(f"Failed to parse AI response: {e}")
            return {
                "summary": "Failed to parse AI analysis",
                "errors": [],
                "root_cause": None,
                "performance_issues": [],
                "recommendations": []
            }
    
    def _basic_analysis(self, container_name: str, logs: str) -> Dict[str, Any]:
        """Basic pattern-based log analysis without AI."""
        
        lines = logs.splitlines()
        errors = []
        warnings = []
        
        # Pattern matching for common issues
        error_patterns = [
            (r'(?i)(error|exception|fatal|critical)', 'ERROR'),
            (r'(?i)(warning|warn)', 'WARNING'),
            (r'(?i)(out of memory|oom)', 'CRITICAL'),
            (r'(?i)(connection refused|timeout)', 'ERROR'),
            (r'(?i)(panic|segfault)', 'CRITICAL'),
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern, severity in error_patterns:
                if re.search(pattern, line):
                    entry = {
                        "severity": severity,
                        "message": line.strip(),
                        "line_number": i
                    }
                    if severity in ['CRITICAL', 'ERROR']:
                        errors.append(entry)
                    else:
                        warnings.append(entry)
                    break
        
        stats = self._extract_stats(logs)
        
        return {
            "success": True,
            "container": container_name,
            "analyzed_at": datetime.now().isoformat(),
            "analysis": {
                "summary": f"Found {len(errors)} errors and {len(warnings)} warnings in {len(lines)} log lines",
                "errors": errors[:10],  # Top 10
                "warnings": warnings[:10],  # Top 10
                "root_cause": self._infer_root_cause(errors),
                "performance_issues": [],
                "recommendations": self._generate_basic_recommendations(errors, warnings),
                "stats": stats
            }
        }
    
    def _extract_stats(self, logs: str) -> Dict[str, int]:
        """Extract basic statistics from logs."""
        lines = logs.splitlines()
        
        return {
            "total_lines": len(lines),
            "error_count": sum(1 for line in lines if re.search(r'(?i)error', line)),
            "warning_count": sum(1 for line in lines if re.search(r'(?i)warning', line)),
            "critical_count": sum(1 for line in lines if re.search(r'(?i)(critical|fatal)', line)),
        }
    
    def _infer_root_cause(self, errors: List[Dict]) -> Optional[str]:
        """Infer root cause from error patterns."""
        if not errors:
            return None
        
        # Look for common patterns
        error_messages = ' '.join([e['message'] for e in errors[:5]])
        
        if re.search(r'(?i)out of memory|oom', error_messages):
            return "Memory exhaustion - container may need increased memory limits"
        elif re.search(r'(?i)connection refused|econnrefused', error_messages):
            return "Service connectivity issue - dependent service may be down"
        elif re.search(r'(?i)permission denied|eacces', error_messages):
            return "Permission issue - check file/directory permissions"
        elif re.search(r'(?i)timeout', error_messages):
            return "Timeout issue - service may be slow or unresponsive"
        
        return "Multiple errors detected - review error details for patterns"
    
    def _generate_basic_recommendations(
        self,
        errors: List[Dict],
        warnings: List[Dict]
    ) -> List[str]:
        """Generate basic recommendations based on detected issues."""
        recommendations = []
        
        if not errors and not warnings:
            recommendations.append("No issues detected - container appears healthy")
            return recommendations
        
        error_text = ' '.join([e['message'] for e in errors])
        
        if re.search(r'(?i)out of memory|oom', error_text):
            recommendations.append("Increase container memory limits in docker-compose.yml")
            recommendations.append("Review application memory usage and optimize if needed")
        
        if re.search(r'(?i)connection refused', error_text):
            recommendations.append("Check if dependent services are running")
            recommendations.append("Verify network connectivity and service discovery")
        
        if re.search(r'(?i)permission denied', error_text):
            recommendations.append("Review file permissions and volume mounts")
            recommendations.append("Check container user permissions")
        
        if re.search(r'(?i)timeout', error_text):
            recommendations.append("Increase timeout values in configuration")
            recommendations.append("Investigate slow service response times")
        
        if len(errors) > 0:
            recommendations.append(f"Review detailed error logs ({len(errors)} errors found)")
        
        return recommendations if recommendations else ["Review logs for detailed diagnostics"]


async def analyze_logs_with_ai(
    container_name: str,
    logs: str,
    mcp_client=None,
    context: Optional[str] = None
) -> Dict[str, Any]:
    """Convenience function to analyze logs.
    
    Args:
        container_name: Name of the container
        logs: Raw log content
        mcp_client: MCP client instance for AI sampling
        context: Optional analysis context
        
    Returns:
        Analysis results dictionary
    """
    analyzer = LogAnalyzer(mcp_client)
    return await analyzer.analyze_container_logs(container_name, logs, context)
