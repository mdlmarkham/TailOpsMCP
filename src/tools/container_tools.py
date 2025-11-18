"""Docker container management tools for TailOpsMCP."""
import logging
from typing import Literal, Union, Optional
from datetime import datetime
from fastmcp import FastMCP, Context
from src.auth.middleware import secure_tool
from src.server.dependencies import deps
from src.server.utils import format_response, format_error
from src.tools import stack_tools

logger = logging.getLogger(__name__)

def register_tools(mcp: FastMCP):
    """Register Docker container management tools with MCP instance."""

    @mcp.tool()
    @secure_tool("get_container_list")
    async def get_container_list(format: Literal["json", "toon"] = "toon") -> Union[dict, str]:
        """List all Docker containers with status and image information.

        Args:
            format: Response format - 'toon' (compact, default) or 'json' (verbose)
        """
        try:
            client = deps.get_docker_client()
            containers = client.containers.list(all=True)

            result = []
            for container in containers:
                image_name = container.image.tags[0] if container.image.tags else "unknown"
                result.append({
                    "id": container.id[:12],
                    "name": container.name,
                    "status": container.status,
                    "image": image_name,
                    "created": container.attrs['Created'],
                    "ports": container.ports
                })

            return format_response({"containers": result, "count": len(result)}, format)
        except Exception as e:
            return format_error(e, "get_container_list")

    @mcp.tool()
    @secure_tool("manage_container")
    async def manage_container(
        action: Literal["start", "stop", "restart", "logs"],
        name_or_id: str,
        lines: int = 100
    ) -> dict:
        """Manage Docker container lifecycle: start, stop, restart, or get logs.

        Args:
            action: Operation to perform (start|stop|restart|logs)
            name_or_id: Container name or ID
            lines: Number of log lines to retrieve (only for 'logs' action)
        """
        try:
            client = deps.get_docker_client()
            container = client.containers.get(name_or_id)

            if action == "start":
                container.start()
                return {
                    "success": True,
                    "container": name_or_id,
                    "action": "started",
                    "timestamp": datetime.now().isoformat()
                }
            elif action == "stop":
                container.stop()
                return {
                    "success": True,
                    "container": name_or_id,
                    "action": "stopped",
                    "timestamp": datetime.now().isoformat()
                }
            elif action == "restart":
                container.restart()
                return {
                    "success": True,
                    "container": name_or_id,
                    "action": "restarted",
                    "timestamp": datetime.now().isoformat()
                }
            elif action == "logs":
                logs = container.logs(tail=lines, timestamps=True).decode('utf-8')
                return {
                    "success": True,
                    "container": name_or_id,
                    "action": "logs",
                    "lines": lines,
                    "logs": logs,
                    "timestamp": datetime.now().isoformat()
                }
            else:
                return {"success": False, "error": f"Invalid action: {action}"}
        except Exception as e:
            return format_error(e, "manage_container")

    @mcp.tool()
    @secure_tool("analyze_container_logs")
    async def analyze_container_logs(
        name_or_id: str,
        lines: int = 200,
        context: Optional[str] = None,
        use_ai: bool = True,
        ctx: Context = None
    ) -> dict:
        """Analyze Docker container logs OR system log files using AI to extract insights and identify issues.

        This tool uses AI sampling to intelligently analyze logs, providing:
        - Summary of log contents
        - Identified errors and warnings with severity
        - Root cause analysis
        - Performance issue detection
        - Actionable recommendations

        Args:
            name_or_id: Container name/ID OR path to system log file
                       - For Docker: container name like "nginx" or ID like "abc123"
                       - For system logs: full path like "/var/log/syslog" or "/var/log/auth.log"
                       - Common system logs: syslog, auth.log, kern.log, dmesg, apache2/error.log
            lines: Number of recent log lines to analyze (default: 200)
            context: Optional context about what to look for (e.g., "why did it crash?", "find security issues")
            use_ai: Use AI analysis if available, otherwise fallback to pattern matching

        Returns:
            Comprehensive analysis including summary, errors, root cause, and recommendations

        Examples:
            - Docker: name_or_id="nginx"
            - System: name_or_id="/var/log/syslog"
            - Auth:   name_or_id="/var/log/auth.log"
        """
        try:
            # Check if it's a file path (system log)
            if name_or_id.startswith('/'):
                # System log file analysis
                log_path = name_or_id

                # Read the log file (tail last N lines)
                import subprocess
                result = subprocess.run(
                    ['tail', '-n', str(lines), log_path],
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                if result.returncode != 0:
                    return {
                        "success": False,
                        "error": f"Failed to read log file: {result.stderr}"
                    }

                logs = result.stdout
                log_name = log_path.split('/')[-1]

                # Perform intelligent analysis
                analysis = await deps.log_analyzer.analyze_container_logs(
                    container_name=f"System Log: {log_name}",
                    logs=logs,
                    analysis_context=context,
                    use_ai=use_ai,
                    mcp_context=ctx
                )

                return analysis

            else:
                # Docker container log analysis (original behavior)
                client = deps.get_docker_client()
                container = client.containers.get(name_or_id)
                logs = container.logs(tail=lines, timestamps=True).decode('utf-8')

                # Perform intelligent analysis - pass Context for AI sampling
                analysis = await deps.log_analyzer.analyze_container_logs(
                    container_name=container.name,
                    logs=logs,
                    analysis_context=context,
                    use_ai=use_ai,
                    mcp_context=ctx
                )

                return analysis

        except Exception as e:
            logger.error(f"Log analysis failed: {e}")
            return format_error(e, "analyze_container_logs")

    @mcp.tool()
    @secure_tool("get_docker_networks")
    async def get_docker_networks(format: Literal["json", "toon"] = "toon") -> Union[dict, str]:
        """List Docker networks (compact summary).

        Args:
            format: Response format - 'toon' (compact, default) or 'json' (verbose)
        """
        try:
            client = deps.get_docker_client()
            networks = client.networks.list()

            result = {
                "networks": [
                    {
                        "name": net.name,
                        "id": net.id[:12],
                        "driver": net.attrs['Driver'],
                        "scope": net.attrs['Scope'],
                        "containers": len(net.attrs.get('Containers', {}))
                    }
                    for net in networks
                ],
                "count": len(networks)
            }
            return format_response(result, format)
        except Exception as e:
            return format_error(e, "get_docker_networks")

    @mcp.tool()
    @secure_tool("get_stack_network_info")
    async def get_stack_network_info(
        host: str,
        stack_name: str,
        format: Literal["json", "toon"] = "json",
    ) -> Union[dict, str]:
        """Return Docker stack network metadata via the stack_tools helper."""
        try:
            info = await stack_tools.get_stack_network_info(host, stack_name)
            return format_response(info, format)
        except Exception as e:
            logger.exception("get_stack_network_info failed for host=%s stack=%s", host, stack_name)
            return format_error(e, "get_stack_network_info")

    logger.info("Registered 5 Docker container management tools")
