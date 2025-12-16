"""System administration tools for TailOpsMCP."""

import logging
from typing import Literal
from fastmcp import FastMCP
from src.auth.middleware import secure_tool
from src.server.dependencies import deps
from src.server.utils import format_error

logger = logging.getLogger(__name__)


def register_tools(mcp: FastMCP):
    """Register system administration tools with MCP instance."""

    @mcp.tool()
    @secure_tool("check_system_updates")
    async def manage_packages(
        action: Literal["check", "update", "install"],
        package_name: str = None,
        auto_approve: bool = False,
    ) -> dict:
        """Manage system packages: check updates, update all, or install specific package.

        Args:
            action: Operation to perform (check|update|install)
            package_name: Package name (required for 'install' action)
            auto_approve: Auto-approve without prompting (for update/install)

        Note: update/install require sudo privileges and may take several minutes.
        Supports apt (Debian/Ubuntu) and yum (RHEL/CentOS) based systems.
        """
        try:
            if action == "check":
                result = await deps.package_manager.check_updates()
            elif action == "update":
                result = await deps.package_manager.update_system(auto_approve)
            elif action == "install":
                if not package_name:
                    return {"error": "package_name required for install action"}
                result = await deps.package_manager.install_package(
                    package_name, auto_approve
                )
            else:
                return {"error": f"Invalid action: {action}"}
            return result
        except Exception as e:
            return format_error(e, "manage_packages")

    logger.info("Registered 1 system administration tool")
