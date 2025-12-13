"""Updated tool registry with capability-driven operations."""
import logging
from typing import List
from fastmcp import FastMCP

from src.tools.system_tools import register_tools as register_system_tools
from src.tools.container_tools import register_tools as register_container_tools
from src.tools.stack_tools import register_tools as register_stack_tools
from src.tools.network_tools import register_tools as register_network_tools
from src.tools.file_tools import register_tools as register_file_tools
from src.tools.capability_manager import capability_manager
from src.tools.integration_manager import integration_manager

logger = logging.getLogger(__name__)


def register_all_tools(mcp: FastMCP):
    """Register all tools with the MCP instance using capability-driven patterns."""
    
    # Register individual tool modules
    register_system_tools(mcp)
    register_container_tools(mcp)
    register_stack_tools(mcp)
    register_network_tools(mcp)
    register_file_tools(mcp)
    
    # Register capability management tools
    @mcp.tool()
    async def list_capabilities(capability_type: str = None) -> dict:
        """List all available capabilities, optionally filtered by type.
        
        Args:
            capability_type: Optional capability type filter (system|container|stack|network|file)
        """
        try:
            if capability_type:
                capabilities = capability_manager.get_capabilities(capability_type)
            else:
                capabilities = capability_manager.get_capabilities()
            
            return {
                "success": True,
                "capabilities": [
                    {
                        "name": cap.name,
                        "type": cap.type.value,
                        "description": cap.description,
                        "tier": cap.tier.value,
                        "default_timeout": cap.default_timeout,
                        "parameters": cap.parameters
                    }
                    for cap in capabilities
                ],
                "total_count": len(capabilities)
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    @mcp.tool()
    async def get_target_capabilities(target: str) -> dict:
        """Get capabilities available for a specific target.
        
        Args:
            target: Target system name
        """
        try:
            capabilities = integration_manager.get_target_capabilities(target)
            return {
                "success": True,
                "target": target,
                "capabilities": capabilities
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    @mcp.tool()
    async def validate_operation(
        operation: str,
        target: str,
        parameters: dict
    ) -> dict:
        """Validate an operation without executing it.
        
        Args:
            operation: Operation name
            target: Target system
            parameters: Operation parameters
        """
        try:
            validation_result = await integration_manager.validate_operation(
                operation, target, parameters
            )
            return {
                "success": True,
                "validation": validation_result
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    @mcp.tool()
    async def execute_capability(
        capability_name: str,
        target: str,
        parameters: dict,
        dry_run: bool = False,
        timeout: int = None
    ) -> dict:
        """Execute a capability on a target with full integration.
        
        Args:
            capability_name: Name of the capability to execute
            target: Target system
            parameters: Capability parameters
            dry_run: If True, simulate without executing
            timeout: Custom timeout (uses default if None)
        """
        try:
            result = await capability_manager.execute_capability(
                capability_name, target, parameters, dry_run, timeout
            )
            return result
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    logger.info("Registered all tools with capability-driven operations")


# Export the main registration function
__all__ = ["register_all_tools"]