"""MCP Tool Registry - registers all tools with FastMCP instance."""
import logging
from fastmcp import FastMCP

logger = logging.getLogger(__name__)

def register_all_tools(mcp: FastMCP):
    """Register all MCP tools from tool modules.

    Args:
        mcp: FastMCP instance to register tools with
    """
    from . import (
        system_tools,
        container_tools,
        network_tools,
        file_tools,
        admin_tools,
        image_tools,
        inventory_tools,
        prompts,
    )

    # Register tools from each module
    system_tools.register_tools(mcp)
    container_tools.register_tools(mcp)
    network_tools.register_tools(mcp)
    file_tools.register_tools(mcp)
    admin_tools.register_tools(mcp)
    image_tools.register_tools(mcp)
    inventory_tools.register_tools(mcp)
    prompts.register_prompts(mcp)

    logger.info("All MCP tools registered successfully")
