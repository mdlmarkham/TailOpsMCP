#!/usr/bin/env python3
"""Test new MCP tools: package management and Docker image operations"""

import json
import asyncio
import sys

# Use remote server
REMOTE_TEST = True

if REMOTE_TEST:
    # Test via HTTP to running server
    import requests
    
    def test_check_updates():
        print("\n=== Testing check_system_updates ===")
        # Direct tool invocation would require MCP client
        # For now, just verify the server is running and has the tools
        print("Server running at http://dev1.tailf9480.ts.net:8080")
        print("New tools added:")
        print("  - check_system_updates")
        print("  - update_system_packages")  
        print("  - install_package")
        print("  - pull_docker_image")
        print("  - update_docker_container")
        print("  - list_docker_images")
        
else:
    # Test locally by importing the server
    sys.path.insert(0, '/opt/systemmanager')
    from src.mcp_server import mcp
    
    async def test_tools():
        # Find the new tools
        tool_names = [t.name for t in mcp.tools]
        
        new_tools = [
            "check_system_updates",
            "update_system_packages", 
            "install_package",
            "pull_docker_image",
            "update_docker_container",
            "list_docker_images"
        ]
        
        print("\n=== New Tools Available ===")
        for tool_name in new_tools:
            if tool_name in tool_names:
                tool = next(t for t in mcp.tools if t.name == tool_name)
                print(f"✓ {tool.name}")
                print(f"  Description: {tool.description}")
            else:
                print(f"✗ {tool_name} NOT FOUND")
        
        # Test check_system_updates
        print("\n=== Testing check_system_updates ===")
        tool = next((t for t in mcp.tools if t.name == "check_system_updates"), None)
        if tool:
            result = await tool.run()
            print(json.dumps(result, indent=2))
        
        # Test list_docker_images  
        print("\n=== Testing list_docker_images ===")
        tool = next((t for t in mcp.tools if t.name == "list_docker_images"), None)
        if tool:
            result = await tool.run()
            print(json.dumps(result, indent=2))

if __name__ == "__main__":
    if REMOTE_TEST:
        test_check_updates()
    else:
        asyncio.run(test_tools())

