"""Test the remote FastMCP server"""
import asyncio
from fastmcp import Client

async def test_server():
    # Connect to the remote SSE server
    async with Client("http://dev1.tailf9480.ts.net:8080/sse") as client:
        print("Connected to server!")
        
        # List available tools
        tools = await client.list_tools()
        print(f"\nAvailable tools ({len(tools)}):")
        for tool in tools:
            print(f"  - {tool.name}: {tool.description}")
        
        # Test health_check
        print("\n=== Testing health_check ===")
        result = await client.call_tool("health_check", {})
        print(f"Result: {result.content[0].text}")
        
        # Test get_system_status
        print("\n=== Testing get_system_status ===")
        result = await client.call_tool("get_system_status", {})
        print(f"Result: {result.content[0].text}")
        
        # Test list_directory
        print("\n=== Testing list_directory ===")
        result = await client.call_tool("list_directory", {"path": "/opt"})
        print(f"Result: {result.content[0].text}")
        
        # Test get_network_status
        print("\n=== Testing get_network_status ===")
        result = await client.call_tool("get_network_status", {})
        print(f"Result: {result.content[0].text}")

if __name__ == "__main__":
    asyncio.run(test_server())
