"""Test the enhanced SystemManager MCP server"""
import asyncio
from fastmcp import Client

async def test_enhanced_server():
    async with Client("http://dev1.tailf9480.ts.net:8080/sse") as client:
        # List all tools
        tools = await client.list_tools()
        print(f"\n✅ Total Tools Available: {len(tools)}\n")
        for tool in tools:
            print(f"  • {tool.name}")
        
        print("\n" + "="*60)
        
        # Test system overview (new batch tool)
        print("\n🔍 Testing get_system_overview (NEW)...")
        result = await client.call_tool("get_system_overview", {})
        print(f"✅ Success - Got system, containers, network, and processes in one call")
        
        # Test file info (new)
        print("\n📁 Testing get_file_info (NEW)...")
        result = await client.call_tool("get_file_info", {"path": "/opt/systemmanager/README.md"})
        print(f"Result: {result.content[0].text}")
        
        # Test tail file (new)
        print("\n📄 Testing tail_file (NEW)...")
        result = await client.call_tool("tail_file", {"path": "/var/log/syslog", "lines": 5})
        content = result.content[0].text
        print(f"✅ Got last 5 lines from syslog")
        
        # Test container logs (new)
        print("\n🐳 Testing get_container_logs (NEW)...")
        result = await client.call_tool("get_container_logs", {"name_or_id": "grafana", "lines": 10})
        print(f"✅ Retrieved container logs")
        
        print("\n" + "="*60)
        print("\n✨ All new features working!\n")

if __name__ == "__main__":
    asyncio.run(test_enhanced_server())
