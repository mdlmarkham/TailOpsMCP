import pytest
import asyncio
from src.mcp_server import mcp


class TestMCPProtocol:
    """Test MCP protocol compliance."""
    
    def test_initialization(self):
        """Test MCP server initialization."""
        assert mcp.name == "SystemManager"
        assert len(mcp.tools) > 0
    
    def test_tool_registration(self):
        """Test that tools are properly registered."""
        tool_names = [tool.name for tool in mcp.tools]
        expected_tools = [
            "get_system_status",
            "get_container_list", 
            "list_directory",
            "get_network_status",
            "search_files"
        ]
        
        for tool_name in expected_tools:
            assert tool_name in tool_names, f"Tool {tool_name} not registered"
    
    def test_tool_schemas(self):
        """Test tool schemas are properly defined."""
        for tool in mcp.tools:
            assert tool.name is not None
            assert tool.description is not None
            assert hasattr(tool, 'inputSchema') or tool.inputSchema is None


@pytest.mark.asyncio
async def test_system_status_tool():
    """Test get_system_status tool."""
    # Find the tool
    tool = next((t for t in mcp.tools if t.name == "get_system_status"), None)
    assert tool is not None
    
    # Test basic functionality
    result = await tool.function()
    assert "success" in result
    assert "data" in result or "error" in result


@pytest.mark.asyncio
async def test_container_list_tool():
    """Test get_container_list tool."""
    tool = next((t for t in mcp.tools if t.name == "get_container_list"), None)
    assert tool is not None
    
    # Test with default parameters
    result = await tool.function()
    assert "success" in result


@pytest.mark.asyncio
async def test_list_directory_tool():
    """Test list_directory tool."""
    tool = next((t for t in mcp.tools if t.name == "list_directory"), None)
    assert tool is not None
    
    # Test with root directory
    result = await tool.function(path="/")
    assert "success" in result


@pytest.mark.asyncio
async def test_network_status_tool():
    """Test get_network_status tool."""
    tool = next((t for t in mcp.tools if t.name == "get_network_status"), None)
    assert tool is not None
    
    result = await tool.function()
    assert "success" in result


@pytest.mark.asyncio
async def test_search_files_tool():
    """Test search_files tool."""
    tool = next((t for t in mcp.tools if t.name == "search_files"), None)
    assert tool is not None
    
    result = await tool.function(pattern="*.py", path="/")
    assert "success" in result