import pytest

from src.mcp_server import mcp
from src.auth.token_auth import TokenClaims
from src.auth import middleware as auth_middleware


@pytest.fixture(autouse=True)
def grant_contract_test_access(monkeypatch):
    """Bypass auth for contract tests so MCP tools can run in CI."""
    claims = TokenClaims(agent="contract-tests", scopes=["admin"], expiry=None)

    def _fake_get_claims(self, **kwargs):  # pragma: no cover - test helper
        return claims

    monkeypatch.setattr(
        auth_middleware.SecurityMiddleware,
        "get_claims_from_context",
        _fake_get_claims,
    )


class TestMCPProtocol:
    """Test MCP protocol compliance."""

    @pytest.mark.asyncio
    async def test_initialization(self):
        tools = await mcp.get_tools()
        assert mcp.name == "SystemManager"
        assert len(tools) > 0

    @pytest.mark.asyncio
    async def test_tool_registration(self):
        tools = await mcp.get_tools()
        tool_names = set(tools.keys())
        expected_tools = {
            "get_system_status",
            "get_container_list",
            "file_operations",
            "get_network_status",
            "get_stack_network_info",
        }

        missing = expected_tools - tool_names
        assert not missing, f"Missing tools: {missing}"

    @pytest.mark.asyncio
    async def test_tool_schemas(self):
        tools = await mcp.get_tools()
        for tool in tools.values():
            assert tool.name
            assert tool.description
            assert callable(tool.fn)


@pytest.mark.asyncio
async def test_system_status_tool():
    tools = await mcp.get_tools()
    tool = tools.get("get_system_status")
    assert tool is not None

    result = await tool.fn(format="json")
    assert isinstance(result, dict)
    assert "cpu_percent" in result
    assert "memory_usage" in result


@pytest.mark.asyncio
async def test_container_list_tool():
    tools = await mcp.get_tools()
    tool = tools.get("get_container_list")
    assert tool is not None

    result = await tool.fn(format="json")
    assert isinstance(result, dict)
    assert "containers" in result or "error" in result


@pytest.mark.asyncio
async def test_file_operations_list_tool():
    tools = await mcp.get_tools()
    tool = tools.get("file_operations")
    assert tool is not None

    result = await tool.fn(action="list", path=".")
    assert isinstance(result, dict)
    assert result.get("path") == "."


@pytest.mark.asyncio
async def test_network_status_tool():
    tools = await mcp.get_tools()
    tool = tools.get("get_network_status")
    assert tool is not None

    result = await tool.fn(format="json")
    assert isinstance(result, dict)
    assert "interfaces" in result


@pytest.mark.asyncio
async def test_file_search_tool():
    tools = await mcp.get_tools()
    tool = tools.get("file_operations")
    assert tool is not None

    result = await tool.fn(action="search", path=".", pattern="*.py")
    assert isinstance(result, dict)
    assert result.get("pattern") == "*.py"
