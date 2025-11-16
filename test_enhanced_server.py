"""Integration harness for the enhanced SystemManager MCP server."""

from __future__ import annotations

import asyncio
import os

import pytest
from fastmcp import Client


REMOTE_SSE_URL = os.getenv("SYSTEMMANAGER_REMOTE_SSE_URL")


def _require_remote_url() -> str:
    if not REMOTE_SSE_URL:
        pytest.skip("Set SYSTEMMANAGER_REMOTE_SSE_URL to run enhanced server integration tests")
    return REMOTE_SSE_URL


async def _run_enhanced_scenario(client: Client) -> dict:
    tools = await client.list_tools()
    assert tools, "Remote MCP server returned no tools"

    overview = await client.call_tool("get_system_overview", {})
    file_info = await client.call_tool("get_file_info", {"path": "/opt/systemmanager/README.md"})
    tail_result = await client.call_tool("tail_file", {"path": "/var/log/syslog", "lines": 5})
    logs_result = await client.call_tool("get_container_logs", {"name_or_id": "grafana", "lines": 5})

    return {
        "tool_count": len(tools),
        "overview": overview,
        "file_info": file_info,
        "tail": tail_result,
        "logs": logs_result,
    }


@pytest.mark.integration
@pytest.mark.asyncio
async def test_enhanced_server_features():
    url = _require_remote_url()
    try:
        async with Client(url) as client:
            results = await _run_enhanced_scenario(client)
    except OSError as exc:  # pragma: no cover - network specific
        pytest.skip(f"Remote MCP server unreachable: {exc}")

    assert results["tool_count"] > 0
    assert results["overview"].content, "Overview tool returned empty content"
    assert results["file_info"].content, "File info tool returned empty content"
    assert results["tail"].content, "tail_file returned no content"
    assert results["logs"].content, "get_container_logs returned no content"


async def main() -> None:
    url = os.getenv("SYSTEMMANAGER_REMOTE_SSE_URL")
    if not url:
        raise SystemExit("SYSTEMMANAGER_REMOTE_SSE_URL is required to run this harness")
    async with Client(url) as client:
        await _run_enhanced_scenario(client)


if __name__ == "__main__":
    asyncio.run(main())
