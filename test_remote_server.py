"""Smoke tests for the remote FastMCP server."""

from __future__ import annotations

import asyncio
import os

import pytest
from fastmcp import Client


REMOTE_SSE_URL = os.getenv("SYSTEMMANAGER_REMOTE_SSE_URL")


def _require_remote_url() -> str:
    if not REMOTE_SSE_URL:
        pytest.skip("Set SYSTEMMANAGER_REMOTE_SSE_URL to exercise remote server tests")
    return REMOTE_SSE_URL


async def _round_trip(client: Client, tool_name: str, arguments: dict | None = None):
    result = await client.call_tool(tool_name, arguments or {})
    assert result.content, f"{tool_name} returned no content"
    return result


@pytest.mark.integration
@pytest.mark.asyncio
async def test_remote_server_smoke():
    url = _require_remote_url()
    try:
        async with Client(url) as client:
            tools = await client.list_tools()
            assert tools, "Remote MCP server returned no tools"
            await _round_trip(client, "health_check")
            await _round_trip(client, "get_system_status")
            await _round_trip(client, "get_network_status")
    except OSError as exc:  # pragma: no cover - network specific
        pytest.skip(f"Remote MCP server unreachable: {exc}")


async def main() -> None:
    url = os.getenv("SYSTEMMANAGER_REMOTE_SSE_URL")
    if not url:
        raise SystemExit("SYSTEMMANAGER_REMOTE_SSE_URL is required to run this harness")
    async with Client(url) as client:
        await _round_trip(client, "health_check")
        await _round_trip(client, "get_system_status")
        await _round_trip(client, "get_network_status")


if __name__ == "__main__":
    asyncio.run(main())
