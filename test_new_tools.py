#!/usr/bin/env python3
"""Remote integration tests for package/system tools exposed via FastMCP."""

from __future__ import annotations

import asyncio
import json
import os
from typing import Any, Dict

import pytest
from fastmcp import Client


REMOTE_SSE_URL = os.getenv("SYSTEMMANAGER_REMOTE_SSE_URL")


def _require_remote_url() -> str:
    if not REMOTE_SSE_URL:
        pytest.skip("Set SYSTEMMANAGER_REMOTE_SSE_URL to run remote tool tests")
    return REMOTE_SSE_URL


async def _call_remote_tool(tool: str, arguments: Dict[str, Any] | None = None):
    url = _require_remote_url()
    try:
        async with Client(url) as client:
            result = await client.call_tool(tool, arguments or {})
            assert result.content, f"{tool} returned no content"
            payload = result.content[0].text
            try:
                return json.loads(payload)
            except json.JSONDecodeError:
                return payload
    except OSError as exc:  # pragma: no cover - network specific
        pytest.skip(f"Remote MCP server unreachable: {exc}")


@pytest.mark.integration
@pytest.mark.asyncio
async def test_check_system_updates_tool():
    data = await _call_remote_tool("check_system_updates")
    assert isinstance(data, (dict, list, str))


@pytest.mark.integration
@pytest.mark.asyncio
async def test_list_docker_images_tool():
    data = await _call_remote_tool("list_docker_images")
    if isinstance(data, dict):
        assert "containers" in data or "images" in data or data.get("success") is False


@pytest.mark.integration
@pytest.mark.asyncio
async def test_pull_docker_image_tool():
    data = await _call_remote_tool("pull_docker_image", {"image_name": "alpine", "tag": "latest"})
    assert data, "pull_docker_image returned empty payload"


async def main() -> None:
    await _call_remote_tool("check_system_updates")
    await _call_remote_tool("list_docker_images")
    await _call_remote_tool("pull_docker_image", {"image_name": "alpine", "tag": "latest"})


if __name__ == "__main__":
    if not REMOTE_SSE_URL:
        raise SystemExit("SYSTEMMANAGER_REMOTE_SSE_URL is required to run this harness")
    asyncio.run(main())
