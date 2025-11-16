#!/usr/bin/env python3
"""Optional integration tests for package manager and Docker tooling."""

from __future__ import annotations

import asyncio
import json
import os

import pytest

from src.services.package_manager import PackageManager
from src.services.docker_manager import DockerManager


RUN_DIRECT_TESTS = os.getenv("SYSTEMMANAGER_ENABLE_DIRECT_TESTS", "").lower() in {"1", "true", "yes"}


def _require_direct_env() -> None:
    """Skip tests unless explicitly enabled via environment flag."""

    if not RUN_DIRECT_TESTS:
        pytest.skip(
            "Set SYSTEMMANAGER_ENABLE_DIRECT_TESTS=1 to exercise host-level package/docker integration tests"
        )


async def _exercise_package_manager() -> dict:
    pm = PackageManager()
    print("\n=== Testing Package Manager ===")
    print(f"Package Manager Type: {pm.package_manager}")
    print("\nChecking for updates...")
    result = await pm.check_updates()
    print(json.dumps(result, indent=2))
    return result


async def _exercise_docker_manager() -> dict:
    dm = DockerManager()
    print("\n=== Testing Docker Manager ===")
    print("\nListing Docker images...")
    result = await dm.list_images()
    print(json.dumps(result, indent=2))
    return result


@pytest.mark.integration
@pytest.mark.asyncio
async def test_package_manager_integration():
    _require_direct_env()
    result = await _exercise_package_manager()
    assert isinstance(result, dict)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_docker_manager_integration():
    _require_direct_env()
    result = await _exercise_docker_manager()
    assert isinstance(result, dict)


async def main() -> None:
    """Allow manual execution without pytest."""

    await _exercise_package_manager()
    await _exercise_docker_manager()


if __name__ == "__main__":
    asyncio.run(main())
