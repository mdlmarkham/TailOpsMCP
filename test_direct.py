#!/usr/bin/env python3
"""Test package manager and Docker tools directly on the server"""

import sys
sys.path.insert(0, '/opt/systemmanager')

from src.services.package_manager import PackageManager
from src.services.docker_manager import DockerManager
import asyncio
import json

async def test_package_manager():
    print("\n=== Testing Package Manager ===")
    pm = PackageManager()
    print(f"Package Manager Type: {pm.package_manager}")
    
    print("\nChecking for updates...")
    result = await pm.check_updates()
    print(json.dumps(result, indent=2))

async def test_docker_manager():
    print("\n=== Testing Docker Manager ===")
    dm = DockerManager()
    
    print("\nListing Docker images...")
    result = await dm.list_images()
    print(json.dumps(result, indent=2))
    
    print("\nPulling alpine:latest...")
    result = await dm.pull_image("alpine", "latest")
    print(json.dumps(result, indent=2))

async def main():
    await test_package_manager()
    await test_docker_manager()

if __name__ == "__main__":
    asyncio.run(main())
