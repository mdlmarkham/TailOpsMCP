#!/usr/bin/env python3
"""Test script to verify MCP prompts are registered correctly"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Set minimal environment for testing
os.environ['SYSTEMMANAGER_AUTH_MODE'] = 'token'
os.environ['SYSTEMMANAGER_REQUIRE_AUTH'] = 'false'

import asyncio
from src.mcp_server import mcp

async def test_prompts():
    prompts = await mcp.get_prompts()
    
    print(f"\n✅ Registered {len(prompts)} prompts:\n")
    print("=" * 80)
    
    for name, prompt in sorted(prompts.items()):
        tags_str = f" [{', '.join(sorted(prompt.tags))}]" if prompt.tags else ""
        print(f"\n📝 {name}{tags_str}")
        print(f"   {prompt.description}")
        if prompt.arguments:
            args = [f"{arg.name}{'*' if arg.required else ''}" for arg in prompt.arguments]
            print(f"   Arguments: {', '.join(args)}")
    
    print("\n" + "=" * 80)
    print(f"\nTotal: {len(prompts)} prompts ready for use in Claude Desktop, VS Code, etc.")
    print("\nExample usage in Claude Desktop:")
    print("  'Use the security_audit prompt to check my home lab'")
    print("  'Run health_check to see if everything is ok'")
    print("  'Troubleshoot my nginx container using the troubleshoot_container prompt'")
    print()

if __name__ == "__main__":
    asyncio.run(test_prompts())
