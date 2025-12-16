#!/usr/bin/env python3
"""Test MCP prompts via HTTP protocol"""

import requests
import json
import sys
import os

# Server URL - use localhost when running on the server
SERVER_URL = os.getenv("MCP_SERVER_URL", "http://localhost:8080/mcp")


def test_list_prompts():
    """Test listing prompts via MCP protocol"""
    print("Testing MCP prompts/list endpoint...\n")

    # MCP request to list prompts
    request = {"jsonrpc": "2.0", "id": 1, "method": "prompts/list", "params": {}}

    try:
        response = requests.post(SERVER_URL, json=request, timeout=10)
        response.raise_for_status()

        data = response.json()

        if "error" in data:
            print(f"❌ Error: {data['error']}")
            return False

        if "result" not in data:
            print(f"❌ Unexpected response: {data}")
            return False

        prompts = data["result"].get("prompts", [])

        print(f"✅ Found {len(prompts)} prompts:\n")
        print("=" * 80)

        for prompt in prompts:
            name = prompt.get("name", "unknown")
            description = prompt.get("description", "")
            args = prompt.get("arguments", [])

            print(f"\n📝 {name}")
            print(f"   Description: {description}")
            if args:
                arg_list = [
                    f"{a['name']}{'*' if a.get('required') else ''}" for a in args
                ]
                print(f"   Arguments: {', '.join(arg_list)}")

        print("\n" + "=" * 80)
        print("\n✅ MCP prompts/list endpoint working correctly!")
        return True

    except requests.exceptions.RequestException as e:
        print(f"❌ Request failed: {e}")
        return False
    except json.JSONDecodeError as e:
        print(f"❌ Invalid JSON response: {e}")
        return False


def test_get_prompt():
    """Test getting a specific prompt"""
    print("\n\nTesting MCP prompts/get endpoint...\n")

    # Test getting the health_check prompt
    request = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "prompts/get",
        "params": {"name": "health_check", "arguments": {}},
    }

    try:
        response = requests.post(SERVER_URL, json=request, timeout=10)
        response.raise_for_status()

        data = response.json()

        if "error" in data:
            print(f"❌ Error: {data['error']}")
            return False

        if "result" not in data:
            print(f"❌ Unexpected response: {data}")
            return False

        messages = data["result"].get("messages", [])

        print("✅ Retrieved health_check prompt")
        print(f"   Messages: {len(messages)}")

        if messages:
            print("\n📄 Prompt content preview:")
            print("─" * 80)
            content = messages[0].get("content", {})
            text = (
                content.get("text", "") if isinstance(content, dict) else str(content)
            )
            # Show first 300 characters
            preview = text[:300] + "..." if len(text) > 300 else text
            print(preview)
            print("─" * 80)

        print("\n✅ MCP prompts/get endpoint working correctly!")
        return True

    except requests.exceptions.RequestException as e:
        print(f"❌ Request failed: {e}")
        return False
    except json.JSONDecodeError as e:
        print(f"❌ Invalid JSON response: {e}")
        return False


if __name__ == "__main__":
    success = test_list_prompts()
    if success:
        success = test_get_prompt()

    sys.exit(0 if success else 1)
