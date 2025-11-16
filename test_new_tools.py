#!/usr/bin/env python3
"""Test the new package management and Docker image tools"""

import requests
import json

SERVER_URL = "http://dev1.tailf9480.ts.net:8080/sse"

def call_tool(tool_name: str, arguments: dict = None):
    """Call an MCP tool and return the result"""
    payload = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments or {}
        },
        "id": 1
    }
    
    response = requests.post(SERVER_URL, json=payload)
    data = response.json()
    
    if "result" in data:
        return data["result"]["content"][0]["text"]
    elif "error" in data:
        return f"Error: {data['error']}"
    return data

def test_check_system_updates():
    """Test checking for system updates"""
    print("\n=== Testing check_system_updates ===")
    result = call_tool("check_system_updates")
    print(json.dumps(json.loads(result), indent=2))

def test_list_docker_images():
    """Test listing Docker images"""
    print("\n=== Testing list_docker_images ===")
    result = call_tool("list_docker_images")
    print(json.dumps(json.loads(result), indent=2))

def test_pull_docker_image():
    """Test pulling a Docker image"""
    print("\n=== Testing pull_docker_image (alpine:latest) ===")
    result = call_tool("pull_docker_image", {"image_name": "alpine", "tag": "latest"})
    print(json.dumps(json.loads(result), indent=2))

def list_all_tools():
    """List all available tools"""
    print("\n=== Listing All Tools ===")
    payload = {
        "jsonrpc": "2.0",
        "method": "tools/list",
        "id": 1
    }
    
    response = requests.post(SERVER_URL, json=payload)
    data = response.json()
    
    if "result" in data:
        tools = data["result"]["tools"]
        print(f"Total tools: {len(tools)}\n")
        
        # Filter for new tools
        new_tools = [t for t in tools if any(keyword in t["name"] for keyword in 
                     ["package", "update", "install", "docker_image", "pull_docker"])]
        
        print("New package/Docker tools:")
        for tool in new_tools:
            print(f"  - {tool['name']}: {tool['description'][:80]}...")

if __name__ == "__main__":
    try:
        list_all_tools()
        test_check_system_updates()
        test_list_docker_images()
        test_pull_docker_image()
        
        print("\n✅ All tests completed!")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
