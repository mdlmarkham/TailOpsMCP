"""Example client showing how to request TOON-formatted `get_system_status`.

This is a minimal HTTP example assuming your MCP server is reachable via a
Tailscale Service at `mcp-api.<tailnet>.ts.net` and is serving an HTTP JSON
endpoint that proxies MCP tool calls. Adjust URL/transport to your setup.
"""
import requests

TAILSCALE_SERVICE = "https://mcp-api.example.ts.net:443"


def call_get_system_status(token: str = None, use_toon: bool = True):
    url = f"{TAILSCALE_SERVICE}/tools/get_system_status"
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    params = {}
    if use_toon:
        params["format"] = "toon"

    resp = requests.post(url, json=params, headers=headers, timeout=10)
    resp.raise_for_status()
    payload = resp.json()
    if payload.get("success"):
        data = payload["data"]
        # If TOON used, `data` may be a compact string; otherwise a dict
        if isinstance(data, str) and use_toon:
            print("TOON payload:", data)
        else:
            print("JSON payload:", data)
    else:
        print("Tool error:", payload.get("error"))


if __name__ == "__main__":
    # Replace with real token if your server enforces token verification
    call_get_system_status(token=None, use_toon=True)
