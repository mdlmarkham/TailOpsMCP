"""Test TOON format on live MCP server - measure actual token savings"""
import json

# Sample responses from live MCP server
json_response = """{"processes":[{"memory_percent":0.22825442864271456,"pid":1,"cpu_percent":0,"username":"root","status":"sleeping","name":"systemd"},{"memory_percent":0.3953031437125749,"pid":44,"cpu_percent":0,"username":"root","status":"sleeping","name":"systemd-journald"},{"memory_percent":0.14931075349301398,"pid":103,"cpu_percent":0,"username":"systemd-network","status":"sleeping","name":"systemd-networkd"},{"memory_percent":0.9801685691117765,"pid":229,"cpu_percent":0,"username":"root","status":"sleeping","name":"node"},{"memory_percent":0.0383997629740519,"pid":230,"cpu_percent":0,"username":"root","status":"sleeping","name":"cron"}],"sort_by":"cpu","total_processes":32,"timestamp":"2025-11-15T19:43:05.703815"}"""

# Simulate TOON format
from src.utils.toon import model_to_toon

data = json.loads(json_response)
toon_response = model_to_toon(data)

def token_estimate(s):
    return len(s) // 4

print("🧪 Live MCP Server - TOON Format Comparison")
print("=" * 80)
print(f"\n📊 get_top_processes(limit=5)")
print(f"  JSON:  {len(json_response):4} chars → ~{token_estimate(json_response):3} tokens")
print(f"  TOON:  {len(toon_response):4} chars → ~{token_estimate(toon_response):3} tokens")
savings = ((len(json_response) - len(toon_response)) / len(json_response)) * 100
print(f"  💰 Savings: {savings:.1f}%")
print(f"\n📝 TOON Output:")
print(f"  {toon_response[:150]}...")
print(f"\n✅ TOON format reduces token usage by {savings:.1f}%")
print(f"   Original: ~{token_estimate(json_response)} tokens")
print(f"   With TOON: ~{token_estimate(toon_response)} tokens")
print(f"   Saved: ~{token_estimate(json_response) - token_estimate(toon_response)} tokens")

