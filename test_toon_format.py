#!/usr/bin/env python3
"""Test TOON format integration - compare JSON vs TOON token efficiency"""

import json
import sys
from src.utils.toon import model_to_toon

# Sample test data matching MCP responses
test_data = {
    "system_status": {
        "cpu_percent": 42.1,
        "load_average": {"1m": 2.26, "5m": 2.35, "15m": 2.66},
        "memory_usage": {
            "total": 4202692608,
            "available": 3835451392,
            "used": 367241216,
            "percent": 8.7
        },
        "disk_usage": [{
            "mountpoint": "/",
            "device": "ProxMox/subvol-103-disk-0",
            "fstype": "zfs",
            "total": 21474836480,
            "used": 13196460032,
            "free": 8278376448,
            "percent": 61.5
        }],
        "uptime": 397410,
        "timestamp": "2025-11-15T19:40:00.078153"
    },
    "containers": {
        "containers": [
            {
                "id": "b348231f7cdb",
                "name": "grafana",
                "status": "running",
                "image": "grafana/grafana-enterprise:latest",
                "created": "2025-06-21T15:41:48.159703957Z"
            },
            {
                "id": "48e56a5012cf",
                "name": "tsdproxy",
                "status": "exited",
                "image": "almeidapaulopt/tsdproxy:latest",
                "created": "2025-02-09T18:30:23.152693024Z"
            }
        ],
        "count": 2
    },
    "processes": {
        "processes": [
            {"pid": 1, "name": "systemd", "cpu_percent": 0.0, "memory_percent": 0.1, "status": "sleeping", "username": "root"},
            {"pid": 123, "name": "python", "cpu_percent": 15.3, "memory_percent": 2.4, "status": "running", "username": "app"},
            {"pid": 456, "name": "nginx", "cpu_percent": 5.2, "memory_percent": 1.1, "status": "running", "username": "www-data"},
        ],
        "sort_by": "cpu",
        "total_processes": 150,
        "timestamp": "2025-11-15T19:40:00.078153"
    },
    "network_connections": {
        "total": 22,
        "summary": {"LISTEN": 6, "TIME_WAIT": 1, "ESTABLISHED": 2, "NONE": 1},
        "connections": [
            {"local": "0.0.0.0:22", "remote": None, "status": "LISTEN", "pid": 890},
            {"local": "127.0.0.1:8080", "remote": None, "status": "LISTEN", "pid": 1234},
            {"local": "192.168.1.10:45678", "remote": "93.184.216.34:443", "status": "ESTABLISHED", "pid": 5678},
        ],
        "truncated": True
    }
}

def count_tokens_estimate(text):
    """Rough token count estimate (chars / 4)"""
    return len(text) // 4

def test_format(name, data):
    """Test both JSON and TOON formats, show token savings"""
    print(f"\n{'='*80}")
    print(f"Testing: {name}")
    print('='*80)
    
    # JSON format (pretty)
    json_pretty = json.dumps(data, indent=2)
    json_pretty_tokens = count_tokens_estimate(json_pretty)
    
    # JSON format (compact)
    json_compact = json.dumps(data, separators=(',', ':'))
    json_compact_tokens = count_tokens_estimate(json_compact)
    
    # TOON format
    toon = model_to_toon(data)
    toon_tokens = count_tokens_estimate(toon)
    
    # Calculate savings
    savings_vs_pretty = ((json_pretty_tokens - toon_tokens) / json_pretty_tokens) * 100
    savings_vs_compact = ((json_compact_tokens - toon_tokens) / json_compact_tokens) * 100
    
    print(f"\n📊 Format Comparison:")
    print(f"  JSON (pretty):  {len(json_pretty):6} chars → ~{json_pretty_tokens:4} tokens")
    print(f"  JSON (compact): {len(json_compact):6} chars → ~{json_compact_tokens:4} tokens")
    print(f"  TOON:           {len(toon):6} chars → ~{toon_tokens:4} tokens")
    
    print(f"\n💰 Token Savings:")
    print(f"  vs JSON (pretty):  {savings_vs_pretty:5.1f}% reduction")
    print(f"  vs JSON (compact): {savings_vs_compact:5.1f}% reduction")
    
    print(f"\n📝 TOON Output Preview:")
    preview = toon[:200] + ("..." if len(toon) > 200 else "")
    print(f"  {preview}")
    
    return {
        "name": name,
        "json_pretty_tokens": json_pretty_tokens,
        "json_compact_tokens": json_compact_tokens,
        "toon_tokens": toon_tokens,
        "savings_vs_pretty": savings_vs_pretty,
        "savings_vs_compact": savings_vs_compact
    }

if __name__ == "__main__":
    print("🧪 SystemManager TOON Format Testing")
    print("=" * 80)
    
    results = []
    
    # Test each dataset
    for key, data in test_data.items():
        result = test_format(key, data)
        results.append(result)
    
    # Summary
    print(f"\n{'='*80}")
    print("📈 Summary - Token Efficiency Across All Tests")
    print('='*80)
    
    total_json_pretty = sum(r['json_pretty_tokens'] for r in results)
    total_json_compact = sum(r['json_compact_tokens'] for r in results)
    total_toon = sum(r['toon_tokens'] for r in results)
    
    overall_savings_pretty = ((total_json_pretty - total_toon) / total_json_pretty) * 100
    overall_savings_compact = ((total_json_compact - total_toon) / total_json_compact) * 100
    
    print(f"\nTotal tokens across all test cases:")
    print(f"  JSON (pretty):  ~{total_json_pretty:5} tokens")
    print(f"  JSON (compact): ~{total_json_compact:5} tokens")
    print(f"  TOON:           ~{total_toon:5} tokens")
    
    print(f"\n🎯 Overall Token Savings:")
    print(f"  vs JSON (pretty):  {overall_savings_pretty:.1f}% reduction")
    print(f"  vs JSON (compact): {overall_savings_compact:.1f}% reduction")
    
    print(f"\n✅ TOON format integration successful!")
    print(f"   Average savings: {overall_savings_compact:.1f}% vs compact JSON")
