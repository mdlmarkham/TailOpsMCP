"""Unit tests that validate TOON formatting savings using captured live data."""

from __future__ import annotations

import json

import pytest

from src.utils.toon import model_to_toon


JSON_RESPONSE = """
{
    "processes": [
        {"memory_percent": 0.22825442864271456, "pid": 1, "cpu_percent": 0, "username": "root", "status": "sleeping", "name": "systemd"},
        {"memory_percent": 0.3953031437125749, "pid": 44, "cpu_percent": 0, "username": "root", "status": "sleeping", "name": "systemd-journald"},
        {"memory_percent": 0.14931075349301398, "pid": 103, "cpu_percent": 0, "username": "systemd-network", "status": "sleeping", "name": "systemd-networkd"},
        {"memory_percent": 0.9801685691117765, "pid": 229, "cpu_percent": 0, "username": "root", "status": "sleeping", "name": "node"},
        {"memory_percent": 0.0383997629740519, "pid": 230, "cpu_percent": 0, "username": "root", "status": "sleeping", "name": "cron"}
    ],
    "sort_by": "cpu",
    "total_processes": 32,
    "timestamp": "2025-11-15T19:43:05.703815"
}
""".strip()


def _token_estimate(payload: str) -> int:
    """Simple heuristic mirroring the interactive script."""

    return len(payload) // 4


@pytest.mark.parametrize("response", [JSON_RESPONSE])
def test_toon_format_reduces_token_count(response: str):
    data = json.loads(response)
    toon_response = model_to_toon(data)

    json_tokens = _token_estimate(response)
    toon_tokens = _token_estimate(toon_response)

    assert toon_tokens < json_tokens
    savings_pct = ((json_tokens - toon_tokens) / json_tokens) * 100
    assert savings_pct > 10  # live sample shows significant win


def test_toon_output_contains_process_summary():
    data = json.loads(JSON_RESPONSE)
    toon_response = model_to_toon(data)
    assert "processes" in toon_response.lower()

