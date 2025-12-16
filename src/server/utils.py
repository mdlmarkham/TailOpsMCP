"""Shared utility functions for MCP tools."""

import functools
import time
from typing import Union
from src.integration.toon.serializer import model_to_toon

# Cache storage
_cache = {}


def cached(ttl_seconds: int = 5):
    """Cache function results for ttl_seconds."""

    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            cache_key = f"{func.__name__}:{args}:{kwargs}"
            now = time.time()

            if cache_key in _cache:
                result, timestamp = _cache[cache_key]
                if now - timestamp < ttl_seconds:
                    return result

            result = await func(*args, **kwargs)
            _cache[cache_key] = (result, now)
            return result

        return wrapper

    return decorator


def format_error(e: Exception, tool_name: str) -> dict:
    """Format error with context."""
    return {"error": str(e), "error_type": type(e).__name__, "tool": tool_name}


def format_response(data: dict, format: str = "json") -> Union[dict, str]:
    """Format response as JSON (default) or TOON.

    Args:
        data: Response dictionary
        format: 'json' for standard JSON, 'toon' for compact TOON format

    Returns:
        dict for json format, str for toon format
    """
    if format == "toon":
        return model_to_toon(data)
    return data
