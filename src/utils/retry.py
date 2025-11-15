import asyncio
import functools
from typing import Callable, Any


def retry_with_backoff(max_retries: int = 3, base_delay: float = 0.5):
    """Simple async retry decorator with exponential backoff."""

    def decorator(func: Callable):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs) -> Any:
            attempt = 0
            while True:
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    attempt += 1
                    if attempt > max_retries:
                        raise
                    delay = base_delay * (2 ** (attempt - 1))
                    await asyncio.sleep(delay)

        return wrapper

    return decorator
