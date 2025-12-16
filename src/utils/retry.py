import asyncio
import functools
from typing import Callable, Any, Optional
from dataclasses import dataclass
from enum import Enum


class RetryStrategy(str, Enum):
    """Retry strategy types."""

    EXPONENTIAL = "exponential"
    LINEAR = "linear"
    FIXED = "fixed"


@dataclass
class RetryConfig:
    """Configuration for retry operations."""

    max_retries: int = 3
    base_delay: float = 0.5
    max_delay: Optional[float] = None
    strategy: RetryStrategy = RetryStrategy.EXPONENTIAL
    backoff_multiplier: float = 2.0
    jitter: bool = True
    jitter_range: float = 0.1


def retry_with_backoff(max_retries: int = 3, base_delay: float = 0.5):
    """Simple async retry decorator with exponential backoff."""

    def decorator(func: Callable):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs) -> Any:
            attempt = 0
            while True:
                try:
                    return await func(*args, **kwargs)
                except Exception:
                    attempt += 1
                    if attempt > max_retries:
                        raise
                    delay = base_delay * (2 ** (attempt - 1))
                    await asyncio.sleep(delay)

        return wrapper

    return decorator
