"""Tests for retry utility (retry.py)."""

import pytest
import asyncio
from src.utils.retry import retry_with_backoff


class TestRetryWithBackoff:
    """Test retry_with_backoff decorator."""

    @pytest.mark.asyncio
    async def test_retry_success_first_attempt(self):
        """Test function succeeds on first attempt."""
        call_count = 0

        @retry_with_backoff(max_retries=3, base_delay=0.01)
        async def successful_function():
            nonlocal call_count
            call_count += 1
            return "success"

        result = await successful_function()

        assert result == "success"
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_retry_success_after_failures(self):
        """Test function succeeds after some failures."""
        call_count = 0

        @retry_with_backoff(max_retries=3, base_delay=0.01)
        async def flaky_function():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError("Temporary failure")
            return "success after retries"

        result = await flaky_function()

        assert result == "success after retries"
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_retry_exhausted(self):
        """Test function fails after max retries."""
        call_count = 0

        @retry_with_backoff(max_retries=2, base_delay=0.01)
        async def always_failing():
            nonlocal call_count
            call_count += 1
            raise ValueError("Permanent failure")

        with pytest.raises(ValueError, match="Permanent failure"):
            await always_failing()

        # Should be called 1 initial + 2 retries = 3 times
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_retry_exponential_backoff(self):
        """Test exponential backoff delays."""
        delays = []
        call_count = 0

        @retry_with_backoff(max_retries=3, base_delay=0.1)
        async def track_delays():
            nonlocal call_count
            call_count += 1
            # Always fail to test all retries
            raise ValueError("Fail to trigger retry")

        start_time = asyncio.get_event_loop().time()

        with pytest.raises(ValueError):
            await track_delays()

        end_time = asyncio.get_event_loop().time()
        total_delay = end_time - start_time

        # With base_delay=0.1 and 3 retries:
        # Delay after 1st failure: 0.1 * (2^0) = 0.1
        # Delay after 2nd failure: 0.1 * (2^1) = 0.2
        # Delay after 3rd failure: 0.1 * (2^2) = 0.4
        # Total expected: 0.1 + 0.2 + 0.4 = 0.7 seconds (approximately)
        assert total_delay >= 0.6  # Allow some timing variance
        assert call_count == 4  # 1 initial + 3 retries

    @pytest.mark.asyncio
    async def test_retry_preserves_function_metadata(self):
        """Test retry decorator preserves function name and docstring."""

        @retry_with_backoff(max_retries=2)
        async def documented_function():
            """This is a documented function."""
            return "result"

        assert documented_function.__name__ == "documented_function"
        assert documented_function.__doc__ == "This is a documented function."

    @pytest.mark.asyncio
    async def test_retry_with_arguments(self):
        """Test retry decorator works with function arguments."""

        @retry_with_backoff(max_retries=2, base_delay=0.01)
        async def function_with_args(x, y, z=10):
            if x < 5:
                raise ValueError("x too small")
            return x + y + z

        # Should fail
        with pytest.raises(ValueError, match="x too small"):
            await function_with_args(1, 2, z=3)

        # Should succeed
        result = await function_with_args(10, 20, z=30)
        assert result == 60

    @pytest.mark.asyncio
    async def test_retry_different_exceptions(self):
        """Test retry handles different exception types."""
        call_count = 0

        @retry_with_backoff(max_retries=2, base_delay=0.01)
        async def mixed_exceptions():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise ValueError("First error")
            elif call_count == 2:
                raise RuntimeError("Second error")
            else:
                raise TypeError("Third error")

        with pytest.raises(TypeError, match="Third error"):
            await mixed_exceptions()

        assert call_count == 3

    @pytest.mark.asyncio
    async def test_retry_zero_retries(self):
        """Test retry with max_retries=0."""
        call_count = 0

        @retry_with_backoff(max_retries=0, base_delay=0.01)
        async def no_retries():
            nonlocal call_count
            call_count += 1
            raise ValueError("Immediate failure")

        with pytest.raises(ValueError):
            await no_retries()

        # Should only be called once (no retries)
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_retry_custom_delay(self):
        """Test retry with custom base delay."""

        @retry_with_backoff(max_retries=1, base_delay=0.5)
        async def slow_retry():
            raise ValueError("Fail")

        start_time = asyncio.get_event_loop().time()

        with pytest.raises(ValueError):
            await slow_retry()

        end_time = asyncio.get_event_loop().time()
        elapsed = end_time - start_time

        # Should have delayed approximately 0.5 seconds
        assert elapsed >= 0.4  # Allow some timing variance

    @pytest.mark.asyncio
    async def test_retry_return_values(self):
        """Test retry correctly returns function return values."""

        @retry_with_backoff(max_retries=2, base_delay=0.01)
        async def return_complex_value():
            return {"status": "ok", "data": [1, 2, 3]}

        result = await return_complex_value()

        assert result == {"status": "ok", "data": [1, 2, 3]}


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
