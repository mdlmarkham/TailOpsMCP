"""
Resilient Remote Operation Executor

Provides retry mechanisms, timeout handling, and error recovery for remote
agent operations with comprehensive logging and monitoring.
"""

import asyncio
import logging
from typing import Callable, Any, Optional, Dict, List
from datetime import datetime
from datetime import timezone, timezone
from functools import wraps
from dataclasses import dataclass, field
from enum import Enum

from src.connectors.remote_agent_connector import OperationResult, ConnectionError


logger = logging.getLogger(__name__)


class OperationType(str, Enum):
    """Types of remote operations."""

    COMMAND_EXECUTION = "command_execution"
    FILE_OPERATION = "file_operation"
    SERVICE_OPERATION = "service_operation"
    LOG_RETRIEVAL = "log_retrieval"
    CONTAINER_OPERATION = "container_operation"
    HEALTH_CHECK = "health_check"


class RetryStrategy(str, Enum):
    """Retry strategies for different operation types."""

    EXPONENTIAL_BACKOFF = "exponential_backoff"
    LINEAR_BACKOFF = "linear_backoff"
    FIXED_DELAY = "fixed_delay"
    IMMEDIATE_RETRY = "immediate_retry"
    NO_RETRY = "no_retry"


@dataclass
class ResilientOperationConfig:
    """Configuration for resilient operation execution."""

    operation_type: OperationType
    retry_strategy: RetryStrategy = RetryStrategy.EXPONENTIAL_BACKOFF
    max_retries: int = 3
    base_delay: float = 1.0
    max_delay: float = 60.0
    timeout: float = 30.0
    circuit_breaker_threshold: int = 5
    circuit_breaker_timeout: float = 300.0
    idempotent: bool = True
    critical: bool = False


@dataclass
class OperationMetrics:
    """Metrics for operation tracking."""

    operation_name: str
    operation_type: OperationType
    start_time: datetime
    end_time: Optional[datetime] = None
    duration: Optional[float] = None
    success: bool = False
    retries_attempted: int = 0
    error_message: Optional[str] = None
    error_type: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class CircuitBreaker:
    """Circuit breaker for preventing cascading failures."""

    def __init__(self, threshold: int = 5, timeout: float = 300.0):
        """Initialize circuit breaker.

        Args:
            threshold: Number of failures to open circuit
            timeout: Time to wait before attempting to close circuit
        """
        self.threshold = threshold
        self.timeout = timeout
        self.failure_count = 0
        self.last_failure_time = None
        self.state = "CLOSED"  # CLOSED, OPEN, HALF_OPEN
        self.logger = logging.getLogger(f"{__name__}.CircuitBreaker")

    def can_execute(self) -> bool:
        """Check if operation can be executed.

        Returns:
            True if circuit breaker allows execution
        """
        if self.state == "CLOSED":
            return True
        elif self.state == "OPEN":
            if self._should_attempt_reset():
                self.state = "HALF_OPEN"
                self.logger.info("Circuit breaker moved to HALF_OPEN state")
                return True
            return False
        elif self.state == "HALF_OPEN":
            return True

        return False

    def record_success(self):
        """Record successful operation."""
        self.failure_count = 0
        self.state = "CLOSED"

    def record_failure(self):
        """Record failed operation."""
        self.failure_count += 1
        self.last_failure_time = datetime.now(timezone.utc)

        if self.failure_count >= self.threshold:
            self.state = "OPEN"
            self.logger.warning(
                f"Circuit breaker opened after {self.failure_count} failures"
            )

    def _should_attempt_reset(self) -> bool:
        """Check if circuit breaker should attempt reset.

        Returns:
            True if reset should be attempted
        """
        if self.last_failure_time is None:
            return True

        time_since_failure = (
            datetime.now(timezone.utc) - self.last_failure_time
        ).total_seconds()
        return time_since_failure >= self.timeout

    def get_state(self) -> str:
        """Get current circuit breaker state.

        Returns:
            Current state as string
        """
        return self.state


class ResilientRemoteOperation:
    """Resilient operations with retry and timeout handling."""

    def __init__(self, default_config: Optional[ResilientOperationConfig] = None):
        """Initialize resilient operation executor.

        Args:
            default_config: Default operation configuration
        """
        self.default_config = default_config or ResilientOperationConfig(
            operation_type=OperationType.COMMAND_EXECUTION
        )
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
        self.metrics: List[OperationMetrics] = []
        self.logger = logging.getLogger(__name__)

    async def execute_with_retry(
        self,
        operation: Callable,
        config: Optional[ResilientOperationConfig] = None,
        operation_name: str = "unnamed_operation",
    ) -> OperationResult:
        """Execute operation with retry logic.

        Args:
            operation: Async operation to execute
            config: Operation-specific configuration
            operation_name: Name for logging and metrics

        Returns:
            Operation result
        """
        config = config or self.default_config
        metrics = OperationMetrics(
            operation_name=operation_name,
            operation_type=config.operation_type,
            start_time=datetime.now(timezone.utc),
        )

        try:
            result = await self._execute_with_retry_internal(operation, config, metrics)

            metrics.success = True
            metrics.end_time = datetime.now(timezone.utc)
            metrics.duration = (metrics.end_time - metrics.start_time).total_seconds()

            return result

        except Exception as e:
            metrics.success = False
            metrics.end_time = datetime.now(timezone.utc)
            metrics.duration = (metrics.end_time - metrics.start_time).total_seconds()
            metrics.error_message = str(e)
            metrics.error_type = type(e).__name__

            self.logger.error(
                f"Operation {operation_name} failed after {metrics.retries_attempted} retries: {str(e)}"
            )

            return OperationResult(
                operation=operation_name,
                target="unknown",
                success=False,
                error=str(e),
                execution_time=metrics.duration or 0.0,
                timestamp=datetime.now(timezone.utc),
            )

        finally:
            self.metrics.append(metrics)

            # Keep only last 1000 metrics to prevent memory leaks
            if len(self.metrics) > 1000:
                self.metrics = self.metrics[-1000:]

    async def execute_with_timeout(
        self,
        operation: Callable,
        timeout: float,
        operation_name: str = "timeout_operation",
    ) -> OperationResult:
        """Execute operation with timeout.

        Args:
            operation: Async operation to execute
            timeout: Operation timeout in seconds
            operation_name: Name for logging and metrics

        Returns:
            Operation result
        """
        start_time = datetime.now(timezone.utc)

        try:
            result = await asyncio.wait_for(operation(), timeout=timeout)

            duration = (datetime.now(timezone.utc) - start_time).total_seconds()

            return OperationResult(
                operation=operation_name,
                target="unknown",
                success=True,
                result=result,
                execution_time=duration,
                timestamp=datetime.now(timezone.utc),
            )

        except asyncio.TimeoutError:
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            error_msg = f"Operation {operation_name} timed out after {timeout}s"

            self.logger.error(error_msg)

            return OperationResult(
                operation=operation_name,
                target="unknown",
                success=False,
                error=error_msg,
                execution_time=duration,
                timestamp=datetime.now(timezone.utc),
            )

    async def handle_connection_errors(
        self, operation: Callable, operation_name: str = "connection_operation"
    ) -> OperationResult:
        """Handle connection-related errors with specific retry logic.

        Args:
            operation: Async operation to execute
            operation_name: Name for logging and metrics

        Returns:
            Operation result
        """
        config = ResilientOperationConfig(
            operation_type=OperationType.COMMAND_EXECUTION,
            retry_strategy=RetryStrategy.EXPONENTIAL_BACKOFF,
            max_retries=5,
            base_delay=2.0,
            max_delay=120.0,
            timeout=30.0,
            idempotent=True,
        )

        return await self.execute_with_retry(operation, config, operation_name)

    def get_circuit_breaker(self, target: str) -> CircuitBreaker:
        """Get or create circuit breaker for target.

        Args:
            target: Target identifier

        Returns:
            Circuit breaker instance
        """
        if target not in self.circuit_breakers:
            self.circuit_breakers[target] = CircuitBreaker()

        return self.circuit_breakers[target]

    def get_operation_metrics(
        self, operation_name: Optional[str] = None
    ) -> List[OperationMetrics]:
        """Get operation metrics.

        Args:
            operation_name: Filter by operation name

        Returns:
            List of operation metrics
        """
        if operation_name is None:
            return self.metrics.copy()

        return [m for m in self.metrics if m.operation_name == operation_name]

    def get_success_rate(self, operation_name: Optional[str] = None) -> float:
        """Calculate success rate for operations.

        Args:
            operation_name: Filter by operation name

        Returns:
            Success rate as percentage (0.0 to 1.0)
        """
        metrics = self.get_operation_metrics(operation_name)

        if not metrics:
            return 0.0

        successful = sum(1 for m in metrics if m.success)
        return successful / len(metrics)

    def get_average_duration(self, operation_name: Optional[str] = None) -> float:
        """Calculate average operation duration.

        Args:
            operation_name: Filter by operation name

        Returns:
            Average duration in seconds
        """
        metrics = self.get_operation_metrics(operation_name)
        completed_metrics = [m for m in metrics if m.duration is not None]

        if not completed_metrics:
            return 0.0

        total_duration = sum(m.duration for m in completed_metrics)
        return total_duration / len(completed_metrics)

    async def _execute_with_retry_internal(
        self,
        operation: Callable,
        config: ResilientOperationConfig,
        metrics: OperationMetrics,
    ) -> OperationResult:
        """Internal retry execution logic.

        Args:
            operation: Operation to execute
            config: Operation configuration
            metrics: Metrics to update

        Returns:
            Operation result
        """
        # Check circuit breaker if applicable
        circuit_breaker = self.get_circuit_breaker("default")

        if not circuit_breaker.can_execute():
            raise ConnectionError("Circuit breaker is OPEN - operation not allowed")

        attempt = 0
        last_exception = None

        while attempt <= config.max_retries:
            try:
                # Execute operation with timeout
                if hasattr(operation, "__call__"):
                    result = await asyncio.wait_for(operation(), timeout=config.timeout)
                else:
                    result = await operation

                # Record success
                circuit_breaker.record_success()
                metrics.retries_attempted = attempt

                return OperationResult(
                    operation=metrics.operation_name,
                    target="unknown",
                    success=True,
                    result=result,
                    execution_time=0.0,
                    timestamp=datetime.now(timezone.utc),
                )

            except Exception as e:
                last_exception = e
                attempt += 1
                metrics.retries_attempted = attempt - 1

                # Record failure for circuit breaker
                circuit_breaker.record_failure()

                # Check if we should retry
                if attempt > config.max_retries:
                    break

                # Calculate delay
                if config.retry_strategy == RetryStrategy.EXPONENTIAL_BACKOFF:
                    delay = min(
                        config.base_delay * (2 ** (attempt - 1)), config.max_delay
                    )
                elif config.retry_strategy == RetryStrategy.LINEAR_BACKOFF:
                    delay = min(config.base_delay * attempt, config.max_delay)
                elif config.retry_strategy == RetryStrategy.FIXED_DELAY:
                    delay = config.base_delay
                elif config.retry_strategy == RetryStrategy.IMMEDIATE_RETRY:
                    delay = 0
                else:  # NO_RETRY
                    break

                self.logger.warning(
                    f"Operation {metrics.operation_name} failed (attempt {attempt}), "
                    f"retrying in {delay}s: {str(e)}"
                )

                await asyncio.sleep(delay)

        # All retries exhausted
        circuit_breaker.record_failure()
        raise last_exception


class ResilientOperationDecorator:
    """Decorator for making functions resilient."""

    def __init__(
        self,
        config: Optional[ResilientOperationConfig] = None,
        operation_name: Optional[str] = None,
    ):
        """Initialize decorator.

        Args:
            config: Operation configuration
            operation_name: Operation name for metrics
        """
        self.config = config or ResilientOperationConfig(
            operation_type=OperationType.COMMAND_EXECUTION
        )
        self.operation_name = operation_name
        self.executor = ResilientRemoteOperation(self.config)

    def __call__(self, func: Callable) -> Callable:
        """Apply resilience decorator to function.

        Args:
            func: Function to decorate

        Returns:
            Decorated function
        """
        operation_name = self.operation_name or func.__name__

        @wraps(func)
        async def wrapper(*args, **kwargs):
            async def operation():
                return await func(*args, **kwargs)

            return await self.executor.execute_with_retry(
                operation, self.config, operation_name
            )

        return wrapper


# Convenience decorators
def resilient_operation(
    operation_type: OperationType = OperationType.COMMAND_EXECUTION,
    retry_strategy: RetryStrategy = RetryStrategy.EXPONENTIAL_BACKOFF,
    max_retries: int = 3,
    timeout: float = 30.0,
    operation_name: Optional[str] = None,
):
    """Decorator for making operations resilient.

    Args:
        operation_type: Type of operation
        retry_strategy: Retry strategy to use
        max_retries: Maximum number of retries
        timeout: Operation timeout
        operation_name: Name for metrics

    Returns:
        Decorator function
    """
    config = ResilientOperationConfig(
        operation_type=operation_type,
        retry_strategy=retry_strategy,
        max_retries=max_retries,
        timeout=timeout,
    )

    return ResilientOperationDecorator(config, operation_name)


def resilient_command(operation_name: Optional[str] = None):
    """Decorator for resilient command execution.

    Args:
        operation_name: Name for metrics

    Returns:
        Decorator function
    """
    return resilient_operation(
        operation_type=OperationType.COMMAND_EXECUTION, operation_name=operation_name
    )


def resilient_file_operation(operation_name: Optional[str] = None):
    """Decorator for resilient file operations.

    Args:
        operation_name: Name for metrics

    Returns:
        Decorator function
    """
    return resilient_operation(
        operation_type=OperationType.FILE_OPERATION,
        retry_strategy=RetryStrategy.LINEAR_BACKOFF,
        max_retries=2,  # Fewer retries for file operations
        timeout=60.0,
        operation_name=operation_name,
    )


def resilient_service_operation(operation_name: Optional[str] = None):
    """Decorator for resilient service operations.

    Args:
        operation_name: Name for metrics

    Returns:
        Decorator function
    """
    return resilient_operation(
        operation_type=OperationType.SERVICE_OPERATION,
        retry_strategy=RetryStrategy.EXPONENTIAL_BACKOFF,
        max_retries=3,
        timeout=120.0,  # Longer timeout for service operations
        operation_name=operation_name,
    )
