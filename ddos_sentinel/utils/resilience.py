"""
Resilience utilities: retry logic, circuit breakers, graceful degradation.
"""

import time
import functools
from typing import Callable, Optional, Tuple, Type
from datetime import datetime, timedelta
import structlog

from ddos_sentinel.errors import ErrorRecovery, DDoSSentinelError

logger = structlog.get_logger(__name__)


def retry_with_backoff(
    max_attempts: int = 3,
    initial_delay: float = 1.0,
    backoff_factor: float = 2.0,
    max_delay: float = 60.0,
    retryable_exceptions: Tuple[Type[Exception], ...] = (Exception,)
):
    """
    Retry decorator with exponential backoff.

    Args:
        max_attempts: Maximum retry attempts
        initial_delay: Initial delay in seconds
        backoff_factor: Backoff multiplier
        max_delay: Maximum delay between retries
        retryable_exceptions: Exceptions that trigger retry

    Example:
        @retry_with_backoff(max_attempts=3, initial_delay=1.0)
        def unstable_operation():
            ...
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            delay = initial_delay
            last_exception = None

            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)

                except retryable_exceptions as e:
                    last_exception = e

                    # Check if retryable
                    if not ErrorRecovery.can_retry(e):
                        logger.warning(
                            "Error not retryable",
                            error=str(e),
                            function=func.__name__
                        )
                        raise

                    # Last attempt - don't wait
                    if attempt == max_attempts:
                        break

                    logger.warning(
                        "Operation failed, retrying",
                        attempt=attempt,
                        max_attempts=max_attempts,
                        delay=delay,
                        error=str(e),
                        function=func.__name__
                    )

                    time.sleep(delay)
                    delay = min(delay * backoff_factor, max_delay)

            # All retries exhausted
            logger.error(
                "All retry attempts failed",
                function=func.__name__,
                error=str(last_exception)
            )
            raise last_exception

        return wrapper
    return decorator


class CircuitBreaker:
    """
    Circuit breaker pattern implementation.

    Prevents cascading failures by temporarily disabling operations
    that are consistently failing.
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: int = 60,
        expected_exception: Type[Exception] = Exception
    ):
        """
        Initialize circuit breaker.

        Args:
            failure_threshold: Number of failures before opening circuit
            recovery_timeout: Seconds to wait before attempting recovery
            expected_exception: Exception type that triggers circuit
        """
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception

        self._failure_count = 0
        self._last_failure_time: Optional[datetime] = None
        self._state = "closed"  # closed, open, half_open

    def call(self, func: Callable, *args, **kwargs):
        """
        Call function through circuit breaker.

        Args:
            func: Function to call
            *args: Positional arguments
            **kwargs: Keyword arguments

        Returns:
            Function result

        Raises:
            Exception: If circuit is open or function fails
        """
        if self._state == "open":
            if self._should_attempt_reset():
                self._state = "half_open"
                logger.info("Circuit breaker entering half-open state")
            else:
                raise DDoSSentinelError(
                    "Circuit breaker is open",
                    context={
                        "function": func.__name__,
                        "failures": self._failure_count,
                        "last_failure": self._last_failure_time.isoformat()
                        if self._last_failure_time else None
                    }
                )

        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result

        except self.expected_exception as e:
            self._on_failure()
            raise

    def _on_success(self):
        """Handle successful call."""
        self._failure_count = 0
        if self._state == "half_open":
            self._state = "closed"
            logger.info("Circuit breaker closed after successful recovery")

    def _on_failure(self):
        """Handle failed call."""
        self._failure_count += 1
        self._last_failure_time = datetime.now()

        if self._failure_count >= self.failure_threshold:
            self._state = "open"
            logger.error(
                "Circuit breaker opened",
                failure_count=self._failure_count,
                threshold=self.failure_threshold
            )

    def _should_attempt_reset(self) -> bool:
        """Check if enough time has passed to attempt reset."""
        if self._last_failure_time is None:
            return True

        elapsed = (datetime.now() - self._last_failure_time).total_seconds()
        return elapsed >= self.recovery_timeout

    def get_state(self) -> dict:
        """Get current circuit breaker state."""
        return {
            "state": self._state,
            "failure_count": self._failure_count,
            "last_failure": (
                self._last_failure_time.isoformat()
                if self._last_failure_time else None
            )
        }


class GracefulDegradation:
    """
    Graceful degradation strategies for handling failures.
    """

    @staticmethod
    def with_fallback(primary_func: Callable, fallback_func: Callable):
        """
        Execute primary function with fallback on failure.

        Args:
            primary_func: Primary function to try
            fallback_func: Fallback function if primary fails

        Returns:
            Result from primary or fallback
        """
        try:
            logger.debug("Attempting primary function", func=primary_func.__name__)
            return primary_func()

        except Exception as e:
            logger.warning(
                "Primary function failed, using fallback",
                primary=primary_func.__name__,
                fallback=fallback_func.__name__,
                error=str(e)
            )
            return fallback_func()

    @staticmethod
    def partial_results(func: Callable, items: list, continue_on_error: bool = True):
        """
        Process items and return partial results even if some fail.

        Args:
            func: Function to apply to each item
            items: List of items to process
            continue_on_error: Continue processing after errors

        Returns:
            Tuple of (results, errors)
        """
        results = []
        errors = []

        for i, item in enumerate(items):
            try:
                result = func(item)
                results.append(result)

            except Exception as e:
                logger.warning(
                    "Failed to process item",
                    index=i,
                    error=str(e)
                )
                errors.append((i, item, e))

                if not continue_on_error:
                    break

        logger.info(
            "Partial processing complete",
            successful=len(results),
            failed=len(errors),
            total=len(items)
        )

        return results, errors


class ResourceLimiter:
    """
    Limit resource usage to prevent exhaustion.
    """

    def __init__(self, max_items: int):
        """
        Initialize resource limiter.

        Args:
            max_items: Maximum number of items to allow
        """
        self.max_items = max_items
        self.current_count = 0

    def acquire(self, count: int = 1) -> bool:
        """
        Try to acquire resources.

        Args:
            count: Number of resources to acquire

        Returns:
            True if acquired, False if limit exceeded
        """
        if self.current_count + count > self.max_items:
            logger.warning(
                "Resource limit exceeded",
                current=self.current_count,
                requested=count,
                limit=self.max_items
            )
            return False

        self.current_count += count
        return True

    def release(self, count: int = 1):
        """
        Release resources.

        Args:
            count: Number of resources to release
        """
        self.current_count = max(0, self.current_count - count)

    def get_usage(self) -> dict:
        """Get current resource usage."""
        return {
            "current": self.current_count,
            "limit": self.max_items,
            "available": self.max_items - self.current_count,
            "usage_percent": (self.current_count / self.max_items * 100)
            if self.max_items > 0 else 0
        }
