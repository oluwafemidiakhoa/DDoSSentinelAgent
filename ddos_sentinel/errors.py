"""
Custom exceptions and error handling for DDoS Sentinel Agent.
"""

from typing import Optional, Dict, Any
from enum import Enum


class ErrorSeverity(Enum):
    """Error severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DDoSSentinelError(Exception):
    """Base exception for DDoS Sentinel Agent."""

    def __init__(
        self,
        message: str,
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        context: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize error.

        Args:
            message: Error message
            severity: Error severity level
            context: Additional context
        """
        self.message = message
        self.severity = severity
        self.context = context or {}
        super().__init__(self.message)


class IngestionError(DDoSSentinelError):
    """Errors during traffic ingestion."""
    pass


class PCAPError(IngestionError):
    """Errors reading/parsing PCAP files."""
    pass


class DetectionError(DDoSSentinelError):
    """Errors during detection analysis."""
    pass


class ConfigurationError(DDoSSentinelError):
    """Configuration errors."""
    pass


class SafeAgentError(DDoSSentinelError):
    """SafeDeepAgent integration errors."""
    pass


class ValidationError(DDoSSentinelError):
    """Data validation errors."""
    pass


class ResourceExhaustedError(DDoSSentinelError):
    """Resource exhaustion (memory, CPU, etc.)."""

    def __init__(self, resource: str, current: Any, limit: Any):
        """
        Initialize resource exhaustion error.

        Args:
            resource: Resource that was exhausted
            current: Current usage
            limit: Usage limit
        """
        message = f"{resource} exhausted: {current} exceeds limit {limit}"
        context = {
            "resource": resource,
            "current": current,
            "limit": limit
        }
        super().__init__(
            message=message,
            severity=ErrorSeverity.HIGH,
            context=context
        )


class RateLimitExceededError(DDoSSentinelError):
    """Rate limit exceeded."""

    def __init__(self, limit: int, current: int):
        """
        Initialize rate limit error.

        Args:
            limit: Rate limit
            current: Current rate
        """
        message = f"Rate limit exceeded: {current} > {limit}"
        context = {"limit": limit, "current": current}
        super().__init__(
            message=message,
            severity=ErrorSeverity.MEDIUM,
            context=context
        )


# Error recovery strategies
class ErrorRecovery:
    """Error recovery strategies."""

    @staticmethod
    def can_retry(error: Exception) -> bool:
        """
        Determine if an error is retryable.

        Args:
            error: Exception that occurred

        Returns:
            True if error is retryable
        """
        retryable_errors = (
            IOError,
            ConnectionError,
            TimeoutError,
        )

        non_retryable_errors = (
            ValidationError,
            ConfigurationError,
            ResourceExhaustedError,
        )

        if isinstance(error, non_retryable_errors):
            return False

        if isinstance(error, retryable_errors):
            return True

        # Default: retry if not explicitly non-retryable
        return True

    @staticmethod
    def get_fallback_action(error: Exception) -> str:
        """
        Get recommended fallback action for error.

        Args:
            error: Exception that occurred

        Returns:
            Recommended action
        """
        if isinstance(error, ResourceExhaustedError):
            return "reduce_batch_size"

        if isinstance(error, RateLimitExceededError):
            return "apply_backpressure"

        if isinstance(error, PCAPError):
            return "skip_and_continue"

        if isinstance(error, DetectionError):
            return "use_simple_heuristics"

        return "abort_and_alert"
