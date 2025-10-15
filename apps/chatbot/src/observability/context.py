"""
Request correlation ID context management using contextvars.

Provides thread-safe request correlation IDs that propagate through async calls
without explicit parameter passing. Each request gets a unique UUID that appears
in all log lines, making distributed tracing and debugging much easier.

Usage:
    # At request entry point (main.py, api.py)
    from src.observability import set_correlation_id
    import uuid

    set_correlation_id(str(uuid.uuid4()))

    # In any downstream code (llm_provider.py, query_handler.py)
    from src.observability import get_correlation_id

    logger.info("Processing request", extra={
        "correlation_id": get_correlation_id()
    })
"""

import logging
import re
import uuid
from contextvars import ContextVar

logger = logging.getLogger(__name__)

# Thread-safe context variable for correlation ID
# Each async task gets its own context, preventing ID conflicts
correlation_id_var: ContextVar[str] = ContextVar("correlation_id", default="")

# UUID v4 format validation pattern (RFC 4122)
# Format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
# where x is any hexadecimal digit and y is one of 8, 9, A, or B
UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def set_correlation_id(cid: str) -> None:
    """
    Set correlation ID for current request context with format validation.

    This function enforces UUID v4 format for correlation IDs to prevent
    malformed IDs from breaking log parsing or causing security issues.
    If an invalid format is provided, a new UUID is generated automatically.

    Args:
        cid: Unique correlation ID (must be valid UUID v4 format)

    Example:
        >>> import uuid
        >>> set_correlation_id(str(uuid.uuid4()))

    Security Note:
        Invalid correlation IDs are automatically replaced with new UUIDs
        rather than raising exceptions to maintain service availability.
    """
    # Validate UUID format for defense-in-depth
    if not isinstance(cid, str) or not UUID_PATTERN.match(cid):
        logger.warning(
            "Invalid correlation ID format detected, generating new UUID: %s",
            cid[:20] if isinstance(cid, str) else type(cid).__name__,
        )
        cid = str(uuid.uuid4())

    correlation_id_var.set(cid)


def get_correlation_id() -> str:
    """
    Get correlation ID for current request context.

    Returns:
        Correlation ID string, or empty string if not set

    Example:
        >>> correlation_id = get_correlation_id()
        >>> logger.info("Processing", extra={"correlation_id": correlation_id})
    """
    return correlation_id_var.get()
