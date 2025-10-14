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

from contextvars import ContextVar

# Thread-safe context variable for correlation ID
# Each async task gets its own context, preventing ID conflicts
correlation_id_var: ContextVar[str] = ContextVar("correlation_id", default="")


def set_correlation_id(cid: str) -> None:
    """
    Set correlation ID for current request context.

    Args:
        cid: Unique correlation ID (typically UUID)

    Example:
        >>> import uuid
        >>> set_correlation_id(str(uuid.uuid4()))
    """
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
