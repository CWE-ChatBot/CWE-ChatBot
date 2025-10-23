"""
Logging filters for security and observability.

Provides log filters for sanitizing and validating structured logging fields
to prevent log injection attacks and ensure data integrity.
"""

import logging
import re

# UUID v4 format validation pattern (RFC 4122)
UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


class CorrelationIDFilter(logging.Filter):
    """
    Logging filter to sanitize and validate correlation IDs.

    This filter ensures that correlation IDs in structured logs are valid UUIDs
    to prevent log injection attacks, log parsing errors, and monitoring issues.

    Defense-in-Depth Layer:
        This filter provides an additional validation layer beyond the
        set_correlation_id() function. Even if malformed IDs somehow reach
        the logging system, they will be sanitized here.

    Usage:
        >>> import logging
        >>> logger = logging.getLogger(__name__)
        >>> logger.addFilter(CorrelationIDFilter())

    Security Note:
        Invalid correlation IDs are replaced with "INVALID" rather than
        being logged as-is to prevent:
        - Log injection attacks (newlines, control characters)
        - Log parsing errors (non-UUID formats)
        - Monitoring/alerting bypasses (crafted IDs)
    """

    def filter(self, record: logging.LogRecord) -> bool:
        """
        Filter log records to sanitize correlation_id field.

        Args:
            record: LogRecord to filter

        Returns:
            True (always allows the log record through after sanitization)
        """
        # Check if record has correlation_id in extra fields
        if hasattr(record, "correlation_id"):
            cid = record.correlation_id  # type: ignore[attr-defined]

            # Validate correlation ID format
            if not isinstance(cid, str):
                # Non-string correlation ID (should never happen)
                record.correlation_id = "INVALID_TYPE"  # type: ignore[attr-defined]
            elif not UUID_PATTERN.match(cid):
                # Invalid UUID format - sanitize to prevent injection
                record.correlation_id = "INVALID_FORMAT"  # type: ignore[attr-defined]

        # Always return True to allow the log record through
        return True


class SensitiveDataFilter(logging.Filter):
    """
    Logging filter to redact sensitive data patterns from log messages.

    This filter scans log messages for common sensitive data patterns
    (API keys, tokens, passwords) and redacts them before logging.

    Patterns Detected:
        - API keys (sk-*, AIza*, etc.)
        - JWT tokens (eyJ*)
        - Bearer tokens
        - Password fields
        - Database connection strings

    Usage:
        >>> import logging
        >>> logger = logging.getLogger(__name__)
        >>> logger.addFilter(SensitiveDataFilter())

    Security Note:
        This is a defense-in-depth measure. Code should never log sensitive
        data in the first place, but this filter catches accidental leaks.
    """

    # Sensitive data patterns to redact
    PATTERNS = [
        # API keys (Gemini, OpenAI, etc.)
        (re.compile(r"(sk-[a-zA-Z0-9]{20,})", re.IGNORECASE), "[REDACTED_API_KEY]"),
        (
            re.compile(r"(AIza[a-zA-Z0-9_-]{35})", re.IGNORECASE),
            "[REDACTED_GEMINI_KEY]",
        ),
        # JWT tokens
        (
            re.compile(r"(eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)"),
            "[REDACTED_JWT]",
        ),
        # Bearer tokens
        (
            re.compile(r"(Bearer\s+[a-zA-Z0-9_-]{20,})", re.IGNORECASE),
            "[REDACTED_BEARER]",
        ),
        # Password fields in JSON/dict
        (
            re.compile(r"(['\"]password['\"]:\s*['\"][^'\"]+['\"])", re.IGNORECASE),
            '"password":"[REDACTED]"',
        ),
        # Database connection strings
        (
            re.compile(r"(postgresql://[^:]+:[^@]+@[^\s]+)", re.IGNORECASE),
            "postgresql://[REDACTED]@[REDACTED]",
        ),
    ]

    def filter(self, record: logging.LogRecord) -> bool:
        """
        Filter log records to redact sensitive data from message.

        Args:
            record: LogRecord to filter

        Returns:
            True (always allows the log record through after redaction)
        """
        # Redact sensitive patterns from log message
        if hasattr(record, "msg") and isinstance(record.msg, str):
            for pattern, replacement in self.PATTERNS:
                record.msg = pattern.sub(replacement, record.msg)

        # Also check formatted message (after % formatting)
        if hasattr(record, "getMessage"):
            try:
                original_message = record.getMessage()
                redacted_message = original_message
                for pattern, replacement in self.PATTERNS:
                    redacted_message = pattern.sub(replacement, redacted_message)

                # Update message if redaction occurred
                if redacted_message != original_message:
                    # Store redacted message back (this is a bit hacky but works)
                    record.msg = redacted_message
                    record.args = ()  # Clear args to prevent re-formatting
            except Exception:
                # If getMessage() fails, don't crash - just pass through
                pass

        return True


def configure_observability_filters(logger: logging.Logger) -> None:
    """
    Configure logging filters for observability and security.

    This function adds all observability-related filters to the given logger.
    Should be called during application initialization.

    Args:
        logger: Logger to configure (typically root logger)

    Example:
        >>> import logging
        >>> root_logger = logging.getLogger()
        >>> configure_observability_filters(root_logger)
    """
    logger.addFilter(CorrelationIDFilter())
    logger.addFilter(SensitiveDataFilter())
