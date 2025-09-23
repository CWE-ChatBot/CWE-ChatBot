"""
Secure Logging Utility for CWE ChatBot

This module provides secure logging functionality that prevents information
disclosure while maintaining useful debugging information for developers.

Key Features:
- Exception type logging without sensitive details in production
- Full exception details only in debug mode
- Structured logging with security-safe formatting
- Configurable sensitivity levels
"""

import logging
import os
from typing import Any, Optional, Dict
import traceback


class SecureLogger:
    """
    Secure logger wrapper that prevents information disclosure in production.
    
    Provides methods for logging exceptions and errors in a security-conscious way,
    ensuring sensitive information is not exposed in production logs while
    maintaining debugging capabilities in development.
    """
    
    def __init__(self, logger: logging.Logger):
        """
        Initialize secure logger wrapper.
        
        Args:
            logger: The underlying logger instance to wrap
        """
        self.logger = logger
        self.is_debug_mode = self._is_debug_mode()
        self.is_development = self._is_development_environment()
    
    def _is_debug_mode(self) -> bool:
        """Check if debug mode is enabled."""
        return self.logger.isEnabledFor(logging.DEBUG)
    
    def _is_development_environment(self) -> bool:
        """Check if running in development environment."""
        env = os.getenv('ENVIRONMENT', 'production').lower()
        return env in ('development', 'dev', 'local', 'debug')
    
    def log_exception(
        self, 
        message: str, 
        exception: Exception, 
        level: int = logging.ERROR,
        extra_context: Optional[Dict[str, Any]] = None
    ):
        """
        Log an exception in a security-conscious way.
        
        Args:
            message: Base log message describing what failed
            exception: The exception that occurred
            level: Logging level (default: ERROR)
            extra_context: Additional context to include in logs
        """
        # Base information that's safe to log in production
        safe_info = {
            'exception_type': type(exception).__name__,
            'operation': message
        }
        # Include hashed session/user IDs and request_id for traceability
        try:
            if extra_context:
                sid = extra_context.get('session_id') or extra_context.get('session')
                if sid:
                    safe_info['session_hash'] = self._hash_sensitive_value(str(sid))
                rid = extra_context.get('request_id') or extra_context.get('req_id')
                if rid:
                    safe_info['request_id'] = str(rid)
        except Exception:
            pass
        
        if extra_context:
            # Avoid leaking sensitive fields in production; only attach non-sensitive extras in debug
            if self.is_debug_mode or self.is_development:
                safe_info.update(extra_context)
        
        # Create production-safe log message
        safe_message = f"{message}: {type(exception).__name__}"
        
        # Log at the requested level
        self.logger.log(level, safe_message, extra=safe_info)
        
        # In debug mode or development, log full details
        if self.is_debug_mode or self.is_development:
            detailed_message = f"{message} - Full details: {str(exception)}"
            self.logger.debug(detailed_message, exc_info=True)
    
    def log_security_event(
        self, 
        event_type: str, 
        details: Dict[str, Any],
        level: int = logging.WARNING
    ) -> None:
        """
        Log a security-related event.
        
        Args:
            event_type: Type of security event
            details: Event details (will be sanitized)
            level: Logging level (default: WARNING)
        """
        # Sanitize details for production logging
        safe_details = self._sanitize_security_details(details)
        
        security_event = {
            'event_type': 'security_event',
            'security_event_type': event_type,
            **safe_details
        }
        
        message = f"Security event: {event_type}"
        self.logger.log(level, message, extra=security_event)
    
    def _sanitize_security_details(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize security event details for safe logging.
        
        Args:
            details: Raw event details
            
        Returns:
            Sanitized details safe for production logging
        """
        safe_details = {}
        
        # List of keys that are safe to log
        safe_keys = {
            'event_type', 'violation_type', 'action_type', 'severity',
            'timestamp', 'source', 'component', 'session_hash'
        }
        
        # List of keys that should be hashed or excluded
        sensitive_keys = {
            'session_id', 'user_id', 'ip_address', 'user_agent', 'token'
        }
        
        for key, value in details.items():
            if key in safe_keys:
                safe_details[key] = value
            elif key in sensitive_keys:
                # Hash sensitive values
                safe_details[f"{key}_hash"] = self._hash_sensitive_value(str(value))
            elif self.is_debug_mode or self.is_development:
                # Include in debug mode only
                safe_details[key] = value
        
        return safe_details
    
    def _hash_sensitive_value(self, value: str) -> str:
        """Hash a sensitive value for safe logging."""
        import hashlib
        return hashlib.md5(value.encode()).hexdigest()[:16]
    
    # Convenience methods that delegate to the underlying logger
    def debug(self, message: str, *args: Any, **kwargs: Any) -> None:
        """Log debug message."""
        self.logger.debug(message, *args, **kwargs)
    
    def info(self, message: str, *args, **kwargs):
        """Log info message."""
        self.logger.info(message, *args, **kwargs)
    
    def warning(self, message: str, *args, **kwargs):
        """Log warning message."""
        self.logger.warning(message, *args, **kwargs)
    
    def error(self, message: str, *args: Any, **kwargs: Any) -> None:
        """Log error message (use log_exception for exceptions)."""
        self.logger.error(message, *args, **kwargs)
    
    def critical(self, message: str, *args: Any, **kwargs: Any) -> None:
        """Log critical message."""
        self.logger.critical(message, *args, **kwargs)


def get_secure_logger(name: str) -> SecureLogger:
    """
    Get a secure logger instance.
    
    Args:
        name: Logger name (typically __name__)
        
    Returns:
        SecureLogger instance
    """
    underlying_logger = logging.getLogger(name)
    return SecureLogger(underlying_logger)


# Convenience function for exception logging
def log_exception_securely(
    logger: logging.Logger, 
    message: str, 
    exception: Exception,
    extra_context: Optional[Dict[str, Any]] = None
) -> None:
    """
    Log an exception securely using any standard logger.
    
    Args:
        logger: Standard logger instance
        message: Error message
        exception: Exception to log
        extra_context: Additional context
    """
    secure_logger = SecureLogger(logger)
    secure_logger.log_exception(message, exception, extra_context=extra_context)
