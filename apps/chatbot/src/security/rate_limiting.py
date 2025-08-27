"""
Rate Limiting for CWE ChatBot DoS Protection

This module provides rate limiting functionality to prevent DoS attacks
on the CWE ChatBot application endpoints and actions.

Key Features:
- Configurable rate limits per endpoint/action
- IP-based and session-based rate limiting
- Sliding window algorithm for accurate rate tracking
- Thread-safe operations
- Automatic cleanup of expired entries
"""

import logging
import threading
import time
from typing import Dict, Tuple, Optional, Callable, Any
from functools import wraps
from collections import defaultdict, deque
from .secure_logging import get_secure_logger

logger = get_secure_logger(__name__)


class RateLimiter:
    """
    Rate limiter using sliding window algorithm.
    
    Tracks requests over time and enforces configurable limits
    to prevent abuse and DoS attacks.
    """
    
    def __init__(self, max_requests: int, window_seconds: int, cleanup_interval: int = 300):
        """
        Initialize rate limiter.
        
        Args:
            max_requests: Maximum requests allowed in time window
            window_seconds: Time window in seconds
            cleanup_interval: How often to cleanup expired entries (seconds)
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.cleanup_interval = cleanup_interval
        
        # Track requests: key -> deque of timestamps
        self._requests: Dict[str, deque] = defaultdict(deque)
        self._lock = threading.RLock()
        self._last_cleanup = time.time()
        
        logger.info(f"RateLimiter initialized: {max_requests} requests per {window_seconds}s")
    
    def is_allowed(self, key: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Check if request is allowed under rate limit.
        
        Args:
            key: Unique identifier for rate limiting (IP, session, etc.)
            
        Returns:
            Tuple of (allowed, metadata) where metadata contains rate limit info
        """
        with self._lock:
            current_time = time.time()
            
            # Cleanup old entries periodically
            if current_time - self._last_cleanup > self.cleanup_interval:
                self._cleanup_expired_entries(current_time)
                self._last_cleanup = current_time
            
            # Get request history for this key
            request_times = self._requests[key]
            
            # Remove requests outside the window
            cutoff_time = current_time - self.window_seconds
            while request_times and request_times[0] <= cutoff_time:
                request_times.popleft()
            
            # Check if under limit
            current_count = len(request_times)
            allowed = current_count < self.max_requests
            
            if allowed:
                # Record this request
                request_times.append(current_time)
            
            # Calculate metadata
            remaining = max(0, self.max_requests - current_count - (1 if allowed else 0))
            reset_time = request_times[0] + self.window_seconds if request_times else current_time
            
            metadata = {
                'limit': self.max_requests,
                'remaining': remaining,
                'reset_time': reset_time,
                'window_seconds': self.window_seconds,
                'current_count': current_count
            }
            
            return allowed, metadata
    
    def _cleanup_expired_entries(self, current_time: float):
        """Clean up expired request tracking entries."""
        try:
            cutoff_time = current_time - self.window_seconds
            keys_to_remove = []
            
            for key, request_times in self._requests.items():
                # Remove expired requests
                while request_times and request_times[0] <= cutoff_time:
                    request_times.popleft()
                
                # If no recent requests, remove the key entirely
                if not request_times:
                    keys_to_remove.append(key)
            
            for key in keys_to_remove:
                del self._requests[key]
            
            if keys_to_remove:
                logger.debug(f"Cleaned up {len(keys_to_remove)} expired rate limit entries")
                
        except Exception as e:
            logger.log_exception("Rate limiter cleanup failed", e)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current rate limiter statistics."""
        with self._lock:
            return {
                'active_keys': len(self._requests),
                'max_requests': self.max_requests,
                'window_seconds': self.window_seconds,
                'total_tracked_requests': sum(len(times) for times in self._requests.values())
            }


class RateLimitExceeded(Exception):
    """Exception raised when rate limit is exceeded."""
    
    def __init__(self, message: str, retry_after: int = None, metadata: Dict[str, Any] = None):
        super().__init__(message)
        self.retry_after = retry_after
        self.metadata = metadata or {}


# Global rate limiters for different endpoints/actions
_rate_limiters: Dict[str, RateLimiter] = {}
_rate_limiter_lock = threading.Lock()


def get_rate_limiter(name: str, max_requests: int, window_seconds: int) -> RateLimiter:
    """Get or create a rate limiter instance."""
    with _rate_limiter_lock:
        if name not in _rate_limiters:
            _rate_limiters[name] = RateLimiter(max_requests, window_seconds)
        return _rate_limiters[name]


def rate_limit(
    max_requests: int = 10, 
    window: int = 60,
    key_func: Optional[Callable] = None,
    name: Optional[str] = None
):
    """
    Decorator to apply rate limiting to functions.
    
    Args:
        max_requests: Maximum requests allowed in time window
        window: Time window in seconds  
        key_func: Function to generate rate limit key (default: uses session info)
        name: Name for the rate limiter (default: function name)
        
    Example:
        @rate_limit(max_requests=5, window=60)
        def process_action(session_id, action_data):
            # This function limited to 5 calls per minute per session
            pass
    """
    def decorator(func: Callable) -> Callable:
        limiter_name = name or f"{func.__module__}.{func.__name__}"
        
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Get rate limiter
            limiter = get_rate_limiter(limiter_name, max_requests, window)
            
            # Generate rate limit key
            if key_func:
                rate_key = key_func(*args, **kwargs)
            else:
                # Default: try to extract session_id from arguments
                rate_key = _extract_session_key(*args, **kwargs)
            
            # Check rate limit
            allowed, metadata = limiter.is_allowed(rate_key)
            
            if not allowed:
                retry_after = int(metadata.get('reset_time', time.time()) - time.time())
                raise RateLimitExceeded(
                    f"Rate limit exceeded for {limiter_name}. "
                    f"Try again in {retry_after} seconds.",
                    retry_after=retry_after,
                    metadata=metadata
                )
            
            # Log rate limit info for monitoring
            logger.debug(f"Rate limit check passed for {limiter_name}: "
                        f"{metadata['current_count']}/{metadata['limit']} requests used")
            
            return func(*args, **kwargs)
        
        return wrapper
    return decorator


def _extract_session_key(*args, **kwargs) -> str:
    """Extract session-based rate limiting key from function arguments."""
    # Try to find session_id in kwargs
    if 'session_id' in kwargs:
        return f"session:{kwargs['session_id']}"
    
    # Try to find session_id in args (common patterns)
    for arg in args:
        if hasattr(arg, 'session_id'):
            return f"session:{arg.session_id}"
        elif isinstance(arg, str) and arg.startswith(('session_', 'sess_')):
            return f"session:{arg}"
    
    # Try to get IP-based key from Chainlit context
    try:
        import chainlit as cl
        user = cl.user_session.get("user")
        if user and hasattr(user, 'identifier'):
            return f"user:{user.identifier}"
    except Exception:
        pass
    
    # Fallback to generic key (will apply global rate limit)
    return "anonymous"


# Pre-configured rate limiters for common use cases
def action_button_rate_limit(max_requests: int = 10, window: int = 60):
    """Rate limiter specifically for action button clicks."""
    return rate_limit(
        max_requests=max_requests,
        window=window,
        name="action_buttons"
    )


def query_rate_limit(max_requests: int = 20, window: int = 60):
    """Rate limiter for user queries."""
    return rate_limit(
        max_requests=max_requests,
        window=window,
        name="user_queries"
    )


def api_rate_limit(max_requests: int = 100, window: int = 3600):
    """Rate limiter for general API calls."""
    return rate_limit(
        max_requests=max_requests,
        window=window,
        name="api_calls"
    )


# Rate limit monitoring
def get_rate_limit_stats() -> Dict[str, Any]:
    """Get statistics for all active rate limiters."""
    with _rate_limiter_lock:
        stats = {}
        for name, limiter in _rate_limiters.items():
            stats[name] = limiter.get_stats()
        return stats


def reset_rate_limits():
    """Reset all rate limiters (for testing/admin purposes)."""
    with _rate_limiter_lock:
        global _rate_limiters
        _rate_limiters.clear()
        logger.info("All rate limiters reset")