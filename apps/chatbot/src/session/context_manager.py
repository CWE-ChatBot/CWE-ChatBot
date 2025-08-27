"""
Session Context Manager for Story 2.2 - Conversational Memory

This module provides secure session management for maintaining conversational context
while ensuring strict session isolation between users.

Key Features:
- Secure session context storage using Chainlit's session management
- Strict session isolation (no context contamination)
- Context history for follow-up questions
- Automatic session cleanup
"""

import logging
from typing import Optional, Dict, Any, List
import threading
from datetime import datetime, timedelta
import chainlit as cl

logger = logging.getLogger(__name__)


class SessionContextManager:
    """
    Manages conversational context within user sessions with strict security isolation.
    
    This class ensures that each user's conversational context is completely isolated
    and cannot contaminate other user sessions. It provides thread-safe operations
    for storing and retrieving context information.
    """
    
    # Class-level lock for thread safety
    _lock = threading.Lock()
    
    # Session cleanup configuration
    DEFAULT_SESSION_TIMEOUT = timedelta(hours=2)
    MAX_CONTEXT_HISTORY = 5  # Maximum number of previous CWEs to remember
    
    def __init__(self, session_timeout: Optional[timedelta] = None):
        """
        Initialize session context manager.
        
        Args:
            session_timeout: How long to keep session context before cleanup
        """
        self.session_timeout = session_timeout or self.DEFAULT_SESSION_TIMEOUT
        logger.info("SessionContextManager initialized")
    
    def set_current_cwe(self, cwe_id: str, cwe_data: Optional[Dict[str, Any]] = None) -> bool:
        """
        Store current CWE in session with security isolation.
        
        Args:
            cwe_id: CWE identifier (e.g., "CWE-79")
            cwe_data: Optional comprehensive CWE data
            
        Returns:
            True if stored successfully, False otherwise
        """
        try:
            # Get current session ID from Chainlit
            session_id = self._get_session_id()
            if not session_id:
                logger.warning("No valid session ID available")
                return False
            
            with self._lock:
                # Get or initialize session context
                context = cl.user_session.get("cwe_context", {})
                
                # Update current CWE
                context["current_cwe"] = {
                    "cwe_id": cwe_id,
                    "timestamp": datetime.utcnow().isoformat(),
                    "data": cwe_data or {}
                }
                
                # Add to history (maintain max history size)
                if "history" not in context:
                    context["history"] = []
                
                # Don't add to history if it's the same as the current one
                if not context["history"] or context["history"][-1]["cwe_id"] != cwe_id:
                    context["history"].append({
                        "cwe_id": cwe_id,
                        "timestamp": datetime.utcnow().isoformat(),
                        "data": cwe_data or {}
                    })
                
                # Trim history to max size
                if len(context["history"]) > self.MAX_CONTEXT_HISTORY:
                    context["history"] = context["history"][-self.MAX_CONTEXT_HISTORY:]
                
                # Store back in session
                cl.user_session.set("cwe_context", context)
                
                logger.debug(f"Set current CWE to {cwe_id} for session {session_id}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to set current CWE {cwe_id}: {e}")
            return False
    
    def get_current_cwe(self) -> Optional[Dict[str, Any]]:
        """
        Retrieve current CWE from session.
        
        Returns:
            Dictionary with current CWE data or None if not set
        """
        try:
            session_id = self._get_session_id()
            if not session_id:
                return None
            
            with self._lock:
                context = cl.user_session.get("cwe_context", {})
                current_cwe = context.get("current_cwe")
                
                if current_cwe:
                    # Validate timestamp (ensure it's not too old)
                    timestamp_str = current_cwe.get("timestamp")
                    if timestamp_str:
                        timestamp = datetime.fromisoformat(timestamp_str)
                        if datetime.utcnow() - timestamp > self.session_timeout:
                            logger.info(f"Current CWE context expired for session {session_id}")
                            self.clear_session()
                            return None
                
                logger.debug(f"Retrieved current CWE: {current_cwe.get('cwe_id') if current_cwe else None}")
                return current_cwe
                
        except Exception as e:
            logger.error(f"Failed to get current CWE: {e}")
            return None
    
    def get_context_history(self) -> List[Dict[str, Any]]:
        """
        Get the conversation history for context.
        
        Returns:
            List of previous CWE contexts in chronological order
        """
        try:
            session_id = self._get_session_id()
            if not session_id:
                return []
            
            with self._lock:
                context = cl.user_session.get("cwe_context", {})
                history = context.get("history", [])
                
                # Filter out expired entries
                valid_history = []
                cutoff_time = datetime.utcnow() - self.session_timeout
                
                for entry in history:
                    timestamp_str = entry.get("timestamp")
                    if timestamp_str:
                        timestamp = datetime.fromisoformat(timestamp_str)
                        if timestamp > cutoff_time:
                            valid_history.append(entry)
                
                logger.debug(f"Retrieved {len(valid_history)} valid history entries")
                return valid_history
                
        except Exception as e:
            logger.error(f"Failed to get context history: {e}")
            return []
    
    def has_context(self) -> bool:
        """
        Check if there's any valid context in the current session.
        
        Returns:
            True if there's valid context, False otherwise
        """
        current_cwe = self.get_current_cwe()
        return current_cwe is not None
    
    def clear_session(self) -> bool:
        """
        Clear all session context.
        
        Returns:
            True if cleared successfully, False otherwise
        """
        try:
            session_id = self._get_session_id()
            if not session_id:
                return False
            
            with self._lock:
                # Clear CWE context but preserve other session data
                cl.user_session.set("cwe_context", {})
                
                logger.info(f"Cleared session context for session {session_id}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to clear session: {e}")
            return False
    
    def get_session_summary(self) -> Dict[str, Any]:
        """
        Get a summary of the current session state for debugging.
        
        Returns:
            Dictionary with session summary information
        """
        try:
            session_id = self._get_session_id()
            current_cwe = self.get_current_cwe()
            history = self.get_context_history()
            
            return {
                "session_id": session_id,
                "has_context": current_cwe is not None,
                "current_cwe": current_cwe.get("cwe_id") if current_cwe else None,
                "history_count": len(history),
                "history_cwes": [entry.get("cwe_id") for entry in history],
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to get session summary: {e}")
            return {"error": str(e)}
    
    def _get_session_id(self) -> Optional[str]:
        """
        Get the current session ID from Chainlit.
        
        Returns:
            Session ID string or None if not available
        """
        try:
            # Try to get session ID from Chainlit's user session
            session_id = cl.user_session.get("id")
            if not session_id:
                # Generate a new session ID if one doesn't exist
                import uuid
                session_id = str(uuid.uuid4())
                cl.user_session.set("id", session_id)
                logger.info(f"Generated new session ID: {session_id}")
            
            return session_id
            
        except Exception as e:
            logger.error(f"Failed to get session ID: {e}")
            return None
    
    @classmethod
    def cleanup_expired_sessions(cls) -> int:
        """
        Clean up expired session data (class method for periodic cleanup).
        
        Returns:
            Number of sessions cleaned up
        """
        # Note: This is a placeholder as Chainlit handles session cleanup
        # In a production system, this would clean up persistent session storage
        logger.info("Session cleanup completed (handled by Chainlit)")
        return 0