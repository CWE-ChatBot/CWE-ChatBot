"""
Session Security Validator for Story 2.2 - Session Isolation Verification

This module provides security validation to ensure that session isolation is maintained
and that no context contamination occurs between different user sessions.

Key Security Features:
- Session isolation verification
- Context contamination detection  
- Security audit logging
- Session boundary enforcement
"""

import logging
from typing import Dict, Any, List, Optional
import threading
import time
from datetime import datetime
import chainlit as cl

logger = logging.getLogger(__name__)


class SessionSecurityValidator:
    """
    Validates session security and isolation to prevent context contamination.
    
    This class provides security controls to ensure that conversational context
    cannot leak between different user sessions, which would be a critical
    security vulnerability.
    """
    
    # Thread-safe instance tracking for security validation
    _active_sessions = {}
    _lock = threading.Lock()
    
    def __init__(self):
        """Initialize session security validator."""
        self.validation_count = 0
        logger.info("SessionSecurityValidator initialized")
    
    def validate_session_isolation(self, session_id: str) -> bool:
        """
        Verify that session isolation is maintained for the given session.
        
        Args:
            session_id: Session identifier to validate
            
        Returns:
            True if session is properly isolated, False if contamination detected
        """
        try:
            with self._lock:
                self.validation_count += 1
                
                # Check if this is a valid session ID format
                if not self._is_valid_session_id(session_id):
                    logger.error(f"Invalid session ID format: {session_id}")
                    return False
                
                # Record this session as active
                self._active_sessions[session_id] = {
                    "first_seen": time.time(),
                    "last_validated": time.time(),
                    "validation_count": self._active_sessions.get(session_id, {}).get("validation_count", 0) + 1
                }
                
                # Verify session context is isolated
                isolation_valid = self._verify_context_isolation(session_id)
                
                # Log security validation result
                if isolation_valid:
                    logger.debug(f"Session isolation validated for {session_id}")
                else:
                    logger.error(f"Session isolation FAILED for {session_id}")
                    self._log_security_violation(session_id, "isolation_failure")
                
                return isolation_valid
                
        except Exception as e:
            logger.error(f"Session isolation validation failed: {e}")
            self._log_security_violation(session_id, "validation_error", str(e))
            return False
    
    def detect_context_contamination(self, session_id: str, context_data: Dict[str, Any]) -> bool:
        """
        Detect if context data shows signs of contamination from other sessions.
        
        Args:
            session_id: Current session identifier
            context_data: Context data to analyze
            
        Returns:
            True if contamination detected, False if clean
        """
        try:
            # Check for suspicious context patterns that might indicate contamination
            contamination_indicators = []
            
            # Check 1: Multiple session IDs in context data
            if self._check_multiple_session_ids(context_data):
                contamination_indicators.append("multiple_session_ids")
            
            # Check 2: Timestamp inconsistencies
            if self._check_timestamp_anomalies(session_id, context_data):
                contamination_indicators.append("timestamp_anomalies")
            
            # Check 3: Context size anomalies
            if self._check_context_size_anomalies(context_data):
                contamination_indicators.append("context_size_anomalies")
            
            # Log any contamination indicators
            if contamination_indicators:
                logger.error(f"Context contamination detected for {session_id}: {contamination_indicators}")
                self._log_security_violation(
                    session_id, 
                    "context_contamination", 
                    f"Indicators: {', '.join(contamination_indicators)}"
                )
                return True
            
            logger.debug(f"Context contamination check passed for {session_id}")
            return False
            
        except Exception as e:
            logger.error(f"Context contamination detection failed: {e}")
            return True  # Err on the side of caution
    
    def validate_session_boundaries(self, session_id: str) -> Dict[str, Any]:
        """
        Validate that session boundaries are properly enforced.
        
        Args:
            session_id: Session identifier to validate
            
        Returns:
            Dictionary with validation results and security metrics
        """
        try:
            validation_results = {
                "session_id": session_id,
                "timestamp": datetime.utcnow().isoformat(),
                "isolation_valid": False,
                "contamination_detected": False,
                "security_score": 0.0,
                "issues": []
            }
            
            # Test 1: Session isolation
            isolation_valid = self.validate_session_isolation(session_id)
            validation_results["isolation_valid"] = isolation_valid
            
            if not isolation_valid:
                validation_results["issues"].append("isolation_failure")
            
            # Test 2: Context contamination (get current context safely)
            try:
                current_context = cl.user_session.get("cwe_context", {})
                contamination_detected = self.detect_context_contamination(session_id, current_context)
                validation_results["contamination_detected"] = contamination_detected
                
                if contamination_detected:
                    validation_results["issues"].append("context_contamination")
            except Exception:
                validation_results["issues"].append("context_access_error")
            
            # Test 3: Session metadata consistency
            metadata_valid = self._validate_session_metadata(session_id)
            if not metadata_valid:
                validation_results["issues"].append("metadata_inconsistency")
            
            # Calculate security score
            max_score = 100.0
            issue_penalty = 25.0 * len(validation_results["issues"])
            validation_results["security_score"] = max(0.0, max_score - issue_penalty)
            
            # Log validation summary
            if validation_results["issues"]:
                logger.warning(f"Session boundary validation issues for {session_id}: {validation_results['issues']}")
            else:
                logger.debug(f"Session boundary validation passed for {session_id}")
            
            return validation_results
            
        except Exception as e:
            logger.error(f"Session boundary validation failed: {e}")
            return {
                "session_id": session_id,
                "error": str(e),
                "security_score": 0.0,
                "issues": ["validation_error"]
            }
    
    def get_security_metrics(self) -> Dict[str, Any]:
        """
        Get overall security metrics for monitoring.
        
        Returns:
            Dictionary with security metrics
        """
        try:
            with self._lock:
                current_time = time.time()
                active_count = len([
                    s for s, data in self._active_sessions.items()
                    if current_time - data["last_validated"] < 3600  # Active in last hour
                ])
                
                return {
                    "total_validations": self.validation_count,
                    "active_sessions": active_count,
                    "total_tracked_sessions": len(self._active_sessions),
                    "validator_uptime": current_time,
                    "timestamp": datetime.utcnow().isoformat()
                }
                
        except Exception as e:
            logger.error(f"Failed to get security metrics: {e}")
            return {"error": str(e)}
    
    def _is_valid_session_id(self, session_id: str) -> bool:
        """Validate session ID format."""
        if not session_id or not isinstance(session_id, str):
            return False
        
        # Basic validation - should be a reasonable length string
        if len(session_id) < 8 or len(session_id) > 128:
            return False
        
        # Should not contain suspicious characters
        suspicious_chars = ["<", ">", "&", "\"", "'", "\\", "/"]
        if any(char in session_id for char in suspicious_chars):
            return False
        
        return True
    
    def _verify_context_isolation(self, session_id: str) -> bool:
        """Verify that context is properly isolated to this session."""
        try:
            # Check that we can access session context without errors
            context = cl.user_session.get("cwe_context", {})
            
            # Verify context structure is reasonable
            if not isinstance(context, dict):
                return False
            
            # Check for reasonable context size (prevent memory attacks)
            context_str = str(context)
            if len(context_str) > 10000:  # 10KB limit per session context
                logger.warning(f"Session context size exceeds limit: {len(context_str)} bytes")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Context isolation verification failed: {e}")
            return False
    
    def _check_multiple_session_ids(self, context_data: Dict[str, Any]) -> bool:
        """Check if context contains references to multiple session IDs."""
        # This is a placeholder - in a real implementation, we'd check for
        # session ID patterns in the context data
        context_str = str(context_data).lower()
        
        # Look for multiple UUID-like patterns (simplified check)
        import re
        uuid_pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
        uuid_matches = re.findall(uuid_pattern, context_str)
        
        # More than one unique UUID might indicate contamination
        return len(set(uuid_matches)) > 1
    
    def _check_timestamp_anomalies(self, session_id: str, context_data: Dict[str, Any]) -> bool:
        """Check for timestamp anomalies that might indicate contamination."""
        try:
            # Check if timestamps in context are reasonable
            current_time = datetime.utcnow()
            
            # Extract timestamps from context (this is a simplified check)
            for key, value in context_data.items():
                if isinstance(value, dict) and "timestamp" in value:
                    timestamp_str = value["timestamp"]
                    try:
                        timestamp = datetime.fromisoformat(timestamp_str)
                        # Check if timestamp is too far in the past or future
                        time_diff = abs((current_time - timestamp).total_seconds())
                        if time_diff > 86400:  # More than 24 hours
                            return True
                    except ValueError:
                        return True  # Invalid timestamp format
            
            return False
            
        except Exception:
            return True  # Err on the side of caution
    
    def _check_context_size_anomalies(self, context_data: Dict[str, Any]) -> bool:
        """Check for unusual context size that might indicate contamination."""
        try:
            # Check total context size
            context_str = str(context_data)
            size_bytes = len(context_str.encode('utf-8'))
            
            # Flag if context is unusually large (might indicate accumulated data)
            if size_bytes > 5000:  # 5KB threshold
                logger.warning(f"Context size anomaly detected: {size_bytes} bytes")
                return True
            
            # Check depth of nesting (prevent deeply nested attacks)
            max_depth = self._get_dict_depth(context_data)
            if max_depth > 10:
                logger.warning(f"Context depth anomaly detected: {max_depth} levels")
                return True
            
            return False
            
        except Exception:
            return True  # Err on the side of caution
    
    def _get_dict_depth(self, d: Any, depth: int = 0) -> int:
        """Get the maximum depth of a nested dictionary."""
        if not isinstance(d, dict):
            return depth
        
        if not d:
            return depth + 1
        
        return max(self._get_dict_depth(v, depth + 1) for v in d.values())
    
    def _validate_session_metadata(self, session_id: str) -> bool:
        """Validate session metadata consistency."""
        try:
            # Check if session is tracked properly
            with self._lock:
                session_info = self._active_sessions.get(session_id)
                if not session_info:
                    return False
                
                # Basic consistency checks
                current_time = time.time()
                if session_info["first_seen"] > current_time:
                    return False
                
                if session_info["last_validated"] > current_time:
                    return False
                
                return True
                
        except Exception:
            return False
    
    def _log_security_violation(self, session_id: str, violation_type: str, details: str = "") -> None:
        """Log security violations for audit purposes."""
        violation_log = {
            "timestamp": datetime.utcnow().isoformat(),
            "session_id": session_id,
            "violation_type": violation_type,
            "details": details,
            "validator_instance": id(self)
        }
        
        logger.error(f"SECURITY VIOLATION: {violation_log}")
        
        # In a production system, this would also:
        # - Send alerts to security team
        # - Update security metrics
        # - Potentially block the session