"""
Unit tests for Story 2.2 Session Management components.

Tests session context management, security validation, and session isolation.
"""

# Mock Chainlit before importing session components
import sys
import threading
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

import pytest

mock_cl = Mock()
mock_cl.user_session = Mock()
sys.modules["chainlit"] = mock_cl

from src.session.context_manager import SessionContextManager
from src.session.session_security import SessionSecurityValidator


class TestSessionContextManager:
    """Test session context management functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.session_manager = SessionContextManager()

        # Mock Chainlit user session
        self.mock_session_data = {}
        mock_cl.user_session.get.side_effect = (
            lambda key, default=None: self.mock_session_data.get(key, default)
        )
        mock_cl.user_session.set.side_effect = (
            lambda key, value: self.mock_session_data.update({key: value})
        )

    def test_initialization(self):
        """Test SessionContextManager initialization."""
        manager = SessionContextManager()
        assert manager.session_timeout == SessionContextManager.DEFAULT_SESSION_TIMEOUT
        assert manager.MAX_CONTEXT_HISTORY == 5

    def test_set_current_cwe_success(self):
        """Test successfully setting current CWE in session."""
        # Mock session ID
        with patch.object(
            self.session_manager, "_get_session_id", return_value="test-session-123"
        ):
            success = self.session_manager.set_current_cwe(
                "CWE-79", {"description": "XSS vulnerability"}
            )

            assert success is True
            assert "cwe_context" in self.mock_session_data

            context = self.mock_session_data["cwe_context"]
            assert context["current_cwe"]["cwe_id"] == "CWE-79"
            assert "timestamp" in context["current_cwe"]
            assert len(context["history"]) == 1

    def test_set_current_cwe_no_session(self):
        """Test setting CWE fails when no session ID available."""
        with patch.object(self.session_manager, "_get_session_id", return_value=None):
            success = self.session_manager.set_current_cwe("CWE-79")
            assert success is False

    def test_get_current_cwe_success(self):
        """Test successfully retrieving current CWE from session."""
        # Set up context first
        with patch.object(
            self.session_manager, "_get_session_id", return_value="test-session-123"
        ):
            self.session_manager.set_current_cwe("CWE-89", {"name": "SQL Injection"})

        # Retrieve context
        with patch.object(
            self.session_manager, "_get_session_id", return_value="test-session-123"
        ):
            current_cwe = self.session_manager.get_current_cwe()

            assert current_cwe is not None
            assert current_cwe["cwe_id"] == "CWE-89"
            assert current_cwe["data"]["name"] == "SQL Injection"

    def test_get_current_cwe_no_context(self):
        """Test retrieving CWE when no context exists."""
        with patch.object(
            self.session_manager, "_get_session_id", return_value="test-session-123"
        ):
            current_cwe = self.session_manager.get_current_cwe()
            assert current_cwe is None

    def test_get_current_cwe_expired(self):
        """Test retrieving CWE when context has expired."""
        # Set up expired context
        old_timestamp = (datetime.utcnow() - timedelta(hours=3)).isoformat()
        self.mock_session_data["cwe_context"] = {
            "current_cwe": {"cwe_id": "CWE-79", "timestamp": old_timestamp}
        }

        with patch.object(
            self.session_manager, "_get_session_id", return_value="test-session-123"
        ):
            current_cwe = self.session_manager.get_current_cwe()

            # Should return None due to expiration and clear session
            assert current_cwe is None
            assert self.mock_session_data.get("cwe_context", {}) == {}

    def test_context_history_management(self):
        """Test that context history is properly managed."""
        with patch.object(
            self.session_manager, "_get_session_id", return_value="test-session-123"
        ):
            # Add multiple CWEs to test history management
            cwes = ["CWE-79", "CWE-89", "CWE-120", "CWE-20", "CWE-787", "CWE-125"]

            for cwe in cwes:
                self.session_manager.set_current_cwe(cwe, {"name": f"Test {cwe}"})

            context = self.mock_session_data["cwe_context"]

            # Should maintain max history size
            assert len(context["history"]) <= SessionContextManager.MAX_CONTEXT_HISTORY

            # Most recent entries should be preserved
            history_cwes = [entry["cwe_id"] for entry in context["history"]]
            assert "CWE-125" in history_cwes  # Most recent should be included

    def test_session_isolation(self):
        """Test that different session IDs maintain separate contexts."""
        # Session 1
        with patch.object(
            self.session_manager, "_get_session_id", return_value="session-1"
        ):
            session_1_data = {}
            mock_cl.user_session.get.side_effect = (
                lambda key, default=None: session_1_data.get(key, default)
            )
            mock_cl.user_session.set.side_effect = (
                lambda key, value: session_1_data.update({key: value})
            )

            self.session_manager.set_current_cwe("CWE-79")

        # Session 2
        with patch.object(
            self.session_manager, "_get_session_id", return_value="session-2"
        ):
            session_2_data = {}
            mock_cl.user_session.get.side_effect = (
                lambda key, default=None: session_2_data.get(key, default)
            )
            mock_cl.user_session.set.side_effect = (
                lambda key, value: session_2_data.update({key: value})
            )

            self.session_manager.set_current_cwe("CWE-89")
            current_cwe = self.session_manager.get_current_cwe()

            # Should only see Session 2's CWE
            assert current_cwe["cwe_id"] == "CWE-89"

    def test_clear_session(self):
        """Test clearing session context."""
        with patch.object(
            self.session_manager, "_get_session_id", return_value="test-session-123"
        ):
            # Set up context
            self.session_manager.set_current_cwe("CWE-79")
            assert self.session_manager.has_context() is True

            # Clear session
            success = self.session_manager.clear_session()
            assert success is True
            assert self.session_manager.has_context() is False

    def test_thread_safety(self):
        """Test thread safety of session operations."""
        results = []

        def worker(session_id, cwe_id):
            with patch.object(
                self.session_manager, "_get_session_id", return_value=session_id
            ):
                # Each thread works with its own mock session data
                thread_data = {}
                with patch.object(
                    mock_cl.user_session,
                    "get",
                    side_effect=lambda key, default=None: thread_data.get(key, default),
                ):
                    with patch.object(
                        mock_cl.user_session,
                        "set",
                        side_effect=lambda key, value: thread_data.update({key: value}),
                    ):
                        success = self.session_manager.set_current_cwe(cwe_id)
                        results.append((session_id, cwe_id, success))

        # Run multiple threads
        threads = []
        for i in range(5):
            thread = threading.Thread(target=worker, args=(f"session-{i}", f"CWE-{i}"))
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # All operations should succeed
        assert len(results) == 5
        assert all(success for _, _, success in results)


class TestSessionSecurityValidator:
    """Test session security validation functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.security_validator = SessionSecurityValidator()

    def test_initialization(self):
        """Test SessionSecurityValidator initialization."""
        validator = SessionSecurityValidator()
        assert validator.validation_count == 0
        assert hasattr(validator, "_active_sessions")

    def test_validate_session_isolation_valid_session(self):
        """Test session isolation validation with valid session."""
        session_id = "valid-session-123"

        with patch.object(
            self.security_validator, "_verify_context_isolation", return_value=True
        ):
            result = self.security_validator.validate_session_isolation(session_id)

            assert result is True
            assert self.security_validator.validation_count > 0
            assert session_id in self.security_validator._active_sessions

    def test_validate_session_isolation_invalid_format(self):
        """Test session isolation validation with invalid session ID format."""
        invalid_ids = ["", None, "abc", "<script>alert(1)</script>", "a" * 200]

        for invalid_id in invalid_ids:
            result = self.security_validator.validate_session_isolation(invalid_id)
            assert result is False

    def test_detect_context_contamination_clean(self):
        """Test context contamination detection with clean data."""
        session_id = "clean-session-123"
        clean_context = {
            "current_cwe": {
                "cwe_id": "CWE-79",
                "timestamp": datetime.utcnow().isoformat(),
            },
            "history": [],
        }

        contamination = self.security_validator.detect_context_contamination(
            session_id, clean_context
        )
        assert contamination is False

    def test_detect_context_contamination_suspicious(self):
        """Test context contamination detection with suspicious patterns."""
        session_id = "test-session-123"

        # Test with multiple UUID patterns (potential contamination)
        contaminated_context = {
            "session_refs": [
                "12345678-1234-1234-1234-123456789abc",
                "87654321-4321-4321-4321-cba987654321",
            ],
            "data": "some data",
        }

        with patch.object(
            self.security_validator, "_check_multiple_session_ids", return_value=True
        ):
            contamination = self.security_validator.detect_context_contamination(
                session_id, contaminated_context
            )
            assert contamination is True

    def test_validate_session_boundaries(self):
        """Test comprehensive session boundary validation."""
        session_id = "boundary-test-session"

        with patch.object(
            self.security_validator, "validate_session_isolation", return_value=True
        ):
            with patch.object(
                self.security_validator,
                "detect_context_contamination",
                return_value=False,
            ):
                with patch.object(
                    self.security_validator,
                    "_validate_session_metadata",
                    return_value=True,
                ):
                    result = self.security_validator.validate_session_boundaries(
                        session_id
                    )

                    assert isinstance(result, dict)
                    assert result["session_id"] == session_id
                    assert result["isolation_valid"] is True
                    assert result["contamination_detected"] is False
                    assert (
                        result["security_score"] > 90.0
                    )  # High score for clean session
                    assert len(result["issues"]) == 0

    def test_validate_session_boundaries_with_issues(self):
        """Test session boundary validation with security issues."""
        session_id = "problematic-session"

        with patch.object(
            self.security_validator, "validate_session_isolation", return_value=False
        ):
            with patch.object(
                self.security_validator,
                "detect_context_contamination",
                return_value=True,
            ):
                result = self.security_validator.validate_session_boundaries(session_id)

                assert result["isolation_valid"] is False
                assert result["contamination_detected"] is True
                assert result["security_score"] < 50.0  # Low score due to issues
                assert len(result["issues"]) > 0

    def test_security_metrics(self):
        """Test security metrics collection."""
        # Perform some validations to generate metrics
        for i in range(3):
            self.security_validator.validate_session_isolation(f"session-{i}")

        metrics = self.security_validator.get_security_metrics()

        assert isinstance(metrics, dict)
        assert metrics["total_validations"] >= 3
        assert "active_sessions" in metrics
        assert "timestamp" in metrics

    def test_context_size_limits(self):
        """Test context size anomaly detection."""
        # Create oversized context
        large_context = {"large_data": "x" * 10000}  # 10KB of data

        result = self.security_validator._check_context_size_anomalies(large_context)
        assert result is True  # Should detect size anomaly

        # Test normal sized context
        normal_context = {"current_cwe": {"cwe_id": "CWE-79"}, "history": []}

        result = self.security_validator._check_context_size_anomalies(normal_context)
        assert result is False  # Should pass size check

    def test_timestamp_validation(self):
        """Test timestamp anomaly detection."""
        session_id = "timestamp-test-session"

        # Test with very old timestamp (should be flagged)
        old_context = {
            "current_cwe": {
                "cwe_id": "CWE-79",
                "timestamp": (datetime.utcnow() - timedelta(days=2)).isoformat(),
            }
        }

        result = self.security_validator._check_timestamp_anomalies(
            session_id, old_context
        )
        assert result is True  # Should detect timestamp anomaly

        # Test with recent timestamp (should pass)
        recent_context = {
            "current_cwe": {
                "cwe_id": "CWE-79",
                "timestamp": datetime.utcnow().isoformat(),
            }
        }

        result = self.security_validator._check_timestamp_anomalies(
            session_id, recent_context
        )
        assert result is False  # Should pass timestamp check


@pytest.mark.integration
class TestSessionIntegration:
    """Integration tests for session management components."""

    def setup_method(self):
        """Set up integration test fixtures."""
        self.session_manager = SessionContextManager()
        self.security_validator = SessionSecurityValidator()

    def test_session_workflow_integration(self):
        """Test complete session workflow integration."""
        session_id = "integration-test-session"

        with patch.object(
            self.session_manager, "_get_session_id", return_value=session_id
        ):
            # Mock session data for this test
            session_data = {}
            mock_cl.user_session.get.side_effect = (
                lambda key, default=None: session_data.get(key, default)
            )
            mock_cl.user_session.set.side_effect = (
                lambda key, value: session_data.update({key: value})
            )

            # 1. Validate session security
            security_valid = self.security_validator.validate_session_isolation(
                session_id
            )
            assert security_valid is True

            # 2. Set context
            context_set = self.session_manager.set_current_cwe(
                "CWE-79", {"name": "XSS"}
            )
            assert context_set is True

            # 3. Validate no contamination
            context = session_data.get("cwe_context", {})
            contamination = self.security_validator.detect_context_contamination(
                session_id, context
            )
            assert contamination is False

            # 4. Retrieve context
            current_cwe = self.session_manager.get_current_cwe()
            assert current_cwe is not None
            assert current_cwe["cwe_id"] == "CWE-79"

            # 5. Clear context
            cleared = self.session_manager.clear_session()
            assert cleared is True

            # 6. Verify context is gone
            assert self.session_manager.has_context() is False

    def test_enhanced_security_logging(self):
        """Test enhanced structured security logging (M2 security fix)."""
        import json
        from unittest.mock import patch

        # Capture log output
        with patch("src.session.session_security.logger") as mock_logger:
            # Trigger a security violation
            self.security_validator._log_security_violation(
                "test-session-123", "isolation_failure", "Test violation details"
            )

            # Verify structured logging was called
            assert mock_logger.error.called
            logged_call = mock_logger.error.call_args[0][0]

            # Parse the JSON log entry
            log_data = json.loads(logged_call)

            # Verify structured log format
            assert log_data["event_type"] == "security_violation"
            assert log_data["violation_type"] == "isolation_failure"
            assert log_data["severity"] == "HIGH"  # isolation_failure is high severity
            assert log_data["details"] == "Test violation details"
            assert "timestamp" in log_data
            assert "session_id" in log_data  # Should be hashed
            assert log_data["session_id"] != "test-session-123"  # Should be hashed

    def test_security_logging_helper_methods(self):
        """Test security logging helper methods (M2 security fix)."""
        # Test session ID hashing
        hashed_id = self.security_validator._hash_session_id("test-session-123")
        assert hashed_id != "test-session-123"
        assert len(hashed_id) == 16  # Truncated hash
        assert hashed_id == self.security_validator._hash_session_id(
            "test-session-123"
        )  # Consistent

        # Test empty session ID
        hashed_empty = self.security_validator._hash_session_id("")
        assert hashed_empty == "unknown"

        # Test severity levels
        assert (
            self.security_validator._get_violation_severity("isolation_failure")
            == "HIGH"
        )
        assert (
            self.security_validator._get_violation_severity("validation_error")
            == "MEDIUM"
        )
        assert self.security_validator._get_violation_severity("unknown_type") == "LOW"

        # Test client IP (should return None in test environment)
        client_ip = self.security_validator._get_client_ip()
        assert client_ip is None
