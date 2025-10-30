"""
Unit tests for Bootstrapper component initialization.

Tests the R18 Phase 2 refactoring of initialize_components().
"""

import os
from unittest.mock import MagicMock, patch

import pytest

from apps.chatbot.bootstrap import Bootstrapper, Components


class TestBootstrapper:
    """Test Bootstrapper initialization logic."""

    def test_successful_initialization(self, monkeypatch):
        """Test successful component initialization."""
        # Mock environment
        monkeypatch.setenv("DATABASE_URL", "postgresql://test:test@localhost/test")
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")

        # Mock dependencies
        mock_cm = MagicMock()
        mock_cm.get_system_health.return_value = {"database": True}

        def cm_factory(database_url, gemini_api_key, engine):
            return mock_cm

        # Initialize
        bootstrapper = Bootstrapper(db_factory=None, cm_factory=cm_factory)
        components = bootstrapper.initialize()

        # Assert
        assert components.ok is True
        assert components.conversation_manager is mock_cm
        assert components.input_sanitizer is not None
        assert components.security_validator is not None
        assert components.file_processor is not None

    def test_missing_gemini_key(self, monkeypatch):
        """Test initialization fails without GEMINI_API_KEY and no offline mode."""
        monkeypatch.setenv("DATABASE_URL", "postgresql://test:test@localhost/test")
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.delenv("DISABLE_AI", raising=False)

        mock_cm = MagicMock()

        def cm_factory(database_url, gemini_api_key, engine):
            return mock_cm

        bootstrapper = Bootstrapper(db_factory=None, cm_factory=cm_factory)
        components = bootstrapper.initialize()

        assert components.ok is False
        assert components.conversation_manager is None

    def test_offline_mode_without_key(self, monkeypatch):
        """Test initialization succeeds in offline mode without GEMINI_API_KEY."""
        monkeypatch.setenv("DATABASE_URL", "postgresql://test:test@localhost/test")
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.setenv("DISABLE_AI", "1")

        mock_cm = MagicMock()
        mock_cm.get_system_health.return_value = {"database": True}

        def cm_factory(database_url, gemini_api_key, engine):
            return mock_cm

        bootstrapper = Bootstrapper(db_factory=None, cm_factory=cm_factory)
        components = bootstrapper.initialize()

        assert components.ok is True

    def test_database_health_check_failure(self, monkeypatch):
        """Test initialization fails when database health check fails."""
        monkeypatch.setenv("DATABASE_URL", "postgresql://test:test@localhost/test")
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")

        mock_cm = MagicMock()
        mock_cm.get_system_health.return_value = {"database": False}

        def cm_factory(database_url, gemini_api_key, engine):
            return mock_cm

        bootstrapper = Bootstrapper(db_factory=None, cm_factory=cm_factory)
        components = bootstrapper.initialize()

        assert components.ok is False

    def test_private_ip_connection(self, monkeypatch):
        """Test Private IP database connection path."""
        monkeypatch.setenv("DB_HOST", "10.0.0.1")
        monkeypatch.setenv("DB_USER", "test_user")
        monkeypatch.setenv("DB_PASSWORD", "test_pass")
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")

        mock_engine = MagicMock()
        mock_cm = MagicMock()
        mock_cm.get_system_health.return_value = {"database": True}

        def cm_factory(database_url, gemini_api_key, engine):
            return mock_cm

        # Patch the engine function where it's imported (inside the method)
        with patch("src.db.engine", return_value=mock_engine):
            bootstrapper = Bootstrapper(db_factory=None, cm_factory=cm_factory)
            components = bootstrapper.initialize()

            assert components.ok is True
            assert components.db_engine is mock_engine

    def test_cloud_sql_connector(self, monkeypatch):
        """Test Cloud SQL Connector path."""
        monkeypatch.setenv("INSTANCE_CONN_NAME", "project:region:instance")
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")

        mock_engine = MagicMock()
        mock_cm = MagicMock()
        mock_cm.get_system_health.return_value = {"database": True}

        def cm_factory(database_url, gemini_api_key, engine):
            return mock_cm

        with patch("src.db.engine", return_value=mock_engine):
            bootstrapper = Bootstrapper(db_factory=None, cm_factory=cm_factory)
            components = bootstrapper.initialize()

            assert components.ok is True


    def test_traditional_database_url(self, monkeypatch):
        """Test traditional DATABASE_URL path."""
        monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@localhost/db")
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")

        mock_cm = MagicMock()
        mock_cm.get_system_health.return_value = {"database": True}

        def cm_factory(database_url, gemini_api_key, engine):
            assert database_url == "postgresql://user:pass@localhost/db"
            return mock_cm

        bootstrapper = Bootstrapper(db_factory=None, cm_factory=cm_factory)
        components = bootstrapper.initialize()

        assert components.ok is True
        assert components.db_engine is None  # No engine for traditional URL
