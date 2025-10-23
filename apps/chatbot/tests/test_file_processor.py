"""
Unit tests for FileProcessor class (Story 4.3 - Ephemeral PDF Extraction System).

Tests cover:
- AC1: Content type detection via magic bytes
- AC3: Text file validation and processing
- AC7: Error taxonomy with stable error codes

Note: PDF worker integration and OIDC tests are in test_pdf_worker_integration.py
"""

import pytest

from apps.chatbot.src.file_processor import FileProcessor


class TestContentTypeDetection:
    """Tests for AC1: Content type detection via magic bytes."""

    @pytest.fixture
    def processor(self, monkeypatch):
        monkeypatch.setenv("PDF_WORKER_URL", "https://example.com/pdf-worker")
        return FileProcessor()

    def test_detect_pdf_via_magic_bytes(self, processor):
        """Should detect PDF files via %PDF- magic bytes."""
        content = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"
        assert processor.detect_file_type(content) == "pdf"

    def test_detect_text_file_utf8(self, processor):
        """Should detect text files with UTF-8 encoding."""
        content = "This is a plain text file\nwith multiple lines.".encode("utf-8")
        assert processor.detect_file_type(content) == "text"

    def test_reject_binary_with_nul_bytes(self, processor):
        """Should reject binary files containing NUL bytes."""
        content = b"Some text\x00with binary\x00data"
        assert processor.detect_file_type(content) == "unknown"

    def test_reject_low_printable_ratio(self, processor):
        """Should reject files with <90% printable characters."""
        # 10 printable chars, 90 non-printable = 10% ratio
        content = b"Valid text" + bytes(range(128, 218))
        assert processor.detect_file_type(content) == "unknown"

    def test_accept_high_printable_ratio(self, processor):
        """Should accept text files with ≥90% printable characters."""
        # Create text with 95% printable (tabs, newlines, spaces count)
        content = ("Valid text " * 95 + "\x7f" * 5).encode("utf-8")
        result = processor.detect_file_type(content)
        assert result == "text"


class TestTextFileProcessing:
    """Tests for AC3: Text file validation and processing."""

    @pytest.fixture
    def processor(self, monkeypatch):
        monkeypatch.setenv("PDF_WORKER_URL", "https://example.com/pdf-worker")
        return FileProcessor()

    @pytest.mark.asyncio
    async def test_process_valid_utf8_text(self, processor):
        """Should successfully process valid UTF-8 text files."""
        content = "This is valid UTF-8 text\nwith multiple lines.".encode("utf-8")
        result = await processor.process_text_file(content)
        assert result == "This is valid UTF-8 text\nwith multiple lines."

    @pytest.mark.asyncio
    async def test_reject_nul_bytes(self, processor):
        """Should reject text files containing NUL bytes."""
        content = b"Some text\x00with binary"
        with pytest.raises(ValueError, match="binary_text_rejected"):
            await processor.process_text_file(content)

    @pytest.mark.asyncio
    async def test_truncate_large_text(self, processor):
        """Should truncate text exceeding 1M characters."""
        # Create 1.5M character text
        content = ("a" * 1_500_000).encode("utf-8")
        result = await processor.process_text_file(content)
        assert len(result) <= 1_000_100  # 1M + truncation message


class TestErrorTaxonomy:
    """Tests for AC7: Stable error codes with friendly messages."""

    @pytest.fixture
    def processor(self, monkeypatch):
        monkeypatch.setenv("PDF_WORKER_URL", "https://example.com/pdf-worker")
        return FileProcessor()

    def test_all_error_codes_mapped(self, processor):
        """Should have friendly messages for all error codes."""
        error_codes = [
            "too_large",
            "encrypted_pdf_unsupported",
            "pdf_magic_missing",
            "pdf_too_many_pages",
            "pdf_corrupted",
            "pdf_sanitization_failed",
            "text_line_too_long",
            "binary_text_rejected",
            "text_encoding_failed",
            "worker_unavailable",
            "worker_timeout",
            "auth_failed",
            "unknown_content_type",
            "processing_failed",
        ]

        for code in error_codes:
            message = processor.get_friendly_error(code)
            assert message is not None
            assert len(message) > 0
            assert code not in message  # Should not expose internal codes

    def test_friendly_error_messages_user_appropriate(self, processor):
        """Error messages should be clear and actionable for users."""
        message = processor.get_friendly_error("too_large")
        assert "10MB" in message
        assert "limit" in message.lower()

        message = processor.get_friendly_error("encrypted_pdf_unsupported")
        assert "encrypted" in message.lower()
        assert "not supported" in message.lower()


class TestInitialization:
    """Test FileProcessor initialization and configuration."""

    def test_initialization_with_env_var(self, monkeypatch):
        """Should read PDF_WORKER_URL from environment."""
        monkeypatch.setenv("PDF_WORKER_URL", "https://test-url.com/worker")
        processor = FileProcessor()
        assert processor.pdf_worker_url == "https://test-url.com/worker"

    def test_initialization_without_env_var(self, monkeypatch):
        """Should handle missing PDF_WORKER_URL gracefully."""
        monkeypatch.delenv("PDF_WORKER_URL", raising=False)
        processor = FileProcessor()
        assert processor.pdf_worker_url is None

    def test_default_configuration(self, monkeypatch):
        """Should set correct default values."""
        monkeypatch.setenv("PDF_WORKER_URL", "https://example.com")
        processor = FileProcessor()
        assert processor.max_file_size_mb == 10
        assert processor.max_file_size_bytes == 10 * 1024 * 1024
        assert processor.max_output_chars == 1_000_000
        assert processor.pdf_worker_timeout == 55
        assert processor.min_printable_ratio == 0.85
        assert processor.max_line_length == 2 * 1024 * 1024
