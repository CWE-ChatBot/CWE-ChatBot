#!/usr/bin/env python3
"""
Test FileProcessor error handling to prevent error messages being analyzed as content.

Story 4.3 - Verifies that unexpected exceptions show user-friendly errors,
not raw error text that could be misinterpreted as PDF content.
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch
import asyncio


class TestFileProcessorErrorHandling:
    """Test error handling in file attachment processing."""

    @pytest.mark.asyncio
    async def test_unexpected_exception_shows_friendly_error(self):
        """
        Test that unexpected exceptions during file processing show user-friendly messages.

        REGRESSION TEST: Previously, raw error text was appended to extracted_content,
        causing error messages to be analyzed as document content.
        """
        from src.file_processor import FileProcessor

        processor = FileProcessor()

        # Create a mock message with file element that will trigger an exception
        mock_message = Mock()
        mock_element = Mock()
        mock_element.type = 'file'
        mock_element.name = 'test.pdf'

        # Make _get_file_content raise an unexpected exception
        with patch.object(
            processor,
            '_get_file_content',
            side_effect=RuntimeError("Unexpected error: h2 package not installed")
        ):
            mock_message.elements = [mock_element]

            # Process attachments
            result = await processor.process_attachments(mock_message)

            # Verify result contains user-friendly error, NOT raw exception text
            assert result is not None
            assert "test.pdf" in result

            # CRITICAL: Should NOT contain the raw error message
            assert "h2 package not installed" not in result
            assert "Unexpected error: h2" not in result

            # Should contain friendly error message
            assert "unexpected error occurred" in result.lower()
            assert "try again" in result.lower() or "contact support" in result.lower()

    @pytest.mark.asyncio
    async def test_http2_error_not_leaked_to_user(self):
        """
        Test that HTTP/2 configuration errors show friendly messages.

        SPECIFIC REGRESSION: The h2 package error was being shown to users as PDF content.
        """
        from src.file_processor import FileProcessor

        processor = FileProcessor()

        mock_message = Mock()
        mock_element = Mock()
        mock_element.type = 'file'
        mock_element.name = 'document.pdf'

        # Simulate the exact error that occurred in production
        error_message = (
            "Using http2=True, but the 'h2' package is not installed. "
            "Make sure to install httpx using pip install httpx[http2]"
        )

        with patch.object(
            processor,
            '_get_file_content',
            side_effect=RuntimeError(error_message)
        ):
            mock_message.elements = [mock_element]
            result = await processor.process_attachments(mock_message)

            # Verify the technical error is NOT exposed to user
            assert "http2=True" not in result
            assert "h2 package" not in result
            assert "pip install" not in result
            assert "httpx[http2]" not in result

            # Should show generic friendly error
            assert "unexpected error" in result.lower()

    @pytest.mark.asyncio
    async def test_value_error_shows_mapped_friendly_message(self):
        """
        Test that ValueError exceptions (expected errors) show mapped friendly messages.

        This is the CORRECT error handling path - ValueErrors should be mapped.
        """
        from src.file_processor import FileProcessor

        processor = FileProcessor()

        mock_message = Mock()
        mock_element = Mock()
        mock_element.type = 'file'
        mock_element.name = 'large.pdf'
        mock_element.content = b'fake pdf content'

        # Simulate file too large error
        with patch.object(
            processor,
            '_get_file_content',
            return_value=b'x' * (11 * 1024 * 1024)  # 11MB
        ):
            mock_message.elements = [mock_element]
            result = await processor.process_attachments(mock_message)

            # Should show the mapped error message from get_friendly_error()
            assert "10MB limit" in result or "exceeds" in result.lower()
            assert "large.pdf" in result

    @pytest.mark.asyncio
    async def test_pdf_worker_auth_error_friendly_message(self):
        """Test that PDF worker authentication errors show friendly messages."""
        from src.file_processor import FileProcessor

        processor = FileProcessor()
        processor.pdf_worker_url = "https://example.com/pdf-worker"

        mock_message = Mock()
        mock_element = Mock()
        mock_element.type = 'file'
        mock_element.name = 'secure.pdf'

        # Mock file content
        with patch.object(
            processor,
            '_get_file_content',
            return_value=b'%PDF-1.4 fake pdf'
        ):
            # Mock PDF worker call to raise auth error
            with patch.object(
                processor,
                'call_pdf_worker',
                side_effect=ValueError("auth_failed")
            ):
                mock_message.elements = [mock_element]
                result = await processor.process_attachments(mock_message)

                # Should show friendly auth error message
                assert "auth" in result.lower() or "permission" in result.lower()
                # Should NOT show raw error code
                assert "auth_failed" not in result

    def test_error_message_mapping_completeness(self):
        """
        Test that all error codes have friendly message mappings.

        Ensures get_friendly_error() has entries for all raised ValueErrors.
        """
        from src.file_processor import FileProcessor

        processor = FileProcessor()

        # Known error codes that can be raised
        error_codes = [
            'too_large',
            'too_many_pages',
            'timeout',
            'invalid_content_type',
            'pdf_magic_missing',
            'encrypted_pdf_unsupported',
            'image_only_pdf_unsupported',
            'binary_text_rejected',
            'text_encoding_failed',
            'decoding_failed',
            'text_line_too_long',
            'line_too_long',
            'pdf_too_many_pages',
            'pdf_corrupted',
            'pdf_sanitization_failed',
            'pdf_worker_not_configured',
            'auth_failed',
            'pdf_processing_failed',
        ]

        for error_code in error_codes:
            friendly_msg = processor.get_friendly_error(error_code)

            # Should return a user-friendly message, not the error code itself
            assert friendly_msg != error_code
            assert len(friendly_msg) > 10  # Actual message, not just code
            assert not friendly_msg.startswith("_")  # Not a variable name


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
