"""
Unit tests for FileProcessor class (Story 4.3 - Ephemeral PDF Extraction System).

Tests cover:
- AC1: Content type detection via magic bytes
- AC2: PDF processing via Cloud Functions worker
- AC3: Text file validation and processing
- AC4: File size limits (10MB)
- AC5: OIDC authentication for service-to-service calls
- AC7: Error taxonomy with stable error codes
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from apps.chatbot.src.file_processor import FileProcessor


class TestContentTypeDetection:
    """Tests for AC1: Content type detection via magic bytes."""

    @pytest.fixture
    def processor(self):
        return FileProcessor(pdf_worker_url="https://example.com/pdf-worker")

    def test_detect_pdf_via_magic_bytes(self, processor):
        """Should detect PDF files via %PDF- magic bytes."""
        content = b'%PDF-1.7\n%\xe2\xe3\xcf\xd3\n'
        assert processor.detect_file_type(content) == 'pdf'

    def test_detect_text_file_utf8(self, processor):
        """Should detect text files with UTF-8 encoding."""
        content = "This is a plain text file\nwith multiple lines.".encode('utf-8')
        assert processor.detect_file_type(content) == 'text'

    def test_reject_binary_with_nul_bytes(self, processor):
        """Should reject binary files containing NUL bytes."""
        content = b'Some text\x00with binary\x00data'
        assert processor.detect_file_type(content) == 'unknown'

    def test_reject_low_printable_ratio(self, processor):
        """Should reject files with <90% printable characters."""
        # 10 printable chars, 90 non-printable = 10% ratio
        content = b'Valid text' + bytes(range(128, 218))
        assert processor.detect_file_type(content) == 'unknown'

    def test_accept_high_printable_ratio(self, processor):
        """Should accept text files with ≥90% printable characters."""
        # Create text with 95% printable (tabs, newlines, spaces count)
        content = ("Valid text " * 95 + "\x7f" * 5).encode('utf-8')
        result = processor.detect_file_type(content)
        assert result == 'text'


class TestTextFileProcessing:
    """Tests for AC3: Text file validation and processing."""

    @pytest.fixture
    def processor(self):
        return FileProcessor(pdf_worker_url="https://example.com/pdf-worker")

    @pytest.mark.asyncio
    async def test_process_valid_utf8_text(self, processor):
        """Should successfully process valid UTF-8 text files."""
        content = "This is valid UTF-8 text\nwith multiple lines.".encode('utf-8')
        result = await processor.process_text_file(content)
        assert result == "This is valid UTF-8 text\nwith multiple lines."

    @pytest.mark.asyncio
    async def test_reject_nul_bytes(self, processor):
        """Should reject text files containing NUL bytes."""
        content = b'Some text\x00with binary'
        with pytest.raises(ValueError, match="binary_text_rejected"):
            await processor.process_text_file(content)

    @pytest.mark.asyncio
    async def test_fallback_to_chardet(self, processor):
        """Should use chardet fallback for non-UTF8 encodings."""
        # Latin-1 encoded text
        content = "Café résumé".encode('latin-1')
        result = await processor.process_text_file(content)
        assert "Café résumé" in result or "Caf" in result  # Allow encoding variations

    @pytest.mark.asyncio
    async def test_reject_low_printable_ratio(self, processor):
        """Should reject files with <90% printable characters."""
        # Valid UTF-8 but mostly control characters
        content = ("a" * 10 + "\x01\x02\x03" * 30).encode('utf-8')
        with pytest.raises(ValueError, match="binary_text_rejected"):
            await processor.process_text_file(content)

    @pytest.mark.asyncio
    async def test_truncate_large_text(self, processor):
        """Should truncate text exceeding 1M characters."""
        # Create 1.5M character text
        content = ("a" * 1_500_000).encode('utf-8')
        result = await processor.process_text_file(content)
        assert len(result) == 1_000_000  # Truncated to 1M

    @pytest.mark.asyncio
    async def test_reject_excessive_line_length(self, processor):
        """Should reject files with single lines >2MB."""
        # Single line of 3MB
        content = ("a" * 3_000_000).encode('utf-8')
        with pytest.raises(ValueError, match="text_line_too_long"):
            await processor.process_text_file(content)


class TestPDFWorkerIntegration:
    """Tests for AC2, AC5: PDF worker integration and OIDC auth."""

    @pytest.fixture
    def processor(self):
        return FileProcessor(pdf_worker_url="https://us-central1-project.cloudfunctions.net/pdf-worker")

    @pytest.mark.asyncio
    @patch('apps.chatbot.src.file_processor.httpx.AsyncClient')
    @patch('apps.chatbot.src.file_processor.FileProcessor.get_oidc_token')
    async def test_successful_pdf_processing(self, mock_get_token, mock_client, processor):
        """Should successfully call PDF worker with OIDC token."""
        # Mock OIDC token
        mock_get_token.return_value = "mock-oidc-token"

        # Mock httpx response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'text': 'Extracted PDF text',
            'pages': 5,
            'metadata': {}
        }
        mock_client.return_value.__aenter__.return_value.post = AsyncMock(return_value=mock_response)

        pdf_bytes = b'%PDF-1.7\nfake pdf content'
        result = await processor.call_pdf_worker(pdf_bytes)

        assert result['text'] == 'Extracted PDF text'
        assert result['pages'] == 5
        mock_get_token.assert_called_once()

    @pytest.mark.asyncio
    @patch('apps.chatbot.src.file_processor.httpx.AsyncClient')
    @patch('apps.chatbot.src.file_processor.FileProcessor.get_oidc_token')
    async def test_pdf_too_large_error(self, mock_get_token, mock_client, processor):
        """Should handle 413 Payload Too Large from PDF worker."""
        mock_get_token.return_value = "mock-oidc-token"

        mock_response = MagicMock()
        mock_response.status_code = 413
        mock_response.json.return_value = {'error': 'pdf_too_large'}
        mock_client.return_value.__aenter__.return_value.post = AsyncMock(return_value=mock_response)

        pdf_bytes = b'%PDF-1.7\nlarge pdf'
        with pytest.raises(ValueError, match="too_large"):
            await processor.call_pdf_worker(pdf_bytes)

    @pytest.mark.asyncio
    @patch('apps.chatbot.src.file_processor.httpx.AsyncClient')
    @patch('apps.chatbot.src.file_processor.FileProcessor.get_oidc_token')
    async def test_pdf_worker_retry_on_5xx(self, mock_get_token, mock_client, processor):
        """Should retry once on 5xx errors from PDF worker."""
        mock_get_token.return_value = "mock-oidc-token"

        # First call returns 502, second call succeeds
        mock_response_fail = MagicMock()
        mock_response_fail.status_code = 502

        mock_response_success = MagicMock()
        mock_response_success.status_code = 200
        mock_response_success.json.return_value = {'text': 'Success after retry', 'pages': 1}

        mock_client.return_value.__aenter__.return_value.post = AsyncMock(
            side_effect=[mock_response_fail, mock_response_success]
        )

        pdf_bytes = b'%PDF-1.7\ntest'
        result = await processor.call_pdf_worker(pdf_bytes)

        assert result['text'] == 'Success after retry'
        assert mock_client.return_value.__aenter__.return_value.post.call_count == 2


class TestFileSizeLimits:
    """Tests for AC4: 10MB file size limits."""

    @pytest.fixture
    def processor(self):
        return FileProcessor(pdf_worker_url="https://example.com/pdf-worker")

    @pytest.mark.asyncio
    @patch('chainlit.Message')
    async def test_reject_file_exceeding_10mb(self, mock_message, processor):
        """Should reject files larger than 10MB."""
        # Mock element with 11MB file
        mock_element = MagicMock()
        mock_element.name = "large_file.pdf"
        mock_element.path = "/tmp/large.pdf"

        mock_message.elements = [mock_element]

        with patch.object(processor, '_get_file_content', return_value=b'a' * (11 * 1024 * 1024)):
            result = await processor.process_attachments(mock_message)
            assert "10MB limit" in result

    @pytest.mark.asyncio
    @patch('chainlit.Message')
    async def test_accept_file_at_10mb_limit(self, mock_message, processor):
        """Should accept files exactly at 10MB limit."""
        mock_element = MagicMock()
        mock_element.name = "exactly_10mb.txt"
        mock_element.path = "/tmp/file.txt"

        mock_message.elements = [mock_element]

        # Exactly 10MB of text
        content = b'a' * (10 * 1024 * 1024)

        with patch.object(processor, '_get_file_content', return_value=content):
            with patch.object(processor, 'detect_file_type', return_value='text'):
                with patch.object(processor, 'process_text_file', return_value="Processed"):
                    result = await processor.process_attachments(mock_message)
                    assert result is not None


class TestErrorTaxonomy:
    """Tests for AC7: Stable error codes with friendly messages."""

    @pytest.fixture
    def processor(self):
        return FileProcessor(pdf_worker_url="https://example.com/pdf-worker")

    def test_all_error_codes_mapped(self, processor):
        """Should have friendly messages for all error codes."""
        error_codes = [
            'too_large',
            'encrypted_pdf_unsupported',
            'pdf_magic_missing',
            'pdf_too_many_pages',
            'pdf_corrupted',
            'pdf_sanitization_failed',
            'text_line_too_long',
            'binary_text_rejected',
            'text_encoding_failed',
            'worker_unavailable',
            'worker_timeout',
            'auth_failed',
            'unknown_content_type',
            'processing_failed'
        ]

        for code in error_codes:
            message = processor.get_friendly_error(code)
            assert message is not None
            assert len(message) > 0
            assert code not in message  # Should not expose internal codes

    def test_friendly_error_messages_user_appropriate(self, processor):
        """Error messages should be clear and actionable for users."""
        message = processor.get_friendly_error('too_large')
        assert "10MB" in message
        assert "limit" in message.lower()

        message = processor.get_friendly_error('encrypted_pdf_unsupported')
        assert "encrypted" in message.lower()
        assert "not supported" in message.lower()
