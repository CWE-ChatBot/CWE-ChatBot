# apps/cwe_ingestion/tests/unit/test_downloader.py
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests


def test_cwe_downloader_class_exists():
    """Test CWEDownloader class can be imported and instantiated."""
    from apps.cwe_ingestion.downloader import CWEDownloader

    downloader = CWEDownloader()
    assert downloader is not None
    # This test MUST fail first - CWEDownloader doesn't exist yet

def test_downloader_initializes_with_default_url():
    """Test downloader initializes with correct default MITRE URL."""
    from apps.cwe_ingestion.downloader import CWEDownloader

    downloader = CWEDownloader()
    assert downloader.source_url == "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
    assert downloader.timeout == 30
    assert downloader.verify_ssl is True

def test_downloader_accepts_custom_configuration():
    """Test downloader can be configured with custom parameters."""
    from apps.cwe_ingestion.downloader import CWEDownloader

    custom_url = "https://example.com/cwe.zip"
    downloader = CWEDownloader(source_url=custom_url, timeout=60, verify_ssl=False)

    assert downloader.source_url == custom_url
    assert downloader.timeout == 60
    assert downloader.verify_ssl is False

@patch('requests.get')
def test_download_file_success(mock_get):
    """Test successful CWE file download."""
    from apps.cwe_ingestion.downloader import CWEDownloader

    # Mock successful response
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.iter_content.return_value = [b'test_content']
    mock_get.return_value = mock_response

    downloader = CWEDownloader()

    with tempfile.TemporaryDirectory() as temp_dir:
        output_path = Path(temp_dir) / "cwe_data.zip"
        result = downloader.download_file(str(output_path))

        assert result is True
        assert output_path.exists()
        mock_get.assert_called_once_with(
            downloader.source_url,
            timeout=30,
            verify=True,
            stream=True
        )

@patch('requests.get')
def test_download_file_network_error(mock_get):
    """Test download handles network errors gracefully."""
    from apps.cwe_ingestion.downloader import CWEDownloader

    # Mock network error
    mock_get.side_effect = requests.RequestException("Network error")

    downloader = CWEDownloader()

    with tempfile.TemporaryDirectory() as temp_dir:
        output_path = Path(temp_dir) / "cwe_data.zip"

        with pytest.raises(Exception):
            downloader.download_file(str(output_path))

def test_extract_cwe_xml_from_zip():
    """Test extraction of CWE XML from ZIP archive."""
    from apps.cwe_ingestion.downloader import CWEDownloader

    downloader = CWEDownloader()

    # This test will validate ZIP extraction functionality
    # Implementation details will be added after downloader module is created
    assert hasattr(downloader, '_extract_cwe_xml')

def test_downloader_security_features():
    """Test that downloader has security features enabled."""
    from apps.cwe_ingestion.downloader import CWEDownloader

    downloader = CWEDownloader()

    # Check SSL verification enabled by default
    assert downloader.verify_ssl is True

    # Check reasonable timeout set
    assert downloader.timeout > 0 and downloader.timeout <= 300
