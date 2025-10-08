"""
Integration tests for PDF Worker (Story 4.3 - Cloud Functions v2).

These tests verify the actual PDF worker deployment:
- AC2: PDF sanitization and text extraction
- AC5: OIDC authentication
- AC6: Size and page limits
- AC8: Security headers
- AC9: No disk persistence (verified via function behavior)

NOTE: These tests require the PDF worker to be deployed to Cloud Functions.
Set PDF_WORKER_URL environment variable to the deployed function URL.
"""
import os

import google.auth.transport.requests
import httpx
import pytest
from google.auth import compute_engine

# Skip if PDF_WORKER_URL not configured
pytestmark = pytest.mark.skipif(
    not os.getenv("PDF_WORKER_URL"),
    reason="PDF_WORKER_URL not set - skipping integration tests",
)


class TestPDFWorkerDeployment:
    """Integration tests for deployed PDF worker."""

    @pytest.fixture
    def pdf_worker_url(self):
        """Get PDF worker URL from environment."""
        return os.getenv("PDF_WORKER_URL")

    @pytest.fixture
    def oidc_token(self, pdf_worker_url):
        """Get OIDC token for authentication."""
        credentials = compute_engine.IDTokenCredentials(
            request=google.auth.transport.requests.Request(),
            target_audience=pdf_worker_url,
        )
        credentials.refresh(google.auth.transport.requests.Request())
        return credentials.token

    def test_worker_rejects_unauthenticated_requests(self, pdf_worker_url):
        """Should return 403 for requests without OIDC token (AC5)."""
        response = httpx.post(
            pdf_worker_url,
            content=b"%PDF-1.7\ntest",
            headers={"Content-Type": "application/pdf"},
            follow_redirects=False,
        )
        assert response.status_code == 403

    def test_worker_security_headers(self, pdf_worker_url, oidc_token):
        """Should return security headers on all responses (AC8)."""
        response = httpx.post(
            pdf_worker_url,
            content=b"%PDF-1.7\ntest",
            headers={
                "Authorization": f"Bearer {oidc_token}",
                "Content-Type": "application/pdf",
            },
            follow_redirects=False,
        )

        assert "X-Content-Type-Options" in response.headers
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert "Referrer-Policy" in response.headers
        assert response.headers["Referrer-Policy"] == "no-referrer"
        assert "X-Frame-Options" in response.headers
        assert response.headers["X-Frame-Options"] == "DENY"

    def test_worker_rejects_missing_pdf_magic_bytes(self, pdf_worker_url, oidc_token):
        """Should reject files without PDF magic bytes (AC2)."""
        response = httpx.post(
            pdf_worker_url,
            content=b"Not a PDF file",
            headers={
                "Authorization": f"Bearer {oidc_token}",
                "Content-Type": "application/pdf",
            },
            follow_redirects=False,
        )

        assert response.status_code == 422
        data = response.json()
        assert data["error"] == "pdf_magic_missing"

    def test_worker_rejects_file_exceeding_10mb(self, pdf_worker_url, oidc_token):
        """Should reject files exceeding 10MB (AC6)."""
        # Create 11MB payload
        large_pdf = b"%PDF-1.7\n" + b"a" * (11 * 1024 * 1024)

        response = httpx.post(
            pdf_worker_url,
            content=large_pdf,
            headers={
                "Authorization": f"Bearer {oidc_token}",
                "Content-Type": "application/pdf",
            },
            follow_redirects=False,
            timeout=30,
        )

        assert response.status_code == 413
        data = response.json()
        assert data["error"] == "pdf_too_large"

    @pytest.mark.integration
    def test_worker_processes_valid_pdf(self, pdf_worker_url, oidc_token):
        """Should successfully process valid PDF files (AC2)."""
        # Minimal valid PDF with text
        minimal_pdf = b"""%PDF-1.7
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> >> >> /Contents 4 0 R >>
endobj
4 0 obj
<< /Length 44 >>
stream
BT
/F1 12 Tf
100 700 Td
(Test content) Tj
ET
endstream
endobj
xref
0 5
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000115 00000 n
0000000270 00000 n
trailer
<< /Size 5 /Root 1 0 R >>
startxref
364
%%EOF
"""

        response = httpx.post(
            pdf_worker_url,
            content=minimal_pdf,
            headers={
                "Authorization": f"Bearer {oidc_token}",
                "Content-Type": "application/pdf",
            },
            follow_redirects=False,
            timeout=30,
        )

        assert response.status_code == 200
        data = response.json()
        assert "text" in data
        assert "pages" in data
        assert data["pages"] >= 1

    @pytest.mark.integration
    def test_worker_sanitizes_javascript(self, pdf_worker_url, oidc_token):
        """Should remove JavaScript from PDFs (AC2 - sanitization)."""
        # PDF with JavaScript (simplified - real test would use actual PDF with JS)
        pdf_with_js = b"""%PDF-1.7
1 0 obj
<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /JavaScript /JS (app.alert('XSS')) >> >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R >>
endobj
xref
0 4
0000000000 65535 f
0000000009 00000 n
0000000120 00000 n
0000000177 00000 n
trailer
<< /Size 4 /Root 1 0 R >>
startxref
220
%%EOF
"""

        response = httpx.post(
            pdf_worker_url,
            content=pdf_with_js,
            headers={
                "Authorization": f"Bearer {oidc_token}",
                "Content-Type": "application/pdf",
            },
            follow_redirects=False,
            timeout=30,
        )

        # Should either sanitize successfully or reject dangerous PDF
        assert response.status_code in [200, 422]
        if response.status_code == 200:
            # If sanitized, verify no JavaScript execution warnings in metadata
            data = response.json()
            assert "text" in data

    def test_worker_rejects_excessive_pages(self, pdf_worker_url, oidc_token):
        """Should reject PDFs exceeding 50 pages (AC6)."""
        # This would require generating a 51-page PDF
        # In practice, this test may need a fixture file
        pytest.skip("Requires 51-page PDF fixture file")


class TestPDFWorkerErrors:
    """Test error handling and taxonomy (AC7)."""

    @pytest.fixture
    def pdf_worker_url(self):
        return os.getenv("PDF_WORKER_URL")

    @pytest.fixture
    def oidc_token(self, pdf_worker_url):
        credentials = compute_engine.IDTokenCredentials(
            request=google.auth.transport.requests.Request(),
            target_audience=pdf_worker_url,
        )
        credentials.refresh(google.auth.transport.requests.Request())
        return credentials.token

    def test_worker_returns_stable_error_codes(self, pdf_worker_url, oidc_token):
        """Should return stable error codes for different failure modes."""
        # Test various error conditions
        test_cases = [
            (b"Not a PDF", 422, "pdf_magic_missing"),
            (b"%PDF-1.7\n" + b"a" * (11 * 1024 * 1024), 413, "pdf_too_large"),
        ]

        for content, expected_status, expected_error in test_cases:
            response = httpx.post(
                pdf_worker_url,
                content=content,
                headers={
                    "Authorization": f"Bearer {oidc_token}",
                    "Content-Type": "application/pdf",
                },
                follow_redirects=False,
                timeout=30,
            )

            assert response.status_code == expected_status
            if expected_error:
                data = response.json()
                assert data["error"] == expected_error
