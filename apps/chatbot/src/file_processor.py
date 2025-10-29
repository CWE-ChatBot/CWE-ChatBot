#!/usr/bin/env python3
"""
File Processing - Ephemeral Document Ingestion (Story 4.3)
Processes uploaded files (PDF via Cloud Functions, text locally) for vulnerability information extraction.

Security Features:
- PDF isolation via Cloud Functions v2 worker (OIDC authenticated)
- Content type detection via magic bytes (not file extension)
- Strict text validation (NUL bytes, UTF-8, printable ratio)
- Memory-only processing (no disk persistence)
- Size limits (10MB) and truncation (1M chars)
- No content logging
"""

import asyncio
import logging
import os
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING, Any, Dict, List, Optional

import chainlit as cl

# Optional imports for OIDC and HTTP client
try:
    import google.auth  # noqa: F401

    HAS_GOOGLE_AUTH = True
except ImportError:
    HAS_GOOGLE_AUTH = False

try:
    import httpx

    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False
    if not TYPE_CHECKING:
        httpx = None  # type: ignore[assignment]

try:
    import chardet  # pyright: ignore[reportMissingImports]

    HAS_CHARDET = True
except ImportError:
    HAS_CHARDET = False
    chardet = None  # type: ignore[assignment,unused-ignore]

logger = logging.getLogger(__name__)

# Thread pool for blocking I/O (PDF worker calls)
_executor = ThreadPoolExecutor(max_workers=4)

# Shared HTTP client for connection pooling (reduces connection churn)
# Created lazily on first use to avoid initialization issues
_httpx_client: Optional["httpx.Client"] = None


def _get_httpx_client() -> "httpx.Client":
    """Get or create shared HTTP client with connection pooling and HTTP/2 support."""
    import httpx  # Import here to ensure it's available in this scope

    global _httpx_client
    if _httpx_client is None:
        if not HAS_HTTPX:
            raise RuntimeError("httpx library required for PDF processing")
        _httpx_client = httpx.Client(
            timeout=55,
            follow_redirects=False,
            limits=httpx.Limits(max_keepalive_connections=5, max_connections=10),
            http2=True,  # Enable HTTP/2 for lower latency (multiplexing, header compression)
        )
    return _httpx_client


class FileProcessor:
    """
    Ephemeral Document Ingestion processor (Story 4.3).

    Handles:
    - PDF processing via isolated Cloud Functions v2 worker
    - Text file validation and processing (local, in-memory)
    - Content type detection (magic bytes, not extensions)
    - OIDC authentication for service-to-service calls
    """

    def __init__(self) -> None:
        """Initialize ephemeral file processor."""
        # Maximum file size: 10MB (AC1, AC6)
        self.max_file_size_mb = 10
        self.max_file_size_bytes = self.max_file_size_mb * 1024 * 1024

        # Maximum output: 1M chars (AC4)
        self.max_output_chars = 1_000_000

        # PDF worker configuration
        self.pdf_worker_url = os.getenv("PDF_WORKER_URL")
        self.pdf_worker_timeout = 55  # AC6: Client timeout ≤ 55s

        # Text validation thresholds
        # Printable ratio threshold set to 0.85 to accept legitimate technical text with symbols,
        # while still rejecting binary-like content (AC3)
        self.min_printable_ratio = 0.85  # AC3
        self.max_line_length = 2 * 1024 * 1024  # AC3: 2MB per line

    def detect_file_type(self, content: bytes) -> str:
        """
        Detect file type via magic bytes (content sniffing).

        AC1: File type determined via content sniffing, not extensions.

        Args:
            content: Raw file bytes

        Returns:
            'pdf', 'text', or 'unknown'
        """
        if not content:
            return "unknown"

        # PDF magic bytes
        if content.startswith(b"%PDF-"):
            return "pdf"

        # Text validation: NUL byte check
        if b"\x00" in content:
            return "unknown"

        # Try UTF-8 decode and check printable ratio
        try:
            text = content.decode("utf-8", errors="strict")
            # Calculate printable ratio (allow \n, \r, \t)
            printable = sum(1 for c in text if c.isprintable() or c in "\n\r\t")
            ratio = printable / len(text) if text else 0

            if ratio >= self.min_printable_ratio:
                return "text"
        except UnicodeDecodeError:
            pass

        return "unknown"

    async def get_oidc_token(self, audience: str) -> str:
        """
        Fetch OIDC ID token from metadata server (runs in thread pool to avoid blocking).

        AC5: OIDC authentication for service-to-service calls.

        Args:
            audience: Target audience (function URL)

        Returns:
            OIDC ID token

        Raises:
            RuntimeError: If google-auth not available or token fetch fails
        """
        if not HAS_GOOGLE_AUTH:
            raise RuntimeError("google-auth library required for OIDC authentication")

        def _fetch_token_sync() -> str:
            """Synchronous token fetch for thread pool execution."""
            import google.auth.transport.requests as transport_requests
            import google.oauth2.id_token

            try:
                # Fetch ID token using google.oauth2.id_token.fetch_id_token()
                # This is the recommended approach for Cloud Run -> Cloud Run/Functions calls
                auth_req = transport_requests.Request()
                token = google.oauth2.id_token.fetch_id_token(auth_req, audience)
                logger.info(
                    f"Successfully fetched OIDC token for audience: {audience[:50]}..."
                )
                return str(token)
            except Exception as e:
                logger.error(f"OIDC token fetch failed: {type(e).__name__}: {e}")
                logger.error(f"Audience: {audience}")
                raise

        try:
            # Run blocking metadata server call in thread pool
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(_executor, _fetch_token_sync)
        except Exception as e:
            logger.error(f"OIDC token fetch failed: {type(e).__name__}: {e}")
            raise RuntimeError("auth_failed")

    def _call_pdf_worker_sync(
        self, pdf_bytes: bytes, url: str, token: str
    ) -> Dict[str, Any]:
        """
        Synchronous PDF worker call for ThreadPoolExecutor.

        Uses shared HTTP client for connection pooling to reduce connection churn.

        Args:
            pdf_bytes: Raw PDF bytes
            url: PDF worker URL
            token: OIDC ID token

        Returns:
            {'text': str, 'pages': int, 'sanitized': bool}

        Raises:
            ValueError: With error code for user-friendly messages
        """
        import httpx  # Import here to ensure it's available in this scope

        # Get shared HTTP client (connection pooling)
        client = _get_httpx_client()

        # Call worker with single retry on transient 5xx (AC6)
        max_attempts = 2
        for attempt in range(max_attempts):
            try:
                response = client.post(
                    url,
                    content=pdf_bytes,
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Content-Type": "application/pdf",
                    },
                    timeout=self.pdf_worker_timeout,
                )

                # Check response status
                if response.status_code == 200:
                    return dict(response.json())
                elif response.status_code == 413:
                    raise ValueError("too_large")
                elif response.status_code == 422:
                    # Parse error code from response
                    try:
                        error_data = response.json()
                        error_code = error_data.get("error", "invalid_content")
                    except Exception:
                        error_code = "invalid_content"
                    raise ValueError(error_code)
                elif response.status_code in (401, 403):
                    raise ValueError("auth_failed")
                elif response.status_code >= 500:
                    # Retry on 5xx if first attempt
                    if attempt < max_attempts - 1:
                        logger.warning(
                            f"PDF worker returned {response.status_code}, retrying..."
                        )
                        import time

                        time.sleep(0.5 * (2**attempt))  # Jittered backoff
                        continue
                    raise ValueError("pdf_processing_failed")
                else:
                    raise ValueError("pdf_processing_failed")

            except httpx.TimeoutException:
                raise ValueError("timeout")
            except httpx.HTTPError as e:
                logger.error(f"HTTP error calling PDF worker: {e}")
                raise ValueError("pdf_processing_failed")

        raise ValueError("pdf_processing_failed")

    async def call_pdf_worker(self, pdf_bytes: bytes) -> Dict[str, Any]:
        """
        Call Cloud Functions PDF worker with OIDC authentication (non-blocking).

        AC2, AC5, AC6: Isolated PDF processing with OIDC auth.

        Uses ThreadPoolExecutor to avoid blocking the event loop during HTTP calls,
        which prevents WebSocket disconnections during PDF processing.

        Args:
            pdf_bytes: Raw PDF bytes

        Returns:
            {'text': str, 'pages': int, 'sanitized': bool}

        Raises:
            ValueError: With error code for user-friendly messages
        """
        if not self.pdf_worker_url:
            raise ValueError("pdf_worker_not_configured")

        # Get OIDC token (async call to metadata server)
        try:
            token = await self.get_oidc_token(audience=self.pdf_worker_url)
        except RuntimeError:
            raise ValueError("auth_failed")

        # Run blocking HTTP call in thread pool to avoid blocking event loop
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            _executor, self._call_pdf_worker_sync, pdf_bytes, self.pdf_worker_url, token
        )

    async def process_text_file(self, content: bytes) -> str:
        """
        Process text file with strict validation (AC3).

        Security:
        - NUL byte rejection
        - UTF-8 strict decoding
        - Printable ratio check (≥0.9)
        - Line length limit (2MB)
        - Character truncation (1M)

        Args:
            content: Raw file bytes

        Returns:
            Validated and truncated text

        Raises:
            ValueError: With error code if validation fails
        """
        # Reject NUL bytes (AC3)
        if b"\x00" in content:
            raise ValueError("binary_text_rejected")

        # UTF-8 decode with strict errors (AC3)
        try:
            text = content.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            # Fallback: try chardet detection once (AC3)
            if HAS_CHARDET:
                import chardet  # pyright: ignore[reportMissingImports]  # Import here to ensure it's available

                detected = chardet.detect(content)
                if detected["confidence"] < 0.8:
                    raise ValueError("decoding_failed")
                try:
                    text = content.decode(detected["encoding"], errors="strict")
                except Exception:
                    raise ValueError("decoding_failed")
            else:
                raise ValueError("decoding_failed")

        # Check printable ratio (AC3)
        printable = sum(1 for c in text if c.isprintable() or c in "\n\r\t")
        ratio = printable / len(text) if text else 0
        if ratio < self.min_printable_ratio:
            raise ValueError("binary_text_rejected")

        # Reject pathologically long lines (AC3)
        lines = text.split("\n")
        if any(len(line) > self.max_line_length for line in lines):
            raise ValueError("line_too_long")

        # Truncate to max chars (AC4)
        if len(text) > self.max_output_chars:
            text = text[: self.max_output_chars]
            logger.info(
                f"Text truncated from {len(text)} to {self.max_output_chars} chars"
            )
            return text + "\n\n[Content truncated at 1,000,000 characters]"

        return text

    def get_friendly_error(self, error_code: str) -> str:
        """Map error codes to user-friendly messages (AC7)."""
        messages = {
            "too_large": "File exceeds 10MB limit. Please upload a smaller file.",
            "too_many_pages": "PDF exceeds 50 pages. Please split into smaller documents.",
            "timeout": "File processing timed out. Try a smaller file.",
            "invalid_content_type": "Unsupported file type. Please upload PDF or text files.",
            "pdf_magic_missing": "File does not appear to be a valid PDF.",
            "encrypted_pdf_unsupported": "Encrypted PDFs are not supported. Please remove password protection.",
            "image_only_pdf_unsupported": "Image-only PDFs require OCR which is not supported.",
            "binary_text_rejected": "File contains binary data and cannot be processed as text.",
            "text_encoding_failed": "Text encoding could not be determined.",
            "decoding_failed": "Text encoding could not be determined.",  # Alias for text_encoding_failed
            "text_line_too_long": "File contains excessively long lines.",
            "line_too_long": "File contains excessively long lines.",  # Alias for text_line_too_long
            "pdf_too_many_pages": "PDF exceeds 50 pages. Please split into smaller documents.",
            "pdf_corrupted": "PDF file appears to be corrupted or invalid.",
            "pdf_sanitization_failed": "PDF security sanitization failed.",
            "auth_failed": "PDF processing service authentication failed.",
            "worker_unavailable": "PDF processing service is temporarily unavailable. Please try again.",
            "worker_timeout": "PDF processing service timed out. Try a smaller file.",
            "pdf_worker_not_configured": "PDF processing is not configured.",
            "pdf_processing_failed": "PDF processing failed. Please try again.",
            "processing_failed": "File processing failed. Please try again.",
            "unknown_content_type": "File type could not be determined.",
        }
        return messages.get(error_code, f"File processing error: {error_code}")

    async def process_attachments(self, message: cl.Message) -> Optional[str]:
        """
        Process file attachments using ephemeral document ingestion (Story 4.3).

        AC1: Size validation (10MB)
        AC1, AC2, AC3: Content type detection and processing

        Args:
            message: Chainlit message with potential file attachments

        Returns:
            Extracted text content from files, or None if no files/issues
        """
        if not hasattr(message, "elements") or not message.elements:
            logger.debug("No file attachments found in message")
            return None

        extracted_content = []

        for element in message.elements:
            if hasattr(element, "type") and element.type == "file":
                try:
                    # Get file content
                    file_content = await self._get_file_content(element)

                    # AC1: Size validation (10MB)
                    if len(file_content) > self.max_file_size_bytes:
                        file_size_mb = len(file_content) / (1024 * 1024)
                        error_msg = self.get_friendly_error("too_large")
                        extracted_content.append(
                            f"\n--- File: {element.name} ---\n{error_msg}\n"
                        )
                        logger.warning(
                            f"File too large: {element.name} ({file_size_mb:.1f}MB)"
                        )
                        continue

                    # AC1: Detect file type via magic bytes (not extension)
                    file_type = self.detect_file_type(file_content)

                    if file_type == "pdf":
                        # AC2: Process PDF via isolated Cloud Functions worker
                        try:
                            result = await self.call_pdf_worker(file_content)
                            text = result["text"]
                            pages = result["pages"]
                            file_info = f"\n--- File: {element.name} ({pages} pages, sanitized) ---\n"
                            extracted_content.append(file_info + text)
                            logger.info(
                                f"PDF processed: {element.name}, {pages} pages, {len(text)} chars"
                            )
                        except ValueError as e:
                            error_msg = self.get_friendly_error(str(e))
                            extracted_content.append(
                                f"\n--- File: {element.name} ---\n{error_msg}\n"
                            )
                            logger.warning(
                                f"PDF processing failed for {element.name}: {str(e)}"
                            )

                    elif file_type == "text":
                        # AC3: Process text file locally with strict validation
                        try:
                            text = await self.process_text_file(file_content)
                            file_info = f"\n--- File: {element.name} ---\n"
                            extracted_content.append(file_info + text)
                            logger.info(
                                f"Text processed: {element.name}, {len(text)} chars"
                            )
                        except ValueError as e:
                            error_msg = self.get_friendly_error(str(e))
                            extracted_content.append(
                                f"\n--- File: {element.name} ---\n{error_msg}\n"
                            )
                            logger.warning(
                                f"Text processing failed for {element.name}: {str(e)}"
                            )

                    else:
                        # Unsupported file type
                        error_msg = self.get_friendly_error("invalid_content_type")
                        extracted_content.append(
                            f"\n--- File: {element.name} ---\n{error_msg}\n"
                        )
                        logger.warning(f"Unsupported file type: {element.name}")

                except Exception as e:
                    # Log the full error for debugging
                    logger.error(
                        f"Unexpected error processing file {element.name}: {type(e).__name__}: {e}"
                    )
                    if os.getenv("LOG_LEVEL") == "DEBUG":
                        import traceback

                        traceback.print_exc()

                    # Show user-friendly error instead of raw exception text
                    error_msg = "An unexpected error occurred while processing this file. Please try again or contact support if the issue persists."
                    extracted_content.append(
                        f"\n--- File: {element.name} ---\n{error_msg}\n"
                    )

        if extracted_content:
            return "\n".join(extracted_content)
        return None

    async def _get_file_content(self, file_element: Any) -> bytes:
        """
        Get raw file content from Chainlit file element.

        Args:
            file_element: Chainlit file element

        Returns:
            Raw file bytes

        Raises:
            RuntimeError: If file content cannot be accessed
        """
        if hasattr(file_element, "content") and file_element.content is not None:
            return bytes(file_element.content)
        elif hasattr(file_element, "path") and file_element.path:
            return await asyncio.to_thread(self._read_file_from_path, file_element.path)
        else:
            raise RuntimeError(
                f"Cannot access file content for {getattr(file_element, 'name', 'unknown')}"
            )

    def _read_file_from_path(self, file_path: str) -> bytes:
        """Helper method to read file content from path (for asyncio.to_thread).
        Optional hardening: ensure path resides under an allow-listed temp directory.
        """
        # B108: /tmp is secure default for Chainlit temp uploads, overridable via env var
        base = os.getenv("UPLOAD_TMP_DIR", "/tmp")  # nosec B108
        real = os.path.realpath(file_path)
        base_real = os.path.realpath(base)
        if not real.startswith(base_real + os.sep):
            raise RuntimeError("Disallowed file path")
        with open(real, "rb") as f:
            return f.read()

    def analyze_vulnerability_content(self, content: str) -> Dict[str, Any]:
        """
        Analyze extracted content for vulnerability indicators.

        Args:
            content: Extracted file content

        Returns:
            Analysis results with vulnerability indicators
        """
        content_lower = content.lower()

        # Look for vulnerability indicators
        vulnerability_indicators = {
            "cve_references": self._find_cve_references(content),
            "vulnerability_types": self._identify_vulnerability_types(content_lower),
            "product_information": self._extract_product_info(content),
            "impact_indicators": self._find_impact_indicators(content_lower),
            "attack_vectors": self._identify_attack_vectors(content_lower),
            "severity_indicators": self._find_severity_indicators(content_lower),
        }

        return {
            "content_length": len(content),
            "has_vulnerability_content": any(vulnerability_indicators.values()),
            "indicators": vulnerability_indicators,
            "confidence_score": self._calculate_confidence_score(
                vulnerability_indicators
            ),
        }

    def _find_cve_references(self, content: str) -> List[str]:
        """Find CVE references in content."""
        import re

        cve_pattern = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
        return list(set(cve_pattern.findall(content)))

    def _identify_vulnerability_types(self, content_lower: str) -> List[str]:
        """Identify vulnerability types mentioned."""
        vuln_types = [
            "sql injection",
            "cross-site scripting",
            "buffer overflow",
            "authentication bypass",
            "privilege escalation",
            "remote code execution",
            "denial of service",
            "information disclosure",
            "path traversal",
            "csrf",
            "xxe",
            "deserialization",
            "race condition",
        ]

        found_types = []
        for vuln_type in vuln_types:
            if vuln_type in content_lower:
                found_types.append(vuln_type)

        return found_types

    def _extract_product_info(self, content: str) -> Dict[str, Any]:
        """Extract product and vendor information."""
        import re

        # Look for version patterns
        version_pattern = re.compile(
            r"version\s+([0-9]+(?:\.[0-9]+)*(?:-[a-zA-Z0-9]+)*)", re.IGNORECASE
        )
        versions = list(set(version_pattern.findall(content)))

        # Look for common product/vendor patterns
        product_indicators = [
            "product",
            "software",
            "application",
            "system",
            "platform",
        ]
        vendor_indicators = ["vendor", "company", "developer", "manufacturer"]

        return {
            "versions": versions,
            "product_mentions": len(
                [word for word in product_indicators if word in content.lower()]
            ),
            "vendor_mentions": len(
                [word for word in vendor_indicators if word in content.lower()]
            ),
        }

    def _find_impact_indicators(self, content_lower: str) -> List[str]:
        """Find impact-related indicators."""
        impact_terms = [
            "execute arbitrary code",
            "remote code execution",
            "privilege escalation",
            "data disclosure",
            "information leak",
            "denial of service",
            "bypass authentication",
            "gain access",
            "unauthorized",
        ]

        return [term for term in impact_terms if term in content_lower]

    def _identify_attack_vectors(self, content_lower: str) -> List[str]:
        """Identify attack vectors mentioned."""
        attack_vectors = [
            "crafted request",
            "malicious input",
            "specially crafted",
            "malformed request",
            "user input",
            "file upload",
            "network request",
            "authenticated user",
            "remote attacker",
        ]

        return [vector for vector in attack_vectors if vector in content_lower]

    def _find_severity_indicators(self, content_lower: str) -> Dict[str, bool]:
        """Find severity-related indicators."""
        return {
            "critical": any(
                term in content_lower for term in ["critical", "severe", "high risk"]
            ),
            "high": any(
                term in content_lower for term in ["high", "important", "significant"]
            ),
            "medium": any(term in content_lower for term in ["medium", "moderate"]),
            "low": any(
                term in content_lower for term in ["low", "minor", "informational"]
            ),
        }

    def _calculate_confidence_score(self, indicators: Dict[str, Any]) -> int:
        """Calculate confidence score based on found indicators."""
        score = 0

        # CVE references add confidence
        if indicators.get("cve_references"):
            score += 30

        # Vulnerability types add confidence
        vuln_types = indicators.get("vulnerability_types", [])
        score += min(len(vuln_types) * 15, 40)

        # Product information adds confidence
        product_info = indicators.get("product_information", {})
        if product_info.get("versions"):
            score += 20
        if product_info.get("product_mentions", 0) > 0:
            score += 10

        # Impact and attack vectors add confidence
        if indicators.get("impact_indicators"):
            score += 15
        if indicators.get("attack_vectors"):
            score += 10

        return min(score, 100)
