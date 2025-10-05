#!/usr/bin/env python3
"""
Cloud Functions v2 PDF Worker - Ephemeral PDF Processing

Security Features:
- PDF sanitization (remove JavaScript, embedded files, XFA)
- Magic byte validation
- Size and page limits
- No disk persistence (memory-only via BytesIO)
- OIDC authentication via Cloud Functions IAM
- No content logging (metadata only)
"""
import io
import json
import logging
import os
from typing import Any, Dict, Tuple

# Optional imports - will fail gracefully if not available
try:
    import pikepdf
    HAS_PIKEPDF = True
except ImportError:
    HAS_PIKEPDF = False

try:
    from pdfminer.high_level import extract_text
    HAS_PDFMINER = True
except ImportError:
    HAS_PDFMINER = False

# Configure logging (metadata only, no content)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Constants
MAX_BYTES = 10 * 1024 * 1024  # 10MB
MAX_PAGES = 50
MAX_OUTPUT_CHARS = 1_000_000


def sanitize_pdf(pdf_data: bytes) -> bytes:
    """
    Sanitize PDF by removing dangerous elements.

    Removes:
    - /OpenAction (auto-execute on open)
    - /AA (additional actions)
    - JavaScript
    - XFA forms
    - Embedded files

    Args:
        pdf_data: Raw PDF bytes

    Returns:
        Sanitized PDF bytes

    Raises:
        Exception: If PDF cannot be sanitized
    """
    if not HAS_PIKEPDF:
        raise ImportError("pikepdf not available")

    pdf = pikepdf.open(io.BytesIO(pdf_data))

    # Remove auto-execute actions
    if '/OpenAction' in pdf.Root:
        del pdf.Root['/OpenAction']

    if '/AA' in pdf.Root:
        del pdf.Root['/AA']

    # Remove JavaScript
    if '/Names' in pdf.Root:
        names = pdf.Root['/Names']
        if '/JavaScript' in names:
            del names['/JavaScript']

    # Remove XFA forms
    if '/AcroForm' in pdf.Root:
        acro_form = pdf.Root['/AcroForm']
        if '/XFA' in acro_form:
            del acro_form['/XFA']

    # Remove embedded files
    if '/Names' in pdf.Root:
        names = pdf.Root['/Names']
        if '/EmbeddedFiles' in names:
            del names['/EmbeddedFiles']

    # Save to bytes
    output = io.BytesIO()
    pdf.save(output)
    pdf.close()

    return output.getvalue()


def extract_pdf_text(pdf_data: bytes) -> str:
    """
    Extract text from PDF using pdfminer.

    Args:
        pdf_data: Sanitized PDF bytes

    Returns:
        Extracted text

    Raises:
        Exception: If text extraction fails
    """
    if not HAS_PDFMINER:
        raise ImportError("pdfminer.six not available")

    text = extract_text(io.BytesIO(pdf_data))

    # Truncate to max chars
    if len(text) > MAX_OUTPUT_CHARS:
        text = text[:MAX_OUTPUT_CHARS]
        text += "\n\n[Content truncated at 1,000,000 characters]"

    return text


def count_pdf_pages(pdf_data: bytes) -> int:
    """
    Count pages in PDF.

    Args:
        pdf_data: PDF bytes

    Returns:
        Number of pages
    """
    if not HAS_PIKEPDF:
        return 0

    try:
        pdf = pikepdf.open(io.BytesIO(pdf_data))
        page_count = len(pdf.pages)
        pdf.close()
        return page_count
    except Exception:
        return 0


def pdf_worker(request):
    """
    Cloud Functions v2 entry point for PDF processing.

    This is a simple HTTP function that processes PDFs with:
    - Magic byte validation
    - Size limits (10MB, 50 pages)
    - PDF sanitization (remove JavaScript, etc.)
    - Text extraction
    - Memory-only processing (no disk writes)

    Args:
        request: Flask request object from Cloud Functions

    Returns:
        Tuple of (response_body, status_code, headers)
    """
    # Security headers
    headers = {
        'Content-Type': 'application/json',
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'no-referrer',
        'X-Frame-Options': 'DENY',
    }

    # Only accept POST
    if request.method != 'POST':
        return (
            json.dumps({'error': 'method_not_allowed'}),
            405,
            headers
        )

    # Check library availability
    if not HAS_PIKEPDF or not HAS_PDFMINER:
        logger.error("Required libraries not available")
        return (
            json.dumps({'error': 'server_misconfigured'}),
            500,
            headers
        )

    # Get request body
    try:
        pdf_data = request.get_data()
    except Exception as e:
        logger.error(f"Failed to get request data: {e}")
        return (
            json.dumps({'error': 'invalid_request'}),
            400,
            headers
        )

    # Validate size
    if len(pdf_data) > MAX_BYTES:
        logger.warning(f"PDF too large: {len(pdf_data)} bytes")
        return (
            json.dumps({'error': 'pdf_too_large'}),
            413,
            headers
        )

    # Validate PDF magic bytes
    if not pdf_data.startswith(b'%PDF-'):
        logger.warning("PDF magic bytes missing")
        return (
            json.dumps({'error': 'pdf_magic_missing'}),
            422,
            headers
        )

    # Count pages
    try:
        page_count = count_pdf_pages(pdf_data)
        if page_count > MAX_PAGES:
            logger.warning(f"PDF has too many pages: {page_count}")
            return (
                json.dumps({'error': 'pdf_too_many_pages'}),
                422,
                headers
            )
    except Exception as e:
        logger.error(f"Failed to count pages: {e}")
        return (
            json.dumps({'error': 'pdf_corrupted'}),
            422,
            headers
        )

    # Sanitize PDF
    try:
        sanitized_data = sanitize_pdf(pdf_data)
        logger.info(f"PDF sanitized successfully: {len(sanitized_data)} bytes")
    except Exception as e:
        logger.error(f"PDF sanitization failed: {e}")
        return (
            json.dumps({'error': 'pdf_sanitization_failed'}),
            422,
            headers
        )

    # Extract text
    try:
        text = extract_pdf_text(sanitized_data)
        logger.info(f"Text extracted: {len(text)} characters, {page_count} pages")
    except Exception as e:
        logger.error(f"Text extraction failed: {e}")
        return (
            json.dumps({'error': 'pdf_processing_failed'}),
            500,
            headers
        )

    # Return success response
    response = {
        'text': text,
        'pages': page_count,
        'sanitized': True,
        'metadata': {
            'original_size': len(pdf_data),
            'sanitized_size': len(sanitized_data),
            'text_length': len(text)
        }
    }

    return (
        json.dumps(response),
        200,
        headers
    )
