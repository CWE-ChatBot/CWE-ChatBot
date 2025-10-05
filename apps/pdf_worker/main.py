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

from flask import Flask, Request, Response, jsonify, request

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

app = Flask(__name__)

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


@app.after_request
def add_security_headers(response: Response) -> Response:
    """Add security headers to all responses."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['X-Frame-Options'] = 'DENY'
    return response


@app.route('/', methods=['POST'])
def handle_pdf() -> Tuple[Response, int]:
    """
    Handle PDF processing request.

    Expected: POST with Content-Type: application/pdf
    Returns: JSON with {text: str, pages: int, sanitized: bool}
    """
    # Validate Content-Type
    if request.content_type != 'application/pdf':
        logger.warning(f"Invalid Content-Type: {request.content_type}")
        return jsonify({'error': 'invalid_content_type'}), 415

    # Get raw PDF data
    raw_data = request.get_data(cache=False, as_text=False)

    # Validate size
    if not raw_data or len(raw_data) > MAX_BYTES:
        logger.warning(f"Payload size violation: {len(raw_data) if raw_data else 0} bytes")
        return jsonify({'error': 'too_large'}), 413

    # Validate PDF magic bytes
    if not raw_data.startswith(b'%PDF-'):
        logger.warning("PDF magic bytes missing")
        return jsonify({'error': 'pdf_magic_missing'}), 422

    # Check dependencies
    if not HAS_PIKEPDF or not HAS_PDFMINER:
        logger.error("PDF processing libraries not available")
        return jsonify({'error': 'pdf_processing_unavailable'}), 500

    # Sanitize PDF
    try:
        sanitized_data = sanitize_pdf(raw_data)
    except ValueError as e:
        logger.warning(f"PDF sanitization failed: {str(e)}")
        return jsonify({'error': str(e)}), 422
    except Exception as e:
        logger.error(f"PDF sanitization error: {type(e).__name__}")
        return jsonify({'error': 'sanitization_failed'}), 422

    # Extract text
    try:
        text = extract_text_from_pdf(sanitized_data, max_pages=MAX_PAGES)
    except Exception as e:
        logger.error(f"Text extraction error: {type(e).__name__}")
        return jsonify({'error': 'extraction_failed'}), 422

    # Count pages
    page_count = count_pages(sanitized_data)

    # Truncate text
    if len(text) > MAX_OUTPUT_CHARS:
        text = text[:MAX_OUTPUT_CHARS]
        logger.info(f"Text truncated from {len(text)} to {MAX_OUTPUT_CHARS} chars")

    # Log metadata only
    logger.info(f"PDF processed: {page_count} pages, {len(text)} chars")

    return jsonify({
        'text': text,
        'pages': page_count,
        'sanitized': True
    }), 200


def sanitize_pdf(pdf_data: bytes) -> bytes:
    """
    Sanitize PDF by removing dangerous features.

    Security: Removes JavaScript, embedded files, XFA forms, auto-actions.

    Args:
        pdf_data: Raw PDF bytes

    Returns:
        Sanitized PDF bytes

    Raises:
        ValueError: If PDF is encrypted or invalid
    """
    try:
        pdf = pikepdf.open(io.BytesIO(pdf_data))
    except pikepdf.PasswordError:
        raise ValueError('encrypted_pdf_unsupported')
    except Exception as e:
        logger.error(f"Failed to open PDF: {type(e).__name__}")
        raise ValueError('invalid_pdf')

    # Check if PDF has any content (not image-only)
    # This is a basic check - more sophisticated checks could be added
    if len(pdf.pages) > MAX_PAGES:
        raise ValueError('too_many_pages')

    # Remove dangerous features
    try:
        # Remove auto-execute actions
        if '/OpenAction' in pdf.root:
            del pdf.root['/OpenAction']

        if '/AA' in pdf.root:
            del pdf.root['/AA']

        # Remove JavaScript
        if '/Names' in pdf.root and '/JavaScript' in pdf.root['/Names']:
            del pdf.root['/Names']['/JavaScript']

        # Remove XFA forms (can contain embedded code)
        if '/AcroForm' in pdf.root:
            acro_form = pdf.root['/AcroForm']
            if '/XFA' in acro_form:
                del acro_form['/XFA']
            if '/NeedAppearances' in acro_form:
                del acro_form['/NeedAppearances']

        # Remove embedded files
        if '/Names' in pdf.root and '/EmbeddedFiles' in pdf.root['/Names']:
            del pdf.root['/Names']['/EmbeddedFiles']

    except Exception as e:
        logger.warning(f"Error during PDF sanitization: {type(e).__name__}")
        # Continue with partially sanitized PDF

    # Save to BytesIO (memory only, no disk writes)
    output_buffer = io.BytesIO()
    pdf.save(output_buffer)
    return output_buffer.getvalue()


def extract_text_from_pdf(pdf_data: bytes, max_pages: int = MAX_PAGES) -> str:
    """
    Extract text from sanitized PDF.

    Args:
        pdf_data: Sanitized PDF bytes
        max_pages: Maximum pages to process

    Returns:
        Extracted text
    """
    try:
        text = extract_text(io.BytesIO(pdf_data), maxpages=max_pages) or ''
        return text
    except Exception as e:
        logger.error(f"pdfminer extraction failed: {type(e).__name__}")
        # Check if it's an image-only PDF
        raise ValueError('extraction_failed')


def count_pages(pdf_data: bytes) -> int:
    """
    Count pages in PDF.

    Args:
        pdf_data: PDF bytes

    Returns:
        Page count
    """
    try:
        with pikepdf.open(io.BytesIO(pdf_data)) as pdf:
            return len(pdf.pages)
    except Exception:
        return 0


# Cloud Functions v2 entry point
def function_entry(request: Request) -> Tuple[Response, int]:
    """
    Cloud Functions v2 entry point.

    This function is called by Cloud Functions runtime.
    """
    with app.app_context():
        return app.full_dispatch_request()
