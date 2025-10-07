#!/usr/bin/env python3
"""
Cloud Functions v2 PDF Worker - Ephemeral PDF Processing

Security Features:
- PDF sanitization (remove JavaScript, embedded files, XFA)
- Magic byte validation
- Size and page limits
- No disk persistence (memory-only via BytesIO)
- Protected at edge via Cloud Functions IAM / HTTPS LB (no inline token validation here)
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

try:
    from google.cloud import modelarmor_v1
    from google.api_core.retry import Retry
    from google.api_core.client_options import ClientOptions
    HAS_MODEL_ARMOR = True
except ImportError:
    HAS_MODEL_ARMOR = False

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

# Model Armor configuration
MODEL_ARMOR_ENABLED = os.getenv('MODEL_ARMOR_ENABLED', 'false').lower() == 'true'
MODEL_ARMOR_LOCATION = os.getenv('MODEL_ARMOR_LOCATION', 'us-central1')
MODEL_ARMOR_TEMPLATE_ID = os.getenv('MODEL_ARMOR_TEMPLATE_ID', 'llm-guardrails-default')
GOOGLE_CLOUD_PROJECT = os.getenv('GOOGLE_CLOUD_PROJECT')


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

    Notes:
        - Encrypted/password-protected PDFs will fail to open; we return a
          specific error code to the client for better UX.
        - We intentionally remove auto-actions, JS, XFA, and embedded files to
          reduce the attack surface from untrusted PDFs.
        - If sanitization fails for any reason, the upload is rejected.

    Returns:
        Sanitized PDF bytes

    Raises:
        ValueError: If PDF is encrypted
        Exception: If PDF cannot be sanitized
    """
    if not HAS_PIKEPDF:
        raise ImportError("pikepdf not available")

    pdf = pikepdf.open(io.BytesIO(pdf_data))

    # If the PDF is encrypted, fail early with a clear error
    if pdf.is_encrypted:
        pdf.close()
        raise ValueError("encrypted_pdf")

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


def sanitize_text_with_model_armor(text: str) -> Tuple[bool, str]:
    """
    Sanitize extracted PDF text using Model Armor before sending to LLM.

    This prevents malicious content injection via PDF uploads.

    Args:
        text: Extracted PDF text

    Returns:
        Tuple of (is_safe, text_or_error_message)
        - (True, text): Safe to send to LLM
        - (False, error_msg): BLOCKED - do not send to LLM
    """
    if not MODEL_ARMOR_ENABLED:
        logger.info("Model Armor disabled - skipping PDF text sanitization")
        return True, text

    if not HAS_MODEL_ARMOR:
        logger.error("Model Armor enabled but library not available")
        # Fail-closed: block if Model Armor unavailable
        return False, "PDF text sanitization unavailable"

    # Defensive: short, user-friendly retry/timeout policy
    retry = Retry(initial=0.2, maximum=1.0, multiplier=2.0, deadline=3.0)
    timeout = 3.0

    if not GOOGLE_CLOUD_PROJECT:
        logger.error("GOOGLE_CLOUD_PROJECT not set")
        return False, "PDF text sanitization misconfigured"

    try:
        # Create Model Armor client with regional endpoint
        api_endpoint = f"modelarmor.{MODEL_ARMOR_LOCATION}.rep.googleapis.com"
        client = modelarmor_v1.ModelArmorClient(
            client_options=ClientOptions(api_endpoint=api_endpoint)
        )

        # Build template path
        template_path = f"projects/{GOOGLE_CLOUD_PROJECT}/locations/{MODEL_ARMOR_LOCATION}/templates/{MODEL_ARMOR_TEMPLATE_ID}"

        # Create sanitize request
        user_prompt_data = modelarmor_v1.DataItem(text=text)
        request = modelarmor_v1.SanitizeUserPromptRequest(
            name=template_path,
            user_prompt_data=user_prompt_data,
        )

        # Call Model Armor API
        response = client.sanitize_user_prompt(
            request=request,
            retry=retry,
            timeout=timeout,
        )

        # Check result
        sanitization_result = response.sanitization_result
        if sanitization_result.filter_match_state == modelarmor_v1.FilterMatchState.NO_MATCH_FOUND:
            logger.info(f"Model Armor: PDF text ALLOWED ({len(text)} chars)")
            return True, text

        # MATCH_FOUND = malicious content detected
        logger.critical(
            f"Model Armor BLOCKED PDF text upload: match_state={sanitization_result.filter_match_state.name}"
        )
        return False, "PDF contains unsafe content and cannot be processed"

    except Exception as e:
        logger.error(f"Model Armor PDF sanitization failed: {e}")
        # Fail-closed on error
        return False, "PDF text sanitization error"


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

    # Enforce content type (defense-in-depth)
    if request.headers.get('Content-Type', '').split(';', 1)[0].lower() != 'application/pdf':
        return (json.dumps({'error': 'unsupported_media_type'}), 415, headers)

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
        # Provide clearer signal for encrypted PDFs
        if isinstance(e, ValueError) and str(e) == "encrypted_pdf":
            logger.warning("Encrypted/password-protected PDF rejected")
            return (
                json.dumps({'error': 'pdf_encrypted'}),
                422,
                headers
            )
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

    # Sanitize extracted text with Model Armor (prevent malicious content injection)
    is_safe, sanitized_text = sanitize_text_with_model_armor(text)
    if not is_safe:
        logger.warning(f"Model Armor blocked PDF text: {sanitized_text}")
        return (
            json.dumps({'error': 'pdf_content_blocked', 'message': sanitized_text}),
            422,
            headers
        )

    # Return success response
    response = {
        'text': sanitized_text,
        'pages': page_count,
        'sanitized': True,
        'model_armor_checked': MODEL_ARMOR_ENABLED,
        'limits': {
            'max_bytes': MAX_BYTES,
            'max_pages': MAX_PAGES,
            'max_output_chars': MAX_OUTPUT_CHARS
        },
        'metadata': {
            'original_size': len(pdf_data),
            'sanitized_size': len(sanitized_data),
            'text_length': len(sanitized_text)
        }
    }

    return (
        json.dumps(response),
        200,
        headers
    )
