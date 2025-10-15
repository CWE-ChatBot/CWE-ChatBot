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
- Dual MIME validation (header + libmagic if available)
- Strict metadata policy (no filename echo; clear PDF metadata/XMP)
"""

import base64
import hashlib
import io
import json
import logging
import os
import signal
import subprocess
import sys
import time
from typing import Tuple

try:
    import resource  # Linux rlimits
except Exception:  # pragma: no cover
    resource = None

# Optional imports - will fail gracefully if not available
try:
    import pikepdf

    HAS_PIKEPDF = True
except ImportError:
    HAS_PIKEPDF = False

try:
    from pdfminer.high_level import extract_text_to_fp
    from pdfminer.layout import LAParams

    HAS_PDFMINER = True
except ImportError:
    HAS_PDFMINER = False

# Optional: content sniffing with libmagic
try:
    import magic  # python-magic (requires libmagic in runtime image)

    HAS_LIBMAGIC = True
except ImportError:
    HAS_LIBMAGIC = False

try:
    from google.api_core.client_options import ClientOptions
    from google.api_core.retry import Retry
    from google.cloud import modelarmor_v1

    HAS_MODEL_ARMOR = True
except ImportError:
    HAS_MODEL_ARMOR = False

# Configure logging (metadata only, no content)
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Constants
MAX_BYTES = 10 * 1024 * 1024  # 10MB
MAX_PAGES = 50
MAX_OUTPUT_CHARS = 1_000_000
TRUNCATION_NOTICE = f"\n\n[Content truncated at {MAX_OUTPUT_CHARS:,} characters]"

# Model Armor configuration
MODEL_ARMOR_ENABLED = os.getenv("MODEL_ARMOR_ENABLED", "false").lower() == "true"
MODEL_ARMOR_LOCATION = os.getenv("MODEL_ARMOR_LOCATION", "us-central1")
MODEL_ARMOR_TEMPLATE_ID = os.getenv("MODEL_ARMOR_TEMPLATE_ID", "llm-guardrails-default")
GOOGLE_CLOUD_PROJECT = os.getenv("GOOGLE_CLOUD_PROJECT")
ISOLATE_SANITIZER = os.getenv("ISOLATE_SANITIZER", "false").lower() == "true"

# Explicitly export entry points for tooling/static analyzers
__all__ = [
    "pdf_worker",
    "sanitize_pdf",
    "extract_pdf_text",
    "sanitize_text_with_model_armor",
    "count_pdf_pages",
    "sanitize_and_count_isolated",
]


def _jlog(level: str, **fields):
    """Emit a single-line JSON log without content or filenames."""
    fields.setdefault("ts", time.time())
    msg = json.dumps(fields, separators=(",", ":"), sort_keys=True)
    getattr(logger, level)(msg)


def sanitize_pdf(pdf_data: bytes) -> bytes:
    """
    Sanitize PDF by removing dangerous elements.

    Removes:
    - /OpenAction (auto-execute on open)
    - /AA (additional actions)
    - JavaScript
    - XFA forms
    - Embedded files
    - Annotations
    - URI/Launch actions
    - RichMedia
    - Document metadata (Info dictionary and XMP)

    Args:
        pdf_data: Raw PDF bytes

    Notes:
        - Encrypted/password-protected PDFs will fail to open; we return a
          specific error code to the client for better UX.
        - We intentionally remove auto-actions, JS, XFA, and embedded files to
          reduce the attack surface from untrusted PDFs.
        - If sanitization fails for any reason, the upload is rejected.
        - Implements strict CDR (Content Disarm and Reconstruction) policy

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

    # ---- Strict metadata policy ----
    # Clear document info dictionary
    pdf.docinfo = pikepdf.Dictionary()
    # Remove XMP metadata stream if present
    if "/Metadata" in pdf.Root:
        try:
            del pdf.Root["/Metadata"]
        except Exception:
            pass

    # Remove auto-execute actions
    if "/OpenAction" in pdf.Root:
        del pdf.Root["/OpenAction"]

    if "/AA" in pdf.Root:
        del pdf.Root["/AA"]

    # Remove JavaScript
    if "/Names" in pdf.Root:
        names = pdf.Root["/Names"]
        if "/JavaScript" in names:
            del names["/JavaScript"]
        # Remove EmbeddedFiles at name tree level
        if "/EmbeddedFiles" in names:
            del names["/EmbeddedFiles"]
        # Remove URI name tree if present
        if "/URI" in names:
            try:
                del names["/URI"]
            except Exception:
                pass

    # Remove XFA forms
    if "/AcroForm" in pdf.Root:
        acro_form = pdf.Root["/AcroForm"]
        if "/XFA" in acro_form:
            del acro_form["/XFA"]
        # Also drop JS actions on forms if any
        if "/JS" in acro_form:
            try:
                del acro_form["/JS"]
            except Exception:
                pass

    # Remove RichMedia (embedded multimedia)
    if "/RichMedia" in pdf.Root:
        try:
            del pdf.Root["/RichMedia"]
        except Exception:
            pass

    # Drop all page-level annotations & AA (you stated you don't need annotations)
    try:
        for page in pdf.pages:
            if "/AA" in page:
                del page["/AA"]
            if "/Annots" in page:
                del page["/Annots"]
    except Exception:
        # If iteration fails for some malformed docs, keep going; sanitizer should still succeed.
        pass

    # Save to bytes
    output = io.BytesIO()
    pdf.save(output)
    pdf.close()

    return output.getvalue()


def extract_pdf_text(pdf_data: bytes, max_pages: int = MAX_PAGES) -> str:
    """
    Extract text from PDF using pdfminer with bounded resources.

    Args:
        pdf_data: Sanitized PDF bytes
        max_pages: Maximum pages to process

    Returns:
        Extracted text

    Raises:
        Exception: If text extraction fails
    """
    if not HAS_PDFMINER:
        raise ImportError("pdfminer.six not available")

    buf = io.StringIO()
    laparams = LAParams()  # defaults are fine; adjust if needed
    extract_text_to_fp(
        io.BytesIO(pdf_data),
        buf,
        laparams=laparams,
        caching=False,
        maxpages=max_pages,
    )
    text = buf.getvalue()

    # Truncate to max chars
    if len(text) > MAX_OUTPUT_CHARS:
        text = text[:MAX_OUTPUT_CHARS] + TRUNCATION_NOTICE

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
        if (
            sanitization_result.filter_match_state
            == modelarmor_v1.FilterMatchState.NO_MATCH_FOUND
        ):
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


# -------------------------------
# Subprocess-isolated sanitization
# -------------------------------
def _set_subprocess_limits():
    """
    Linux-only rlimits to contain sanitizer.
    - Memory cap via RLIMIT_AS (address space)
    - CPU seconds via RLIMIT_CPU
    - File size 0 (no file writes)
    - Limit open files and forks
    - Lower CPU priority
    """
    if resource is None:
        return
    try:
        # ~512 MiB address space cap for worker (tune as needed)
        resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
        # CPU time: 5s hard cap
        resource.setrlimit(resource.RLIMIT_CPU, (5, 5))
        # No file writes (avoid accidental disk use)
        resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
        # Limit open files
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
        # Limit forks
        if hasattr(resource, "RLIMIT_NPROC"):
            resource.setrlimit(resource.RLIMIT_NPROC, (16, 16))
        try:
            os.nice(10)
        except Exception:
            pass
        # Reset signal handlers
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except Exception:
        # If limits can't be set, proceed; isolation is best-effort.
        pass


def _run_worker(pdf_data: bytes, timeout_s: float = 10.0) -> Tuple[bytes, int]:
    """
    Invoke this module in worker mode to sanitize & count pages with rlimits.
    Communicates via stdin (pdf bytes) and stdout (JSON with base64).
    """
    cmd = [sys.executable, os.path.abspath(__file__), "--worker"]
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        preexec_fn=_set_subprocess_limits if resource is not None else None,
        close_fds=True,
        # Pass through env but avoid leaking creds into child process memory dumps
        env={
            k: v
            for k, v in os.environ.items()
            if k not in ("GOOGLE_APPLICATION_CREDENTIALS",)
        },
    )
    try:
        out, err = proc.communicate(input=pdf_data, timeout=timeout_s)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.wait(timeout=1.0)
        except Exception:
            pass
        raise TimeoutError("sanitizer_timeout")

    if proc.returncode != 0:
        # Worker failed; include a short error marker but no content
        raise RuntimeError(
            f"sanitizer_failed:{proc.returncode}:{err.decode(errors='ignore')[:200]}"
        )

    try:
        payload = json.loads(out.decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("bad_worker_payload")
        b64 = payload.get("sanitized_b64")
        pages = int(payload.get("pages", 0))
        if not b64:
            raise ValueError("missing_sanitized_b64")
        sanitized = base64.b64decode(b64)
        return sanitized, pages
    except Exception as e:
        raise RuntimeError(f"sanitizer_bad_output:{e}")


def sanitize_and_count_isolated(pdf_data: bytes) -> Tuple[bytes, int]:
    """
    Public helper: run sanitize + count in a resource-limited subprocess.
    Falls back to in-process if not enabled.
    """
    if not ISOLATE_SANITIZER:
        sanitized = sanitize_pdf(pdf_data)
        pages = count_pdf_pages(sanitized)
        return sanitized, pages
    return _run_worker(pdf_data)


def _worker_main():
    """
    Worker entrypoint (invoked with --worker).
    Reads PDF bytes from stdin; writes JSON {pages, sanitized_b64} to stdout.
    Exits non-zero on any error.
    """
    try:
        raw = sys.stdin.buffer.read()
        if not raw or not raw.startswith(b"%PDF-"):
            print(json.dumps({"error": "pdf_magic_missing"}))
            sys.exit(2)
        sanitized = sanitize_pdf(raw)
        pages = count_pdf_pages(sanitized)
        out = {
            "pages": pages,
            "sanitized_b64": base64.b64encode(sanitized).decode("ascii"),
        }
        sys.stdout.write(json.dumps(out))
        sys.stdout.flush()
        sys.exit(0)
    except Exception as e:
        sys.stderr.write(str(e)[:500])
        sys.stderr.flush()
        sys.exit(2)


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
        "Content-Type": "application/json",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "X-Frame-Options": "DENY",
        # Prevent caching of extracted text
        "Cache-Control": "no-store",
    }

    # Only accept POST
    if request.method != "POST":
        return (json.dumps({"error": "method_not_allowed"}), 405, headers)

    # Enforce content type (defense-in-depth)
    if (
        request.headers.get("Content-Type", "").split(";", 1)[0].lower()
        != "application/pdf"
    ):
        return (json.dumps({"error": "unsupported_media_type"}), 415, headers)

    # Check library availability
    if not HAS_PIKEPDF or not HAS_PDFMINER:
        logger.error("Required libraries not available")
        return (json.dumps({"error": "server_misconfigured"}), 500, headers)

    # Get request body
    try:
        pdf_data = request.get_data()
    except Exception as e:
        logger.error(f"Failed to get request data: {e}")
        return (json.dumps({"error": "invalid_request"}), 400, headers)

    # Structured, content-free request log (no filename)
    pdf_sha256 = hashlib.sha256(pdf_data).hexdigest()
    _jlog(
        "info",
        event="request_received",
        sha256=pdf_sha256,
        bytes=len(pdf_data),
        content_type=request.headers.get("Content-Type", ""),
    )

    # Validate size
    if len(pdf_data) > MAX_BYTES:
        _jlog("warning", event="pdf_too_large", sha256=pdf_sha256, bytes=len(pdf_data))
        return (json.dumps({"error": "pdf_too_large"}), 413, headers)

    # Optional content-based MIME validation (OWASP dual validation)
    if HAS_LIBMAGIC:
        try:
            detected_mime = magic.Magic(mime=True).from_buffer(pdf_data[:4096])
            # Deny generic octet-stream; require a PDF MIME
            if detected_mime == "application/octet-stream":
                _jlog("warning", event="mime_octet_stream_blocked", sha256=pdf_sha256)
                return (json.dumps({"error": "unsupported_media_type"}), 415, headers)
            if detected_mime not in ("application/pdf", "application/x-pdf"):
                _jlog(
                    "warning",
                    event="mime_not_pdf",
                    sha256=pdf_sha256,
                    detected_mime=detected_mime,
                )
                return (json.dumps({"error": "unsupported_media_type"}), 415, headers)
        except Exception as e:
            _jlog(
                "error",
                event="mime_sniff_failed",
                sha256=pdf_sha256,
                error=str(e)[:120],
            )
            # Proceed; we still have magic-byte and parser checks.

    # Validate PDF magic bytes
    if not pdf_data.startswith(b"%PDF-"):
        _jlog("warning", event="pdf_magic_missing", sha256=pdf_sha256)
        return (json.dumps({"error": "pdf_magic_missing"}), 422, headers)

    # Sanitize PDF (in isolated subprocess if enabled) and count pages on sanitized data
    try:
        sanitized_data, page_count = sanitize_and_count_isolated(pdf_data)
        _jlog(
            "info",
            event="pdf_sanitized",
            sha256=pdf_sha256,
            sanitized_bytes=len(sanitized_data),
            pages=page_count,
            isolated=ISOLATE_SANITIZER,
        )
    except Exception as e:
        # Provide clearer signal for encrypted PDFs
        if isinstance(e, ValueError) and str(e) == "encrypted_pdf":
            _jlog("warning", event="pdf_encrypted", sha256=pdf_sha256)
            return (json.dumps({"error": "pdf_encrypted"}), 422, headers)
        msg = str(e)
        if isinstance(e, TimeoutError) or "sanitizer_timeout" in msg:
            _jlog("error", event="pdf_sanitization_timeout", sha256=pdf_sha256)
            return (
                json.dumps({"error": "pdf_sanitization_failed", "message": "timeout"}),
                422,
                headers,
            )
        _jlog(
            "error", event="pdf_sanitization_failed", sha256=pdf_sha256, error=msg[:200]
        )
        return (json.dumps({"error": "pdf_sanitization_failed"}), 422, headers)

    # Gate on page limits after sanitization
    if page_count > MAX_PAGES:
        _jlog(
            "warning", event="pdf_too_many_pages", sha256=pdf_sha256, pages=page_count
        )
        return (json.dumps({"error": "pdf_too_many_pages"}), 422, headers)

    # Extract text
    try:
        text = extract_pdf_text(sanitized_data, max_pages=min(page_count, MAX_PAGES))
        _jlog(
            "info",
            event="text_extracted",
            sha256=pdf_sha256,
            text_chars=len(text),
            pages=page_count,
        )
    except Exception as e:
        _jlog(
            "error",
            event="pdf_processing_failed",
            sha256=pdf_sha256,
            error=str(e)[:200],
        )
        return (json.dumps({"error": "pdf_processing_failed"}), 500, headers)

    # Sanitize extracted text with Model Armor (prevent malicious content injection)
    is_safe, sanitized_text = sanitize_text_with_model_armor(text)
    if not is_safe:
        _jlog("warning", event="pdf_content_blocked", sha256=pdf_sha256)
        return (
            json.dumps({"error": "pdf_content_blocked", "message": sanitized_text}),
            422,
            headers,
        )

    # Return success response
    response = {
        "text": sanitized_text,
        "pages": page_count,
        "sanitized": True,
        "model_armor_checked": MODEL_ARMOR_ENABLED,
        "limits": {
            "max_bytes": MAX_BYTES,
            "max_pages": MAX_PAGES,
            "max_output_chars": MAX_OUTPUT_CHARS,
        },
        "metadata": {
            "original_size": len(pdf_data),
            "sanitized_size": len(sanitized_data),
            "text_length": len(sanitized_text),
        },
    }

    return (json.dumps(response), 200, headers)


# Keep a concrete reference so tools like vulture see usage
_HANDLERS: tuple[object, ...] = (pdf_worker,)


# Alias to match deployment flag if used
function_entry = pdf_worker


if __name__ == "__main__" and "--worker" in sys.argv:
    # Run worker entrypoint if invoked as a subprocess
    _worker_main()
    sys.exit(0)
