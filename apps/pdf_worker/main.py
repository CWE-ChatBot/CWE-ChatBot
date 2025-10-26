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
import threading
import time
from types import ModuleType
from typing import Any, Dict, Optional, Tuple

try:
    import resource as _resource  # Linux rlimits

    resource: ModuleType | None = _resource
except Exception:  # pragma: no cover
    resource = None

# Hard requirements: pikepdf and pdfminer must be installed
# Hard requirement: libmagic via python-magic for MIME sniffing
import magic  # python-magic (requires libmagic shared library in runtime image)
import pikepdf
from pdfminer.high_level import extract_text_to_fp
from pdfminer.layout import LAParams

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

# Thread-local libmagic instances for thread safety
_magic_local = threading.local()


def _magic_mime(buf: bytes) -> str:
    m = getattr(_magic_local, "inst", None)
    if m is None:
        _magic_local.inst = m = magic.Magic(mime=True)
    return str(m.from_buffer(buf))


# Compatibility alias for tests/tools expecting this flag
HAS_LIBMAGIC = True  # compat: legacy checks expect this symbol

# Lazy-cached Model Armor client
_MODEL_ARMOR_CLIENT: Any | None = None
_ma_lock = threading.Lock()

# Fail fast if Model Armor is required by config but library is missing
if MODEL_ARMOR_ENABLED and not HAS_MODEL_ARMOR:
    raise ImportError(
        "MODEL_ARMOR_ENABLED=true but google-cloud-modelarmor is not installed"
    )

# Explicitly export entry points for tooling/static analyzers
__all__ = [
    "pdf_worker",
    "sanitize_pdf",
    "extract_pdf_text",
    "sanitize_text_with_model_armor",
    "count_pdf_pages",
    "sanitize_and_count_isolated",
]


def _jlog(level: str, **fields: object) -> None:
    """Emit a single-line JSON log without content or filenames."""
    fields.setdefault("ts", time.time())
    msg = json.dumps(fields, separators=(",", ":"), sort_keys=True)
    getattr(logger, level)(msg)


def _err(
    headers: Dict[str, str], code: str, http: int = 422, msg: Optional[str] = None
) -> Tuple[str, int, Dict[str, str]]:
    body: Dict[str, Any] = {"error": code}
    if msg:
        body["message"] = msg
    return json.dumps(body), http, headers


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
    # pikepdf is a hard requirement; if missing, module import would fail

    with pikepdf.open(io.BytesIO(pdf_data)) as src:
        # If the PDF is encrypted, fail early with a clear error
        if src.is_encrypted:
            raise ValueError("encrypted_pdf")

        # Rebuild from scratch (CDR): new PDF, import pages only
        out_pdf = pikepdf.Pdf.new()
        out_pdf.docinfo = pikepdf.Dictionary()  # clear metadata

        # Import pages
        for page in src.pages:
            out_pdf.pages.append(page)

        # Remove risky root entries that may be imported indirectly
        for key in ("/Names", "/AcroForm", "/RichMedia", "/Metadata"):
            out_pdf.Root.pop(key, None)
        for k in ("/PieceInfo", "/LastModified", "/Perms", "/OCProperties"):
            out_pdf.Root.pop(k, None)

        # Drop page-level AA/Annots in rebuilt doc as well
        try:
            for page in out_pdf.pages:
                page.pop("/AA", None)
                page.pop("/Annots", None)
        except Exception:
            pass

        # Save to bytes
        output = io.BytesIO()
        out_pdf.save(output)
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
    # pdfminer is a hard requirement; if missing, module import would fail

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
        client = _get_model_armor_client()

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
    try:
        with pikepdf.open(io.BytesIO(pdf_data)) as pdf:
            page_count = len(pdf.pages)
            return page_count
    except Exception:
        return 0


# -------------------------------
# Subprocess-isolated sanitization
# -------------------------------
def _set_subprocess_limits() -> None:
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
        if proc.returncode != 0:
            # Worker failed; include a trimmed, printable-only error marker (no content)
            raw_err = err.decode(errors="ignore") if err else ""
            err_txt = "".join(ch for ch in raw_err if 31 < ord(ch) < 127)[:200]
            raise RuntimeError(f"sanitizer_failed:{proc.returncode}:{err_txt}")

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
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.wait(timeout=1.0)
        except Exception:
            pass
        raise TimeoutError("sanitizer_timeout")
    finally:
        # Close pipes to avoid FD accumulation under churn
        try:
            if proc.stdin:
                proc.stdin.close()
        except Exception:
            pass
        try:
            if proc.stdout:
                proc.stdout.close()
        except Exception:
            pass
        try:
            if proc.stderr:
                proc.stderr.close()
        except Exception:
            pass


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


def _worker_main() -> None:
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


def pdf_worker(request: Any) -> Tuple[str, int, Dict[str, str]]:
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
    headers.update(
        {
            "Content-Security-Policy": "default-src 'none'",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        }
    )

    # Only accept POST
    if request.method != "POST":
        headers["Allow"] = "POST"
        return _err(headers, "method_not_allowed", 405)

    # Enforce content type (defense-in-depth)
    if (
        request.headers.get("Content-Type", "").split(";", 1)[0].lower()
        != "application/pdf"
    ):
        return _err(headers, "unsupported_media_type", 415)

    # Hard dependencies (pikepdf/pdfminer) are required at import time.

    # Get request body
    try:
        pdf_data = request.get_data()
    except Exception as e:
        logger.error(f"Failed to get request data: {e}")
        return _err(headers, "invalid_request", 400)

    # Reject empty bodies early
    if not pdf_data:
        _jlog("warning", event="pdf_empty_body")
        return _err(headers, "pdf_empty_body", 422)

    # Request timing start
    t0 = time.time()
    # Structured, content-free request log (no content hash yet, avoid CPU on oversize)
    _jlog(
        "info",
        event="request_received",
        bytes=len(pdf_data),
        content_type=request.headers.get("Content-Type", ""),
    )

    # Validate size
    if len(pdf_data) > MAX_BYTES:
        _jlog("warning", event="pdf_too_large", bytes=len(pdf_data))
        _jlog("info", event="done", duration_ms=int((time.time() - t0) * 1000))
        return _err(headers, "pdf_too_large", 413)

    # Compute content hash after passing size check
    # DevSkim DS197836 false positive: hashing PDF bytes (not time-derived)
    pdf_sha256 = hashlib.sha256(pdf_data).hexdigest()  # devskim: ignore DS197836

    # Content-based MIME validation (OWASP dual validation)
    try:
        detected_mime = _magic_mime(pdf_data[:4096])
        # Accept common variants from libmagic
        mime_ok = detected_mime in (
            "application/pdf",
            "application/x-pdf",
        ) or detected_mime.startswith("application/pdf")
        # Deny generic octet-stream; require a PDF MIME
        if detected_mime == "application/octet-stream" or not mime_ok:
            if detected_mime == "application/octet-stream":
                _jlog("warning", event="mime_octet_stream_blocked", sha256=pdf_sha256)
            else:
                _jlog(
                    "warning",
                    event="mime_not_pdf",
                    sha256=pdf_sha256,
                    detected_mime=detected_mime,
                )
            _jlog(
                "info",
                event="done",
                sha256=pdf_sha256,
                duration_ms=int((time.time() - t0) * 1000),
            )
            return _err(headers, "unsupported_media_type", 415)
    except Exception as e:
        _jlog(
            "error",
            event="mime_sniff_failed",
            sha256=pdf_sha256,
            error=str(e)[:120],
        )
        # Fail closed: sniffing must work when libmagic is required
        _jlog(
            "info",
            event="done",
            sha256=pdf_sha256,
            duration_ms=int((time.time() - t0) * 1000),
        )
        return _err(headers, "unsupported_media_type", 415)

    # Validate PDF magic bytes
    if not pdf_data.startswith(b"%PDF-"):
        _jlog("warning", event="pdf_magic_missing", sha256=pdf_sha256)
        _jlog(
            "info",
            event="done",
            sha256=pdf_sha256,
            duration_ms=int((time.time() - t0) * 1000),
        )
        return _err(headers, "pdf_magic_missing", 422)

    # Optional fast-path: block encrypted PDFs by scanning for /Encrypt marker
    try:
        if b"/Encrypt" in pdf_data[:8192]:
            _jlog("warning", event="pdf_encrypt_marker", sha256=pdf_sha256)
            _jlog(
                "info",
                event="done",
                sha256=pdf_sha256,
                duration_ms=int((time.time() - t0) * 1000),
            )
            return _err(headers, "pdf_encrypted", 422)
    except Exception:
        pass

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
            _jlog(
                "info",
                event="done",
                sha256=pdf_sha256,
                duration_ms=int((time.time() - t0) * 1000),
            )
            return _err(headers, "pdf_encrypted", 422)
        msg = str(e)
        if isinstance(e, TimeoutError) or "sanitizer_timeout" in msg:
            _jlog("error", event="pdf_sanitization_timeout", sha256=pdf_sha256)
            _jlog(
                "info",
                event="done",
                sha256=pdf_sha256,
                duration_ms=int((time.time() - t0) * 1000),
            )
            return _err(headers, "pdf_sanitization_failed", 422, msg="timeout")
        _jlog(
            "error", event="pdf_sanitization_failed", sha256=pdf_sha256, error=msg[:200]
        )
        _jlog(
            "info",
            event="done",
            sha256=pdf_sha256,
            duration_ms=int((time.time() - t0) * 1000),
        )
        return _err(headers, "pdf_sanitization_failed", 422)

    # Gate on page limits after sanitization
    if page_count > MAX_PAGES:
        _jlog(
            "warning", event="pdf_too_many_pages", sha256=pdf_sha256, pages=page_count
        )
        _jlog(
            "info",
            event="done",
            sha256=pdf_sha256,
            duration_ms=int((time.time() - t0) * 1000),
        )
        return _err(headers, "pdf_too_many_pages", 422)

    # Reject zero-page PDFs
    if page_count <= 0:
        _jlog("warning", event="pdf_zero_pages", sha256=pdf_sha256)
        _jlog(
            "info",
            event="done",
            sha256=pdf_sha256,
            duration_ms=int((time.time() - t0) * 1000),
        )
        return _err(headers, "pdf_zero_pages", 422)

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
        _jlog(
            "info",
            event="done",
            sha256=pdf_sha256,
            duration_ms=int((time.time() - t0) * 1000),
        )
        return _err(headers, "pdf_processing_failed", 500)

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

    _jlog(
        "info",
        event="done",
        sha256=pdf_sha256,
        duration_ms=int((time.time() - t0) * 1000),
    )
    return (json.dumps(response), 200, headers)


# Keep a concrete reference so tools like vulture see usage
_HANDLERS: tuple[object, ...] = (pdf_worker,)


# Alias to match deployment flag if used
function_entry = pdf_worker


if __name__ == "__main__" and "--worker" in sys.argv:
    # Run worker entrypoint if invoked as a subprocess
    _worker_main()
    sys.exit(0)


def _get_model_armor_client() -> Any:
    global _MODEL_ARMOR_CLIENT
    if _MODEL_ARMOR_CLIENT is None:
        with _ma_lock:
            if _MODEL_ARMOR_CLIENT is None:
                api_endpoint = f"modelarmor.{MODEL_ARMOR_LOCATION}.rep.googleapis.com"
                _MODEL_ARMOR_CLIENT = modelarmor_v1.ModelArmorClient(
                    client_options=ClientOptions(api_endpoint=api_endpoint)
                )
    return _MODEL_ARMOR_CLIENT
