--- a/ingest/main.py
+++ b/ingest/main.py
@@ -1,18 +1,30 @@
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
+ - Dual MIME validation (header + libmagic if available)
+ - Strict metadata policy (no filename echo; clear PDF metadata/XMP)
 """
 
 import io
 import json
 import logging
 import os
+import sys
+import base64
+import subprocess
+import signal
+import hashlib
+import time
+from typing import Tuple
+try:
+    import resource  # Linux rlimits
+except Exception:  # pragma: no cover
+    resource = None
 
 # Optional imports - will fail gracefully if not available
 try:
     import pikepdf
@@ -23,7 +35,16 @@
     HAS_PIKEPDF = False
 
 try:
-    from pdfminer_high_level import extract_text
+    from pdfminer.high_level import extract_text_to_fp
+    from pdfminer.layout import LAParams
     HAS_PDFMINER = True
 except ImportError:
     HAS_PDFMINER = False
+
+# Optional: content sniffing with libmagic
+try:
+    import magic  # python-magic (requires libmagic in runtime image)
+    HAS_LIBMAGIC = True
+except ImportError:
+    HAS_LIBMAGIC = False
 
 try:
     from google.api_core.client_options import ClientOptions
@@ -44,17 +65,22 @@
 logger = logging.getLogger(__name__)
 
 # Constants
 MAX_BYTES = 10 * 1024 * 1024  # 10MB
 MAX_PAGES = 50
 MAX_OUTPUT_CHARS = 1_000_000
+TRUNCATION_NOTICE = f"\n\n[Content truncated at {MAX_OUTPUT_CHARS:,} characters]"
 
 # Model Armor configuration
 MODEL_ARMOR_ENABLED = os.getenv("MODEL_ARMOR_ENABLED", "false").lower() == "true"
 MODEL_ARMOR_LOCATION = os.getenv("MODEL_ARMOR_LOCATION", "us-central1")
 MODEL_ARMOR_TEMPLATE_ID = os.getenv("MODEL_ARMOR_TEMPLATE_ID", "llm-guardrails-default")
 GOOGLE_CLOUD_PROJECT = os.getenv("GOOGLE_CLOUD_PROJECT")
+ISOLATE_SANITIZER = os.getenv("ISOLATE_SANITIZER", "false").lower() == "true"
 
 # Explicitly export entry points for tooling/static analyzers
 __all__ = [
     "pdf_worker",
     "sanitize_pdf",
     "extract_pdf_text",
     "sanitize_text_with_model_armor",
     "count_pdf_pages",
+    "sanitize_and_count_isolated",
 ]
 
+def _jlog(level: str, **fields):
+    """Emit a single-line JSON log without content or filenames."""
+    fields.setdefault("ts", time.time())
+    msg = json.dumps(fields, separators=(",", ":"), sort_keys=True)
+    getattr(logger, level)(msg)
+
 
 def sanitize_pdf(pdf_data: bytes) -> bytes:
     """
     Sanitize PDF by removing dangerous elements.
 
@@ -75,6 +101,9 @@
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
 
+    # ---- Strict metadata policy ----
+    # Clear document info dictionary
+    pdf.docinfo = pikepdf.Dictionary()
+    # Remove XMP metadata stream if present
+    if "/Metadata" in pdf.Root:
+        try:
+            del pdf.Root["/Metadata"]
+        except Exception:
+            pass
+
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
+        # Remove EmbeddedFiles at name tree level
+        if "/EmbeddedFiles" in names:
+            del names["/EmbeddedFiles"]
+        # Remove URI name tree if present
+        if "/URI" in names:
+            try:
+                del names["/URI"]
+            except Exception:
+                pass
 
     # Remove XFA forms
     if "/AcroForm" in pdf.Root:
         acro_form = pdf.Root["/AcroForm"]
         if "/XFA" in acro_form:
             del acro_form["/XFA"]
+        # Also drop JS actions on forms if any
+        if "/JS" in acro_form:
+            try:
+                del acro_form["/JS"]
+            except Exception:
+                pass
 
-    # Remove embedded files
-    if "/Names" in pdf.Root:
-        names = pdf.Root["/Names"]
-        if "/EmbeddedFiles" in names:
-            del names["/EmbeddedFiles"]
+    # Remove RichMedia (embedded multimedia)
+    if "/RichMedia" in pdf.Root:
+        try:
+            del pdf.Root["/RichMedia"]
+        except Exception:
+            pass
+
+    # Drop all page-level annotations & AA (you stated you don't need annotations)
+    try:
+        for page in pdf.pages:
+            if "/AA" in page:
+                del page["/AA"]
+            if "/Annots" in page:
+                del page["/Annots"]
+    except Exception:
+        # If iteration fails for some malformed docs, keep going; sanitizer should still succeed.
+        pass
 
     # Save to bytes
     output = io.BytesIO()
     pdf.save(output)
     pdf.close()
 
     return output.getvalue()
 
 
-def extract_pdf_text(pdf_data: bytes) -> str:
+def extract_pdf_text(pdf_data: bytes, max_pages: int = MAX_PAGES) -> str:
     """
-    Extract text from PDF using pdfminer.
+    Extract text from PDF using pdfminer with bounded resources.
 
     Args:
-        pdf_data: Sanitized PDF bytes
+        pdf_data: Sanitized PDF bytes
+        max_pages: Maximum pages to process
 
     Returns:
         Extracted text
 
     Raises:
         Exception: If text extraction fails
     """
     if not HAS_PDFMINER:
         raise ImportError("pdfminer.six not available")
 
-    text = extract_text(io.BytesIO(pdf_data))
+    buf = io.StringIO()
+    laparams = LAParams()  # defaults are fine; adjust if needed
+    extract_text_to_fp(
+        io.BytesIO(pdf_data),
+        buf,
+        laparams=laparams,
+        caching=False,
+        maxpages=max_pages,
+    )
+    text = buf.getvalue()
 
     # Truncate to max chars
     if len(text) > MAX_OUTPUT_CHARS:
-        text = text[:MAX_OUTPUT_CHARS]
-        text += "\n\n[Content truncated at 1,000,000 characters]"
+        text = text[:MAX_OUTPUT_CHARS] + TRUNCATION_NOTICE
 
     return text
 
@@ -236,6 +290,108 @@
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
         env={k: v for k, v in os.environ.items() if k not in ("GOOGLE_APPLICATION_CREDENTIALS",)},
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
         raise RuntimeError(f"sanitizer_failed:{proc.returncode}:{err.decode(errors='ignore')[:200]}")
 
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
         out = {"pages": pages, "sanitized_b64": base64.b64encode(sanitized).decode("ascii")}
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
@@ -249,11 +405,13 @@
     # Security headers
     headers = {
         "Content-Type": "application/json",
         "X-Content-Type-Options": "nosniff",
         "Referrer-Policy": "no-referrer",
         "X-Frame-Options": "DENY",
+        # Prevent caching of extracted text
+        "Cache-Control": "no-store",
     }
 
     # Only accept POST
     if request.method != "POST":
         return (json.dumps({"error": "method_not_allowed"}), 405, headers)
@@ -271,28 +429,66 @@
     try:
         pdf_data = request.get_data()
     except Exception as e:
         logger.error(f"Failed to get request data: {e}")
         return (json.dumps({"error": "invalid_request"}), 400, headers)
 
+    # Structured, content-free request log (no filename)
+    pdf_sha256 = hashlib.sha256(pdf_data).hexdigest()
+    _jlog(
+        "info",
+        event="request_received",
+        sha256=pdf_sha256,
+        bytes=len(pdf_data),
+        content_type=request.headers.get("Content-Type", ""),
+    )
+
     # Validate size
     if len(pdf_data) > MAX_BYTES:
-        logger.warning(f"PDF too large: {len(pdf_data)} bytes")
+        _jlog("warning", event="pdf_too_large", sha256=pdf_sha256, bytes=len(pdf_data))
         return (json.dumps({"error": "pdf_too_large"}), 413, headers)
 
+    # Optional content-based MIME validation (OWASP dual validation)
+    if HAS_LIBMAGIC:
+        try:
+            detected_mime = magic.Magic(mime=True).from_buffer(pdf_data[:4096])
+            # Deny generic octet-stream; require a PDF MIME
+            if detected_mime == "application/octet-stream":
+                _jlog("warning", event="mime_octet_stream_blocked", sha256=pdf_sha256)
+                return (json.dumps({"error": "unsupported_media_type"}), 415, headers)
+            if detected_mime not in ("application/pdf", "application/x-pdf"):
+                _jlog("warning", event="mime_not_pdf", sha256=pdf_sha256, detected_mime=detected_mime)
+                return (json.dumps({"error": "unsupported_media_type"}), 415, headers)
+        except Exception as e:
+            _jlog("error", event="mime_sniff_failed", sha256=pdf_sha256, error=str(e)[:120])
+            # Proceed; we still have magic-byte and parser checks.
+
     # Validate PDF magic bytes
     if not pdf_data.startswith(b"%PDF-"):
-        logger.warning("PDF magic bytes missing")
+        _jlog("warning", event="pdf_magic_missing", sha256=pdf_sha256)
         return (json.dumps({"error": "pdf_magic_missing"}), 422, headers)
 
-    # Sanitize PDF
+    # Sanitize PDF (in isolated subprocess if enabled) and count pages on sanitized data
     try:
-        sanitized_data = sanitize_pdf(pdf_data)
-        logger.info(f"PDF sanitized successfully: {len(sanitized_data)} bytes")
+        sanitized_data, page_count = sanitize_and_count_isolated(pdf_data)
+        _jlog(
+            "info",
+            event="pdf_sanitized",
+            sha256=pdf_sha256,
+            sanitized_bytes=len(sanitized_data),
+            pages=page_count,
+            isolated=ISOLATE_SANITIZER,
+        )
     except Exception as e:
         # Provide clearer signal for encrypted PDFs
         if isinstance(e, ValueError) and str(e) == "encrypted_pdf":
-            logger.warning("Encrypted/password-protected PDF rejected")
+            _jlog("warning", event="pdf_encrypted", sha256=pdf_sha256)
             return (json.dumps({"error": "pdf_encrypted"}), 422, headers)
-        logger.error(f"PDF sanitization failed: {e}")
+        msg = str(e)
+        if isinstance(e, TimeoutError) or "sanitizer_timeout" in msg:
+            _jlog("error", event="pdf_sanitization_timeout", sha256=pdf_sha256)
+            return (json.dumps({"error": "pdf_sanitization_failed", "message": "timeout"}), 422, headers)
+        _jlog("error", event="pdf_sanitization_failed", sha256=pdf_sha256, error=msg[:200])
         return (json.dumps({"error": "pdf_sanitization_failed"}), 422, headers)
 
+    # Gate on page limits after sanitization
+    if page_count > MAX_PAGES:
+        _jlog("warning", event="pdf_too_many_pages", sha256=pdf_sha256, pages=page_count)
+        return (json.dumps({"error": "pdf_too_many_pages"}), 422, headers)
+
     # Extract text
     try:
-        text = extract_pdf_text(sanitized_data)
-        logger.info(f"Text extracted: {len(text)} characters, {page_count} pages")
+        text = extract_pdf_text(sanitized_data, max_pages=min(page_count, MAX_PAGES))
+        _jlog(
+            "info",
+            event="text_extracted",
+            sha256=pdf_sha256,
+            text_chars=len(text),
+            pages=page_count,
+        )
     except Exception as e:
-        logger.error(f"Text extraction failed: {e}")
+        _jlog("error", event="pdf_processing_failed", sha256=pdf_sha256, error=str(e)[:200])
         return (json.dumps({"error": "pdf_processing_failed"}), 500, headers)
 
     # Sanitize extracted text with Model Armor (prevent malicious content injection)
     is_safe, sanitized_text = sanitize_text_with_model_armor(text)
     if not is_safe:
-        logger.warning(f"Model Armor blocked PDF text: {sanitized_text}")
+        _jlog("warning", event="pdf_content_blocked", sha256=pdf_sha256)
         return (
             json.dumps({"error": "pdf_content_blocked", "message": sanitized_text}),
             422,
             headers,
         )
@@ -338,9 +534,17 @@
     }
 
     return (json.dumps(response), 200, headers)
 
 
 # Keep a concrete reference so tools like vulture see usage
 _HANDLERS: tuple[object, ...] = (pdf_worker,)
 
+
+# Alias to match deployment flag if used
+function_entry = pdf_worker
+
+
+if __name__ == "__main__" and "--worker" in sys.argv:
+    # Run worker entrypoint if invoked as a subprocess
+    _worker_main()
+    sys.exit(0)
