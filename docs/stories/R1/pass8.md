but the file attachment applies to all roles not just cve creator
ChatGPT said:
Thought for 59s

got it — here’s a focused patch that wires file attachments for all roles, not just CVE Creator. It:

processes PDF and text/* attachments (size-limited)

merges a sanitized, truncated attachment summary into the user query before retrieval

adds a synthetic “Attachment Summary” context chunk so the LLM sees it in the CWE Context block

works in both streaming & non-streaming paths

keeps backwards compatibility (new params are optional)

1) Broaden attachments beyond CVE Creator
*** a/src/file_processor.py
--- b/src/file_processor.py
@@
-"""
-File Processing - CVE Creator Support
-Processes uploaded files (PDFs, text documents) for vulnerability information extraction.
-"""
+"""
+File Processing - Attachment Support (All Roles)
+Processes uploaded files (PDFs and text documents) for vulnerability information extraction.
+"""
@@
-    def __init__(self) -> None:
-        """Initialize file processor - PDF only for CVE Creator."""
-        self.supported_types = [
-            'application/pdf'
-        ]
-        # Maximum file size: 10MB for PDF documents
+    def __init__(self) -> None:
+        """Initialize file processor - supports PDFs and text/*."""
+        # NOTE: We explicitly allow PDFs and any text/* MIME. Other types are rejected.
+        self.supported_pdf = 'application/pdf'
+        # Maximum file size: 10MB
         self.max_file_size_mb = 10
         self.max_file_size_bytes = self.max_file_size_mb * 1024 * 1024
@@     async def process_attachments(self, message: cl.Message) -> Optional[str]:
-                # Check if file type is supported (PDF only)
-                mime_type = getattr(element, 'mime', 'application/octet-stream')
-                if mime_type not in self.supported_types:
-                    file_info = f"\n--- File: {element.name} (Unsupported Format) ---\n"
-                    extracted_content.append(file_info + f"Only PDF files up to {self.max_file_size_mb}MB are supported. Found: {mime_type}\nPlease upload a PDF file containing your vulnerability research, security advisory, or technical documentation.\n")
-                    logger.warning(f"Unsupported file type: {element.name} ({mime_type})")
-                    continue
+                # Check if file type is supported (PDF or text/*)
+                mime_type = getattr(element, 'mime', 'application/octet-stream')
+                is_pdf = (mime_type == self.supported_pdf)
+                is_text = isinstance(mime_type, str) and mime_type.startswith('text/')
+                if not (is_pdf or is_text):
+                    file_info = f"\n--- File: {element.name} (Unsupported Format) ---\n"
+                    extracted_content.append(
+                        file_info +
+                        f"Only PDF or text/* files up to {self.max_file_size_mb}MB are supported. "
+                        f"Found: {mime_type}\nPlease upload a PDF/text file containing your vulnerability "
+                        f"research, security advisory, or technical documentation.\n"
+                    )
+                    logger.warning(f"Unsupported file type: {element.name} ({mime_type})")
+                    continue
@@     async def _extract_file_content(self, file_element: Any) -> Optional[str]:
-            mime_type = getattr(file_element, 'mime', 'application/octet-stream')
-
-            if mime_type == 'application/pdf':
+            mime_type = getattr(file_element, 'mime', 'application/octet-stream')
+
+            if mime_type == 'application/pdf':
                 return await asyncio.to_thread(self._extract_pdf_content, file_content)
-            elif mime_type.startswith('text/'):
+            elif isinstance(mime_type, str) and mime_type.startswith('text/'):
                 return self._extract_text_content(file_content)
             else:
                 # Try to treat as text first
                 try:
                     decoded_content: str = file_content.decode('utf-8')
                     return decoded_content
                 except UnicodeDecodeError:
                     logger.warning(f"Cannot decode {file_element.name} as text")
                     return f"[Binary file - {file_element.name} - unable to extract text content]"

2) Use attachments for all personas in conversation flow
*** a/src/conversation.py
--- b/src/conversation.py
@@
-from typing import Dict, List, Any, Optional, AsyncGenerator
+from typing import Dict, List, Any, Optional, AsyncGenerator
 from dataclasses import dataclass, field
 from datetime import datetime
 import asyncio
+import os
 import chainlit as cl
 
 from src.user_context import UserContext, UserPersona
 from src.input_security import InputSanitizer, SecurityValidator
 from src.query_handler import CWEQueryHandler
 from src.response_generator import ResponseGenerator
+from src.file_processor import FileProcessor
@@ class ConversationManager:
     def __init__(
         self,
         database_url: str,
         gemini_api_key: str,
         context_manager: Optional[Any] = None  # kept for backward-compat; no longer used
     ):
@@
             self.query_handler = CWEQueryHandler(database_url, gemini_api_key)
             self.response_generator = ResponseGenerator(gemini_api_key)
+            self.file_processor = FileProcessor()
+            self.ATTACH_SUMMARY_CHARS = int(os.getenv("ATTACH_SUMMARY_CHARS", "1800"))
 
             # No local message storage; rely on Chainlit's built-in persistence
@@
-    async def process_user_message_streaming(
+    async def process_user_message_streaming(
         self,
         session_id: str,
         message_content: str,
-        message_id: str
+        message_id: str,
+        cl_message: Optional[cl.Message] = None,  # NEW: pass the Chainlit user message to read attachments
     ) -> Dict[str, Any]:
@@
-            # Sanitize input (pass persona for context-specific handling)
-            sanitization_result = self.input_sanitizer.sanitize_input(message_content, context.persona)
+            # (A) Extract attachment text (PDF/text) if any, then merge into the raw input
+            attachment_text = None
+            if cl_message is not None:
+                attachment_text = await self.file_processor.process_attachments(cl_message)
+
+            raw_combined = message_content.strip() if isinstance(message_content, str) else ""
+            if attachment_text:
+                # Summarize/truncate to keep prompts tight
+                attachment_snippet = self._summarize_attachment(attachment_text)
+                if raw_combined:
+                    raw_combined = f"{raw_combined}\n\n[Attachment Summary]\n{attachment_snippet}"
+                else:
+                    raw_combined = f"[Attachment Summary]\n{attachment_snippet}"
+
+            # Sanitize combined input (pass persona for context-specific handling)
+            sanitization_result = self.input_sanitizer.sanitize_input(raw_combined, context.persona)
@@
-            # Validate CWE relevance (pass persona for context-specific validation)
-            if not self.input_sanitizer.validate_cwe_context(sanitized_query, context.persona):
+            # Validate CWE relevance; if attachments exist, let them serve as context even if text was sparse
+            if not self.input_sanitizer.validate_cwe_context(sanitized_query, context.persona) and not attachment_text:
                 fallback_response = self.input_sanitizer.generate_fallback_message(
                     ["non_cwe_query"],
                     context.persona
                 )
@@
-            # Handle CVE Creator differently - it doesn't need CWE database retrieval
+            # Handle CVE Creator differently - no CWE DB required (but still benefits from attachments in query)
             if context.persona == "CVE Creator":
@@
-                    response = await self.response_generator.generate_response_streaming(
+                    response = await self.response_generator.generate_response_streaming(
                         sanitized_query,
-                        [],  # Empty chunks - CVE Creator doesn't use CWE database
+                        [],  # CVE Creator doesn't use CWE DB chunks
                         context.persona,
                         msg
                     )
@@
-            else:
+            else:
                 # Process query using hybrid retrieval for other personas
                 async with cl.Step(name="Retrieve CWE Information", type="retrieval") as retrieval_step:
                     retrieval_step.input = f"Searching CWE database for: {sanitized_query[:100]}..."
@@
-                    if retrieved_chunks:
+                    if retrieved_chunks:
                         retrieved_cwes = list(set(chunk["metadata"]["cwe_id"] for chunk in retrieved_chunks))
                         retrieval_step.output = f"Found {len(retrieved_chunks)} relevant chunks from CWEs: {', '.join(retrieved_cwes[:5])}{'...' if len(retrieved_cwes) > 5 else ''}"
                     else:
                         retrieval_step.output = "No relevant CWE information found"
 
-                if not retrieved_chunks:
-                    # No relevant information found
-                    fallback_response = self.response_generator._generate_fallback_response(
-                        sanitized_query,
-                        context.persona
-                    )
-
-                    msg = cl.Message(content=fallback_response)
-                    await msg.send()
-
-                    return {
-                        "response": fallback_response,
-                        "session_id": session_id,
-                        "is_safe": True,
-                        "retrieved_chunks": 0,
-                        "message": msg
-                    }
+                # If we have attachment context, add it as a synthetic chunk to inform generation
+                if attachment_text:
+                    attachment_snippet = self._summarize_attachment(attachment_text)
+                    attachment_chunk = {
+                        "metadata": {
+                            "cwe_id": "ATTACHMENT",
+                            "name": "User Attachment Extract",
+                            "section": "Attachment Summary",
+                        },
+                        "document": attachment_snippet,
+                        "scores": {"hybrid": 0.0},
+                    }
+                    retrieved_chunks.append(attachment_chunk)
+
+                if not retrieved_chunks:
+                    # If nothing found and no attachments, use fallback. If we have only attachments,
+                    # proceed to generation with the attachment chunk so the LLM can still help.
+                    if not attachment_text:
+                        fallback_response = self.response_generator._generate_fallback_response(
+                            sanitized_query,
+                            context.persona
+                        )
+                        msg = cl.Message(content=fallback_response)
+                        await msg.send()
+                        return {
+                            "response": fallback_response,
+                            "session_id": session_id,
+                            "is_safe": True,
+                            "retrieved_chunks": 0,
+                            "message": msg
+                        }
@@
                     response = await self.response_generator.generate_response_streaming(
                         sanitized_query,
                         retrieved_chunks,
                         context.persona,
                         msg
                     )
@@
             # Extract CWEs for context tracking
-            retrieved_cwes = list(set(
-                chunk["metadata"]["cwe_id"] for chunk in retrieved_chunks
-            ))
+            retrieved_cwes = list(set(
+                chunk["metadata"].get("cwe_id", "CWE-UNKNOWN") for chunk in retrieved_chunks
+            )) if retrieved_chunks else []
@@
         except Exception as e:
             logger.error(f"Error processing streaming message: {e}")
@@
-    async def process_user_message(
+    async def process_user_message(
         self,
         session_id: str,
         message_content: str,
-        message_id: str
+        message_id: str,
+        cl_message: Optional[cl.Message] = None,  # NEW: pass Chainlit user message for attachments
     ) -> Dict[str, Any]:
@@
-            # Sanitize input (pass persona for context-specific handling)
-            sanitization_result = self.input_sanitizer.sanitize_input(message_content, context.persona)
+            # (A) Extract and merge attachments first
+            attachment_text = None
+            if cl_message is not None:
+                attachment_text = await self.file_processor.process_attachments(cl_message)
+
+            raw_combined = message_content.strip() if isinstance(message_content, str) else ""
+            if attachment_text:
+                attachment_snippet = self._summarize_attachment(attachment_text)
+                if raw_combined:
+                    raw_combined = f"{raw_combined}\n\n[Attachment Summary]\n{attachment_snippet}"
+                else:
+                    raw_combined = f"[Attachment Summary]\n{attachment_snippet}"
+
+            # Sanitize combined input
+            sanitization_result = self.input_sanitizer.sanitize_input(raw_combined, context.persona)
@@
-            # Validate CWE relevance (pass persona for context-specific validation)
-            if not self.input_sanitizer.validate_cwe_context(sanitized_query, context.persona):
+            # Validate CWE relevance; if attachments exist, allow them to provide the context
+            if not self.input_sanitizer.validate_cwe_context(sanitized_query, context.persona) and not attachment_text:
                 fallback_response = self.input_sanitizer.generate_fallback_message(
                     ["non_cwe_query"],
                     context.persona
                 )
                 return {
                     "response": fallback_response,
                     "session_id": session_id,
                     "is_safe": True,
                     "is_cwe_relevant": False
                 }
@@
-            else:
+            else:
                 # Process query using hybrid retrieval for other personas
                 async with cl.Step(name="Retrieve CWE Information", type="retrieval") as retrieval_step:
                     retrieval_step.input = f"Searching CWE database for: {sanitized_query[:100]}..."
@@
-                    if retrieved_chunks:
+                    if retrieved_chunks:
                         retrieved_cwes = list(set(chunk["metadata"]["cwe_id"] for chunk in retrieved_chunks))
                         retrieval_step.output = f"Found {len(retrieved_chunks)} relevant chunks from CWEs: {', '.join(retrieved_cwes[:5])}{'...' if len(retrieved_cwes) > 5 else ''}"
                     else:
                         retrieval_step.output = "No relevant CWE information found"
 
-                if not retrieved_chunks:
-                    # No relevant information found
-                    fallback_response = self.response_generator._generate_fallback_response(
-                        sanitized_query,
-                        context.persona
-                    )
-                    return {
-                        "response": fallback_response,
-                        "session_id": session_id,
-                        "is_safe": True,
-                        "retrieved_chunks": 0
-                    }
+                # Add synthetic attachment chunk if we have attachment context
+                if attachment_text:
+                    attachment_snippet = self._summarize_attachment(attachment_text)
+                    attachment_chunk = {
+                        "metadata": {
+                            "cwe_id": "ATTACHMENT",
+                            "name": "User Attachment Extract",
+                            "section": "Attachment Summary",
+                        },
+                        "document": attachment_snippet,
+                        "scores": {"hybrid": 0.0},
+                    }
+                    retrieved_chunks.append(attachment_chunk)
+
+                if not retrieved_chunks:
+                    # If nothing found and no attachments, fall back; otherwise use attachment-only context
+                    if not attachment_text:
+                        fallback_response = self.response_generator._generate_fallback_response(
+                            sanitized_query,
+                            context.persona
+                        )
+                        return {
+                            "response": fallback_response,
+                            "session_id": session_id,
+                            "is_safe": True,
+                            "retrieved_chunks": 0
+                        }
@@
             # Extract CWEs for context tracking
-            retrieved_cwes = list(set(
-                chunk["metadata"]["cwe_id"] for chunk in retrieved_chunks
-            ))
+            retrieved_cwes = list(set(
+                chunk["metadata"].get("cwe_id", "CWE-UNKNOWN") for chunk in retrieved_chunks
+            )) if retrieved_chunks else []
@@
     def _add_message(self, session_id: str, message: ConversationMessage) -> None:
         """No-op for local storage; Chainlit persists messages in its data layer."""
         logger.debug(f"Message recorded (type={message.message_type}) for session {session_id}")
+
+    def _summarize_attachment(self, text: str) -> str:
+        """
+        Create a concise, safe snippet from extracted attachment text.
+        Keeps the first N chars and trims to the last sentence boundary where possible.
+        """
+        if not text:
+            return ""
+        snippet = text.strip()
+        if len(snippet) <= self.ATTACH_SUMMARY_CHARS:
+            return snippet
+        cut = self.ATTACH_SUMMARY_CHARS
+        # try to cut at a sentence boundary within the last 200 chars of the window
+        window = snippet[:cut]
+        tail = window[-200:]
+        last_period = tail.rfind(".")
+        if last_period != -1:
+            return window[:-200 + last_period + 1].strip() + " ..."
+        return window.rstrip() + " ..."

3) (Optional) Entry point usage example (Chainlit)

If your Chainlit handler currently calls process_user_message_streaming(...) without the user message, pass it now so attachments can be read:

# example: .chainlit/main.py (or wherever you wire ConversationManager)
import chainlit as cl
from src.conversation import ConversationManager
from src.config import config

conv = ConversationManager(
    database_url=f"postgresql://{config.pg_user}:{config.pg_password}@{config.pg_host}:{config.pg_port}/{config.pg_database}",
    gemini_api_key=config.gemini_api_key,
)

@cl.on_message
async def on_message(message: cl.Message):
    session_id = cl.user_session.get("id") or cl.user_session.id  # depending on your setup
    await conv.process_user_message_streaming(
        session_id=session_id,
        message_content=message.content,
        message_id=message.id,
        cl_message=message,  # <-- pass the Chainlit message to enable attachments
    )


That’s it. With these changes, any role can upload a PDF or text file to seed context. The system will sanitize + trim the extract, feed it into retrieval (as part of the query) and into generation (as an “Attachment Summary” context block), and gracefully fall back if the CWE DB returns nothing.