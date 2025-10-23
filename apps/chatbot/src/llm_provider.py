"""
LLM Provider adapter to abstract underlying model backends.
Supports Google Generative AI and an optional Vertex AI provider.
Falls back to offline mode if explicitly configured.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any, Dict, Optional, cast

from tenacity import (
    AsyncRetrying,
    retry_if_exception,
    stop_after_attempt,
    wait_random_exponential,
)

from src.observability import get_correlation_id

logger = logging.getLogger(__name__)


def _is_transient_llm_error(e: BaseException) -> bool:
    """Conservatively treat common network hiccups and retriable service faults as transient."""
    transient_types = (asyncio.TimeoutError,)
    # Avoid hard deps: rely on class names / messages if SDK types differ
    msg = str(e).lower()
    return isinstance(e, transient_types) or any(
        s in msg
        for s in (
            "temporarily unavailable",
            "retry",
            "try again",
            "deadline exceeded",
            "unavailable",
            "connection reset",
            "connection aborted",
            "timeout",
            "dns",
            "name resolution",
            "502",
            "503",
            "504",
        )
    )


class LLMProvider:
    async def generate(self, prompt: str) -> str:
        raise NotImplementedError


class GoogleProvider(LLMProvider):
    def __init__(
        self,
        api_key: str,
        model_name: str,
        generation_config: Dict[str, Any] | None = None,
        safety_settings: Dict[str, Any] | None = None,
    ) -> None:
        import google.generativeai as genai

        # Some type stubs for google.generativeai may not export these symbols;
        # cast to Any to avoid false positives.
        _genai_any = cast(Any, genai)
        _genai_any.configure(api_key=api_key)
        self._model = _genai_any.GenerativeModel(model_name)
        self._gen_cfg = generation_config or {}

        # Configure safety settings - use provided settings or default
        # to permissive for cybersecurity content
        self._safety: Any = safety_settings if safety_settings is not None else None
        if safety_settings is not None:
            # Already provided by caller
            logger.info(
                "GoogleProvider using explicit safety_settings: %s", safety_settings
            )
        else:
            # Default to permissive settings for cybersecurity content
            try:
                from google.generativeai.types import (
                    HarmBlockThreshold,
                    HarmCategory,
                )

                self._safety = [
                    {
                        "category": HarmCategory.HARM_CATEGORY_HARASSMENT,
                        "threshold": HarmBlockThreshold.BLOCK_NONE,
                    },
                    {
                        "category": HarmCategory.HARM_CATEGORY_HATE_SPEECH,
                        "threshold": HarmBlockThreshold.BLOCK_NONE,
                    },
                    {
                        "category": HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT,
                        "threshold": HarmBlockThreshold.BLOCK_NONE,
                    },
                    {
                        "category": HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
                        "threshold": HarmBlockThreshold.BLOCK_NONE,
                    },
                ]
                logger.info("Google default safety: BLOCK_NONE")
            except ImportError:
                # Fallback using string names
                self._safety = [
                    {
                        "category": "HARM_CATEGORY_HARASSMENT",
                        "threshold": "BLOCK_NONE",
                    },
                    {
                        "category": "HARM_CATEGORY_HATE_SPEECH",
                        "threshold": "BLOCK_NONE",
                    },
                    {
                        "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
                        "threshold": "BLOCK_NONE",
                    },
                    {
                        "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
                        "threshold": "BLOCK_NONE",
                    },
                ]
                logger.info("Google default safety (string fallback): BLOCK_NONE")

    async def generate(self, prompt: str) -> str:
        correlation_id = get_correlation_id()
        logger.debug(
            "Starting non-streaming generation with safety_settings: %s",
            self._safety,
            extra={"correlation_id": correlation_id},
        )
        # Light retries for brief network hiccups
        attempts = int(os.getenv("LLM_RETRY_ATTEMPTS", "3"))
        timeout_s = float(os.getenv("LLM_REQUEST_TIMEOUT_SEC", "30"))
        async for attempt in AsyncRetrying(
            stop=stop_after_attempt(attempts),
            wait=wait_random_exponential(
                multiplier=0.3, max=float(os.getenv("LLM_RETRY_MAX_WAIT", "2.5"))
            ),
            retry=retry_if_exception(_is_transient_llm_error),
            reraise=True,
        ):
            with attempt:
                attempt_num = attempt.retry_state.attempt_number
                logger.info(
                    "LLM request attempt %d/%d",
                    attempt_num,
                    attempts,
                    extra={
                        "correlation_id": correlation_id,
                        "attempt_number": attempt_num,
                        "max_attempts": attempts,
                    },
                )
                try:
                    resp = await asyncio.wait_for(
                        cast(Any, self._model).generate_content_async(
                            prompt,
                            generation_config=cast(Any, self._gen_cfg),
                            safety_settings=cast(Any, self._safety),
                        ),
                        timeout=timeout_s,
                    )
                    # Log response details for debugging truncation issues
                    response_text = resp.text or ""
                    finish_reason = None
                    if getattr(resp, "candidates", None):
                        finish_reason = getattr(
                            resp.candidates[0], "finish_reason", None
                        )
                    # Normalize enums/ints/strings to an upper-case string for comparison
                    finish_norm = (
                        str(finish_reason).upper()
                        if finish_reason is not None
                        else "UNKNOWN"
                    )
                    logger.info(
                        "Gemini generation completed: %d chars, finish_reason=%s",
                        len(response_text),
                        finish_reason,
                        extra={
                            "correlation_id": correlation_id,
                            "attempt_number": attempt_num,
                            "response_length": len(response_text),
                        },
                    )
                    # Accept common STOP variants; warn on anything else (possible truncation)
                    if finish_norm not in {"STOP", "FINISH_REASON_STOP", "1"}:
                        logger.warning(
                            "Non-normal finish_reason: %s - response may be truncated",
                            finish_reason,
                            extra={"correlation_id": correlation_id},
                        )
                    return response_text
                except Exception as e:
                    will_retry = attempt_num < attempts
                    logger.warning(
                        "LLM request failed on attempt %d/%d: %s",
                        attempt_num,
                        attempts,
                        type(e).__name__,
                        extra={
                            "correlation_id": correlation_id,
                            "attempt_number": attempt_num,
                            "error_type": type(e).__name__,
                            "will_retry": will_retry,
                        },
                    )
                    raise
        # Unreachable: AsyncRetrying with reraise=True will always raise if all retries fail
        raise RuntimeError("All retry attempts exhausted")  # pragma: no cover


class VertexProvider(LLMProvider):
    def __init__(
        self,
        model_name: str,
        project: Optional[str] = None,
        location: Optional[str] = None,
        generation_config: Dict[str, Any] | None = None,
        safety_settings: Dict[str, Any] | None = None,
    ) -> None:
        try:
            import vertexai
            from vertexai.generative_models import GenerativeModel
        except Exception as e:  # pragma: no cover - optional dependency
            raise RuntimeError(
                "Vertex AI libraries not installed (install google-cloud-aiplatform)"
            ) from e

        # Initialize Vertex AI with project and location
        if not project or not location:
            raise ValueError(
                "Project and location required for Vertex AI initialization"
            )

        vertexai.init(project=project, location=location)
        logger.info(
            "VertexProvider initialized: project=%s, location=%s", project, location
        )

        self._model = GenerativeModel(model_name)
        self._gen_cfg = generation_config or {}

        # Configure safety settings - use provided settings or default to
        # permissive for cybersecurity content
        self._safety: Any = safety_settings if safety_settings is not None else None
        if safety_settings is not None:
            logger.info(
                "VertexProvider using explicit safety_settings: %s", safety_settings
            )
        else:
            # Default to permissive settings for cybersecurity content (same as
            # GoogleProvider). Vertex AI uses its own SafetySetting types.
            try:
                from vertexai.generative_models import (
                    HarmBlockThreshold,
                    HarmCategory,
                    SafetySetting,
                )

                self._safety = [
                    SafetySetting(
                        category=HarmCategory.HARM_CATEGORY_HARASSMENT,
                        threshold=HarmBlockThreshold.BLOCK_NONE,
                    ),
                    SafetySetting(
                        category=HarmCategory.HARM_CATEGORY_HATE_SPEECH,
                        threshold=HarmBlockThreshold.BLOCK_NONE,
                    ),
                    SafetySetting(
                        category=HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT,
                        threshold=HarmBlockThreshold.BLOCK_NONE,
                    ),
                    SafetySetting(
                        category=HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
                        threshold=HarmBlockThreshold.BLOCK_NONE,
                    ),
                ]
                logger.info("Vertex default safety: BLOCK_NONE")
            except ImportError as e:
                logger.error(f"Failed to import Vertex AI SafetySetting types: {e}")
                # Fallback - no safety settings (Vertex AI will use defaults)
                self._safety = None
                logger.warning("VertexProvider using Vertex AI default safety settings")

    async def generate(self, prompt: str) -> str:
        correlation_id = get_correlation_id()
        logger.debug(
            "Vertex starting non-streaming generation with safety_settings: %s",
            self._safety,
        )
        attempts = int(os.getenv("LLM_RETRY_ATTEMPTS", "3"))
        timeout_s = float(os.getenv("LLM_REQUEST_TIMEOUT_SEC", "30"))
        async for attempt in AsyncRetrying(
            stop=stop_after_attempt(attempts),
            wait=wait_random_exponential(
                multiplier=0.3, max=float(os.getenv("LLM_RETRY_MAX_WAIT", "2.5"))
            ),
            retry=retry_if_exception(_is_transient_llm_error),
            reraise=True,
        ):
            with attempt:
                attempt_num = attempt.retry_state.attempt_number
                logger.info(
                    "Vertex LLM request attempt %d/%d",
                    attempt_num,
                    attempts,
                    extra={
                        "correlation_id": correlation_id,
                        "attempt_number": attempt_num,
                        "max_attempts": attempts,
                    },
                )
                try:
                    resp = await asyncio.wait_for(
                        cast(Any, self._model).generate_content_async(
                            prompt,
                            generation_config=cast(Any, self._gen_cfg),
                            safety_settings=cast(Any, self._safety),
                        ),
                        timeout=timeout_s,
                    )
                    response_text = resp.text or ""
                    logger.info(
                        "Vertex generation completed: %d chars",
                        len(response_text),
                        extra={
                            "correlation_id": correlation_id,
                            "attempt_number": attempt_num,
                            "response_length": len(response_text),
                        },
                    )
                    return response_text
                except Exception as e:
                    will_retry = attempt_num < attempts
                    logger.warning(
                        "Vertex LLM request failed on attempt %d/%d: %s",
                        attempt_num,
                        attempts,
                        type(e).__name__,
                        extra={
                            "correlation_id": correlation_id,
                            "attempt_number": attempt_num,
                            "error_type": type(e).__name__,
                            "will_retry": will_retry,
                        },
                    )
                    raise
        # Unreachable: AsyncRetrying with reraise=True will always raise if all retries fail
        raise RuntimeError("All retry attempts exhausted")  # pragma: no cover


class OfflineProvider(LLMProvider):
    def __init__(self, persona: str | None = None) -> None:
        self._persona = persona or "Assistant"

    async def generate(self, prompt: str) -> str:
        return f"[offline-mode] {self._persona} response for: " + prompt[:120]


def get_llm_provider(
    *,
    provider: Optional[str],
    api_key: Optional[str],
    model_name: str,
    generation_config: Dict[str, Any] | None,
    safety_settings: Dict[str, Any] | None,
    offline: bool,
    persona: Optional[str] = None,
) -> LLMProvider:
    if offline:
        return OfflineProvider(persona=persona)

    provider = (provider or os.getenv("PROVIDER") or "google").lower()
    if provider == "google":
        if not api_key:
            raise ValueError("GEMINI_API_KEY required for Google provider")
        return GoogleProvider(
            api_key=api_key,
            model_name=model_name,
            generation_config=generation_config,
            safety_settings=safety_settings,
        )
    elif provider == "vertex":  # pragma: no cover - optional path
        project = os.getenv("GOOGLE_CLOUD_PROJECT")
        location = os.getenv("VERTEX_AI_LOCATION")
        if not project or not location:
            raise ValueError(
                "GOOGLE_CLOUD_PROJECT and VERTEX_AI_LOCATION env vars required"
            )
        # Do NOT pass safety_settings here. VertexProvider creates its own safety
        # settings objects. The app_config types target GoogleProvider and are
        # incompatible with Vertex types.
        return VertexProvider(
            model_name=model_name,
            project=project,
            location=location,
            generation_config=generation_config,
            # Let VertexProvider create proper SafetySetting objects
            safety_settings=None,
        )
    else:
        raise ValueError(f"Unsupported LLM provider: {provider}")
