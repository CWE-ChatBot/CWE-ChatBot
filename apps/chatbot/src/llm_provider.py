"""
LLM Provider adapter to abstract underlying model backends.
Supports Google Generative AI and an optional Vertex AI provider.
Falls back to offline mode if explicitly configured.
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, Any, AsyncGenerator, Dict, Optional, cast

logger = logging.getLogger(__name__)


class LLMProvider:
    async def generate_stream(self, prompt: str) -> AsyncGenerator[str, None]:
        # Make this appear as an async generator to static type checkers
        if TYPE_CHECKING:  # pragma: no cover
            yield ""  # ensures AsyncGenerator return type compatibility
        raise NotImplementedError

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

    async def generate_stream(self, prompt: str) -> AsyncGenerator[str, None]:
        logger.debug(
            "Starting streaming generation with safety_settings: %s", self._safety
        )
        try:
            stream = await cast(Any, self._model).generate_content_async(
                prompt,
                generation_config=cast(Any, self._gen_cfg),
                safety_settings=cast(Any, self._safety),
                stream=True,
            )
            logger.debug("Streaming generation started successfully")
            async for chunk in stream:
                if getattr(chunk, "text", None):
                    yield chunk.text
        except Exception as e:
            logger.error(f"Gemini generation failed with error: {e}")
            logger.error(f"Error type: {type(e).__name__}")
            raise e

    async def generate(self, prompt: str) -> str:
        logger.debug(
            "Starting non-streaming generation with safety_settings: %s", self._safety
        )
        try:
            resp = await cast(Any, self._model).generate_content_async(
                prompt,
                generation_config=cast(Any, self._gen_cfg),
                safety_settings=cast(Any, self._safety),
            )
            # Log response details for debugging truncation issues
            response_text = resp.text or ""
            finish_reason = getattr(
                resp.candidates[0] if resp.candidates else None,
                "finish_reason",
                "UNKNOWN",
            )
            logger.info(
                f"Gemini generation completed: {len(response_text)} chars, finish_reason={finish_reason}"
            )
            if finish_reason not in ["STOP", 1]:  # STOP=1 is normal completion
                logger.warning(
                    f"Non-normal finish_reason: {finish_reason} - response may be truncated"
                )
            return response_text
        except Exception as e:
            logger.error(f"Gemini generation failed with error: {e}")
            logger.error(f"Error type: {type(e).__name__}")
            raise e


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

    async def generate_stream(self, prompt: str) -> AsyncGenerator[str, None]:
        logger.debug(
            "Vertex starting streaming generation with safety_settings: %s",
            self._safety,
        )
        try:
            # Use async method with stream=True
            stream = await cast(Any, self._model).generate_content_async(
                prompt,
                generation_config=cast(Any, self._gen_cfg),
                safety_settings=cast(Any, self._safety),
                stream=True,
            )
            logger.debug("Vertex streaming generation started successfully")
            async for chunk in stream:
                if getattr(chunk, "text", None):
                    yield chunk.text
        except Exception as e:
            logger.error(f"Vertex AI streaming generation failed with error: {e}")
            logger.error(f"Error type: {type(e).__name__}")
            raise e

    async def generate(self, prompt: str) -> str:
        logger.debug(
            "Vertex starting non-streaming generation with safety_settings: %s",
            self._safety,
        )
        try:
            # Use async method
            resp = await cast(Any, self._model).generate_content_async(
                prompt,
                generation_config=cast(Any, self._gen_cfg),
                safety_settings=cast(Any, self._safety),
            )
            logger.debug("Vertex non-streaming generation completed successfully")
            return resp.text or ""
        except Exception as e:
            logger.error(f"Vertex AI generation failed with error: {e}")
            logger.error(f"Error type: {type(e).__name__}")
            raise e


class OfflineProvider(LLMProvider):
    def __init__(self, persona: str | None = None) -> None:
        self._persona = persona or "Assistant"

    async def generate_stream(self, prompt: str) -> AsyncGenerator[str, None]:
        yield f"[offline-mode] {self._persona} response preview for: " + prompt[:120]

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
