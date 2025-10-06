"""
LLM Provider adapter to abstract underlying model backends.
Supports Google Generative AI and an optional Vertex AI provider.
Falls back to offline mode if explicitly configured.
"""

from __future__ import annotations

import os
import logging
from typing import AsyncGenerator, Optional, Dict, Any

logger = logging.getLogger(__name__)


class LLMProvider:
    async def generate_stream(self, prompt: str) -> AsyncGenerator[str, None]:
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
        import google.generativeai as genai  # type: ignore

        self._genai = genai
        self._genai.configure(api_key=api_key)
        self._model = genai.GenerativeModel(model_name)
        self._gen_cfg = generation_config or {}

        # Configure safety settings - use provided settings or default to permissive for cybersecurity content
        if safety_settings is not None:
            self._safety = safety_settings
            logger.info(f"GoogleProvider using explicit safety_settings: {safety_settings}")
        else:
            # Default to permissive settings for cybersecurity content
            try:
                from google.generativeai.types import HarmCategory, HarmBlockThreshold  # type: ignore
                self._safety = [
                    {"category": HarmCategory.HARM_CATEGORY_HARASSMENT, "threshold": HarmBlockThreshold.BLOCK_NONE},
                    {"category": HarmCategory.HARM_CATEGORY_HATE_SPEECH, "threshold": HarmBlockThreshold.BLOCK_NONE},
                    {"category": HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT, "threshold": HarmBlockThreshold.BLOCK_NONE},
                    {"category": HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT, "threshold": HarmBlockThreshold.BLOCK_NONE},
                ]
                logger.info("GoogleProvider configured with default BLOCK_NONE for cybersecurity content")
            except ImportError:
                # Fallback using string names
                self._safety = [
                    {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
                ]
                logger.info("GoogleProvider configured with default BLOCK_NONE using string fallback")

    async def generate_stream(self, prompt: str) -> AsyncGenerator[str, None]:
        logger.debug(f"Starting streaming generation with safety_settings: {self._safety}")
        try:
            stream = await self._model.generate_content_async(
                prompt,
                generation_config=self._gen_cfg,
                safety_settings=self._safety,
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
        logger.debug(f"Starting non-streaming generation with safety_settings: {self._safety}")
        try:
            resp = await self._model.generate_content_async(
                prompt,
                generation_config=self._gen_cfg,
                safety_settings=self._safety,
            )
            logger.debug("Non-streaming generation completed successfully")
            return resp.text or ""
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
            import vertexai  # type: ignore
            from vertexai.generative_models import GenerativeModel  # type: ignore
        except Exception as e:  # pragma: no cover - optional dependency
            raise RuntimeError("Vertex AI libraries not installed. Run: pip install google-cloud-aiplatform") from e

        # Initialize Vertex AI with project and location
        if not project or not location:
            raise ValueError("Both project and location required for Vertex AI initialization")

        vertexai.init(project=project, location=location)
        logger.info(f"VertexProvider initialized for project '{project}' in '{location}'")

        self._model = GenerativeModel(model_name)
        self._gen_cfg = generation_config or {}

        # Configure safety settings - use provided settings or default to permissive for cybersecurity content
        if safety_settings is not None:
            self._safety = safety_settings
            logger.info(f"VertexProvider using explicit safety_settings: {safety_settings}")
        else:
            # Default to permissive settings for cybersecurity content (same as GoogleProvider)
            # Vertex AI uses its own types from vertexai.generative_models
            try:
                from vertexai.generative_models import HarmCategory, HarmBlockThreshold, SafetySetting  # type: ignore
                self._safety = [
                    SafetySetting(category=HarmCategory.HARM_CATEGORY_HARASSMENT, threshold=HarmBlockThreshold.BLOCK_NONE),
                    SafetySetting(category=HarmCategory.HARM_CATEGORY_HATE_SPEECH, threshold=HarmBlockThreshold.BLOCK_NONE),
                    SafetySetting(category=HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT, threshold=HarmBlockThreshold.BLOCK_NONE),
                    SafetySetting(category=HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT, threshold=HarmBlockThreshold.BLOCK_NONE),
                ]
                logger.info("VertexProvider configured with default BLOCK_NONE for cybersecurity content")
            except ImportError as e:
                logger.error(f"Failed to import Vertex AI SafetySetting types: {e}")
                # Fallback - no safety settings (Vertex AI will use defaults)
                self._safety = None
                logger.warning("VertexProvider using Vertex AI default safety settings")

    async def generate_stream(self, prompt: str) -> AsyncGenerator[str, None]:
        logger.debug(f"Vertex starting streaming generation with safety_settings: {self._safety}")
        try:
            # Use async method with stream=True
            stream = await self._model.generate_content_async(
                prompt,
                generation_config=self._gen_cfg,
                safety_settings=self._safety,
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
        logger.debug(f"Vertex starting non-streaming generation with safety_settings: {self._safety}")
        try:
            # Use async method
            resp = await self._model.generate_content_async(
                prompt,
                generation_config=self._gen_cfg,
                safety_settings=self._safety,
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
            raise ValueError("GOOGLE_CLOUD_PROJECT and VERTEX_AI_LOCATION env vars required for Vertex provider")
        # Note: Do NOT pass safety_settings - VertexProvider creates its own SafetySetting objects
        # The safety_settings parameter from app_config uses GoogleProvider types which are incompatible
        return VertexProvider(
            model_name=model_name,
            project=project,
            location=location,
            generation_config=generation_config,
            safety_settings=None,  # Let VertexProvider create proper SafetySetting objects
        )
    else:
        raise ValueError(f"Unsupported LLM provider: {provider}")
