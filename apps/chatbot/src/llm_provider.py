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

        # AGGRESSIVE: Properly disable safety settings for Gemini 2.5 Flash Lite cybersecurity content
        # Use the correct safety category names from official docs
        try:
            from google.generativeai.types import HarmCategory, HarmBlockThreshold  # type: ignore

            # Official safety settings for Gemini 2.5 Flash Lite - BLOCK_NONE for all categories
            self._safety = [
                {"category": HarmCategory.HARM_CATEGORY_HARASSMENT, "threshold": HarmBlockThreshold.BLOCK_NONE},
                {"category": HarmCategory.HARM_CATEGORY_HATE_SPEECH, "threshold": HarmBlockThreshold.BLOCK_NONE},
                {"category": HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT, "threshold": HarmBlockThreshold.BLOCK_NONE},
                {"category": HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT, "threshold": HarmBlockThreshold.BLOCK_NONE},
            ]
            logger.info("GoogleProvider configured with BLOCK_NONE for all safety categories (Gemini 2.5 Flash Lite)")
        except ImportError:
            # Fallback using string names
            self._safety = [
                {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
            ]
            logger.info("GoogleProvider configured with BLOCK_NONE using string fallback")

        # If user explicitly provides safety settings, respect them
        if safety_settings is not None:
            self._safety = safety_settings
            logger.info(f"GoogleProvider using explicit safety_settings: {safety_settings}")

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
    ) -> None:
        try:
            import vertexai  # type: ignore
            from vertexai.generative_models import GenerativeModel  # type: ignore
        except Exception as e:  # pragma: no cover - optional dependency
            raise RuntimeError("Vertex AI libraries not installed") from e

        # Initialize vertex
        if project and location:
            vertexai.init(project=project, location=location)
        self._model = GenerativeModel(model_name)
        self._gen_cfg = generation_config or {}

    async def generate_stream(self, prompt: str) -> AsyncGenerator[str, None]:
        # Vertex SDK may not support async streaming in this environment; use sync call
        resp = self._model.generate_content(prompt, **self._gen_cfg)
        text = getattr(resp, "text", "")
        if text:
            yield text

    async def generate(self, prompt: str) -> str:
        resp = self._model.generate_content(prompt, **self._gen_cfg)
        return getattr(resp, "text", "") or ""


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
        return VertexProvider(
            model_name=model_name,
            project=project,
            location=location,
            generation_config=generation_config,
        )
    else:
        raise ValueError(f"Unsupported LLM provider: {provider}")
