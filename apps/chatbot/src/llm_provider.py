"""
LLM Provider adapter to abstract underlying model backends.
Supports Google Generative AI and an optional Vertex AI provider.
Falls back to offline mode if explicitly configured.
"""

from __future__ import annotations

import os
from typing import AsyncGenerator, Optional, Dict, Any


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
        self._safety = safety_settings or {}

    async def generate_stream(self, prompt: str) -> AsyncGenerator[str, None]:
        stream = await self._model.generate_content_async(
            prompt,
            generation_config=self._gen_cfg,
            safety_settings=self._safety,
            stream=True,
        )
        async for chunk in stream:
            if getattr(chunk, "text", None):
                yield chunk.text

    async def generate(self, prompt: str) -> str:
        resp = await self._model.generate_content_async(
            prompt,
            generation_config=self._gen_cfg,
            safety_settings=self._safety,
        )
        return resp.text or ""


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
