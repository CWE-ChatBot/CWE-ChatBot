"""
Model Armor Guard - Pre/Post Sanitization for LLM I/O

Provides model-agnostic guardrails using Google Cloud Model Armor Sanitize APIs.
Works with any LLM provider (Vertex AI, Gemini API, OpenAI, Anthropic, etc.).

Security Pattern:
1. SanitizeUserPrompt BEFORE LLM generation
2. SanitizeModelResponse AFTER LLM generation
3. Fail-closed on BLOCK/SANITIZE/INCONCLUSIVE results
"""

from __future__ import annotations

import hashlib
import logging
import os
from typing import Any, Optional, Tuple

from google.api_core.retry import Retry

logger = logging.getLogger(__name__)


class ModelArmorGuard:
    """
    Pre/post sanitization guard using Model Armor APIs.

    This class wraps Google Cloud Model Armor sanitize APIs to provide
    provider-agnostic LLM input/output protection.
    """

    def __init__(
        self,
        project: str,
        location: str,
        template_id: str,
        enabled: bool = True,
    ):
        """
        Initialize Model Armor guard.

        Args:
            project: GCP project ID
            location: GCP region (e.g., 'us-central1')
            template_id: Model Armor template ID
            enabled: Whether Model Armor is enabled (allows easy disable via env var)
        """
        self.project = project
        self.location = location
        self.template_id = template_id
        self.enabled = enabled

        # Build template path
        self.template_path = (
            f"projects/{project}/locations/{location}/templates/{template_id}"
        )

        # Lazy-load client only if enabled
        self._client: Optional[Any] = None

        if self.enabled:
            logger.info(
                f"Model Armor guard enabled with template: {self.template_path}"
            )
        else:
            logger.info("Model Armor guard disabled (skipping sanitization)")

    def _get_client(self) -> Any:
        """Lazy-load Model Armor client with regional endpoint."""
        if self._client is None:
            try:
                from google.api_core.client_options import ClientOptions
                from google.cloud.modelarmor_v1 import ModelArmorAsyncClient

                # CRITICAL: Model Armor requires regional endpoint
                # Format: modelarmor.<region>.rep.googleapis.com
                api_endpoint = f"modelarmor.{self.location}.rep.googleapis.com"

                # Use async client for Chainlit with regional endpoint
                self._client = ModelArmorAsyncClient(
                    client_options=ClientOptions(api_endpoint=api_endpoint)
                )
                logger.debug(
                    f"Model Armor client initialized with endpoint: {api_endpoint}"
                )
            except ImportError as e:
                logger.error(f"Failed to import Model Armor client: {e}")
                logger.error("Install with: poetry add google-cloud-modelarmor")
                raise RuntimeError("google-cloud-modelarmor not installed") from e
        return self._client

    @staticmethod
    def _stable_hash(s: str) -> str:
        """Deterministic, privacy-preserving short hash for log correlation."""
        try:
            return hashlib.sha256(s.encode("utf-8")).hexdigest()[:16]
        except Exception:
            return "hash_err"

    async def sanitize_user_prompt(self, prompt: str) -> Tuple[bool, str]:
        """
        Sanitize user input before sending to LLM.

        This must be called BEFORE any LLM generation to detect:
        - Prompt injection attacks
        - Jailbreak attempts
        - Data loss / PII exfiltration attempts
        - Malicious URLs

        Args:
            prompt: User's input query

        Returns:
            Tuple of (is_safe, message_or_prompt):
            - (True, prompt): Safe to proceed with LLM generation
            - (False, error_message): BLOCKED - show generic error to user

        Examples:
            >>> is_safe, msg = await guard.sanitize_user_prompt("What is CWE-79?")
            >>> if not is_safe:
            >>>     return msg  # Generic error
            >>> # Proceed with LLM generation...
        """
        if not self.enabled:
            # Model Armor disabled - pass through
            return True, prompt

        try:
            from google.cloud import modelarmor_v1

            logger.debug(f"Sanitizing user prompt (length: {len(prompt)})")

            # Create request
            user_prompt_data = modelarmor_v1.DataItem(text=prompt)
            request = modelarmor_v1.SanitizeUserPromptRequest(
                name=self.template_path,
                user_prompt_data=user_prompt_data,
            )

            # Call Model Armor API with retry/timeout
            client = self._get_client()
            # Tight, user-friendly retry/timeout policy
            retry = Retry(initial=0.2, maximum=1.0, multiplier=2.0, deadline=3.0)
            timeout = 3.0
            response = await client.sanitize_user_prompt(
                request=request,
                retry=retry,
                timeout=timeout,
            )

            # Check sanitization result
            # API returns: sanitizationResult.filterMatchState = NO_MATCH_FOUND | MATCH_FOUND
            sanitization_result = response.sanitization_result
            if (
                sanitization_result.filter_match_state
                == modelarmor_v1.FilterMatchState.NO_MATCH_FOUND
            ):
                logger.debug("Model Armor: User prompt ALLOWED (NO_MATCH_FOUND)")
                return True, prompt

            # MATCH_FOUND = unsafe content detected - fail-closed
            logger.critical(
                "Model Armor BLOCKED user prompt",
                extra={
                    "match_state": sanitization_result.filter_match_state.name,
                    "policy": self.template_path,
                    "filter_results": str(sanitization_result.filter_results)
                    if hasattr(sanitization_result, "filter_results")
                    else None,
                    "prompt_hash": self._stable_hash(prompt),
                },
            )
            return (
                False,
                "I cannot process that request. Please rephrase your question.",
            )

        except Exception as e:
            logger.error(f"Model Armor sanitize_user_prompt failed: {e}")
            # Fail-closed on errors - better safe than sorry
            logger.critical(
                "Model Armor error - failing closed",
                extra={"error": str(e), "prompt_hash": self._stable_hash(prompt)},
            )
            return (
                False,
                "Unable to process your request at this time. Please try again later.",
            )

    async def sanitize_model_response(self, response_text: str) -> Tuple[bool, str]:
        """
        Sanitize model output before showing to user.

        This must be called AFTER LLM generation to detect:
        - Unsafe content generation
        - PII leakage
        - Policy violations
        - Harmful content

        Args:
            response_text: LLM's generated response

        Returns:
            Tuple of (is_safe, message_or_response):
            - (True, response_text): Safe to show to user
            - (False, error_message): BLOCKED - show generic error to user

        Examples:
            >>> response = await llm.generate(prompt)
            >>> is_safe, msg = await guard.sanitize_model_response(response)
            >>> if not is_safe:
            >>>     return msg  # Generic error
            >>> return response  # Safe to show
        """
        if not self.enabled:
            # Model Armor disabled - pass through
            return True, response_text

        try:
            from google.cloud import modelarmor_v1

            logger.debug(f"Sanitizing model response (length: {len(response_text)})")

            # Create request
            model_response_data = modelarmor_v1.DataItem(text=response_text)
            request = modelarmor_v1.SanitizeModelResponseRequest(
                name=self.template_path,
                model_response_data=model_response_data,
            )

            # Call Model Armor API with retry/timeout
            client = self._get_client()
            # Same retry/timeout policy
            retry = Retry(initial=0.2, maximum=1.0, multiplier=2.0, deadline=3.0)
            timeout = 3.0
            response = await client.sanitize_model_response(
                request=request,
                retry=retry,
                timeout=timeout,
            )

            # Check sanitization result
            # API returns: sanitizationResult.filterMatchState = NO_MATCH_FOUND | MATCH_FOUND
            sanitization_result = response.sanitization_result
            if (
                sanitization_result.filter_match_state
                == modelarmor_v1.FilterMatchState.NO_MATCH_FOUND
            ):
                logger.debug("Model Armor: Model response ALLOWED (NO_MATCH_FOUND)")
                return True, response_text

            # MATCH_FOUND = unsafe content detected - fail-closed
            logger.critical(
                "Model Armor BLOCKED model response",
                extra={
                    "match_state": sanitization_result.filter_match_state.name,
                    "policy": self.template_path,
                    "filter_results": str(sanitization_result.filter_results)
                    if hasattr(sanitization_result, "filter_results")
                    else None,
                    "response_hash": self._stable_hash(response_text),
                },
            )
            return (
                False,
                "I generated an unsafe response. Please try a different question.",
            )

        except Exception as e:
            logger.error(f"Model Armor sanitize_model_response failed: {e}")
            # Fail-closed on errors
            logger.critical(
                "Model Armor error - failing closed",
                extra={
                    "error": str(e),
                    "response_hash": self._stable_hash(response_text),
                },
            )
            return (
                False,
                "Unable to process the response at this time. Please try again later.",
            )

    async def aclose(self) -> None:
        """Close the async Model Armor client gracefully."""
        if self._client:
            try:
                await self._client.close()
                logger.debug("Model Armor client closed")
            except Exception as e:
                logger.warning(f"Failed to close Model Armor client: {e}")


def create_model_armor_guard_from_env() -> Optional[ModelArmorGuard]:
    """
    Factory function to create ModelArmorGuard from environment variables.

    Environment Variables:
        MODEL_ARMOR_ENABLED: "true" to enable, "false" to disable (default: false)
        GOOGLE_CLOUD_PROJECT: GCP project ID (required if enabled)
        MODEL_ARMOR_LOCATION: GCP region (default: us-central1)
        MODEL_ARMOR_TEMPLATE_ID: Template ID (default: llm-guardrails-default)

    Returns:
        ModelArmorGuard instance if enabled, None if disabled

    Examples:
        >>> guard = create_model_armor_guard_from_env()
        >>> if guard:
        >>>     is_safe, msg = await guard.sanitize_user_prompt(prompt)
    """
    enabled = os.getenv("MODEL_ARMOR_ENABLED", "false").lower() == "true"

    if not enabled:
        logger.info("Model Armor disabled via MODEL_ARMOR_ENABLED=false")
        return None

    project = os.getenv("GOOGLE_CLOUD_PROJECT")
    if not project:
        logger.error("MODEL_ARMOR_ENABLED=true but GOOGLE_CLOUD_PROJECT not set")
        raise ValueError("GOOGLE_CLOUD_PROJECT required when Model Armor is enabled")

    location = os.getenv("MODEL_ARMOR_LOCATION", "us-central1")
    template_id = os.getenv("MODEL_ARMOR_TEMPLATE_ID", "llm-guardrails-default")

    return ModelArmorGuard(
        project=project,
        location=location,
        template_id=template_id,
        enabled=True,
    )
