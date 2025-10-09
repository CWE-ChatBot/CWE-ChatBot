"""
CSRF Protection for Chainlit Actions and State-Changing Operations - Story S-12

Provides token-based CSRF protection for:
- Chainlit Actions (buttons, forms)
- Settings updates
- Feedback submissions
- Other state-changing WebSocket messages

Usage:
    # In on_chat_start:
    csrf_manager = CSRFManager()
    token = csrf_manager.generate_token()
    cl.user_session.set("csrf_token", token)

    # When creating actions:
    token = cl.user_session.get("csrf_token")
    action = cl.Action(name="ask", label="Ask", payload={"csrf_token": token})

    # In action callback:
    @cl.action_callback("ask")
    async def on_ask(action):
        if not require_csrf(action.payload):
            await cl.Message("Invalid request token").send()
            return
        # Process action...
"""

import secrets
from typing import Any, Dict, Optional

import chainlit as cl


class CSRFManager:
    """
    Manages CSRF token generation and validation for Chainlit sessions.

    Each user session gets a unique CSRF token that must be included
    in all state-changing operations (actions, settings, feedback).
    """

    @staticmethod
    def generate_token() -> str:
        """
        Generate a cryptographically secure CSRF token.

        Returns:
            URL-safe base64 token (32 bytes = 256 bits)
        """
        return secrets.token_urlsafe(32)

    @staticmethod
    def get_session_token() -> Optional[str]:
        """
        Get the CSRF token for the current session.

        Returns:
            Token string or None if not set
        """
        token = cl.user_session.get("csrf_token")
        return str(token) if token is not None else None

    @staticmethod
    def set_session_token(token: str) -> None:
        """
        Store CSRF token in user session.

        Args:
            token: CSRF token to store
        """
        cl.user_session.set("csrf_token", token)

    @staticmethod
    def validate_token(provided_token: Optional[str]) -> bool:
        """
        Validate provided CSRF token against session token.

        Uses constant-time comparison to prevent timing attacks.

        Args:
            provided_token: Token from request to validate

        Returns:
            True if token matches, False otherwise
        """
        expected = CSRFManager.get_session_token()

        if not expected or not provided_token:
            return False

        # Constant-time comparison prevents timing attacks
        return secrets.compare_digest(str(expected), str(provided_token))


def require_csrf(payload: Optional[Dict[str, Any]]) -> bool:
    """
    Helper function to validate CSRF token from action/message payload.

    Checks for token in multiple possible locations:
    - payload["csrf_token"]
    - payload["payload"]["csrf_token"] (nested)
    - metadata["csrf_token"]

    Args:
        payload: Payload dictionary from Chainlit action/message

    Returns:
        True if valid token found, False otherwise

    Example:
        @cl.action_callback("submit")
        async def on_submit(action):
            if not require_csrf(action.payload):
                await cl.Message("Invalid request token").send()
                return
            # Process valid action...
    """
    if not payload:
        return False

    # Try direct payload
    token = payload.get("csrf_token")

    # Try nested payload
    if not token and "payload" in payload:
        token = payload["payload"].get("csrf_token")

    # Try metadata
    if not token and "metadata" in payload:
        token = payload["metadata"].get("csrf_token")

    return CSRFManager.validate_token(token)


def require_csrf_from_metadata(metadata: Optional[Dict[str, Any]]) -> bool:
    """
    Validate CSRF token from message metadata.

    Used for settings updates and feedback where metadata is separate.

    Args:
        metadata: Metadata dictionary

    Returns:
        True if valid token found, False otherwise

    Example:
        @cl.on_settings_update
        async def on_settings_update(settings):
            meta = cl.context.session.metadata if hasattr(cl.context.session, "metadata") else {}
            if not require_csrf_from_metadata(meta):
                return
            # Process valid settings update...
    """
    if not metadata:
        return False

    token = metadata.get("csrf_token")
    return CSRFManager.validate_token(token)
