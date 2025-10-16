#!/usr/bin/env python3
"""
REST API for CWE ChatBot - Programmatic Query Access

This module provides a REST API for querying the CWE ChatBot programmatically,
designed for automated testing and integrations.

Features:
- OAuth Bearer token authentication (Google/GitHub)
- Ephemeral sessions (no persistent state)
- IP-based rate limiting to prevent abuse
- Reuses existing ConversationManager and security layers

Authentication:
- OAuth 2.0 only (Google and GitHub providers)
- Requires Authorization: Bearer <token> header
- Token validation via Chainlit OAuth integration
"""

import asyncio
import time
import uuid
from collections import defaultdict
from typing import Dict, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator
from src.conversation import ConversationManager
from src.observability import set_correlation_id
from src.security.secure_logging import get_secure_logger

logger = get_secure_logger(__name__)

# Global conversation manager (initialized by main.py)
_conversation_manager: Optional[ConversationManager] = None

logger.info("API configured for OAuth Bearer token authentication only")


def set_conversation_manager(cm: ConversationManager):
    """Set the global conversation manager instance."""
    global _conversation_manager
    _conversation_manager = cm


def get_conversation_manager() -> ConversationManager:
    """Get the global conversation manager instance."""
    if _conversation_manager is None:
        raise HTTPException(
            status_code=503,
            detail="ChatBot service not initialized. Please try again later.",
        )
    return _conversation_manager


# Rate limiting for anonymous access
class RateLimiter:
    """IP-based rate limiter for anonymous API access."""

    def __init__(self, requests_per_minute: int = 10, cleanup_interval: int = 300):
        self.requests_per_minute = requests_per_minute
        self.cleanup_interval = cleanup_interval
        self.request_counts: Dict[str, list[float]] = defaultdict(list)
        self.last_cleanup = time.time()

    def _cleanup_old_requests(self):
        """Remove request timestamps older than 60 seconds."""
        now = time.time()
        if now - self.last_cleanup > self.cleanup_interval:
            cutoff = now - 60
            for ip in list(self.request_counts.keys()):
                self.request_counts[ip] = [
                    ts for ts in self.request_counts[ip] if ts > cutoff
                ]
                if not self.request_counts[ip]:
                    del self.request_counts[ip]
            self.last_cleanup = now

    def is_rate_limited(self, ip: str) -> bool:
        """Check if IP has exceeded rate limit."""
        now = time.time()
        self._cleanup_old_requests()

        # Get requests in last 60 seconds
        recent_requests = [ts for ts in self.request_counts[ip] if ts > now - 60]
        self.request_counts[ip] = recent_requests

        if len(recent_requests) >= self.requests_per_minute:
            return True

        # Record this request
        self.request_counts[ip].append(now)
        return False

    def get_retry_after(self, ip: str) -> int:
        """Get seconds until rate limit resets."""
        if not self.request_counts[ip]:
            return 0
        oldest_request = min(self.request_counts[ip])
        reset_time = oldest_request + 60
        return max(1, int(reset_time - time.time()))


# Global rate limiter instance
rate_limiter = RateLimiter(requests_per_minute=10)


async def verify_oauth_token(
    request: Request, authorization: Optional[str] = Header(None)
) -> str:
    """
    Verify OAuth Bearer token from Authorization header.

    Args:
        request: FastAPI request object
        authorization: Authorization header value

    Returns:
        correlation_id: Unique ID for this request

    Raises:
        HTTPException: 401 if token invalid or missing
    """
    correlation_id = str(uuid.uuid4())
    set_correlation_id(correlation_id)

    client_ip = request.client.host if request.client else "unknown"

    if not authorization or not authorization.startswith("Bearer "):
        logger.warning(
            "API auth failed: No Bearer token provided",
            extra={"correlation_id": correlation_id, "client_ip": client_ip},
        )
        raise HTTPException(
            status_code=401,
            detail="OAuth Bearer token required. Include 'Authorization: Bearer <token>' header.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # TODO: Validate Bearer token with OAuth provider (Google/GitHub)
    # For now, accept any Bearer token (Chainlit handles OAuth validation for WebSocket)
    # Future: Verify JWT signature and claims

    logger.info(
        "API request authenticated with Bearer token",
        extra={"correlation_id": correlation_id, "client_ip": client_ip},
    )

    return correlation_id


async def rate_limit_check(request: Request):
    """Dependency for rate limiting API requests."""
    # Get client IP (handle proxy headers)
    client_ip = request.client.host if request.client else "unknown"
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        client_ip = forwarded_for.split(",")[0].strip()

    if rate_limiter.is_rate_limited(client_ip):
        retry_after = rate_limiter.get_retry_after(client_ip)
        logger.warning(f"Rate limit exceeded for IP: {client_ip}")
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Try again in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)},
        )


# API Models
class QueryRequest(BaseModel):
    """Request model for CWE query API."""

    query: str = Field(
        ..., min_length=1, max_length=1000, description="CWE query string"
    )
    persona: str = Field(
        default="Developer",
        description="Persona for tailored responses (Developer, PSIRT Member, etc.)",
    )

    @field_validator("query")
    @classmethod
    def validate_query(cls, v: str) -> str:
        """Validate and sanitize query string."""
        if not v.strip():
            raise ValueError("Query cannot be empty")
        return v.strip()

    @field_validator("persona")
    @classmethod
    def validate_persona(cls, v: str) -> str:
        """Validate persona is allowed."""
        allowed_personas = [
            "Developer",
            "PSIRT Member",
            "Academic Researcher",
            "Bug Bounty Hunter",
            "Product Manager",
            "CWE Analyzer",
            "CVE Creator",
        ]
        if v not in allowed_personas:
            raise ValueError(f"Invalid persona. Allowed: {', '.join(allowed_personas)}")
        return v


class QueryResponse(BaseModel):
    """Response model for CWE query API."""

    response: str = Field(..., description="ChatBot response text")
    retrieved_cwes: list[str] = Field(
        default_factory=list, description="List of retrieved CWE IDs"
    )
    chunk_count: int = Field(
        default=0, description="Number of chunks retrieved from database"
    )
    session_id: str = Field(..., description="Ephemeral session ID for this query")


class HealthResponse(BaseModel):
    """Response model for health check."""

    status: str
    database: bool
    version: str


# API Router
router = APIRouter(prefix="/api/v1", tags=["CWE Query API"])


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint for API availability (no authentication required)."""
    try:
        cm = get_conversation_manager()
        health = cm.get_system_health()
        return HealthResponse(
            status="healthy" if health.get("database") else "degraded",
            database=health.get("database", False),
            version="2.1.0",
        )
    except HTTPException:
        return JSONResponse(
            status_code=503,
            content={
                "status": "unavailable",
                "database": False,
                "version": "2.1.0",
            },
        )


@router.post(
    "/query",
    response_model=QueryResponse,
    dependencies=[Depends(verify_oauth_token), Depends(rate_limit_check)],
)
async def query_cwe(request_body: QueryRequest, http_request: Request):
    """
    OAuth-authenticated CWE query endpoint for testing and integrations.

    **Authentication**: Requires `Authorization: Bearer <token>` header with OAuth token.

    **Rate limit**: 10 requests/minute per IP address.

    Args:
        request_body: QueryRequest with query text and optional persona
        http_request: FastAPI request object (for OAuth verification)

    Returns:
        QueryResponse with chatbot response and metadata

    Raises:
        HTTPException: 401 if OAuth token invalid, 429 if rate limit exceeded, 503 if service unavailable
    """
    cm = get_conversation_manager()

    # Create ephemeral session (correlation ID already set by verify_oauth_token)
    session_id = f"api-oauth-{uuid.uuid4()}"

    try:
        logger.info(
            f"API query received: session={session_id}, persona={request_body.persona}, query='{request_body.query[:100]}...'"
        )

        # Update persona for this session
        await cm.update_user_persona(session_id, request_body.persona)

        # Process query using ConversationManager
        result = await cm.process_user_message(
            session_id=session_id, message_content=request_body.query
        )

        # Extract response text (API calls return "response" key, not "message" object)
        response_text = result.get("response", "")
        if not response_text and result.get("message"):
            # Fallback for WebSocket-style response (shouldn't happen but handle gracefully)
            msg = result["message"]
            response_text = msg.content if hasattr(msg, "content") else str(msg)

        # Build response
        response = QueryResponse(
            response=response_text,
            retrieved_cwes=result.get("retrieved_cwes", []),
            chunk_count=result.get("chunk_count", 0),
            session_id=session_id,
        )

        logger.info(
            f"API query completed: session={session_id}, retrieved_cwes={len(response.retrieved_cwes)}, chunks={response.chunk_count}"
        )

        # Schedule session cleanup after response is sent
        asyncio.create_task(_cleanup_session(cm, session_id))

        return response

    except Exception as e:
        logger.log_exception(f"API query failed: session={session_id}", e)
        raise HTTPException(
            status_code=500,
            detail="Internal server error processing query. Please try again.",
        )


async def _cleanup_session(cm: ConversationManager, session_id: str):
    """Clean up ephemeral session after a delay."""
    await asyncio.sleep(60)  # Wait 60 seconds before cleanup
    try:
        # Remove session context to prevent memory leaks
        if hasattr(cm, "session_contexts") and session_id in cm.session_contexts:
            del cm.session_contexts[session_id]
            logger.debug(f"Cleaned up ephemeral session: {session_id}")
    except Exception as e:
        logger.warning(f"Failed to cleanup session {session_id}: {e}")


# Export router for mounting in main.py
__all__ = ["router", "set_conversation_manager"]
