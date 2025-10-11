#!/usr/bin/env python3
"""
REST API for CWE ChatBot - Programmatic Query Access

This module provides a REST API for querying the CWE ChatBot programmatically,
designed primarily for automated testing but also usable for integrations.

Features:
- API key authenticated query endpoint with rate limiting
- Test-login endpoint for hybrid auth mode (Playwright E2E tests)
- Ephemeral sessions (no persistent state)
- IP-based rate limiting to prevent abuse
- Reuses existing ConversationManager and security layers

Auth Modes:
- oauth (production): OAuth only, test-login endpoint disabled
- hybrid (testing/staging): OAuth + test-login endpoint for E2E tests
"""

import asyncio
import hashlib
import os
import secrets
import time
import uuid
from collections import defaultdict
from typing import Dict, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator
from src.app_config import config as app_config
from src.conversation import ConversationManager
from src.secrets import get_test_api_key
from src.security.secure_logging import get_secure_logger

logger = get_secure_logger(__name__)

# Global conversation manager (initialized by main.py)
_conversation_manager: Optional[ConversationManager] = None

# API Key Configuration
# Get from GCP Secret Manager or fall back to TEST_API_KEY env var
# Generate key with: python -c "import secrets; print(secrets.token_urlsafe(32))"
_PROJECT_ID = os.getenv("GOOGLE_CLOUD_PROJECT") or os.getenv("GCP_PROJECT")
_TEST_API_KEY = get_test_api_key(_PROJECT_ID)
_TEST_API_KEY_HASH = None

if _TEST_API_KEY:
    # Store hash instead of plaintext for comparison
    _TEST_API_KEY_HASH = hashlib.sha256(_TEST_API_KEY.encode()).hexdigest()
    logger.info("API key authentication enabled for /api/v1/query endpoint")
else:
    logger.warning(
        "TEST_API_KEY not configured - API endpoint will reject all requests. "
        "Set 'test-api-key' in GCP Secret Manager or TEST_API_KEY env var."
    )


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


async def verify_api_key(x_api_key: str = Header(..., alias="X-API-Key")) -> str:
    """
    Verify API key from X-API-Key header.

    Args:
        x_api_key: API key from request header

    Returns:
        API key if valid

    Raises:
        HTTPException: 401 if API key invalid or missing
    """
    if not _TEST_API_KEY_HASH:
        raise HTTPException(
            status_code=503,
            detail="API key authentication not configured on server",
        )

    # Constant-time comparison to prevent timing attacks
    provided_hash = hashlib.sha256(x_api_key.encode()).hexdigest()

    if not secrets.compare_digest(provided_hash, _TEST_API_KEY_HASH):
        logger.warning("Invalid API key attempt")
        raise HTTPException(
            status_code=401,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "API-Key"},
        )

    return x_api_key


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


class TestLoginResponse(BaseModel):
    """Response model for test-login endpoint."""

    ok: bool
    session_id: str
    expires_in: int  # seconds
    message: str


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


@router.post("/test-login", response_model=TestLoginResponse)
async def test_login(
    response: Response, x_api_key: str = Header(..., alias="X-API-Key")
):
    """
    Test-only endpoint to exchange API key for session cookie (hybrid auth mode).

    **SECURITY**: Only available when AUTH_MODE=hybrid (testing/staging).
    Disabled in production (AUTH_MODE=oauth).

    **Purpose**: Enables Playwright E2E tests to authenticate once and use
    WebSocket/UI without OAuth dance.

    **Flow**:
    1. Test sends X-API-Key header
    2. Validates API key
    3. Mints short-lived session cookie (30 minutes)
    4. Returns session info
    5. Browser/WebSocket uses cookie for subsequent requests

    Args:
        response: FastAPI response object (for setting cookies)
        x_api_key: API key from X-API-Key header

    Returns:
        TestLoginResponse with session info

    Raises:
        HTTPException: 404 if not in hybrid mode, 401 if API key invalid
    """
    # Only available in hybrid auth mode
    if app_config.auth_mode != "hybrid":
        logger.warning(
            "test-login endpoint accessed but AUTH_MODE != hybrid (disabled in production)"
        )
        raise HTTPException(
            status_code=404,
            detail="Not found",  # Hide endpoint existence in production
        )

    # Validate API key (reuse existing verification logic)
    try:
        await verify_api_key(x_api_key)
    except HTTPException:
        logger.warning("test-login: Invalid API key attempt")
        raise

    # Generate test session ID
    session_id = f"test-{int(time.time())}-{uuid.uuid4().hex[:8]}"
    session_expiry = 30 * 60  # 30 minutes

    # Set session cookie (HttpOnly, Secure, SameSite for security)
    response.set_cookie(
        key="test_session_id",
        value=session_id,
        httponly=True,
        secure=True,  # HTTPS only
        samesite="lax",
        max_age=session_expiry,
        path="/",
    )

    logger.info(
        f"test-login: Issued test session {session_id} (expires in {session_expiry}s)"
    )

    return TestLoginResponse(
        ok=True,
        session_id=session_id,
        expires_in=session_expiry,
        message="Test session created. Cookie set for WebSocket/UI authentication.",
    )


@router.post(
    "/query",
    response_model=QueryResponse,
    dependencies=[Depends(verify_api_key), Depends(rate_limit_check)],
)
async def query_cwe(request: QueryRequest):
    """
    Authenticated CWE query endpoint for testing and integrations.

    **Authentication**: Requires `X-API-Key` header with valid API key.

    **Rate limit**: 10 requests/minute per IP address.

    Args:
        request: QueryRequest with query text and optional persona

    Returns:
        QueryResponse with chatbot response and metadata

    Raises:
        HTTPException: 401 if API key invalid, 429 if rate limit exceeded, 503 if service unavailable
    """
    cm = get_conversation_manager()

    # Create ephemeral session for this query
    session_id = f"api-test-{uuid.uuid4()}"

    try:
        logger.info(
            f"API query received: session={session_id}, persona={request.persona}, query='{request.query[:100]}...'"
        )

        # Update persona for this session
        await cm.update_user_persona(session_id, request.persona)

        # Process query using ConversationManager
        result = await cm.process_user_message(
            session_id=session_id, message_content=request.query
        )

        # Extract response text
        response_text = ""
        if result.get("message"):
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
