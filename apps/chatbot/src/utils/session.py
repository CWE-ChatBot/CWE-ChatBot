from __future__ import annotations

from typing import Optional

import chainlit as cl
from src.user_context import UserContext

SESSION_KEY = "user_context"


def get_user_context() -> UserContext:
    """Retrieve or initialize the per-user context stored in Chainlit's session."""
    ctx: Optional[UserContext] = cl.user_session.get(SESSION_KEY)
    if ctx is None:
        ctx = UserContext()
        cl.user_session.set(SESSION_KEY, ctx)
    return ctx


def set_user_context(ctx: UserContext) -> None:
    """Persist an updated user context back into Chainlit's session."""
    cl.user_session.set(SESSION_KEY, ctx)
