"""
Messaging module - R16 Unified Message Path

Provides a single entry point for all inbound user messages across transports
(REST, WebSocket, CLI) with consistent preprocessing, safety checks, routing,
logging, and conversation persistence.
"""

from src.messaging.unified import MessageIn, MessageOut, UnifiedMessagePath

__all__ = ["MessageIn", "MessageOut", "UnifiedMessagePath"]
