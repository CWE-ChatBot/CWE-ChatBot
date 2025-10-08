#!/usr/bin/env python3
"""
UI Chat Profiles Module - Modularized Chainlit chat profile management.
Handles user persona selection and profile creation.
"""

from typing import List

from chainlit import ChatProfile

from src.user_context import UserPersona


def create_chat_profiles() -> List[ChatProfile]:
    """
    Create Chainlit chat profiles from UserPersona enum.
    Extracted from main.py for better organization.
    """
    profiles = []

    for p in UserPersona:
        # Create markdown description for each persona
        description = f"**{p.value}**: {_get_persona_description(p.value)}"
        profiles.append(ChatProfile(name=p.value, markdown_description=description))

    return profiles


def _get_persona_description(persona: str) -> str:
    """Get detailed description for each persona."""
    descriptions = {
        "PSIRT Member": "Product Security Incident Response Team member focused on vulnerability assessment and advisory creation",
        "Developer": "Software developer seeking CWE guidance for secure coding practices and vulnerability remediation",
        "Academic Researcher": "Researcher analyzing CWE patterns, relationships, and cybersecurity trends for academic purposes",
        "Bug Bounty Hunter": "Security researcher identifying and reporting vulnerabilities for bug bounty programs",
        "Product Manager": "Product manager tracking security trends and implementing proactive weakness identification strategies",
        "CWE Analyzer": "Direct CWE analysis specialist for mapping vulnerabilities to specific weakness categories",
        "CVE Creator": "CVE description creator for structured vulnerability documentation and reporting",
    }
    return descriptions.get(persona, f"Cybersecurity professional with {persona} role")
