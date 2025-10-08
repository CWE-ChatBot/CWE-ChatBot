#!/usr/bin/env python3
"""
UI Messaging Module - Modularized Chainlit UI components from main.py.
Handles progressive disclosure, element creation, and UI interactions.
"""

from typing import Any, Dict, List, Literal

import chainlit as cl
from pydantic import BaseModel, Field


class UISettings(BaseModel):
    """Pydantic Chat Settings for native UI."""

    detail_level: Literal["basic", "standard", "detailed"] = Field(
        default="standard", description="Level of detail in responses"
    )
    include_examples: bool = Field(
        default=True, description="Include code examples and practical demonstrations"
    )
    include_mitigations: bool = Field(
        default=True, description="Include prevention and mitigation guidance"
    )


class UIMessaging:
    """
    Handles UI messaging and element creation for Chainlit.
    Centralizes UI logic that was scattered in main.py.
    """

    @staticmethod
    def create_progressive_response(content: str, detail_level: str) -> List[cl.Text]:
        """
        Create progressive disclosure response based on detail level setting.
        Story 3.4: Progressive Disclosure Implementation
        """
        if detail_level == "basic" and len(content) > 300:
            # Create summary with expandable details
            summary = content[:300] + "..."
            remaining = content[300:]

            # Use Chainlit's Text element with expandable content
            return [
                cl.Text(name="Summary", content=summary, display="inline"),
                cl.Text(name="Detailed Information", content=remaining, display="side"),
            ]
        elif detail_level == "detailed":
            # Show full content with additional context
            return [
                cl.Text(name="Detailed Response", content=content, display="inline")
            ]
        else:
            # Standard level - show full content normally
            return [cl.Text(name="Response", content=content, display="inline")]

    @staticmethod
    def create_source_elements(retrieved_chunks: List[Dict[str, Any]]) -> List[cl.Text]:
        """
        Create source reference elements from retrieved chunks.
        Extracted from main.py for better organization.
        """
        elements = []

        # Group chunks by CWE and create source cards
        cwe_groups = {}
        for chunk in retrieved_chunks:
            cwe_id = chunk["metadata"]["cwe_id"]
            if cwe_id not in cwe_groups:
                cwe_groups[cwe_id] = {"name": chunk["metadata"]["name"], "chunks": []}
            cwe_groups[cwe_id]["chunks"].append(chunk)

        # Create source elements for each CWE (skip evidence pseudo-source)
        filtered = [
            (cid, info)
            for cid, info in cwe_groups.items()
            if cid not in ("EVIDENCE", "FILE")
        ]
        for cwe_id, cwe_info in filtered[:3]:  # Limit to top 3 CWEs
            # Get best scoring chunk for this CWE
            best_chunk = max(
                cwe_info["chunks"], key=lambda x: x.get("scores", {}).get("hybrid", 0.0)
            )
            score = best_chunk.get("scores", {}).get("hybrid", 0.0)

            # Create source content showing the CWE information
            source_content = f"**{cwe_id}: {cwe_info['name']}**\n\n"
            source_content += f"**Relevance Score:** {score:.3f}\n\n"

            # Add section content from the best chunk
            section = best_chunk["metadata"].get("section", "Content")
            source_content += f"**{section}:**\n"
            document_text = best_chunk["document"]

            # Truncate if too long
            if len(document_text) > 500:
                source_content += document_text[:500] + "..."
            else:
                source_content += document_text

            # Create Chainlit Text element for the source
            source_element = cl.Text(
                name=f"Source: {cwe_id}",
                content=source_content,
                display="side",  # Display in sidebar
            )
            elements.append(source_element)

        return elements

    @staticmethod
    def create_file_evidence_element(file_context: str) -> cl.Text:
        """
        Create file evidence element from uploaded file context.
        Extracted from main.py for better organization.
        """
        # Truncate for display; full text already passed as isolated context
        preview = file_context
        if len(preview) > 800:
            preview = preview[:800] + "..."

        return cl.Text(name="Uploaded Evidence", content=preview, display="side")

    @staticmethod
    def apply_progressive_disclosure(
        message: cl.Message, ui_settings: Dict[str, Any], elements: List[cl.Text]
    ) -> List[cl.Text]:
        """
        Apply progressive disclosure to a message based on UI settings.
        Returns updated elements list.
        """
        detail_level = ui_settings.get("detail_level", "standard")
        if detail_level == "basic" and hasattr(message, "content"):
            # Create progressive disclosure for long responses
            content = message.content
            if len(content) > 300:
                # Split into summary and details
                summary = content[:300] + "..."
                details = content[300:]

                # Update the main message to show summary
                message.content = summary

                # Add detailed content as a side element
                detail_element = cl.Text(
                    name="Detailed Information", content=details, display="side"
                )
                elements.append(detail_element)

        return elements

    @staticmethod
    async def update_message_with_elements(
        message: cl.Message, elements: List[Any]
    ) -> None:
        """
        Update a Chainlit message with elements.
        Centralizes the message update pattern.
        """
        if elements:
            message.elements = elements
            await message.update()


# Convenience function for backward compatibility
def create_progressive_response(content: str, detail_level: str) -> List[Any]:
    """Backward compatibility function."""
    return UIMessaging.create_progressive_response(content, detail_level)
