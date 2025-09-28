#!/usr/bin/env python3
"""
CWE Analyzer Handler - Manages stateful analyzer persona workflows.

This module extracts complex CWE Analyzer logic from ConversationManager,
implementing the state machine for /ask, /compare, and /exit modes.
"""

import logging
import re
from typing import Dict, Any, List

import chainlit as cl

from src.processing.pipeline import ProcessingPipeline, PipelineResult
from src.security.secure_logging import get_secure_logger

logger = get_secure_logger(__name__)


class AnalyzerModeHandler:
    """
    Handles all CWE Analyzer persona logic with /ask, /compare, /exit modes.

    This class isolates the complex state machine logic that was previously
    embedded in ConversationManager, making it easier to test and maintain.
    """

    def __init__(self, pipeline: ProcessingPipeline):
        """
        Initialize with ProcessingPipeline dependency.

        Args:
            pipeline: ProcessingPipeline for executing analysis workflows
        """
        self.pipeline = pipeline
        logger.info("AnalyzerModeHandler initialized")

    async def process(self, query: str, context) -> PipelineResult:
        """
        Handle all CWE Analyzer workflows - commands, modes, and analysis.

        Args:
            query: User query string
            context: UserContext object with analyzer state

        Returns:
            PipelineResult with response and metadata
        """
        try:
            logger.info(f"Processing analyzer request: '{query[:50]}...' in mode: {getattr(context, 'analyzer_mode', None)}")

            # Handle mode switching commands first
            if re.match(r"^\s*/ask\b", query, flags=re.IGNORECASE):
                context.analyzer_mode = "question"
                return PipelineResult(
                    final_response_text="Question mode activated. Ask about the last analysis or type /exit to leave.",
                    metadata={"mode_switch": True, "mode": "question"}
                )

            if re.match(r"^\s*/compare\b", query, flags=re.IGNORECASE):
                context.analyzer_mode = "compare"
                return PipelineResult(
                    final_response_text="Comparison mode activated. Provide candidate CWE ID(s) (e.g., CWE-79, CWE-80). Type /exit to leave.",
                    metadata={"mode_switch": True, "mode": "compare"}
                )

            # Handle exit commands
            if context.analyzer_mode in ("question", "compare") and (
                re.match(r"^\s*0\b", query) or re.match(r"^\s*/exit\b", query, flags=re.IGNORECASE)
            ):
                context.analyzer_mode = None
                return PipelineResult(
                    final_response_text="Exited follow-up mode. Type /ask to ask a question or /compare to compare CWEs.",
                    metadata={"mode_switch": True, "mode": None}
                )

            # Handle analysis based on current mode
            if context.analyzer_mode == "question":
                return await self._handle_question_mode(query, context)
            elif context.analyzer_mode == "compare":
                return await self._handle_compare_mode(query, context)
            else:
                return await self._handle_initial_analysis(query, context)

        except Exception as e:
            logger.log_exception("Analyzer mode processing failed", e)
            return PipelineResult(
                final_response_text="I encountered an error processing your analysis request. Please try again.",
                is_low_confidence=True
            )

    async def _handle_question_mode(self, query: str, context) -> PipelineResult:
        """Handle follow-up questions about previous analysis."""
        # Reuse previous chunks and build follow-up context
        prev_chunks = getattr(context, 'last_chunks', []) or []
        if not prev_chunks:
            return PipelineResult(
                final_response_text="No previous analysis available. Type /exit to return to analysis mode.",
                metadata={"mode": "question", "error": "no_previous_analysis"}
            )

        # Build specialized query with follow-up context
        prev_recs = getattr(context, 'last_recommendations', []) or []
        prev_ids = [r.get('cwe_id') for r in prev_recs if r.get('cwe_id')]

        followup_query = query
        if prev_ids:
            followup_query += f"\n\n[Follow-up Instruction]\nPrior recommendations: {', '.join(prev_ids)}\nTask: Address the user's follow-up by referencing prior recommendations."

        # Use pipeline with enhanced query
        result = await self.pipeline.process_user_request(followup_query, context)

        # Add mode-specific messaging
        result.final_response_text += "\n\n(Question mode active) Ask another question or type /exit to leave."
        result.metadata["mode"] = "question"

        return result

    async def _handle_compare_mode(self, query: str, context) -> PipelineResult:
        """Handle CWE comparison analysis."""
        # Extract candidate CWE IDs from user input
        from src.processing.query_processor import QueryProcessor
        processor = QueryProcessor()
        processed = processor.preprocess_query(query)
        candidates = list(processed.get("cwe_ids", set()) or [])

        if not candidates:
            return PipelineResult(
                final_response_text="Provide candidate CWE ID(s) to compare. You can type /exit to leave compare mode.",
                metadata={"mode": "compare", "error": "no_candidates"}
            )

        # Build comparison query with prior context
        prev_recs = getattr(context, 'last_recommendations', []) or []
        prev_ids = [r.get('cwe_id') for r in prev_recs if r.get('cwe_id')]

        compare_query = "Use prior evidence for comparison."
        if prev_ids:
            compare_query += f"\n\n[Follow-up Comparison]\nCandidate CWEs: {', '.join(candidates)}\nPrior recommendations: {', '.join(prev_ids)}\nTask: For each candidate, decide suitability: Primary/Secondary/Related/Not a fit with rationale."

        # Use pipeline for comparison analysis
        result = await self.pipeline.process_user_request(compare_query, context)

        # Add mode-specific messaging
        result.final_response_text += "\n\n(Comparison mode active) Provide more candidate CWEs or type /exit to leave."
        result.metadata["mode"] = "compare"
        result.metadata["candidates"] = candidates

        return result

    async def _handle_initial_analysis(self, query: str, context) -> PipelineResult:
        """Handle initial CWE analysis with enhanced retrieval."""
        # Set evidence and enhance query for analysis
        context.set_evidence(query)

        # Extract key phrases and boost query (moved from ConversationManager)
        key_phrases = self._extract_key_phrases(query)
        enhanced_query = query

        boost_terms = []
        if key_phrases.get('rootcause'):
            boost_terms.append(key_phrases['rootcause'])
        if key_phrases.get('weakness'):
            boost_terms.append(key_phrases['weakness'])

        if boost_terms:
            enhanced_query = f"{query} " + " ".join(boost_terms)

        # Add stable hints to emphasize classification
        enhanced_query += " root cause underlying weakness pattern classification mapping"

        # Execute pipeline with enhanced query
        result = await self.pipeline.process_user_request(enhanced_query, context)

        # Store results for follow-up modes
        context.last_recommendations = result.recommendations
        # Note: last_chunks would need to be stored in pipeline metadata if needed

        # Add command hints for user
        result.final_response_text += "\n\nNext: type /ask to ask a question about this analysis, or /compare to compare candidate CWEs."
        result.metadata["mode"] = "initial"

        return result

    def _extract_key_phrases(self, text: str) -> Dict[str, str]:
        """
        Extract rootcause/weakness phrases from text.

        This is moved from ConversationManager._extract_key_phrases.
        """
        try:
            phrases = {}
            patterns = {
                'rootcause': r'(?im)^(?:root\s*cause|rootcause)\s*:\s*(.+)$',
                'weakness': r'(?im)^weakness\s*:\s*(.+)$',
            }
            for key, pattern in patterns.items():
                match = re.search(pattern, text)
                if match:
                    phrases[key] = match.group(1).strip()
            return phrases
        except Exception as e:
            logger.warning(f"Failed to extract key phrases: {e}")
            return {}

    def get_handler_status(self) -> Dict[str, Any]:
        """Get status of the analyzer handler."""
        return {
            "pipeline": bool(self.pipeline),
            "status": "ready"
        }