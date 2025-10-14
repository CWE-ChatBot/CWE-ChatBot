#!/usr/bin/env python3
"""
CWE Analyzer Handler - Manages stateful analyzer persona workflows.

This module extracts complex CWE Analyzer logic from ConversationManager,
implementing the state machine for /ask, /compare, and /exit modes.
"""

import re
from typing import Any, Dict

from src.processing.pipeline import PipelineResult, ProcessingPipeline
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

    async def process(self, query: str, context: Any) -> PipelineResult:
        """
        Handle all CWE Analyzer workflows - commands, modes, and analysis.

        Args:
            query: User query string
            context: UserContext object with analyzer state

        Returns:
            PipelineResult with response and metadata
        """
        try:
            current_mode = getattr(context, "analyzer_mode", None)
            logger.info(
                f"Processing analyzer request: '{query[:50]}...' in mode: {current_mode}"
            )
            logger.info(
                f"Context has last_chunks: {len(getattr(context, 'last_chunks', []))}, last_recommendations: {len(getattr(context, 'last_recommendations', []))}"
            )

            # Handle exit commands
            if current_mode == "question" and (
                re.match(r"^\s*0\b", query)
                or re.match(r"^\s*/exit\b", query, flags=re.IGNORECASE)
            ):
                context.analyzer_mode = None
                return PipelineResult(
                    final_response_text="Exited question mode. You can now start a new analysis or click the ❓ button after an analysis.",
                    metadata={"mode_switch": True, "mode": None},
                )

            # Handle analysis based on current mode
            if current_mode == "question":
                logger.info("Routing to _handle_question_mode")
                return await self._handle_question_mode(query, context)
            else:
                logger.info("Routing to _handle_initial_analysis")
                return await self._handle_initial_analysis(query, context)

        except Exception as e:
            logger.log_exception("Analyzer mode processing failed", e)
            return PipelineResult(
                final_response_text="I encountered an error processing your analysis request. Please try again.",
                is_low_confidence=True,
            )

    async def _handle_question_mode(self, query: str, context: Any) -> PipelineResult:
        """Handle follow-up questions about previous analysis."""
        # Reuse previous chunks and build follow-up context
        prev_chunks = getattr(context, "last_chunks", []) or []
        if not prev_chunks:
            return PipelineResult(
                final_response_text="No previous analysis available. Type /exit to return to analysis mode.",
                metadata={"mode": "question", "error": "no_previous_analysis"},
            )

        # Determine if we need new retrieval based on question content
        prev_recs = getattr(context, "last_recommendations", []) or []
        prev_ids = [r.get("cwe_id") for r in prev_recs if r.get("cwe_id")]

        # Always perform semantic retrieval for follow-up questions to get relevant context
        logger.info("Performing semantic retrieval for follow-up question")

        # Use the original question for semantic retrieval to get most relevant content
        user_prefs = context.get_persona_preferences()
        new_chunks = await self.pipeline.query_handler.process_query(query, user_prefs)

        # Combine chunks with configurable upper limit to prevent memory exhaustion
        from src.app_config import config

        max_total_chunks = config.max_context_chunks
        chunks_to_use = new_chunks + prev_chunks

        # If we exceed the limit, use circular buffer approach (keep most recent)
        if len(chunks_to_use) > max_total_chunks:
            # Keep all new chunks + most recent previous chunks
            recent_prev_count = max_total_chunks - len(new_chunks)
            if recent_prev_count > 0:
                chunks_to_use = new_chunks + prev_chunks[-recent_prev_count:]
            else:
                # If new chunks alone exceed limit, just take the most recent new chunks
                chunks_to_use = new_chunks[-max_total_chunks:]

            logger.info(
                f"Applied circular buffer (limit={max_total_chunks}): reduced from {len(new_chunks) + len(prev_chunks)} to {len(chunks_to_use)} chunks"
            )

        logger.info(
            f"Combined {len(new_chunks)} new chunks with {len(prev_chunks)} previous chunks (total: {len(chunks_to_use)})"
        )

        # Extract any mentioned CWE IDs for tracking
        from src.processing.query_processor import QueryProcessor

        processor = QueryProcessor()
        processed = processor.preprocess_query(query)
        mentioned_cwe_ids = list(processed.get("cwe_ids", set()) or [])

        # Build specialized query with follow-up context
        followup_query = query
        if prev_ids:
            followup_query += f"\n\n[Follow-up Instruction]\nPrior recommendations: {', '.join(prev_ids)}\nTask: Address the user's follow-up question by referencing and building upon the prior analysis. Focus on the specific question asked."

        # Add context about additional retrieval
        if mentioned_cwe_ids:
            followup_query += f"\n\nNote: Additional CWE information retrieved for: {', '.join(mentioned_cwe_ids)}"
        else:
            followup_query += "\n\nNote: Additional security information retrieved based on question content."

        logger.info(
            f"Using {len(chunks_to_use)} chunks (semantic retrieval + stored context) for follow-up question"
        )

        # Generate response using appropriate context
        try:
            # Use special CWE Analyzer Question persona for follow-up questions to avoid full analysis workflow
            response_text = await self.pipeline.response_generator.generate_response(
                followup_query,
                chunks_to_use,
                "CWE Analyzer Question",  # Special persona for answering questions without full analysis
                user_evidence=getattr(context, "file_evidence", None),
            )

            # Combine CWE IDs - mentioned_cwe_ids is always defined, new_cwe_ids only exists if new retrieval happened
            all_retrieved_cwes = (
                prev_ids + mentioned_cwe_ids if mentioned_cwe_ids else prev_ids
            )

            result = PipelineResult(
                final_response_text=response_text,
                recommendations=prev_recs,
                retrieved_cwes=all_retrieved_cwes,
                chunk_count=len(chunks_to_use),
            )

        except Exception as e:
            logger.log_exception("Failed to generate follow-up response", e)
            result = PipelineResult(
                final_response_text="I encountered an error generating the follow-up response. Please try rephrasing your question or type /exit to leave question mode.",
                is_low_confidence=True,
            )

        # Always update stored context since we always perform retrieval for future questions
        context.last_chunks = (
            chunks_to_use  # Store the combined chunks for next question
        )
        logger.info(
            f"Updated stored context with {len(chunks_to_use)} chunks for future questions"
        )

        # Also update retrieved CWEs if any were mentioned
        if mentioned_cwe_ids:
            # Merge new CWE IDs with existing ones (avoid duplicates)
            all_retrieved_cwes = list(set(prev_ids + mentioned_cwe_ids))
            result.retrieved_cwes = all_retrieved_cwes
            logger.info(f"Updated retrieved CWEs to include: {mentioned_cwe_ids}")

        # Add mode metadata (UI will show exit button)
        result.metadata["mode"] = "question"

        return result

    async def _handle_compare_mode(self, query: str, context: Any) -> PipelineResult:
        """Handle CWE comparison analysis."""
        # Extract candidate CWE IDs from user input
        from src.processing.query_processor import QueryProcessor

        processor = QueryProcessor()
        processed = processor.preprocess_query(query)
        candidates = list(processed.get("cwe_ids", set()) or [])

        if not candidates:
            return PipelineResult(
                final_response_text="Provide candidate CWE ID(s) to compare. You can type /exit to leave compare mode.",
                metadata={"mode": "compare", "error": "no_candidates"},
            )

        # Build comparison query with prior context
        prev_recs = getattr(context, "last_recommendations", []) or []
        prev_ids = [r.get("cwe_id") for r in prev_recs if r.get("cwe_id")]

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

    async def _handle_initial_analysis(
        self, query: str, context: Any
    ) -> PipelineResult:
        """Handle initial CWE analysis with enhanced retrieval."""
        # Set evidence and enhance query for analysis
        context.set_evidence(query)

        # Extract key phrases and boost query (moved from ConversationManager)
        key_phrases = self._extract_key_phrases(query)
        enhanced_query = query

        boost_terms = []
        if key_phrases.get("rootcause"):
            boost_terms.append(key_phrases["rootcause"])
        if key_phrases.get("weakness"):
            boost_terms.append(key_phrases["weakness"])

        if boost_terms:
            enhanced_query = f"{query} " + " ".join(boost_terms)

        # Add stable hints to emphasize classification
        enhanced_query += (
            " root cause underlying weakness pattern classification mapping"
        )

        # First, get the raw chunks for follow-up context
        user_prefs = context.get_persona_preferences()
        raw_chunks = await self.pipeline.query_handler.process_query(
            enhanced_query, user_prefs
        )

        # Execute pipeline with enhanced query
        result = await self.pipeline.process_user_request(enhanced_query, context)

        # Store results for follow-up modes
        context.last_recommendations = (
            result.recommendations if hasattr(result, "recommendations") else []
        )
        context.last_chunks = raw_chunks  # Store the actual chunks for follow-up

        logger.info(
            f"Stored analysis results for follow-up: {len(context.last_recommendations)} recommendations, {len(context.last_chunks)} chunks"
        )

        # Action buttons will be shown by main.py, no need for text hints
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
                "rootcause": r"(?im)^(?:root\s*cause|rootcause)\s*:\s*(.+)$",
                "weakness": r"(?im)^weakness\s*:\s*(.+)$",
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
        return {"pipeline": bool(self.pipeline), "status": "ready"}
