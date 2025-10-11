#!/usr/bin/env python3
"""
Processing Pipeline - Orchestrates post-retrieval CWE recommendation generation.

This module separates the business logic of turning raw chunks into recommendations
from the data retrieval logic, implementing proper separation of concerns.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, TypedDict

from src.processing.confidence_calculator import (
    ConfidenceCalculator,
    create_aggregated_cwe,
)
from src.processing.cwe_filter import create_default_filter
from src.processing.explanation_builder import ExplanationBuilder
from src.processing.query_processor import QueryProcessor
from src.processing.query_suggester import QuerySuggester
from src.security.secure_logging import get_secure_logger


class Recommendation(TypedDict):
    """Structured CWE recommendation with confidence and explanation."""

    cwe_id: str
    name: str
    confidence: float
    level: str  # "High", "Medium", "Low", "Very Low"
    explanation: Dict[str, Any]
    top_chunks: List[Dict[str, Any]]
    relationships: Optional[Any]  # For future expansion


class QueryResult(TypedDict):
    """Result of processing a query with recommendations."""

    recommendations: List[Recommendation]
    low_confidence: bool
    improvement_guidance: Optional[Dict[str, Any]]


@dataclass
class PipelineResult:
    """Standardized output from the processing pipeline."""

    final_response_text: str
    recommendations: List[Recommendation] = field(default_factory=list)
    retrieved_cwes: List[str] = field(default_factory=list)
    chunk_count: int = 0
    is_low_confidence: bool = False
    improvement_guidance: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


logger = get_secure_logger(__name__)


class ProcessingPipeline:
    """
    Orchestrates the transformation of raw retrieved chunks into CWE recommendations.

    This class handles the post-retrieval business logic:
    - Aggregating chunks by CWE ID
    - Calculating confidence scores
    - Building explanations
    - Filtering and ranking results
    - Generating improvement guidance

    It uses the individual processing components from src/processing/ to create
    a clean, testable pipeline that's separate from data retrieval concerns.
    """

    def __init__(self, query_handler: Any = None, response_generator: Any = None):
        """
        Initialize the pipeline with dependencies.

        Args:
            query_handler: CWEQueryHandler for data access (optional for backward compatibility)
            response_generator: ResponseGenerator for LLM interactions (optional for backward compatibility)
        """
        # Core processing components
        self.confidence_calculator = ConfidenceCalculator()
        self.cwe_filter = create_default_filter()
        self.explanation_builder = ExplanationBuilder()
        self.query_suggester = QuerySuggester()
        self.query_processor = QueryProcessor()

        # New dependencies for full end-to-end processing
        self.query_handler = query_handler
        self.response_generator = response_generator

        logger.info("ProcessingPipeline initialized with all components")

    def generate_recommendations(
        self, query: str, chunks: List[Dict], user_context: Dict[str, Any]
    ) -> QueryResult:
        """
        Transform raw retrieved chunks into structured CWE recommendations.

        Args:
            query: Original user query
            chunks: Raw chunks from CWEQueryHandler.process_query()
            user_context: User persona and context information

        Returns:
            QueryResult with recommendations, confidence assessment, and guidance
        """
        try:
            logger.info(
                f"Processing {len(chunks)} chunks into recommendations for query: '{query[:50]}...'"
            )

            if not chunks:
                return self._handle_empty_results(query, user_context)

            # Step 1: Aggregate chunks by CWE ID
            cwe_chunks = self._aggregate_chunks_by_cwe(chunks)
            logger.debug(f"Aggregated into {len(cwe_chunks)} unique CWEs")

            # Step 2: Calculate confidence scores for each CWE
            scored_cwes = self._calculate_confidence_scores(query, cwe_chunks)

            # Step 3: Sort by confidence score
            scored_cwes.sort(key=lambda x: x["confidence"], reverse=True)

            # Step 4: Filter and cap recommendations
            filter_result = self.cwe_filter.filter(scored_cwes)
            filtered_recommendations = filter_result["recommendations"]

            logger.info(
                f"Filtered recommendations: {filter_result['original_count']} → {filter_result['final_count']}"
            )

            # Step 5: Convert to Recommendation TypedDict format
            recommendations = self._format_recommendations(filtered_recommendations)

            # Step 6: Assess confidence and generate guidance if needed
            improvement_guidance = self._generate_improvement_guidance(
                query, recommendations, user_context
            )

            # Step 7: Determine overall confidence assessment
            avg_confidence = (
                sum(r["confidence"] for r in recommendations) / len(recommendations)
                if recommendations
                else 0.0
            )
            is_low_confidence = avg_confidence < 0.6 or len(recommendations) < 2

            return QueryResult(
                recommendations=recommendations,
                low_confidence=is_low_confidence,
                improvement_guidance=improvement_guidance,
            )

        except Exception as e:
            logger.log_exception("Pipeline processing failed", e)
            # Return empty result with guidance on error
            return self._handle_empty_results(query, user_context)

    async def process_user_request(
        self, query: str, user_context: Any
    ) -> PipelineResult:
        """
        Complete end-to-end processing from query to validated response.

        This method orchestrates the full workflow:
        1. Retrieve raw chunks
        2. Apply business logic (force-injection, boosting)
        3. Generate recommendations
        4. Fetch canonical metadata
        5. Build LLM prompt
        6. Generate LLM response
        7. Post-process and validate response

        Args:
            query: User query string
            user_context: UserContext object with persona and preferences

        Returns:
            PipelineResult with final response and metadata
        """
        if not self.query_handler or not self.response_generator:
            raise ValueError(
                "ProcessingPipeline requires query_handler and response_generator for end-to-end processing"
            )

        try:
            logger.info(f"Processing end-to-end request for query: '{query[:50]}...'")

            # Step 1: Retrieve raw chunks using the simplified QueryHandler
            user_prefs = user_context.get_persona_preferences()
            raw_chunks = await self.query_handler.process_query(query, user_prefs)

            # Debug: Log what raw retrieval returned
            raw_cwes = [c.get("metadata", {}).get("cwe_id", "UNKNOWN") for c in raw_chunks]
            logger.info(f"[DEBUG_PIPELINE] Raw retrieval returned {len(raw_chunks)} chunks with CWEs: {raw_cwes}")

            # Step 2: Apply business logic (MOVED FROM QueryHandler)
            processed_chunks = self._apply_retrieval_business_logic(query, raw_chunks)

            # Debug: Log after business logic processing
            processed_cwes = [c.get("metadata", {}).get("cwe_id", "UNKNOWN") for c in processed_chunks]
            logger.info(f"[DEBUG_PIPELINE] After business logic: {len(processed_chunks)} chunks with CWEs: {processed_cwes}")

            # Step 3: Generate recommendations (existing logic)
            query_result = self.generate_recommendations(
                query, processed_chunks, user_prefs
            )
            recommendations = query_result["recommendations"]

            # Step 4: Fetch canonical metadata (MOVED FROM ConversationManager)
            rec_ids = [r["cwe_id"] for r in recommendations]
            canonical_metadata = {}
            policy_labels = {}

            if rec_ids and hasattr(self.query_handler, "get_canonical_cwe_metadata"):
                canonical_metadata = self.query_handler.get_canonical_cwe_metadata(
                    rec_ids
                )
                policy_labels = self.query_handler.get_cwe_policy_labels(rec_ids)

            # Step 5: Build enhanced prompt with metadata
            llm_prompt = self._build_llm_prompt(
                query, processed_chunks, user_context, canonical_metadata, policy_labels
            )

            # Step 6: Generate LLM response
            # Debug: Log what chunks are being passed to response generator
            chunks_to_llm_cwes = [
                c.get("metadata", {}).get("cwe_id", "UNKNOWN") for c in processed_chunks
            ]
            logger.info(
                f"[DEBUG_PIPELINE] Passing {len(processed_chunks)} chunks to LLM with CWEs: {chunks_to_llm_cwes}"
            )

            raw_response = await self.response_generator.generate_response_full_once(
                llm_prompt,
                processed_chunks,
                user_context.persona,
                user_evidence=getattr(user_context, "file_evidence", None),
            )

            # Step 7: Post-process and validate response (MOVED FROM ConversationManager)
            final_response = self._harmonize_and_validate_response(raw_response)

            return PipelineResult(
                final_response_text=final_response,
                recommendations=recommendations,
                retrieved_cwes=rec_ids,
                chunk_count=len(processed_chunks),
                is_low_confidence=query_result["low_confidence"],
                improvement_guidance=query_result["improvement_guidance"],
            )

        except Exception as e:
            logger.log_exception("End-to-end pipeline processing failed", e)
            # Return fallback result
            return PipelineResult(
                final_response_text="I apologize, but I'm experiencing technical difficulties processing your request. Please try again.",
                is_low_confidence=True,
            )

    def _handle_empty_results(
        self, query: str, user_context: Dict[str, Any]
    ) -> QueryResult:
        """Handle case when no chunks are retrieved."""
        persona = user_context.get("persona", "Developer")
        improvement_guidance = self.query_suggester.generate_improvement_banner(
            query, persona, 0.0
        )
        return QueryResult(
            recommendations=[],
            low_confidence=True,
            improvement_guidance=improvement_guidance
            if improvement_guidance["show_banner"]
            else None,
        )

    def _aggregate_chunks_by_cwe(self, chunks: List[Dict]) -> Dict[str, Dict]:
        """
        Group chunks by CWE ID and extract metadata.

        Returns:
            Dict mapping CWE ID to {name, chunks, exact_match} data
        """
        cwe_groups = {}

        for chunk in chunks:
            metadata = chunk.get("metadata", {})
            cwe_id = metadata.get("cwe_id")

            if not cwe_id:
                continue

            cwe_id = str(cwe_id).upper()

            if cwe_id not in cwe_groups:
                cwe_groups[cwe_id] = {
                    "name": metadata.get("name", "Unknown"),
                    "chunks": [],
                    "exact_match": False,  # This would be set by caller based on query analysis
                }

            cwe_groups[cwe_id]["chunks"].append(chunk)

        return cwe_groups

    def _calculate_confidence_scores(
        self, query: str, cwe_chunks: Dict[str, Dict]
    ) -> List[Dict]:
        """Calculate confidence scores and build explanations for each CWE."""
        scored_cwes = []

        for cwe_id, cwe_data in cwe_chunks.items():
            try:
                # Determine exact alias/name match to boost confidence
                ql = (query or "").lower()
                name_lower = (cwe_data["name"] or "").lower()
                exact_match = False
                if name_lower and name_lower in ql:
                    exact_match = True
                else:
                    # Look for Aliases chunk and check for phrase matches
                    for ch in cwe_data["chunks"]:
                        section = (ch.get("metadata") or {}).get("section", "")
                        if section == "Aliases":
                            alias_text = (ch.get("document") or "").lower()
                            # Aliases are joined with ';' per entry_to_sections
                            for alias in [
                                a.strip() for a in alias_text.split(";") if a.strip()
                            ]:
                                if alias and alias in ql:
                                    exact_match = True
                                    break
                        if exact_match:
                            break

                # Create AggregatedCWE for confidence calculation
                aggregated = create_aggregated_cwe(
                    cwe_id=cwe_id,
                    name=cwe_data["name"],
                    chunks=cwe_data["chunks"],
                    exact_match=exact_match,
                )

                # Calculate confidence
                confidence, level = self.confidence_calculator.score_and_level(
                    aggregated
                )

                # Build explanation
                explanation = self.explanation_builder.build(
                    query, cwe_id, cwe_data["chunks"]
                )

                scored_cwes.append(
                    {
                        "cwe_id": cwe_id,
                        "name": cwe_data["name"],
                        "confidence": confidence,
                        "level": level,
                        "explanation": explanation,
                        "top_chunks": cwe_data["chunks"][:5],  # Limit for performance
                        "relationships": None,  # TODO: Implement in future task
                    }
                )

            except Exception as e:
                logger.warning(f"Failed to process CWE {cwe_id}: {e}")
                continue

        return scored_cwes

    def _format_recommendations(
        self, filtered_recommendations: List[Dict]
    ) -> List[Recommendation]:
        """Convert internal format to Recommendation TypedDict format."""
        recommendations = []

        for rec in filtered_recommendations:
            try:
                recommendations.append(
                    Recommendation(
                        cwe_id=rec["cwe_id"],
                        name=rec["name"],
                        confidence=rec["confidence"],
                        level=rec["level"],
                        explanation=rec["explanation"],
                        top_chunks=rec["top_chunks"],
                        relationships=rec["relationships"],
                    )
                )
            except Exception as e:
                logger.warning(
                    f"Failed to format recommendation for {rec.get('cwe_id', 'unknown')}: {e}"
                )
                continue

        return recommendations

    def _generate_improvement_guidance(
        self,
        query: str,
        recommendations: List[Recommendation],
        user_context: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """Generate improvement guidance if confidence is low."""
        if not recommendations:
            avg_confidence = 0.0
        else:
            avg_confidence = sum(r["confidence"] for r in recommendations) / len(
                recommendations
            )

        is_low_confidence = avg_confidence < 0.6 or len(recommendations) < 2

        if is_low_confidence:
            persona = user_context.get("persona", "Developer")
            guidance = self.query_suggester.generate_improvement_banner(
                query, persona, avg_confidence
            )
            if guidance["show_banner"]:
                return dict(guidance)

        return None

    def _apply_retrieval_business_logic(
        self, query: str, raw_chunks: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Apply business logic that was moved from CWEQueryHandler.

        This includes force-injection and boosting logic for mentioned CWE IDs.
        """
        # Extract CWE IDs from query using QueryProcessor
        query_analysis = self.query_processor.preprocess_query(query)
        extracted_cwe_ids = query_analysis.get("cwe_ids", set())

        # Debug: Log extracted CWE IDs
        logger.info(f"[DEBUG_PIPELINE] Extracted CWE IDs from query '{query[:50]}': {extracted_cwe_ids}")

        processed_chunks = list(raw_chunks)  # Start with raw results

        # Force-inject canonical sections if mentioned CWE IDs not in results
        if extracted_cwe_ids and self.query_handler:
            # Check which extracted CWE IDs are missing from results
            retrieved_cwe_ids = set()
            for chunk in processed_chunks:
                metadata = chunk.get("metadata", {})
                if metadata.get("cwe_id"):
                    retrieved_cwe_ids.add(metadata.get("cwe_id").upper())

            missing_cwe_ids = [cid for cid in extracted_cwe_ids if cid.upper() not in retrieved_cwe_ids]

            if missing_cwe_ids:
                logger.info(
                    f"[DEBUG_PIPELINE] Force-injecting missing CWE IDs: {missing_cwe_ids} (retrieved: {retrieved_cwe_ids})"
                )
                forced_sections = self.query_handler.fetch_canonical_sections_for_cwes(
                    missing_cwe_ids
                )
                for chunk in forced_sections:
                    scores = chunk.get("scores", {})
                    scores["hybrid"] = scores.get("hybrid", 0.0) + 3.0  # Strong boost
                    chunk["scores"] = scores
                processed_chunks.extend(forced_sections)
                logger.info(
                    f"Force-injected {len(forced_sections)} sections for mentioned CWE IDs: {missing_cwe_ids}"
                )

        # Boost mentioned CWE IDs in existing results
        if extracted_cwe_ids and processed_chunks:
            for cwe_id in extracted_cwe_ids:
                for chunk in processed_chunks:
                    metadata = chunk.get("metadata", {})
                    if str(metadata.get("cwe_id", "")).upper() == cwe_id.upper():
                        scores = chunk.get("scores", {})
                        scores["hybrid"] = scores.get("hybrid", 0.0) + 2.0
                        chunk["scores"] = scores

            # Re-sort after boosting
            processed_chunks.sort(
                key=lambda x: x.get("scores", {}).get("hybrid", 0.0), reverse=True
            )

        return processed_chunks

    def _build_llm_prompt(
        self,
        query: str,
        chunks: List[Dict[str, Any]],
        user_context: Any,
        canonical_metadata: Dict[str, Any],
        policy_labels: Dict[str, Any],
    ) -> str:
        """
        Build enhanced LLM prompt with canonical metadata.

        This logic was moved from ConversationManager.
        """
        enhanced_prompt = query

        # Add canonical metadata block if available
        if canonical_metadata or policy_labels:
            lines = []
            rec_ids = set()

            # Collect CWE IDs from recommendations
            for chunk in chunks:
                metadata = chunk.get("metadata", {})
                if metadata.get("cwe_id"):
                    rec_ids.add(metadata.get("cwe_id"))

            for cwe_id in rec_ids:
                key = str(cwe_id).upper()
                meta = canonical_metadata.get(key, {})
                pol = policy_labels.get(key, {})

                name = meta.get("name", "")
                abstraction = meta.get("abstraction", "")
                status = meta.get("status", "")
                mapping_label = pol.get("mapping_label", "")

                parts = [f"- {cwe_id}"]
                if name:
                    parts.append(f": {name}")
                if abstraction:
                    parts.append(f" | Abstraction: {abstraction}")
                if status:
                    parts.append(f" | Status: {status}")
                if mapping_label:
                    parts.append(f" | Mapping Policy: {mapping_label}")
                lines.append("".join(parts))

            if lines:
                canonical_block = (
                    "\n\n[Canonical CWE Metadata]\n" + "\n".join(lines) + "\n"
                )
                enhanced_prompt += canonical_block
                enhanced_prompt += (
                    "\n[Policy Rules]\n"
                    "Use 'Name' and 'Mapping Policy' exactly as provided in Canonical CWE Metadata (authoritative DB values).\n"
                    "- Prohibited: Not a fit for mapping.\n"
                    "- Discouraged: Generally not a fit; only Secondary if clearly justified.\n"
                    "- Allowed-with-Review: Allowed but call out review rationale.\n"
                    "- Allowed: Use without contradicting the policy.\n"
                    "Do NOT contradict the Mapping Policy or the canonical CWE Name in your output.\n"
                )

        return enhanced_prompt

    def _harmonize_and_validate_response(self, llm_response: str) -> str:
        """
        Post-process LLM response to fix CWE names and policies.

        This logic was moved from ConversationManager.
        """
        if not self.query_handler:
            return llm_response

        # Extract all CWE IDs from the response
        all_cwe_ids = re.findall(r"CWE[-_\s]?(\d{1,5})", llm_response, re.IGNORECASE)
        all_cwe_ids = [f"CWE-{c}" for c in all_cwe_ids]

        if not all_cwe_ids:
            return llm_response

        try:
            # Import harmonization function
            from src.utils.text_post import harmonize_cwe_names_in_table

            # Fetch canonical data for ALL CWE IDs mentioned in response
            canon = self.query_handler.get_canonical_cwe_metadata(all_cwe_ids)
            policies = self.query_handler.get_cwe_policy_labels(all_cwe_ids)

            # Build mapping dictionaries
            id_to_name = {
                k.upper(): v["name"] for k, v in canon.items() if v.get("name")
            }
            id_to_policy = {
                k.upper(): v["mapping_label"]
                for k, v in policies.items()
                if v.get("mapping_label")
            }

            # Apply harmonization
            return str(
                harmonize_cwe_names_in_table(llm_response, id_to_name, id_to_policy)
            )

        except Exception as e:
            logger.warning(f"Failed to harmonize CWE names in response: {e}")
            return llm_response

    def get_pipeline_health(self) -> Dict[str, Any]:
        """Get health status of pipeline components."""
        return {
            "confidence_calculator": bool(self.confidence_calculator),
            "cwe_filter": bool(self.cwe_filter),
            "explanation_builder": bool(self.explanation_builder),
            "query_suggester": bool(self.query_suggester),
            "query_handler": bool(self.query_handler),
            "response_generator": bool(self.response_generator),
            "status": "healthy",
        }
