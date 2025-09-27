#!/usr/bin/env python3
"""
Processing Pipeline - Orchestrates post-retrieval CWE recommendation generation.

This module separates the business logic of turning raw chunks into recommendations
from the data retrieval logic, implementing proper separation of concerns.
"""

import logging
from typing import Dict, List, Any, TypedDict, Optional

from src.processing.confidence_calculator import ConfidenceCalculator, create_aggregated_cwe
from src.processing.cwe_filter import CWEFilter, create_default_filter
from src.processing.explanation_builder import ExplanationBuilder
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

    def __init__(self):
        """Initialize the processing pipeline with all required components."""
        self.confidence_calculator = ConfidenceCalculator()
        self.cwe_filter = create_default_filter()
        self.explanation_builder = ExplanationBuilder()
        self.query_suggester = QuerySuggester()

        logger.info("ProcessingPipeline initialized with all components")

    def generate_recommendations(self, query: str, chunks: List[Dict], user_context: Dict[str, Any]) -> QueryResult:
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
            logger.info(f"Processing {len(chunks)} chunks into recommendations for query: '{query[:50]}...'")

            if not chunks:
                return self._handle_empty_results(query, user_context)

            # Step 1: Aggregate chunks by CWE ID
            cwe_chunks = self._aggregate_chunks_by_cwe(chunks)
            logger.debug(f"Aggregated into {len(cwe_chunks)} unique CWEs")

            # Step 2: Calculate confidence scores for each CWE
            scored_cwes = self._calculate_confidence_scores(query, cwe_chunks)

            # Step 3: Sort by confidence score
            scored_cwes.sort(key=lambda x: x['confidence'], reverse=True)

            # Step 4: Filter and cap recommendations
            filter_result = self.cwe_filter.filter(scored_cwes)
            filtered_recommendations = filter_result['recommendations']

            logger.info(f"Filtered recommendations: {filter_result['original_count']} → {filter_result['final_count']}")

            # Step 5: Convert to Recommendation TypedDict format
            recommendations = self._format_recommendations(filtered_recommendations)

            # Step 6: Assess confidence and generate guidance if needed
            improvement_guidance = self._generate_improvement_guidance(
                query, recommendations, user_context
            )

            # Step 7: Determine overall confidence assessment
            avg_confidence = sum(r['confidence'] for r in recommendations) / len(recommendations) if recommendations else 0.0
            is_low_confidence = avg_confidence < 0.6 or len(recommendations) < 2

            return QueryResult(
                recommendations=recommendations,
                low_confidence=is_low_confidence,
                improvement_guidance=improvement_guidance
            )

        except Exception as e:
            logger.log_exception("Pipeline processing failed", e)
            # Return empty result with guidance on error
            return self._handle_empty_results(query, user_context)

    def _handle_empty_results(self, query: str, user_context: Dict[str, Any]) -> QueryResult:
        """Handle case when no chunks are retrieved."""
        persona = user_context.get('persona', 'Developer')
        improvement_guidance = self.query_suggester.generate_improvement_banner(
            query, persona, 0.0
        )
        return QueryResult(
            recommendations=[],
            low_confidence=True,
            improvement_guidance=improvement_guidance if improvement_guidance["show_banner"] else None
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
                    'name': metadata.get("name", "Unknown"),
                    'chunks': [],
                    'exact_match': False  # This would be set by caller based on query analysis
                }

            cwe_groups[cwe_id]['chunks'].append(chunk)

        return cwe_groups

    def _calculate_confidence_scores(self, query: str, cwe_chunks: Dict[str, Dict]) -> List[Dict]:
        """Calculate confidence scores and build explanations for each CWE."""
        scored_cwes = []

        for cwe_id, cwe_data in cwe_chunks.items():
            try:
                # Determine exact alias/name match to boost confidence
                ql = (query or "").lower()
                name_lower = (cwe_data['name'] or "").lower()
                exact_match = False
                if name_lower and name_lower in ql:
                    exact_match = True
                else:
                    # Look for Aliases chunk and check for phrase matches
                    for ch in cwe_data['chunks']:
                        section = (ch.get('metadata') or {}).get('section', '')
                        if section == 'Aliases':
                            alias_text = (ch.get('document') or '').lower()
                            # Aliases are joined with ';' per entry_to_sections
                            for alias in [a.strip() for a in alias_text.split(';') if a.strip()]:
                                if alias and alias in ql:
                                    exact_match = True
                                    break
                        if exact_match:
                            break

                # Create AggregatedCWE for confidence calculation
                aggregated = create_aggregated_cwe(
                    cwe_id=cwe_id,
                    name=cwe_data['name'],
                    chunks=cwe_data['chunks'],
                    exact_match=exact_match
                )

                # Calculate confidence
                confidence, level = self.confidence_calculator.score_and_level(aggregated)

                # Build explanation
                explanation = self.explanation_builder.build(query, cwe_id, cwe_data['chunks'])

                scored_cwes.append({
                    'cwe_id': cwe_id,
                    'name': cwe_data['name'],
                    'confidence': confidence,
                    'level': level,
                    'explanation': explanation,
                    'top_chunks': cwe_data['chunks'][:5],  # Limit for performance
                    'relationships': None  # TODO: Implement in future task
                })

            except Exception as e:
                logger.warning(f"Failed to process CWE {cwe_id}: {e}")
                continue

        return scored_cwes

    def _format_recommendations(self, filtered_recommendations: List[Dict]) -> List[Recommendation]:
        """Convert internal format to Recommendation TypedDict format."""
        recommendations = []

        for rec in filtered_recommendations:
            try:
                recommendations.append(Recommendation(
                    cwe_id=rec['cwe_id'],
                    name=rec['name'],
                    confidence=rec['confidence'],
                    level=rec['level'],
                    explanation=rec['explanation'],
                    top_chunks=rec['top_chunks'],
                    relationships=rec['relationships']
                ))
            except Exception as e:
                logger.warning(f"Failed to format recommendation for {rec.get('cwe_id', 'unknown')}: {e}")
                continue

        return recommendations

    def _generate_improvement_guidance(self, query: str, recommendations: List[Recommendation], user_context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate improvement guidance if confidence is low."""
        if not recommendations:
            avg_confidence = 0.0
        else:
            avg_confidence = sum(r['confidence'] for r in recommendations) / len(recommendations)

        is_low_confidence = avg_confidence < 0.6 or len(recommendations) < 2

        if is_low_confidence:
            persona = user_context.get('persona', 'Developer')
            guidance = self.query_suggester.generate_improvement_banner(
                query, persona, avg_confidence
            )
            if guidance["show_banner"]:
                return guidance

        return None

    def get_pipeline_health(self) -> Dict[str, Any]:
        """Get health status of pipeline components."""
        return {
            "confidence_calculator": bool(self.confidence_calculator),
            "cwe_filter": bool(self.cwe_filter),
            "explanation_builder": bool(self.explanation_builder),
            "query_suggester": bool(self.query_suggester),
            "status": "healthy"
        }
