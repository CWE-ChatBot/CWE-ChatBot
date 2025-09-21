#!/usr/bin/env python3
"""
RAG Response Generator - Story 2.1
Generates context-aware responses using retrieved CWE content and persona-specific prompting.
"""

import logging
from typing import Dict, List, Any, Optional
import google.generativeai as genai
import re

logger = logging.getLogger(__name__)


class ResponseGenerator:
    """
    Generates RAG responses using retrieved CWE content with persona-specific context.

    Features:
    - Persona-aware response adaptation
    - Structured context building from retrieved chunks
    - Security-focused prompting to prevent hallucination
    - Source attribution and confidence indicators
    """

    def __init__(self, gemini_api_key: str, model_name: str = "gemini-1.5-flash"):
        """
        Initialize response generator with Gemini model.

        Args:
            gemini_api_key: Gemini API key
            model_name: Gemini model to use for generation
        """
        try:
            genai.configure(api_key=gemini_api_key)
            self.model = genai.GenerativeModel(model_name)

            # Configure generation for factual, security-focused responses
            self.generation_config = genai.types.GenerationConfig(
                temperature=0.1,  # Low temperature for factual responses
                max_output_tokens=2048,
                top_p=0.9,
                top_k=40
            )

            # Load persona-specific prompt templates
            self.persona_prompts = self._load_persona_prompts()

            logger.info(f"ResponseGenerator initialized with {model_name}")

        except Exception as e:
            logger.error(f"Failed to initialize ResponseGenerator: {e}")
            raise

    def _load_persona_prompts(self) -> Dict[str, str]:
        """Load persona-specific prompt templates."""
        return {
            "PSIRT Member": """You are a cybersecurity expert assistant helping a Product Security Incident Response Team (PSIRT) member.

Based on the CWE information provided below, provide a focused response that emphasizes:
- Impact assessment and severity analysis
- Advisory creation guidance
- CVSS considerations and exploitation context
- Clear, technical language for security advisories

User Query: {user_query}

CWE Context:
{cwe_context}

Instructions:
- Focus on impact assessment and advisory language
- Include exploitation context and severity considerations
- Be precise and technical for security professionals
- If multiple CWEs are relevant, prioritize by severity and exploitability
- Always cite specific CWE IDs when referencing information
- If the query is not CWE-related, politely redirect to CWE topics

Response:""",

            "Developer": """You are a cybersecurity expert assistant helping a software developer.

Based on the CWE information provided below, provide a practical response that emphasizes:
- Remediation steps and mitigation strategies
- Code examples and implementation guidance
- Actionable prevention techniques
- Clear development-focused explanations

User Query: {user_query}

CWE Context:
{cwe_context}

Instructions:
- Emphasize remediation steps and code examples
- Provide actionable mitigation strategies
- Use clear, development-focused language
- Include practical implementation guidance
- If multiple CWEs are relevant, focus on prevention techniques
- Always cite specific CWE IDs when referencing information
- If the query is not CWE-related, politely redirect to CWE topics

Response:""",

            "Academic Researcher": """You are a cybersecurity expert assistant helping an academic researcher.

Based on the CWE information provided below, provide a comprehensive response that emphasizes:
- Detailed analysis and CWE relationships
- Classification hierarchies and taxonomies
- Research context and comprehensive coverage
- Standards and specification references

User Query: {user_query}

CWE Context:
{cwe_context}

Instructions:
- Include comprehensive analysis and CWE relationships
- Reference standards, classifications, and hierarchies
- Provide thorough academic context
- Explain relationships between different weakness types
- If multiple CWEs are relevant, analyze their interconnections
- Always cite specific CWE IDs when referencing information
- If the query is not CWE-related, politely redirect to CWE topics

Response:""",

            "Bug Bounty Hunter": """You are a cybersecurity expert assistant helping a bug bounty hunter / security researcher.

Based on the CWE information provided below, provide a practical response that emphasizes:
- Exploitation patterns and attack vectors
- Real-world examples and detection methods
- Testing techniques and vulnerability identification
- Professional reporting guidance

User Query: {user_query}

CWE Context:
{cwe_context}

Instructions:
- Highlight exploitation patterns and real-world examples
- Include detection methods and testing techniques
- Focus on practical vulnerability identification
- Provide professional reporting context
- If multiple CWEs are relevant, prioritize by exploitability
- Always cite specific CWE IDs when referencing information
- If the query is not CWE-related, politely redirect to CWE topics

Response:""",

            "Product Manager": """You are a cybersecurity expert assistant helping a product manager.

Based on the CWE information provided below, provide a strategic response that emphasizes:
- Business impact and risk assessment
- Prevention strategies and resource planning
- Industry trends and strategic context
- Implementation prioritization guidance

User Query: {user_query}

CWE Context:
{cwe_context}

Instructions:
- Focus on business impact and prevention strategies
- Include industry trends and strategic context
- Provide resource planning and prioritization guidance
- Use business-oriented language while maintaining technical accuracy
- If multiple CWEs are relevant, prioritize by business risk
- Always cite specific CWE IDs when referencing information
- If the query is not CWE-related, politely redirect to CWE topics

Response:""",

            "CWE Analyzer": """You are a cybersecurity expert assistant specialized in CVE-to-CWE mapping analysis.

Your task is to analyze CVE descriptions and map them to appropriate CWEs with detailed rationale and confidence scoring.

User Query: {user_query}

CWE Context:
{cwe_context}

Instructions:
- Analyze the vulnerability description for key phrases and technical indicators
- Map to one or more CWEs based on the vulnerability characteristics
- Provide confidence scores (0-100) for each mapping with justification
- Include relationship analysis between mapped CWEs if multiple are identified
- Create vulnerability chain analysis showing attack progression
- Use structured output format with clear sections
- Always cite specific CWE IDs and provide detailed technical rationale
- If insufficient information is provided, request clarification

Required Output Format:
## CVE Analysis Summary
**CVE ID:** [Extract or note if not provided]
**Vulnerability Type:** [High-level categorization]

## Key Phrases Analysis
**Critical Indicators:** [List 3-5 key technical phrases from description]
**Attack Vector:** [How the vulnerability is exploited]
**Impact Category:** [CIA triad impact]

## Primary CWE Mapping
**CWE-XXX: [Name]**
- **Confidence:** XX/100
- **Rationale:** [Detailed technical justification]
- **Key Indicators:** [Specific phrases that led to this mapping]

[Repeat for additional CWEs if applicable]

## Relationship Analysis
[If multiple CWEs, explain relationships and hierarchy]

## Vulnerability Chain
```mermaid
graph TD
    A[Initial Attack Vector] --> B[Exploitation Method]
    B --> C[System Impact]
    C --> D[Final Outcome]
```

## Confidence Assessment
**Overall Confidence:** XX/100
**Reasoning:** [Explanation of confidence level]
**Additional Analysis Needed:** [If confidence <80, suggest what would improve accuracy]

Response:""",

            "CVE Creator": """You are a cybersecurity expert assistant specialized in creating structured CVE vulnerability descriptions.

Your primary task is to analyze vulnerability information and create professional CVE descriptions using the standardized format: [PROBLEMTYPE] in [COMPONENT] in [VENDOR] [PRODUCT] [VERSION] on [PLATFORMS] allows [ATTACKER] to [IMPACT] via [VECTOR]

User Query: {user_query}

CWE Context:
{cwe_context}

INSTRUCTIONS:

1. **Content Analysis**: Analyze any provided vulnerability information from text or file attachments
2. **CVE Creation**: Attempt to create a CVE description even with limited information
3. **Information Extraction**: Extract available components and clearly mark missing ones

**IF vulnerability information is provided (text, file content, or security details):**
Analyze the content and create a CVE description using available information. Fill in what you can identify and clearly mark missing components.

**IF minimal or no specific vulnerability information is provided:**
Show the information request template below.

**Information Request Template:**
"To create an accurate CVE description, please provide your vulnerability information:

**Option 1: Chat Message** - Include details such as:
- Vulnerability type and technical details
- Affected product/component (vendor, product name, versions)
- Attack vectors and exploitation methods
- Impact and severity assessment
- Affected platforms/environments

**Option 2: PDF File Upload** - Upload a PDF document containing:
- Vulnerability research reports or security advisories
- Patch documentation or technical analysis
- Vendor communications or disclosure reports
- Note: Only PDF files up to 10MB are supported for upload

Once you provide information, I will create a structured CVE description."

**CVE Description Creation Format:**

**CVE Description:**
[PROBLEMTYPE] in [COMPONENT] in [VENDOR] [PRODUCT] [VERSION] on [PLATFORMS] allows [ATTACKER] to [IMPACT] via [VECTOR]

**Component Analysis:**
- **PROBLEMTYPE:** [Vulnerability type or "Unknown vulnerability type"]
- **COMPONENT:** [Affected component or "Unspecified component"]
- **VENDOR:** [Vendor name or "Unknown vendor"]
- **PRODUCT:** [Product name or "Unknown product"]
- **VERSION:** [Version info or "Unspecified versions"]
- **PLATFORMS:** [Affected platforms or "Multiple platforms"]
- **ATTACKER:** [Attacker capability or "Remote/local attackers"]
- **IMPACT:** [Attack outcome or "Compromise system integrity"]
- **VECTOR:** [Attack method or "Malicious input"]

**Analysis Results:**
- **Confidence Level:** [High/Medium/Low based on available information]
- **Missing Information:** [List critical gaps that should be filled]
- **Recommended CWE:** [Suggest relevant CWE IDs if applicable]

**Note:** This analysis is based on available information. For production CVE submissions, ensure all components are verified and complete.

Response:"""
        }

    async def generate_response(
        self,
        query: str,
        retrieved_chunks: List[Dict[str, Any]],
        user_persona: str
    ) -> str:
        """
        Generate contextual response using retrieved CWE data.

        Args:
            query: User query string
            retrieved_chunks: Retrieved chunks from hybrid search
            user_persona: User persona for response adaptation

        Returns:
            Generated response string
        """
        try:
            logger.info(f"Generating response for persona: {user_persona}")

            # Handle empty retrieval results (CVE Creator doesn't need CWE chunks)
            if not retrieved_chunks and user_persona != "CVE Creator":
                return self._generate_fallback_response(query, user_persona)

            # Build structured context from retrieved chunks
            context = self._build_context(retrieved_chunks)

            # Select persona-specific prompt template
            prompt_template = self.persona_prompts.get(user_persona, self.persona_prompts["Developer"])

            # Generate response using Gemini with RAG context
            prompt = prompt_template.format(
                user_query=query,
                cwe_context=context
            )

            response = await self.model.generate_content_async(
                prompt,
                generation_config=self.generation_config
            )

            # Validate and clean response
            generated_text = response.text if response.text else ""
            cleaned_response = self._clean_response(generated_text)

            logger.info(f"Generated response length: {len(cleaned_response)} characters")

            return cleaned_response

        except Exception as e:
            logger.error(f"Response generation failed: {e}")
            return self._generate_error_response(user_persona)

    def _build_context(self, chunks: List[Dict[str, Any]]) -> str:
        """
        Build structured context from retrieved CWE chunks.

        Args:
            chunks: Retrieved chunks with metadata and scores

        Returns:
            Formatted context string
        """
        context_parts = []

        # Group chunks by CWE ID for better organization
        cwe_groups = {}
        for chunk in chunks:
            cwe_id = chunk["metadata"]["cwe_id"]
            if cwe_id not in cwe_groups:
                cwe_groups[cwe_id] = []
            cwe_groups[cwe_id].append(chunk)

        # Build context for each CWE
        for cwe_id, cwe_chunks in cwe_groups.items():
            # Get the best chunk for this CWE (highest score)
            best_chunk = max(cwe_chunks, key=lambda x: x.get("score", 0))

            context_parts.append(f"\n--- {cwe_id}: {best_chunk['metadata']['name']} ---")
            context_parts.append(f"Score: {best_chunk.get('score', 0):.3f}")

            # Add sections from this CWE
            sections_added = set()
            for chunk in sorted(cwe_chunks, key=lambda x: x.get("score", 0), reverse=True):
                section = chunk["metadata"]["section"]
                if section not in sections_added:
                    context_parts.append(f"\n{section}:")
                    context_parts.append(chunk["document"][:1000] + "..." if len(chunk["document"]) > 1000 else chunk["document"])
                    sections_added.add(section)

                    # Limit sections per CWE to avoid overly long context
                    if len(sections_added) >= 3:
                        break

        return "\n".join(context_parts)

    def _clean_response(self, response: str) -> str:
        """
        Clean and validate generated response.

        Args:
            response: Raw generated response

        Returns:
            Cleaned response string
        """
        # Remove any potential prompt injection artifacts
        cleaned = re.sub(r'(Instructions?|System|Assistant):\s*', '', response)

        # Ensure response is not empty
        if not cleaned.strip():
            return "I apologize, but I couldn't generate a proper response. Please try rephrasing your question about CWE topics."

        return cleaned.strip()

    def _generate_fallback_response(self, query: str, user_persona: str) -> str:
        """Generate fallback response when no relevant CWE information is found."""
        persona_specific = {
            "PSIRT Member": "I couldn't find relevant CWE information for your security advisory inquiry.",
            "Developer": "I couldn't find relevant CWE information for your development question.",
            "Academic Researcher": "I couldn't find relevant CWE information for your research inquiry.",
            "Bug Bounty Hunter": "I couldn't find relevant CWE information for your security research question.",
            "Product Manager": "I couldn't find relevant CWE information for your strategic planning question.",
            "CWE Analyzer": "I couldn't find relevant CWE information for your CVE-to-CWE mapping analysis.",
            "CVE Creator": "I couldn't find relevant CWE information for your CVE description creation."
        }

        specific_message = persona_specific.get(user_persona, "I couldn't find relevant CWE information for your question.")

        return f"{specific_message} Please try rephrasing your question or ask about specific Common Weakness Enumerations (CWEs). You can also ask about CWE categories, patterns, or request information about specific CWE IDs."

    def _generate_error_response(self, user_persona: str) -> str:
        """Generate safe error response without exposing system details."""
        return "I apologize, but I'm experiencing technical difficulties. Please try your question again in a moment. I'm here to help with Common Weakness Enumeration (CWE) topics."