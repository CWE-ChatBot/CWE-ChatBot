# ADR: Embedding Model Choice for CWE Mapping Chatbot

## Summary

We must select an embedding model to support the CWE Chatbot’s Retrieval-Augmented Generation (RAG) pipeline. The choice impacts retrieval accuracy, cost efficiency, and integration with our GCP-centric architecture. Based on updated comparative research, we recommend **OpenAI’s text-embedding-3-small** as the default embedding model, with clear alternatives for performance, control, and GCP-native integration.
- This is the model used previously for the bulk CWE-assignment.
  

## Issue

The CWE corpus requires embeddings that capture both technical semantics (security weaknesses, code-related terms) and hierarchical structure (categories, variants). The embedding model must support high retrieval quality, be cost-effective at scale, and integrate smoothly with our cloud-native design.

## Decision

We will adopt a **tiered recommendation** for embedding models:

* **Default / Primary:** **OpenAI `text-embedding-3-small`**

  * Competitive retrieval performance (MTEB 62.3).
  * Extremely cost-efficient (\$0.02 per million tokens).
  * Large context window (8192 tokens).
  * Flexible vector size via `dimensions` parameter for future tuning.

* **Secondary (Performance-Focused):** **Google `gemini-embedding-001`**

  * Highest benchmarked performance (MTEB 68.3 multilingual).
  * Task-aware embeddings (`task_type` parameter for query vs. document).
  * Strong code/text handling.
  * More expensive (\$0.15 per million tokens) and smaller context window (2048 tokens).

* **Secondary (Control-Focused):** **BAAI `bge-large-en-v1.5`**

  * Open-source, strong retrieval performance (MTEB 64.2).
  * Available via self-hosting (high ops burden) or cheap third-party APIs (as low as \$0.01 per million tokens).
  * Good fit for privacy-sensitive or extreme-scale deployments.

* **Legacy Fallback:** **Google `text-embedding-004`**

  * Low-cost, GCP-native integration.
  * 768-d vectors reduce storage/query costs.
  * Superseded by Gemini, but still viable if minimizing integration complexity is paramount.

## Status

**Decided (2025-08).** Default implementation will use **OpenAI text-embedding-3-small**, with architecture designed to support seamless substitution (BYO model).

## Details

### Assumptions

* Retrieval accuracy is the primary success metric (NFR6: Hallucination Mitigation).
* Integration simplicity matters, but flexibility and cost/performance balance are more critical for default choice.
* Some deployments may require alternatives (e.g., self-hosted for privacy, GCP-only for enterprise).

### Constraints

* Embedding service must be callable from Python SDKs/APIs.
* Vector DB must support chosen dimensionality (768–3072).
* Costs must align with serverless, consumption-based pricing.
* Must remain production-ready with stable APIs.

### Positions

* **Google models**: Strong integration, high performance, but higher cost.
* **OpenAI models**: Balanced performance, flexible dimensions, industry benchmark.
* **Open-source models**: Maximum control/cost efficiency, but high ops burden.

### Argument

* **OpenAI `3-small`** strikes the best balance: strong retrieval, lowest cost, and unmatched flexibility (adjustable dimensions).
* **Gemini-001** is top-tier but premium.
* **BGE v1.5** is disruptive on cost, but only viable where ops burden or API providers are acceptable.
* **Google 004** is cost-effective but outdated relative to newer entrants.

### Implications

* **Abstraction Layer**: We will implement an `EmbeddingModelInterface` with factory pattern to support pluggable providers.
* **Indexing**: Vector DB (e.g., Pinecone/Weaviate) configured per default dimension (1536 for OpenAI 3-small).
* **Monitoring**: Establish periodic benchmarking of CWE queries to validate retrieval accuracy.
* **Future-Proofing**: Architecture allows swap-in of future models (e.g., Gemini successor, OpenAI 4th-gen, or newer OSS).

### Related

* **Requirements:** FR28, FR29 (BYO model/key), NFR6 (hallucination mitigation), NFR1/2 (performance/scalability).
* **Principles:** Serverless First, Cost-Efficiency, Separation of Concerns.
