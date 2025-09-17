# ADR: Embedding Model Choice for CWE Mapping Chatbot (Updated: Incorporate Gemini Embedding)

## Summary

A new Google embedding model, **gemini-embedding-001**, is now generally available. It significantly alters the trade-space for choosing embeddings: it offers state-of-the-art performance, support for multiple output dimensions (768, 1536, 3072 via Matryoshka Representation Learning), and good (but higher) cost. After considering its capabilities versus existing options (OpenAI, OSS, and older Google models), we recommend **gemini-embedding-001** as the new default embedding model for the CWE Chatbot, with other models retained as fallbacks under specific constraints.

---

## New Information

From Google’s announcement and documentation:

* **Model performance**: gemini-embedding-001 has held a top spot on the MTEB Multilingual leaderboard since experimental launch. ([Google Developers Blog][1])
* **Languages & input size**: Supports 100+ languages; maximum input token length is **2048 tokens**. ([Google Developers Blog][1])
* **Output dimensions**: Supports downscaling output embeddings via Matryoshka Representation Learning (MRL). Default is 3072 dimensions; you can choose 1536 or 768. ([Google Developers Blog][1])
* **Pricing**: \$0.15 per 1 million input tokens. There is a free tier for experimentation. ([Google Developers Blog][1])
* **Deprecation of older models**: text-embedding-004 will be deprecated on Jan 14, 2026; some legacy embedding-experimental models are already being phased out. ([Google Developers Blog][1])

---

## Comparison: Gemini vs Existing Alternatives

Here’s how gemini-embedding-001 compares to the other embedding model options in practice, especially as relevant for CWE mapping.

| Model                                              | Retrieval / Semantic Performance                                                                                                                                       | Cost per Input Token                                                                                                                          | Output Embedding Dimension Options                                                                                            | Context / Input Length Limit                                                                                                                   | Integration / Operational Considerations                                                                                                                                                                          |
| -------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Gemini-embedding-001**                           | Very high (top MTEB multilingual), strong code/scientific/legal domain coverage. ([Google Developers Blog][1])                                                         | **\$0.15 / 1M input tokens**. Output tokens are not separately priced (embedding model only cares about input). ([Google Developers Blog][1]) | 3072 (default); can scale down to 1536 or 768 (via MRL) to balance storage/query costs. ([Google Developers Blog][1])         | 2048 input tokens; sufficient for many document chunking schemes. ([Google Developers Blog][1])                                                | Native in Google’s Gemini API and Vertex AI; free tier for experiments; some upcoming batch API options. Existing embedding pipeline likely to need adaptation (vector-size, cost estimation, possibly batching). |
| **OpenAI text-embedding-3-small**                  | Very good performance; perhaps slightly lower than gemini on tasks involving multilingual or code/science/legal, depending on benchmarks (assuming prior MTEB scores). | Lower cost (in your prior ADR you cited \$0.02 per million tokens). Usually cheaper in many use cases.                                        | Fixed dimension (presumably something like 1536 or whatever the model specifies); less flexibility than gemini’s MRL scaling. | Likely a larger or comparable input limit (you had 8192 tokens in your prior ADR for OpenAI model) which gives you more leeway on chunk sizes. | Strong existing integration; probably less vendor-lock-in concerns; possibly better availability globally; potential latency / throughput differences.                                                            |
| **BAAI / OSS large embedding models**              | Good performance; may lag gemini for some multilingual/scientific/code tasks, depending on which model; but might be competitive.                                      | Often very low cost if self-hosted; or modest via third-party APIs. But Ops cost non-negligible.                                              | Dimensions vary; some large models are high dimension; storage/query costs scale.                                             | Depends on hosting; sometimes smaller maximum input size.                                                                                      | Higher maintenance; latency, scaling, availability trade-offs; versioning concerns.                                                                                                                               |
| **Legacy Google models (text-embedding-004 etc.)** | Lower than gemini; being deprecated.                                                                                                                                   | Likely lower cost per token, but diminishing returns vs performance.                                                                          | Smaller dimension; fixed.                                                                                                     | Might have similar input limits.                                                                                                               | Risk of deprecation; future support diminishing.                                                                                                                                                                  |

---

## Decision

We adopt the following **updated embedding model hierarchy** for the CWE Chatbot, replacing the previous default with gemini-embedding-001, with fallback paths:

1. **Default / Primary**: **Google `gemini-embedding-001`**
   Use gemini-embedding-001 at **3072 dimensions** initially, unless cost/storage/latency concerns suggest using a reduced dimension (1536 or 768). This provides best accuracy for retrieval of CWE content (which involves technical language, multilingual case, hierarchical structure) and aligns with Google’s newer models.

2. **Secondary (Cost-Optimized/High-Throughput)**: **OpenAI `text-embedding-3-small`** (or similar)
   When many embeddings must be generated (bulk re-indexing, frequent updates) or cost sensitivity is paramount, use OpenAI’s model or an OSS alternative. Use dimension that gives the best trade-off given storage/query costs.

3. **Backup / Edge Cases**:

   * For privacy-sensitive deployments or where you want full control / self-hosting, use an OSS model.
   * Use legacy Google models only as fallback if gemini-embedding-001 cannot be used (e.g. region unavailability before deprecation date, or compatibility issues).

---

## Rationale

Key reasons for favouring gemini-embedding-001 as default:

* **Performance gains**: Top of benchmarks (MTEB Multilingual), better alignment for code/science/legal domains typical of CWE content.
* **Flexibility in dimensions**: MRL lets us choose lower dimensions when we want cost/latency/storage savings, without entirely changing embeddings model; helps smooth out trade-offs.
* **Future proofing**: Old models are being deprecated; relying on them long term carries risk. gemini is clearly what Google intends to push forward.

Trade-offs / Risks:

* **Higher cost**: \$0.15 / million input tokens is significantly more expensive than the \$0.02 per million (OpenAI) assumed in previous ADR. If usage is high (e.g. many millions of tokens for indexing or frequent queries) this can add up.
* **Smaller input token limit** (2048 vs maybe larger for OpenAI): potentially more chunking overhead; might need more splitting of documents to stay under input limit.
* **Storage & search cost**: Embedding dimension (esp. 3072) implies higher storage per vector, more compute in nearest-neighbour searches. If high query volume, latency or cost could increase.

---

## Implications / What Changes in the System

* Update the embedding abstraction layer to support gemini-embedding-001: ability to specify dimensions (3072/1536/768), measure/track performance (accuracy, latency) per dimension.
* Recompute cost projections: estimate number of input tokens per embedding run (for indexing + queries), factor \$0.15 rate, storage cost for vector DB of that size, query cost.
* Update integration pipelines: ensure compatibility with Gemini API / Vertex AI, including any region/access/permission changes. Possibly migrate embeddings of existing corpus to new model (for consistency).
* Monitor benchmarks (retrieval accuracy, latency) after switching to ensure expected performance is realized; if cost/performance ratio becomes unfavorable, possibly revert to cost-optimized model for parts of workload.

---

## Status

**Decided (2025-09).** Default embedding model for the CWE Chatbot will be **gemini-embedding-001**, using 3072 dimensions initially (with fallback to reduced dimensions if needed). OpenAI text-embedding-3-small will be retained as secondary for cost-sensitive or throughput-sensitive pipelines.

---

## Revised Embedding Model Hierarchy (Updated)

* **Default / Primary**: **Google `gemini-embedding-001`** (3072 dims)
* **Alternate dims**: 1536, 768 for cost/storage/latency optimisation
* **Secondary**: OpenAI `text-embedding-3-small`
* **Fallbacks**: OSS / on-premises embedding models; legacy Google embedding models only in restricted cases


## Cost Estimation


# What I assumed (adjust as needed)

* Pricing: **\$0.15 per 1M input tokens** for `gemini-embedding-001`. ([Google Developers Blog][1])
* One-time indexing cost = (total corpus tokens) × price.
* Monthly cost = (new/changed content tokens + query-embedding tokens) × price.
* Storage estimate assumes one vector per doc; if you chunk, multiply vectors accordingly.
* Float32 vectors ⇒ bytes/vector = `dimensions × 4`. I showed storage at **3072 / 1536 / 768** dims (supported via MRL). ([Google Developers Blog][1])

# Quick read on the default scenarios

* **Small (5k docs × 400 tokens)**
  
  * One-time indexing ≈ **\$0.30**
  * Monthly (2% refresh + 10k queries @ 12 tokens) ≈ **\$0.024**
  * Storage @3072 dims ≈ **0.061 GB** (≈61 MB)

* **Medium (20k × 600)**
  
  * One-time indexing ≈ **\$1.80**
  * Monthly (3% + 100k queries) ≈ **\$0.234**
  * Storage @3072 dims ≈ **0.245 GB**

* **Large (100k × 800)**
  
  * One-time indexing ≈ **\$12.00**
  * Monthly (5% + 1M queries) ≈ **\$2.40**
  * Storage @3072 dims ≈ **1.229 GB**

# Notes & knobs

* **Dimensions vs. cost**: API cost depends on **input tokens**, not on vector size. Dimensions impact **vector DB storage and ANN compute**. If storage/latency matters, consider **1536 or 768** dims; expect a (usually small) quality trade-off. ([Google Developers Blog][1])
* **Token counting**: I assumed no overlap during chunking. If you use overlapped chunks, indexing tokens (and cost) scale up accordingly.
* **Queries**: Query-embedding cost is usually minor, but I included it (avg query 12 tokens; adjust if you embed longer queries).


[1]: https://developers.googleblog.com/en/gemini-embedding-available-gemini-api/
