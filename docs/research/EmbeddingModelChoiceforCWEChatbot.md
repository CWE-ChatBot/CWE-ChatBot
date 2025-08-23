

# **Selecting the Optimal Embedding Model for a Common Weakness Enumeration (CWE) Retrieval System: A Comparative Technical Analysis**

## **Section 1: The Semantic Challenge of Mapping Common Weakness Enumerations**

The development of an intelligent chatbot capable of accurately mapping user queries to the Common Weakness Enumeration (CWE) database presents a formidable challenge in semantic understanding. This endeavor requires more than simple keyword matching; it necessitates a deep comprehension of the intricate structure, specialized terminology, and hierarchical nature of the CWE corpus. The success of such a system hinges on its ability to bridge the significant semantic gap between informal, natural language questions posed by developers and the formal, highly technical specifications that define software and hardware vulnerabilities. At the core of this solution lies the embedding model, a component whose effectiveness will dictate the system's overall accuracy and utility.

### **1.1 Analysis of the CWE Corpus: Structure, Terminology, and Hierarchy**

The Common Weakness Enumeration is not merely a list but a formal, community-sustained category system for software and hardware weaknesses.1 Maintained by the MITRE Corporation, its purpose is to provide a standardized language and structure for identifying, discussing, and preventing common errors throughout the development lifecycle.2 The corpus is extensive, containing over 900 distinct weakness definitions, each meticulously detailed.4

Each CWE entry is a structured data object with multiple fields, including a unique identifier (e.g., CWE-79), a descriptive name ("Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"), a detailed description of the weakness, common modes of introduction, potential consequences, exploitation paths, detection methods, and remediation guidance.2 This rich, multi-faceted information must be converted into a coherent vector representation that captures the essence of the weakness.

The most significant challenge posed by the corpus is its explicit hierarchical structure. The CWE system is organized into four primary structural classifications: Views, Categories, Weaknesses, and Compound Elements.6 This hierarchy creates relationships where weakness types at higher levels represent abstract concepts, while those at deeper levels are more concrete. For instance, a

Weakness entry is further classified by three attributes:

* **Class**: The most abstract type of weakness (e.g., CWE-362: Race Condition).  
* **Base**: A more specific weakness, generally independent of technology (e.g., CWE-567: Unsynchronized Access To Shared Data).  
* **Variant**: A highly specific weakness tied to a particular resource, technology, or context (e.g., CWE-488: Data Leak Between Sessions).6

This structure implies that an effective embedding model must not only differentiate between CWE-89 (SQL Injection) and CWE-79 (Cross-Site Scripting) but also understand their shared parentage within broader categories like "Implementation Weaknesses" or "Improper Input Validation".2 The model's vector space must implicitly represent these relationships, positioning child CWEs in proximity to their parents and related weaknesses within clusters. This requirement suggests that a model's performance should not be judged solely on its retrieval capabilities. The Massive Text Embedding Benchmark (MTEB) evaluates models across a spectrum of tasks, including Retrieval, Clustering, and Classification.8 While Retrieval is the primary concern for this project, strong performance in Clustering (the ability to group similar items) and Classification (the ability to assign items to predefined categories) serves as a powerful secondary indicator. A model that excels in these areas is more likely to have learned the inherent categorical and hierarchical structure of a complex, domain-specific corpus like CWE, leading to more robust and contextually aware retrieval.

### **1.2 Defining the Retrieval Problem: Bridging the Gap Between User Intent and Technical Specification**

The core function of the proposed chatbot is to act as an intelligent intermediary, translating a developer's practical, often informally phrased, problem into a precise mapping within the CWE framework. For example, a user query like, "How can I stop hackers from running their own database commands through my web form?" must be accurately mapped to its corresponding technical classification, CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection').2

This task requires an embedding model that excels at capturing semantic intent, moving far beyond lexical overlap. The model must recognize that "running their own database commands" is semantically equivalent to the formal CWE description of "SQL Injection," even though the phrases share few common words. This is central to the distinction between CWE and the Common Vulnerabilities and Exposures (CVE) system. A CVE answers the question, "What specific issue exists in this software right now?", whereas a CWE answers, "What type of mistake led to that issue, and how can we avoid it?".2 Consequently, the chatbot is not an incident response tool but an educational and preventative one, designed to integrate into the Software Development Lifecycle (SDLC) and promote secure coding practices.2

### **1.3 The Critical Role of Semantic Similarity in CWE Mapping**

The technological foundation for solving this retrieval problem is the concept of vector embeddings. An embedding is a high-dimensional vector of floating-point numbers that serves as a numerical representation of text.11 Advanced embedding models are trained to generate these vectors in such a way that the geometric distance between them in the vector space corresponds to the semantic similarity of the original text.12 Texts with similar meanings will have vectors that are close together, while dissimilar texts will have vectors that are far apart.

For the CWE mapping chatbot, the embedding model must perform two critical transformations. First, it must process each structured CWE entry and generate a document vector that encapsulates its technical meaning. Second, at query time, it must take the user's natural language question and generate a query vector. The retrieval system then identifies the CWE document vectors that are closest to the query vector, using a distance metric like cosine similarity.15 The quality of this mapping is entirely dependent on the embedding model's ability to create a shared semantic space where a developer's informal question and MITRE's formal definition can be accurately and reliably correlated.

## **Section 2: Architectural Blueprint: Retrieval-Augmented Generation for CWE Guidance**

To effectively address the semantic mapping challenge, a Retrieval-Augmented Generation (RAG) architecture is the most suitable design pattern. RAG combines the strengths of information retrieval with the generative power of Large Language Models (LLMs), creating a system that can provide accurate, context-aware, and authoritative answers grounded in a specific knowledge base—in this case, the CWE database.13 This architecture ensures that the chatbot's responses are not hallucinatory but are directly derived from the trusted CWE source material.

### **2.1 The RAG Workflow for a Specialized Chatbot**

The RAG process for the CWE chatbot can be deconstructed into a clear, sequential workflow that operates in two distinct phases: an offline indexing phase and an online retrieval-and-generation phase.11

1. **Data Preparation and Indexing (Offline):** This is the foundational step where the external knowledge base is prepared for retrieval. The entire CWE corpus, consisting of over 900 detailed entries, is systematically processed. Each entry, or a logically segmented "chunk" thereof, is fed into the chosen embedding model. The model converts the text into a high-dimensional numerical vector. These vectors, along with their corresponding text and metadata, are then loaded into a specialized vector database. This process creates a searchable, semantic index of the entire CWE knowledge base.11  
2. **Retrieval (Online):** When a user submits a query to the chatbot (e.g., "What's the best way to handle file uploads securely?"), the online phase begins. The user's query is first passed through the *exact same* embedding model used for indexing. This converts the query into a vector that exists within the same semantic space as the document vectors. This query vector is then used to search the vector database, which employs efficient algorithms (such as Approximate Nearest Neighbor, or ANN) to find the document vectors that are most similar (i.e., closest in the vector space) to the query vector.13  
3. **Augmentation and Generation (Online):** The top-ranked CWE entries retrieved from the vector database are then used to "augment" a prompt for an LLM. Using prompt engineering techniques, the system constructs a new prompt that includes the original user query along with the full text of the retrieved CWE documents as context.16 This augmented prompt effectively instructs the LLM: "Based on the following authoritative CWE information, answer the user's question." The LLM then synthesizes this information to generate a coherent, informative, and factually grounded response that directly addresses the user's query while citing the relevant CWE identifiers.13

### **2.2 The Embedding Model as the Linchpin of the Retrieval Process**

Within the RAG architecture, the embedding model is the single most critical component. It functions as the linchpin of the entire system; its performance directly determines the quality and relevance of the information retrieved. If the embedding model fails to accurately capture the semantic intent of the user's query or the technical nuance of the CWE entries, the retrieval step will return irrelevant documents. This failure at the retrieval stage is catastrophic for the system. An LLM, no matter how powerful, cannot generate a correct answer from incorrect or irrelevant context.13 Therefore, the selection of a high-performing embedding model is not merely an optimization but a fundamental prerequisite for the success of the CWE mapping chatbot.

### **2.3 Key Considerations: Chunking Strategy, Vector Database Interaction, and Prompt Augmentation**

While the embedding model is central, its effectiveness is influenced by several key architectural decisions.

* **Chunking Strategy:** The process of dividing the source documents into smaller pieces for embedding is known as chunking.11 For the CWE corpus, the most logical approach is to treat each individual CWE entry as a single semantic unit or "chunk." Each entry, with its ID, name, description, consequences, and mitigations, forms a self-contained concept.2 This strategy preserves the conceptual integrity of each weakness and is well-suited to the context window limitations of modern embedding models.  
* **Vector Database:** The choice of a vector database is crucial for enabling efficient, low-latency similarity searches at scale.13 The database must be capable of storing and indexing millions of high-dimensional vectors and performing rapid ANN searches. The dimensionality of the vectors produced by the chosen embedding model will be a key factor in selecting a compatible and cost-effective vector database solution.  
* **Prompt Augmentation:** The final step of presenting the retrieved information to the LLM requires careful prompt engineering.16 The prompt must clearly delineate the user's question from the provided context and instruct the model on how to use the context to formulate its answer.

A deeper analysis of the available models reveals a layer of optimization that goes beyond simply selecting the model with the highest benchmark score. The APIs for several leading models expose parameters that allow for task-specific tuning, a feature that can significantly enhance retrieval performance. For example, Google's Vertex AI embedding API includes a task\_type parameter. When indexing the CWE corpus, one should specify task\_type='RETRIEVAL\_DOCUMENT', and when embedding a user's query, one should use task\_type='RETRIEVAL\_QUERY'.19 This distinction is critical because it allows the model to generate different, specialized vector representations for documents (which are typically longer, descriptive, and declarative) versus queries (which are typically shorter, interrogative, and focused). Similarly, the documentation for the BAAI BGE models recommends prepending a specific instruction to queries—"Represent this sentence for searching relevant passages:"—to optimize them for retrieval tasks, an instruction that is not added to the documents being indexed.21 This asymmetry acknowledges that the ideal vector for a piece of knowledge is different from the ideal vector for a question about that knowledge. Models that provide mechanisms to account for this difference are inherently more sophisticated and are likely to yield superior retrieval accuracy compared to models that treat all text inputs identically. This capability becomes a crucial point of differentiation in the model selection process.

## **Section 3: Contender Analysis: A Multi-faceted Model Comparison**

The selection of an embedding model requires a comparative analysis of the leading candidates, weighing their technical specifications, unique features, performance benchmarks, and deployment models. The current market offers a choice between powerful, managed API-based models from providers like Google and OpenAI, and high-performing open-source models, most notably from the Beijing Academy of Artificial Intelligence (BAAI), which offer greater flexibility.

The following table provides a high-level summary of the key contenders analyzed in this report.

| Model Name | Provider/Origin | Type | Max Input Tokens | Native Output Dimensions | Variable Dimensions? | Key Feature |
| :---- | :---- | :---- | :---- | :---- | :---- | :---- |
| gemini-embedding-001 | Google | Managed API | 2048 | 3072 | Yes | State-of-the-art performance; task\_type parameter for optimization.15 |
| text-embedding-004 | Google | Managed API | 2048 | 768 | Yes | Cost-effective predecessor to Gemini, still supported for RAG.15 |
| text-embedding-3-large | OpenAI | Managed API | 8192 | 3072 | Yes | Top-tier performance; dimensions parameter for flexible cost/performance trade-offs.12 |
| text-embedding-3-small | OpenAI | Managed API | 8192 | 1536 | Yes | High performance-to-cost ratio; dimensions parameter for flexibility.12 |
| bge-large-en-v1.5 | BAAI | Open-Source | 512 | 1024 | No | Top-tier open-source performance; flexible deployment (self-hosted or 3rd party API).21 |

### **3.1 Managed API Models: Google and OpenAI**

Managed API models offer a compelling proposition: state-of-the-art performance with minimal operational overhead. Developers can access these models through a simple API call, abstracting away the complexities of infrastructure management, scaling, and maintenance.

#### **3.1.1 Google Vertex AI Models (text-embedding-004, gemini-embedding-001)**

Google has a history of strong offerings in the text embedding space, evolving from earlier models like textembedding-gecko to its current portfolio.25

* **Description and Features:** The current flagship model is gemini-embedding-001. According to its technical report, this model is initialized from the powerful Gemini LLM and is trained on a comprehensive suite of embedding tasks, unifying the capabilities of previous specialized models for English, multilingual, and code tasks.15 It produces a high-dimensional vector of up to 3072, a significant increase from the 768 dimensions of its predecessor,  
  text-embedding-004.15 The most significant feature of Google's embedding APIs is the  
  task\_type parameter. This allows developers to explicitly signal the intended downstream application (e.g., RETRIEVAL\_DOCUMENT, RETRIEVAL\_QUERY, CLASSIFICATION), enabling the model to produce optimized embeddings for that specific task.19 This level of explicit, task-aware optimization is a key differentiator. The older  
  text-embedding-004 model remains a supported and viable option, particularly for applications where the higher dimensionality and cost of the Gemini model are not required.22  
* **Performance:** The gemini-embedding-001 model is positioned as a state-of-the-art performer. It has achieved the top rank on the Massive Text Embedding Benchmark (MTEB) Multilingual leaderboard, substantially outperforming prior models.29 This strong multilingual performance, combined with its explicit training on code, suggests it is exceptionally well-suited for the technical and structured nature of the CWE corpus.

#### **3.1.2 OpenAI Models (text-embedding-3-small, text-embedding-3-large)**

OpenAI's third-generation embedding models represent a significant leap forward in both performance and flexibility compared to the widely adopted text-embedding-ada-002.12

* **Description and Features:** The portfolio consists of two models: text-embedding-3-small and text-embedding-3-large. The large model is designed for maximum accuracy, producing a native 3072-dimension vector, while the small model offers a highly efficient balance of cost and performance with a native 1536-dimension vector.12 Both models feature a generous 8192-token input window, which is beneficial for embedding longer documents without aggressive chunking.12 The standout innovation is the  
  dimensions API parameter. This feature allows developers to request a shorter embedding vector (e.g., 256, 512, 1024\) directly from the API endpoint without switching models.12 This decoupling of model choice from output dimensionality is a strategic advantage. It allows for direct management of the trade-off between embedding quality, storage costs, and computational latency in the vector database. For instance, a project can begin with a lower dimension to minimize costs and later scale up to a higher dimension for improved accuracy by changing a single parameter, without any other code modifications. This flexibility de-risks the initial model selection and provides a clear, low-friction path for future performance tuning, a significant advantage over models with fixed output dimensions.  
* **Performance:** text-embedding-3-large is OpenAI's top-performing model, demonstrating strong results on both multilingual (MIRACL) and English (MTEB) benchmarks.23 The  
  text-embedding-3-small model, while less powerful than large, still significantly outperforms the older ada-002 model at a fraction of the cost, making it a highly disruptive and compelling option for many applications.23

### **3.2 Open-Source Powerhouse: BAAI's bge-large-en-v1.5**

For projects requiring maximum control, customization, or data privacy, open-source models present a powerful alternative. Among these, bge-large-en-v1.5 from the Beijing Academy of Artificial Intelligence (BAAI) has established itself as a leading contender.21

* **Description and Features:** bge-large-en-v1.5 is a 335M parameter model specifically optimized for dense retrieval tasks.24 It has a maximum sequence length of 512 tokens and outputs a 1024-dimension vector.24 The  
  v1.5 update specifically addressed an issue with similarity distribution and improved its retrieval performance, making it highly effective even when no special instruction is prepended to the query.21  
* **Performance:** Upon its release, bge-large-en-v1.5 achieved the top rank on the MTEB leaderboard, demonstrating performance on par with or exceeding many proprietary models of its time.21 Its strong benchmark scores make it a credible alternative to the offerings from Google and OpenAI.  
* **Deployment Options:** The primary advantage of bge-large-en-v1.5 is its deployment flexibility. It can be self-hosted on private infrastructure or a public cloud like Google Cloud Platform (GCP), giving an organization full control over the model, data, and security.39 This approach eliminates reliance on third-party APIs and can be more cost-effective at very high scale, though it carries a significant operational burden. Alternatively, for those seeking the performance of an open-source model without the complexity of self-hosting, numerous third-party providers (e.g., DeepInfra, Together AI, Cloudflare) offer  
  bge-large-en-v1.5 via a managed API, often at highly competitive prices.40 Furthermore, the availability of quantized versions (e.g., GGUF, ONNX) allows for more efficient inference on less powerful hardware, including CPUs.43

## **Section 4: Performance Deep Dive: A Critical Interpretation of MTEB Benchmarks**

While technical specifications and features provide a foundational comparison, a model's empirical performance on standardized benchmarks is a critical factor in the selection process. The Massive Text Embedding Benchmark (MTEB) has become the de facto industry standard for this purpose, offering a holistic evaluation across a wide array of natural language processing tasks.46 However, interpreting these benchmarks requires nuance, particularly for a specialized application like CWE mapping.

### **4.1 Deconstructing the MTEB Score: Focus on the "Retrieval" Task Group**

MTEB evaluates models on eight distinct task categories: Classification, Clustering, Pair Classification, Reranking, Retrieval, Semantic Textual Similarity (STS), Bitext Mining, and Summarization.8 For the CWE chatbot, which relies on a RAG architecture, the

**Retrieval** task group is the most direct and important measure of a model's suitability. This task assesses a model's ability to find relevant documents from a large corpus given a query.9 The primary metric used for this task is Normalized Discounted Cumulative Gain at k (nDCG@k), which measures not only if relevant documents are found but also rewards models for ranking the most relevant documents higher in the results list.9

A compilation of the average MTEB scores for the candidate models reveals a highly competitive landscape:

* **Google gemini-embedding-001**: Achieves a score of **68.32** on the *MTEB Multilingual* benchmark.29 While a direct English-only benchmark score is not provided in the available materials, this top-tier multilingual performance strongly suggests it would be a leading contender on the English benchmark as well.  
* **OpenAI text-embedding-3-large**: Achieves an average MTEB score of **64.6%**.12  
* **BAAI bge-large-en-v1.5**: Achieves an average MTEB score of **64.23%**.24  
* **OpenAI text-embedding-3-small**: Achieves an average MTEB score of **62.3%**.12  
* **Google text-embedding-004**: A specific MTEB score is not available. The documentation consistently states that it is surpassed by gemini-embedding-001, indicating it would score lower than 68.32.29

These scores show that the top-performing models are clustered closely together. The performance gap between bge-large-en-v1.5 (64.23%) and text-embedding-3-large (64.6%) is less than half a percentage point. This marginal difference underscores a critical point: the MTEB leaderboard is a valuable guide, but it should not be treated as an absolute guarantee of performance on a specific, out-of-domain dataset. The available research cautions that small score differences between top models may not be statistically significant.50 The final choice should not be made on the basis of these minor variations alone. Instead, these benchmarks should be used to shortlist a set of high-performing candidates, whose true suitability must then be considered in the context of other factors like cost, features, and domain relevance.

### **4.2 Beyond the Average: Assessing Model Strengths for Domain-Specific Technical Text**

An average MTEB score is computed across numerous general-purpose datasets (e.g., news articles, reviews, web pages).8 The CWE corpus, however, is a highly specialized, technical domain with structured language akin to legal or scientific text. A model's performance on general web text may not perfectly predict its performance on this specific corpus.

Therefore, it is essential to consider any evidence of a model's training or optimization for technical or code-related domains. Google's models present a strong case in this regard. The Vertex AI API explicitly includes a CODE\_RETRIEVAL\_QUERY task type, indicating that the models have been specifically trained to handle queries related to source code.19 The technical report for

gemini-embedding-001 further emphasizes its strong capabilities on code benchmarks, a direct result of being initialized from the powerful, multi-modal Gemini LLM.27 This specialized training could provide a significant advantage when embedding CWE entries, which often contain code snippets, pseudo-code, and descriptions of low-level software and hardware behaviors. This domain-specific aptitude is a qualitative factor that may be more important than a small difference in the general MTEB average score.

### **4.3 Qualitative Considerations: Context Window and Vector Dimensionality**

Two final performance-related characteristics warrant consideration: the maximum input context window and the output vector dimensionality.

* **Context Window:** The context window defines the maximum number of tokens a model can process in a single input. OpenAI's models offer a substantial 8192-token window, compared to Google's 2048-token window and BGE's 512-token window.12 While individual CWE entries are unlikely to exceed 512 tokens, a larger context window provides greater flexibility for the chunking strategy. For example, it could allow for the embedding of a parent CWE along with all of its direct children in a single vector, potentially capturing hierarchical relationships more effectively.  
* **Vector Dimensionality:** Higher-dimensional vectors, such as the 3072 dimensions produced by gemini-embedding-001 and text-embedding-3-large, have the capacity to encode more nuanced semantic information than lower-dimensional vectors like the 1024 from BGE or the 768 from text-embedding-004.15 However, this comes with a direct trade-off in terms of increased storage costs and higher computational requirements for similarity search in the vector database. Here, OpenAI's ability to natively support shortened embeddings via the  
  dimensions parameter is a distinct advantage. Analysis shows that text-embedding-3-large shortened to 256 dimensions still outperforms the full 1536-dimension text-embedding-ada-002 model.23 This feature provides an unparalleled ability to balance performance against operational costs.

## **Section 5: Economic and Operational Calculus: Total Cost of Ownership Analysis**

A comprehensive model selection process must extend beyond performance metrics to include a rigorous analysis of the total cost of ownership (TCO). This involves modeling the costs of using managed APIs, estimating the operational and infrastructure expenses of self-hosting, and considering the economic implications of different deployment strategies. The analysis reveals distinct price-performance tiers among the candidate models, transforming the selection into a strategic business decision.

### **5.1 Modeling API Costs: A Scenario-Based Projection**

For managed API models, pricing is typically based on the number of tokens processed. The cost structure is transparent and predictable, allowing for straightforward financial modeling. The current pricing for the leading contenders is as follows:

* **Google gemini-embedding-001**: $0.15 per 1 million input tokens.51  
* **OpenAI text-embedding-3-large**: $0.13 per 1 million input tokens ($0.00013 per 1,000 tokens).23  
* **Google text-embedding-004**: $0.02 per 1 million input tokens.54  
* **OpenAI text-embedding-3-small**: $0.02 per 1 million input tokens ($0.00002 per 1,000 tokens).23

These prices can be used to project costs for two key activities: the initial, one-time indexing of the CWE corpus and the ongoing, recurring cost of processing user queries. This analysis highlights a clear tiering: a premium performance tier (gemini-embedding-001, text-embedding-3-large) with costs around $0.13-$0.15 per million tokens, and an ultra-low-cost tier (text-embedding-004, text-embedding-3-small) with costs around $0.02 per million tokens. This means a developer must decide if the marginal performance gains offered by the premium models justify a roughly 7-fold increase in operational cost. For many applications, the exceptional performance-to-cost ratio of a model like text-embedding-3-small will be the more compelling value proposition.

### **5.2 Estimating Self-Hosting and Third-Party API Costs**

The open-source bge-large-en-v1.5 model introduces more complex but potentially more favorable economic models.

* **Self-Hosting on Google Cloud Platform (GCP):** This option offers maximum control but involves significant and multifaceted costs.39 A realistic TCO estimate must include:  
  * **Compute Costs:** A Google Kubernetes Engine (GKE) cluster is required for orchestration, which incurs a management fee (approx. $0.10 per cluster per hour).55 More importantly, to achieve acceptable inference latency for a real-time chatbot, GPU-accelerated nodes are necessary. The cost of these nodes can be substantial and represents the primary operational expense.  
  * **Storage Costs:** This includes persistent disks for storing the model weights (1.34 GB for bge-large-en-v1.5) and the costs associated with a managed vector database service like Vertex AI Vector Search.37  
  * **Networking Costs:** Data egress charges apply for any data transferred out of the GCP network.55  
  * **Human Capital Costs:** This is the often-underestimated "hidden cost." Self-hosting requires dedicated DevOps or MLOps engineering time for initial setup, configuration, security hardening, ongoing monitoring, scaling, and patching.39 These personnel costs can often exceed the direct infrastructure costs.  
* **Third-Party APIs for bge-large-en-v1.5:** A compelling alternative to self-hosting is to use a third-party provider that offers bge-large-en-v1.5 as a managed API. This combines the benefits of an open-source model with the convenience of a managed service. Pricing from these providers is highly competitive and often significantly lower than first-party APIs:  
  * **DeepInfra**: Offers bge-large-en-v1.5 at **$0.01 per 1 million input tokens**.42  
  * **Cloudflare Workers AI**: Offers the same model at $0.20 per 1 million input tokens.40

The pricing from a provider like DeepInfra is particularly disruptive. At $0.01 per million tokens, it is half the price of OpenAI's text-embedding-3-small while offering slightly better benchmark performance (64.23% vs. 62.3%). This makes it an extremely strong candidate for budget-conscious projects that still require top-tier performance.

The following table provides a TCO projection to translate these abstract prices into concrete financial estimates.

Table: Total Cost of Ownership Projection  
Assumptions: CWE corpus of 1,000 documents at an average of 500 tokens/document \= 500,000 tokens for one-time indexing. User queries average 50 tokens.

| Model | Cost per 1M Tokens | One-Time Indexing Cost | Monthly Query Cost (100k queries) | Monthly Query Cost (1M queries) | Total First-Year Cost (1M queries/mo) |
| :---- | :---- | :---- | :---- | :---- | :---- |
| gemini-embedding-001 | $0.15 | $0.08 | $0.75 | $7.50 | $90.08 |
| text-embedding-3-large | $0.13 | $0.07 | $0.65 | $6.50 | $78.07 |
| text-embedding-3-small | $0.02 | $0.01 | $0.10 | $1.00 | $12.01 |
| bge-large-en-v1.5 (via DeepInfra) | $0.01 | $0.01 | $0.05 | $0.50 | $6.01 |
| bge-large-en-v1.5 (Self-Hosted Est.) | Variable | N/A | Variable | Variable | \>$1,000s (incl. compute & personnel) |

This projection makes the economic trade-offs starkly clear. The premium models from Google and OpenAI are approximately 13-15 times more expensive for ongoing usage than using bge-large-en-v1.5 through a low-cost third-party API. The cost of self-hosting, once infrastructure and specialized engineering time are factored in, is likely to be orders of magnitude higher than any API-based solution, making it viable only at an extremely large scale where API costs would exceed these fixed operational expenditures.

## **Section 6: Strategic Implementation: Building a Future-Proof Abstraction Layer**

The field of embedding models is characterized by rapid innovation, with new, more powerful, and more cost-effective models being released frequently. The research clearly shows this evolutionary path, from text-embedding-ada-002 to the v3 series, and from text-embedding-004 to the superior Gemini Embedding model.23 A model considered state-of-the-art today may be superseded in six to twelve months.

This rapid pace of change introduces significant architectural risk. Tightly coupling the application's logic to a specific model provider's SDK or API signature creates vendor lock-in and makes future upgrades difficult, time-consuming, and expensive.39 To mitigate this risk, it is imperative to implement an abstraction layer that decouples the core application from the specific implementation details of any single embedding model. This is not merely an engineering best practice; it is a critical strategic decision that ensures the long-term maintainability, flexibility, and cost-effectiveness of the system.

### **6.1 Applying the Abstract Factory Pattern for Embedding Model Integration**

The most suitable software design pattern for this purpose is the **Abstract Factory** pattern. This is a creational pattern that provides an interface for creating families of related objects without specifying their concrete classes.57 In this context, the "family of objects" is the embedding client responsible for interacting with a specific model API. The application code interacts only with the abstract interface, remaining completely unaware of which concrete implementation (e.g., OpenAI, Google, a local BGE model) is being used. This approach allows the underlying embedding model to be swapped out by changing a single line in a configuration file, rather than requiring a widespread and risky code refactoring.

### **6.2 Designing a Unified Interface for Seamless Model Switching**

The implementation of this pattern in Python is best achieved using the abc module to create Abstract Base Classes (ABCs).60 A unified interface can be defined to standardize the process of generating embeddings across all potential models.

First, an abstract base class, EmbeddingModelInterface, is defined. This class declares a common method signature that all concrete implementations must adhere to. For example:

Python

from abc import ABC, abstractmethod

class EmbeddingModelInterface(ABC):  
    """Abstract interface for an embedding model client."""

    @abstractmethod  
    def create\_embeddings(self, texts: list\[str\], task\_type: str) \-\> list\[list\[float\]\]:  
        """  
        Generates embeddings for a list of texts.

        Args:  
            texts: A list of strings to embed.  
            task\_type: A string indicating the task (e.g., 'query', 'document').

        Returns:  
            A list of embedding vectors.  
        """  
        pass

Next, concrete classes are created for each potential model provider. Each class inherits from EmbeddingModelInterface and provides a specific implementation for the create\_embeddings method, handling the unique API calls, authentication, and parameter mapping for its respective service.62

### **6.3 Conceptual Code Examples**

The following conceptual code snippets illustrate how this pattern would be implemented for OpenAI and Google models.

**Concrete Implementation for OpenAI:**

Python

import openai

class OpenAIEmbeddingModel(EmbeddingModelInterface):  
    def \_\_init\_\_(self, api\_key: str, model\_name: str, dimensions: int \= None):  
        self.client \= openai.OpenAI(api\_key=api\_key)  
        self.model\_name \= model\_name  
        self.dimensions \= dimensions

    def create\_embeddings(self, texts: list\[str\], task\_type: str) \-\> list\[list\[float\]\]:  
        \# OpenAI API does not use a task\_type parameter like Google's.  
        \# It is included in the interface for compatibility.  
        params \= {"model": self.model\_name, "input": texts}  
        if self.dimensions:  
            params\["dimensions"\] \= self.dimensions  
          
        response \= self.client.embeddings.create(\*\*params)  
        return \[embedding.embedding for embedding in response.data\]

**Concrete Implementation for Google Vertex AI:**

Python

from google.cloud import aiplatform

class GoogleEmbeddingModel(EmbeddingModelInterface):  
    def \_\_init\_\_(self, project\_id: str, location: str, model\_name: str):  
        aiplatform.init(project=project\_id, location=location)  
        self.model \= aiplatform.TextEmbeddingModel.from\_pretrained(model\_name)

    def create\_embeddings(self, texts: list\[str\], task\_type: str) \-\> list\[list\[float\]\]:  
        \# Maps the generic task\_type to Google's specific values.  
        google\_task\_type\_map \= {  
            'query': 'RETRIEVAL\_QUERY',  
            'document': 'RETRIEVAL\_DOCUMENT'  
        }  
        google\_task \= google\_task\_type\_map.get(task\_type, 'RETRIEVAL\_QUERY')  
          
        embeddings \= self.model.get\_embeddings(texts, task\_type=google\_task)  
        return \[embedding.values for embedding in embeddings\]

**The Abstract Factory:**

Finally, a factory class is created to instantiate the correct concrete model based on a configuration setting.

Python

class EmbeddingModelFactory:  
    @staticmethod  
    def get\_model(config: dict):  
        provider \= config\['provider'\]  
        if provider \== 'openai':  
            return OpenAIEmbeddingModel(  
                api\_key=config\['api\_key'\],  
                model\_name=config\['model\_name'\],  
                dimensions=config.get('dimensions')  
            )  
        elif provider \== 'google':  
            return GoogleEmbeddingModel(  
                project\_id=config\['project\_id'\],  
                location=config\['location'\],  
                model\_name=config\['model\_name'\]  
            )  
        \# Add logic for BGE (local or third-party API) here  
        else:  
            raise ValueError(f"Unknown provider: {provider}")

\# Usage in application code:  
\# config is loaded from a file (e.g., config.yaml)  
\# config \= {'provider': 'openai', 'api\_key': '...', 'model\_name': 'text-embedding-3-small'}  
\# embedding\_client \= EmbeddingModelFactory.get\_model(config)  
\# vectors \= embedding\_client.create\_embeddings(\["my query"\], task\_type='query')

By adopting this architecture, the system is future-proofed. Migrating from text-embedding-3-small to a future, more advanced Google model would involve only adding a new condition to the factory and updating the configuration file. The core application logic, which calls embedding\_client.create\_embeddings(...), remains unchanged. This transforms a potentially major refactoring effort into a simple, low-risk update, allowing the project to continuously leverage the most performant and cost-effective technology available.

## **Section 7: Final Synthesis and Strategic Recommendation**

The selection of the optimal embedding model for the CWE mapping chatbot is a multi-dimensional decision that requires a balanced assessment of performance, cost, unique features, and implementation complexity. The analysis reveals that there is no single "best" model for all scenarios; rather, there is an optimal choice depending on the project's specific priorities, budget, and technical capabilities.

### **7.1 Consolidated Strengths and Weaknesses of Each Candidate Model**

* **Google gemini-embedding-001**:  
  * **Strengths**: Likely the highest-performing model, especially on technical and code-related text due to its Gemini foundation and explicit training.27 The  
    task\_type parameter offers sophisticated, built-in optimization for retrieval tasks.19  
  * **Weaknesses**: Highest cost among the candidates.51 Smaller context window (2048 tokens) compared to OpenAI models.15  
* **OpenAI text-embedding-3-large**:  
  * **Strengths**: Top-tier performance, very close to the best open-source alternatives.23 The  
    dimensions parameter provides unmatched flexibility for managing cost and performance trade-offs.12 Large 8192-token context window.12  
  * **Weaknesses**: Premium pricing, making it one of the more expensive options.53  
* **OpenAI text-embedding-3-small**:  
  * **Strengths**: Exceptional performance-to-cost ratio. Its MTEB score is highly competitive, yet its price is on par with the cheapest models.23 Also benefits from the flexible  
    dimensions parameter and large context window.12  
  * **Weaknesses**: Performance is slightly lower than the top-tier models, though the gap is small.23  
* **BAAI bge-large-en-v1.5**:  
  * **Strengths**: Top-tier open-source performance, competitive with the best proprietary models.24 Offers complete deployment flexibility (self-hosted for control, third-party API for convenience).39 Can be the absolute lowest-cost option when accessed via certain third-party APIs.42  
  * **Weaknesses**: Smaller context window (512 tokens).24 Self-hosting carries a very high operational and personnel cost.39 Lacks advanced API features like variable dimensions or explicit task types.

### **7.2 Primary Recommendation**

For the development of the CWE mapping chatbot, the primary recommendation is to use **OpenAI's text-embedding-3-small model**.

This model represents the optimal intersection of performance, cost, and advanced features. Its MTEB score of 62.3% is remarkably strong, significantly outperforming the previous generation of models and trailing the absolute top-tier models by only a small margin.23 At a cost of just $0.02 per 1 million tokens, it is exceptionally economical, minimizing both the initial indexing cost and ongoing operational expenses.53 Most importantly, it includes the strategic

dimensions parameter, allowing for future-proofing and fine-grained control over the cost-performance curve without being locked into a specific vector size. This combination of "good enough" top-tier performance, rock-bottom pricing, and advanced strategic features makes it the most pragmatic and well-balanced choice for a production-ready application.

### **7.3 Secondary Recommendations**

Alternative models are recommended for organizations with different strategic priorities:

* **For Maximum Performance:** **Google gemini-embedding-001**. If the absolute highest retrieval accuracy on technical documentation is the paramount concern and budget is secondary, the Gemini embedding model is the recommended choice. Its state-of-the-art benchmark scores and specialized training on code and multilingual text make it the most likely candidate to achieve the best possible performance on the challenging CWE corpus.27  
* **For Maximum Control & Lowest Long-Term Cost at Extreme Scale:** **Self-hosted bge-large-en-v1.5**. For organizations with a mature MLOps practice, stringent data privacy requirements, and a projected query volume so high that API costs would be prohibitive, self-hosting the BGE model is the most logical path. This approach provides complete control over the infrastructure and data, and while initial setup costs are high, it can offer the lowest TCO in the long run for very high-throughput systems.39  
* **For the Ultimate Budget-Conscious Approach:** **bge-large-en-v1.5 via a low-cost third-party API**. For startups, research projects, or initial prototypes where minimizing cost is the primary driver, using the BGE model through a provider like DeepInfra at $0.01 per 1 million tokens is an unbeatable value proposition.42 This strategy delivers performance that is competitive with  
  text-embedding-3-large at half the price of text-embedding-3-small, making it the most cost-effective option on the market.

### **7.4 A Roadmap for Implementation and Validation**

To ensure the success of the project, the following actionable steps are recommended:

1. **Implement the Abstraction Layer:** Before writing any application-specific logic, build the Abstract Factory pattern for embedding models as detailed in Section 6\. This is a foundational step that will enable flexibility and mitigate future risk.  
2. **Select Top Contenders for In-Domain Evaluation:** Based on this report, select the primary recommendation (text-embedding-3-small) and one of the secondary recommendations that best fits the project's constraints (e.g., bge-large-en-v1.5 via API for a budget comparison, or gemini-embedding-001 for a performance comparison).  
3. **Conduct a Small-Scale Internal Benchmark:** Create a validation set consisting of a representative sample of the CWE corpus (e.g., 100-200 diverse entries) and a curated list of 50-100 realistic user queries that cover a range of topics and phrasing styles.  
4. **Measure and Compare:** Index the validation corpus using both selected models. Run the test queries through the retrieval system and measure the nDCG@10 score for each model. Additionally, perform a qualitative review of the end-to-end responses generated by the RAG system for each model.  
5. **Make the Final Data-Driven Decision:** Use the empirical evidence from the internal benchmark to make the final model selection. This process validates the findings of this report within the specific context of the CWE domain and ensures that the chosen model provides the best possible performance for this unique and challenging application.

#### **Works cited**

1. en.wikipedia.org, accessed on August 22, 2025, [https://en.wikipedia.org/wiki/Common\_Weakness\_Enumeration](https://en.wikipedia.org/wiki/Common_Weakness_Enumeration)  
2. CWE: Understanding Common Weakness Enumeration in Cloud Security, accessed on August 22, 2025, [https://orca.security/glossary/cwe/](https://orca.security/glossary/cwe/)  
3. Common Weakness Enumeration (CWE) \- Bugcrowd, accessed on August 22, 2025, [https://www.bugcrowd.com/glossary/common-weakness-enumeration-cwe/](https://www.bugcrowd.com/glossary/common-weakness-enumeration-cwe/)  
4. CWE Definitions list and vulnerabilities for CWE entries \- CVE Details, accessed on August 22, 2025, [https://www.cvedetails.com/cwe-definitions/](https://www.cvedetails.com/cwe-definitions/)  
5. Common Weakness Enumeration \- CWE Listing \- ProSec Networks, accessed on August 22, 2025, [https://www.prosec-networks.com/en/blog/cwe/](https://www.prosec-networks.com/en/blog/cwe/)  
6. Vulnerabilities:CWE (Common Weakness Enumeration) Overview | Enhancing information security | IPA Information-technology Promotion Agency, Japan, accessed on August 22, 2025, [https://www.ipa.go.jp/en/security/vulnerabilities/cwe.html](https://www.ipa.go.jp/en/security/vulnerabilities/cwe.html)  
7. CWE-200: Exposure of Sensitive Information to an Unauthorized Actor, accessed on August 22, 2025, [https://cwe.mitre.org/data/definitions/200.html](https://cwe.mitre.org/data/definitions/200.html)  
8. Top embedding models on the MTEB leaderboard | Modal Blog, accessed on August 22, 2025, [https://modal.com/blog/mteb-leaderboard-article](https://modal.com/blog/mteb-leaderboard-article)  
9. MTEB Leaderboard — BGE documentation, accessed on August 22, 2025, [https://bge-model.com/tutorial/4\_Evaluation/4.2.2.html](https://bge-model.com/tutorial/4_Evaluation/4.2.2.html)  
10. Common Weakness Enumeration: Why is it Important? | by InfosecTrain | Medium, accessed on August 22, 2025, [https://medium.com/@Infosec-Train/common-weakness-enumeration-why-is-it-important-ef231635966a](https://medium.com/@Infosec-Train/common-weakness-enumeration-why-is-it-important-ef231635966a)  
11. What is retrieval-augmented generation? \- Red Hat, accessed on August 22, 2025, [https://www.redhat.com/en/topics/ai/what-is-retrieval-augmented-generation](https://www.redhat.com/en/topics/ai/what-is-retrieval-augmented-generation)  
12. Vector embeddings \- OpenAI API, accessed on August 22, 2025, [https://platform.openai.com/docs/guides/embeddings](https://platform.openai.com/docs/guides/embeddings)  
13. What is Retrieval-Augmented Generation (RAG)? | Google Cloud, accessed on August 22, 2025, [https://cloud.google.com/use-cases/retrieval-augmented-generation](https://cloud.google.com/use-cases/retrieval-augmented-generation)  
14. What is Retrieval-Augmented Generation (RAG)? | NVIDIA Glossary, accessed on August 22, 2025, [https://www.nvidia.com/en-us/glossary/retrieval-augmented-generation/](https://www.nvidia.com/en-us/glossary/retrieval-augmented-generation/)  
15. Get text embeddings | Generative AI on Vertex AI \- Google Cloud, accessed on August 22, 2025, [https://cloud.google.com/vertex-ai/generative-ai/docs/embeddings/get-text-embeddings](https://cloud.google.com/vertex-ai/generative-ai/docs/embeddings/get-text-embeddings)  
16. What is RAG? \- Retrieval-Augmented Generation AI Explained \- AWS, accessed on August 22, 2025, [https://aws.amazon.com/what-is/retrieval-augmented-generation/](https://aws.amazon.com/what-is/retrieval-augmented-generation/)  
17. What is RAG (Retrieval Augmented Generation)? \- IBM, accessed on August 22, 2025, [https://www.ibm.com/think/topics/retrieval-augmented-generation](https://www.ibm.com/think/topics/retrieval-augmented-generation)  
18. Retrieval Augmented Generation (RAG) in Azure AI Search \- Microsoft Community, accessed on August 22, 2025, [https://learn.microsoft.com/en-us/azure/search/retrieval-augmented-generation-overview](https://learn.microsoft.com/en-us/azure/search/retrieval-augmented-generation-overview)  
19. Text embeddings API | Generative AI on Vertex AI \- Google Cloud, accessed on August 22, 2025, [https://cloud.google.com/vertex-ai/generative-ai/docs/model-reference/text-embeddings-api](https://cloud.google.com/vertex-ai/generative-ai/docs/model-reference/text-embeddings-api)  
20. Text Embedding New API \- Colab \- Google, accessed on August 22, 2025, [https://colab.research.google.com/github/GoogleCloudPlatform/vertex-ai-samples/blob/859ed6a55d07a023655e4e002864f446b1f9a4a8/notebooks/official/generative\_ai/text\_embedding\_new\_api.ipynb](https://colab.research.google.com/github/GoogleCloudPlatform/vertex-ai-samples/blob/859ed6a55d07a023655e4e002864f446b1f9a4a8/notebooks/official/generative_ai/text_embedding_new_api.ipynb)  
21. BAAI/bge-large-en-v1.5 \- Hugging Face, accessed on August 22, 2025, [https://huggingface.co/BAAI/bge-large-en-v1.5](https://huggingface.co/BAAI/bge-large-en-v1.5)  
22. Use embedding models with Vertex AI RAG Engine \- Google Cloud, accessed on August 22, 2025, [https://cloud.google.com/vertex-ai/generative-ai/docs/rag-engine/use-embedding-models](https://cloud.google.com/vertex-ai/generative-ai/docs/rag-engine/use-embedding-models)  
23. New embedding models and API updates \- OpenAI, accessed on August 22, 2025, [https://openai.com/index/new-embedding-models-and-api-updates/](https://openai.com/index/new-embedding-models-and-api-updates/)  
24. bge-large-en-v1.5 \- PromptLayer, accessed on August 22, 2025, [https://www.promptlayer.com/models/bge-large-en-v15](https://www.promptlayer.com/models/bge-large-en-v15)  
25. Embeddings for Text – Vertex AI \- Google Cloud console, accessed on August 22, 2025, [https://console.cloud.google.com/vertex-ai/publishers/google/model-garden/textembedding-gecko](https://console.cloud.google.com/vertex-ai/publishers/google/model-garden/textembedding-gecko)  
26. Choosing The Right Embedding Model for Your Workload \- Ragwalla, accessed on August 22, 2025, [https://ragwalla.com/docs/guides/choosing-an-embedding-model-for-your-workload](https://ragwalla.com/docs/guides/choosing-an-embedding-model-for-your-workload)  
27. Generalizable Embeddings from Gemini \- arXiv, accessed on August 22, 2025, [https://arxiv.org/html/2503.07891v1](https://arxiv.org/html/2503.07891v1)  
28. Embeddings | Gemini API | Google AI for Developers, accessed on August 22, 2025, [https://ai.google.dev/gemini-api/docs/embeddings](https://ai.google.dev/gemini-api/docs/embeddings)  
29. State-of-the-art text embedding via the Gemini API \- Google Developers Blog, accessed on August 22, 2025, [https://developers.googleblog.com/en/gemini-embedding-text-model-now-available-gemini-api/](https://developers.googleblog.com/en/gemini-embedding-text-model-now-available-gemini-api/)  
30. Google Introduces Gemini Embedding, Its Most Advanced Text Embedding Model Yet, accessed on August 22, 2025, [https://www.maginative.com/article/google-introduces-gemini-embedding-its-most-advanced-text-embedding-model-yet/](https://www.maginative.com/article/google-introduces-gemini-embedding-its-most-advanced-text-embedding-model-yet/)  
31. Exploring Text-Embedding-3-Large: A Comprehensive Guide to the new OpenAI Embeddings | DataCamp, accessed on August 22, 2025, [https://www.datacamp.com/tutorial/exploring-text-embedding-3-large-new-openai-embeddings](https://www.datacamp.com/tutorial/exploring-text-embedding-3-large-new-openai-embeddings)  
32. OpenAI vs Open-Source Multilingual Embedding Models | by Yann-Aël Le Borgne \- Medium, accessed on August 22, 2025, [https://medium.com/data-science/openai-vs-open-source-multilingual-embedding-models-e5ccb7c90f05](https://medium.com/data-science/openai-vs-open-source-multilingual-embedding-models-e5ccb7c90f05)  
33. text-embedding-3-large model | Clarifai \- The World's AI, accessed on August 22, 2025, [https://clarifai.com/openai/embed/models/text-embedding-3-large](https://clarifai.com/openai/embed/models/text-embedding-3-large)  
34. Open AI 3'rd gen embedding models — what's driving the improvements? | by Arun Prasad, accessed on August 22, 2025, [https://medium.com/@arundona/open-ai-3rd-gen-embedding-models-whats-driving-the-improvements-4c23b88751f1](https://medium.com/@arundona/open-ai-3rd-gen-embedding-models-whats-driving-the-improvements-4c23b88751f1)  
35. bge-m3 \- a multilingual embedding model, from the authors of bge-large-en-v1.5 that topped for a long time the MTEB leaderboard : r/LocalLLaMA \- Reddit, accessed on August 22, 2025, [https://www.reddit.com/r/LocalLLaMA/comments/1akpjpn/bgem3\_a\_multilingual\_embedding\_model\_from\_the/](https://www.reddit.com/r/LocalLLaMA/comments/1akpjpn/bgem3_a_multilingual_embedding_model_from_the/)  
36. State-of-art retrieval-augmented LLM: bge-large-en-v1.5 | by Novita AI | Medium, accessed on August 22, 2025, [https://medium.com/@marketing\_novita.ai/state-of-art-retrieval-augmented-llm-bge-large-en-v1-5-4cd5abbcbf0a](https://medium.com/@marketing_novita.ai/state-of-art-retrieval-augmented-llm-bge-large-en-v1-5-4cd5abbcbf0a)  
37. BGE v1 & v1.5 — BGE documentation \- BGE Models, accessed on August 22, 2025, [https://bge-model.com/bge/bge\_v1\_v1.5.html](https://bge-model.com/bge/bge_v1_v1.5.html)  
38. To compare with the MTEB leaderboard (https://huggingface.co/spaces/mteb/leaderb... | Hacker News, accessed on August 22, 2025, [https://news.ycombinator.com/item?id=39133224](https://news.ycombinator.com/item?id=39133224)  
39. Choosing a self-hosted or managed solution for AI app development | Google Cloud Blog, accessed on August 22, 2025, [https://cloud.google.com/blog/products/application-development/choosing-a-self-hosted-or-managed-solution-for-ai-app-development](https://cloud.google.com/blog/products/application-development/choosing-a-self-hosted-or-managed-solution-for-ai-app-development)  
40. bge-large-en-v1.5 \- Workers AI \- Cloudflare Docs, accessed on August 22, 2025, [https://developers.cloudflare.com/workers-ai/models/bge-large-en-v1.5/](https://developers.cloudflare.com/workers-ai/models/bge-large-en-v1.5/)  
41. BGE-Large-EN v1.5 API \- Together AI, accessed on August 22, 2025, [https://www.together.ai/models/bge-large-en-v1-5](https://www.together.ai/models/bge-large-en-v1-5)  
42. Deep Infra: Machine Learning Models and Infrastructure, accessed on August 22, 2025, [https://deepinfra.com/](https://deepinfra.com/)  
43. Qdrant/bge-large-en-v1.5-onnx \- Hugging Face, accessed on August 22, 2025, [https://huggingface.co/Qdrant/bge-large-en-v1.5-onnx](https://huggingface.co/Qdrant/bge-large-en-v1.5-onnx)  
44. CompendiumLabs/bge-large-en-v1.5-gguf \- Hugging Face, accessed on August 22, 2025, [https://huggingface.co/CompendiumLabs/bge-large-en-v1.5-gguf](https://huggingface.co/CompendiumLabs/bge-large-en-v1.5-gguf)  
45. RedHatAI/bge-large-en-v1.5-quant \- Hugging Face, accessed on August 22, 2025, [https://huggingface.co/RedHatAI/bge-large-en-v1.5-quant](https://huggingface.co/RedHatAI/bge-large-en-v1.5-quant)  
46. MTEB Leaderboard \- a Hugging Face Space by mteb, accessed on August 22, 2025, [https://huggingface.co/spaces/mteb/leaderboard](https://huggingface.co/spaces/mteb/leaderboard)  
47. MTEB — BGE documentation, accessed on August 22, 2025, [https://bge-model.com/API/evaluation/mteb.html](https://bge-model.com/API/evaluation/mteb.html)  
48. MTEB: Massive Text Embedding Benchmark \- Hugging Face, accessed on August 22, 2025, [https://huggingface.co/blog/mteb](https://huggingface.co/blog/mteb)  
49. NVIDIA Text Embedding Model Tops MTEB Leaderboard, accessed on August 22, 2025, [https://developer.nvidia.com/blog/nvidia-text-embedding-model-tops-mteb-leaderboard/](https://developer.nvidia.com/blog/nvidia-text-embedding-model-tops-mteb-leaderboard/)  
50. MTEB Leaderboard : User guide and best practices \- Hugging Face, accessed on August 22, 2025, [https://huggingface.co/blog/lyon-nlp-group/mteb-leaderboard-best-practices](https://huggingface.co/blog/lyon-nlp-group/mteb-leaderboard-best-practices)  
51. Gemini Developer API Pricing | Gemini API | Google AI for Developers, accessed on August 22, 2025, [https://ai.google.dev/gemini-api/docs/pricing](https://ai.google.dev/gemini-api/docs/pricing)  
52. Gemini Embedding now generally available in the Gemini API \- Google Developers Blog, accessed on August 22, 2025, [https://developers.googleblog.com/en/gemini-embedding-available-gemini-api/](https://developers.googleblog.com/en/gemini-embedding-available-gemini-api/)  
53. OpenAI Embeddings Pricing Calculator \- InvertedStone, accessed on August 22, 2025, [https://invertedstone.com/calculators/embedding-pricing-calculator](https://invertedstone.com/calculators/embedding-pricing-calculator)  
54. Run Text Embedding 004 on your data \- Oxen.ai, accessed on August 22, 2025, [https://www.oxen.ai/ai/models/text-embedding-004](https://www.oxen.ai/ai/models/text-embedding-004)  
55. Google Cloud Pricing: The Complete Guide | Spot.io, accessed on August 22, 2025, [https://spot.io/resources/google-cloud-pricing/google-cloud-pricing-the-complete-guide/](https://spot.io/resources/google-cloud-pricing/google-cloud-pricing-the-complete-guide/)  
56. Cost of a Google Cloud hosting plan : r/googlecloud \- Reddit, accessed on August 22, 2025, [https://www.reddit.com/r/googlecloud/comments/163pwpt/cost\_of\_a\_google\_cloud\_hosting\_plan/](https://www.reddit.com/r/googlecloud/comments/163pwpt/cost_of_a_google_cloud_hosting_plan/)  
57. Abstract Factory in Python / Design Patterns \- Refactoring.Guru, accessed on August 22, 2025, [https://refactoring.guru/design-patterns/abstract-factory/python/example](https://refactoring.guru/design-patterns/abstract-factory/python/example)  
58. Design Patterns Tutorial \- GeeksforGeeks, accessed on August 22, 2025, [https://www.geeksforgeeks.org/system-design/software-design-patterns/](https://www.geeksforgeeks.org/system-design/software-design-patterns/)  
59. Python Design Patterns, accessed on August 22, 2025, [https://python-patterns.guide/](https://python-patterns.guide/)  
60. Design Patterns in Python: Abstract Factory | Medium, accessed on August 22, 2025, [https://medium.com/@amirm.lavasani/design-patterns-in-python-abstract-factory-2dcae06e5d29](https://medium.com/@amirm.lavasani/design-patterns-in-python-abstract-factory-2dcae06e5d29)  
61. Data Abstraction in Python \- GeeksforGeeks, accessed on August 22, 2025, [https://www.geeksforgeeks.org/python/data-abstraction-in-python/](https://www.geeksforgeeks.org/python/data-abstraction-in-python/)  
62. Proper way to create an abstraction layer in python \- Stack Overflow, accessed on August 22, 2025, [https://stackoverflow.com/questions/3813577/proper-way-to-create-an-abstraction-layer-in-python](https://stackoverflow.com/questions/3813577/proper-way-to-create-an-abstraction-layer-in-python)  
63. Getting started with Amazon Titan Text Embeddings in Amazon Bedrock \- AWS, accessed on August 22, 2025, [https://aws.amazon.com/blogs/machine-learning/getting-started-with-amazon-titan-text-embeddings/](https://aws.amazon.com/blogs/machine-learning/getting-started-with-amazon-titan-text-embeddings/)