# **ADR: Database Choice for CWE Chatbot**

## **Summary**

We need a persistent data store for the CWE Chatbot that can handle both structured application data (users, chat history) and vector embeddings for the RAG pipeline. To prioritize architectural simplicity and low, predictable costs for our initial deployment, we will use a single **Cloud SQL for PostgreSQL** instance with the **pgvector extension enabled**. This consolidates all data into one managed service.

## **Issue**

The application requires a database solution that can efficiently store and query two distinct types of data:

1. **Transactional Data:** User profiles, conversation logs, and application settings.  
2. **Vector Data:** Embeddings of the CWE corpus (\~1000 entries) for real-time similarity search.

We considered using separate, specialized services (e.g., Firestore for transactional data and Vertex AI Vector Search for embeddings) versus a unified approach. The chosen solution must be a managed service, cost-effective for a low-traffic application, and performant enough for interactive use.

## **Decision**

We will use a single **Cloud SQL for PostgreSQL** instance as the sole database for the application.

* **Structured Data:** Standard relational tables (users, conversations, messages) will be used for all application data.  
* **Vector Data:** The pgvector extension will be enabled on the instance. A dedicated cwe\_embeddings table will store the vector embeddings and their associated metadata.

This approach provides a single, unified data layer for the entire application, simplifying development, deployment, and maintenance.

## **Status**

**Decided** (2025-08-26). The implementation will proceed with a small, shared-core Cloud SQL for PostgreSQL instance.

## **Details**

### **Assumptions**

* The CWE corpus is small and relatively static (\~1000 entries, \~2KB each). The performance of pgvector on a small, managed instance will be more than sufficient for this scale.  
* Architectural simplicity and a low, predictable monthly cost are higher priorities than the massive scalability offered by separate, specialized vector databases for the initial version of this project.  
* A single data store is an acceptable architectural choice for the MVP.

### **Constraints**

* The solution must be a **managed service** to minimize operational overhead.  
* The service must support both standard SQL for transactional operations and vector similarity search for the RAG functionality.  
* The monthly cost must be low and predictable for a project with minimal initial traffic.

### **Positions**

* **Separate Services (e.g., Firestore \+ Vertex AI Vector Search):**  
  * *Pros:* Highly scalable, fully serverless (scales to zero), and purpose-built for their respective tasks.  
  * *Cons:* More complex architecture, requires managing two different data sources and SDKs, and the baseline cost for managed vector services can be higher than a small SQL instance.  
* **Consolidated Service (Cloud SQL \+ pgvector):**  
  * *Pros:* Drastically simpler architecture with a single connection point, mature and well-understood technology, and a low, predictable monthly cost for a small instance.  
  * *Cons:* Not serverless (the instance runs 24/7), and could become a performance bottleneck if the vector dataset or query volume grows exponentially.  
* **External Hosted Services (e.g., Qdrant Cloud, Pinecone, Neon):**  
  * *Pros:* Fully managed, often purpose-built for vector search, and some offer serverless pricing models (Neon).  
  * *Cons:* Dismissed primarily for simplicity and latency. Introducing an external, non-GCP service adds another network hop outside of Google's network, potentially increasing query latency. It also adds architectural complexity in terms of security (VPC peering/firewall rules), billing, and requiring a separate SDK.  
* **In-Memory Vector DB (e.g., FAISS, ChromaDB in-memory):**  
  * *Pros:* Extremely fast for vector lookups as the index is held in RAM.  
  * *Cons:* Dismissed because it only solves half the problem. We still require a persistent, transactional database for user data. This would force us to manage two systems (one in-memory for vectors, one persistent for users), which contradicts the primary goal of architectural simplicity. It is more efficient to add vector capabilities to the already-required persistent store.  
* **Data Warehouse (BigQuery):**  
  * *Pros:* Massively scalable for analytics and has vector search capabilities.  
  * *Cons:* Dismissed as it is an analytical database (OLAP), not a transactional one (OLTP). It is designed for large-scale analytical queries, not the fast, single-row read/write operations required by a real-time chatbot. Using it for this purpose would result in high latency and unpredictable costs.

### **Argument**

For a dataset of only \~1000 vector embeddings, the performance of pgvector is excellent and does not require a dedicated, specialized service. The primary benefit of this decision is **simplicity**. By using a single database within the same cloud provider (GCP), we reduce the number of moving parts, simplify the application's data access layer, and avoid cross-cloud network latency.

Furthermore, a small, shared-core Cloud SQL instance offers a very **low and predictable monthly cost** (estimated at \~$15-25), which is ideal for a new project. This avoids the potentially variable costs and architectural complexity of integrating third-party services.

### **Implications**

* The application's entire data access layer will be built around a single PostgreSQL client/SDK.  
* The data ingestion pipeline will be simplified, as it only needs to write to a table within the existing Cloud SQL database.  
* This decision can be revisited in the future. If the application's usage scales significantly, the vector data can be migrated to a dedicated service like Vertex AI Vector Search with minimal changes to the core application logic, as the data access layer will already be abstracted.

### **Related**

* **Requirements:** NFR5 (Codebase Adherence), NFR6 (Hallucination Mitigation).  
* **Principles:** Serverless First (for compute), Cost-Efficiency, Simplicity.