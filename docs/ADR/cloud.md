# **ADR: Cloud Provider Choice for CWE Chatbot**

## **Summary**

We must select a primary cloud provider to host the entire CWE Chatbot application stack. The choice will dictate the available services, cost structure, and operational model. After evaluating the major providers, we have decided to build and deploy exclusively on **Google Cloud Platform (GCP)**. GCP offers a superior combination of price-performance for its generative AI services, a mature serverless ecosystem, and a strong commitment to open-source technologies that aligns with our architecture.

## **Issue**

The project requires a cloud platform that can cost-effectively run a modern, AI-driven application. Key requirements include a managed environment for a containerized Python backend, a low-cost managed database with vector support, and access to high-performance, pay-as-you-go generative AI models. The provider must offer a clear path to scale from a low-traffic MVP to a production-grade service without significant architectural changes.

## **Decision**

We will use **Google Cloud Platform (GCP)** as the exclusive cloud provider for all infrastructure, data, and AI services for the CWE Chatbot.

* **Compute:** Cloud Run for the serverless container.  
* **Database:** Cloud SQL for the managed PostgreSQL database.  
* **AI/ML:** Vertex AI for accessing foundation models (embeddings, generative text).  
* **Authentication:** Identity Platform for managed user sign-in.  
* **Security:** Cloud Armor for WAF and DDoS protection.

## **Status**

**Decided** (2025-06-26). All infrastructure and deployment efforts will be focused on the GCP ecosystem.

## **Details**

### **Assumptions**

* The primary workload is a Python-based generative AI application.  
* Cost-efficiency, especially at low-to-moderate scale, is a critical business driver.  
* A strong, integrated serverless and AI/ML platform will accelerate development more than a platform with a wider breadth of disparate services.

### **Constraints**

* The provider must offer a fully managed environment for containers and databases.  
* Must provide API access to state-of-the-art generative AI and embedding models with a consumption-based pricing model.  
* Must have a robust security model, including WAF capabilities and managed identity services.

### **Positions**

* **Google Cloud Platform (GCP):**  
  * *Pros:* Best-in-class AI/ML services with Vertex AI and Gemini models. Excellent price-performance for serverless compute with Cloud Run. Strong data analytics and Kubernetes (GKE) heritage. Often seen as more cost-effective for compute and AI workloads.  
  * *Cons:* Smaller market share compared to AWS and Azure, which can mean a smaller community and fewer third-party tools in some niche areas.  
* **Amazon Web Services (AWS):**  
  * *Pros:* Largest market share, most extensive and mature suite of services, and a vast ecosystem of partners and documentation.  
  * *Cons:* AI/ML offerings (SageMaker, Bedrock) can be more complex to integrate. Pricing models are notoriously complex and can lead to unexpected costs if not carefully managed.  
* **Microsoft Azure:**  
  * *Pros:* Strong position in the enterprise market with seamless integration for existing Microsoft customers (e.g., Office 365, Active Directory). Azure OpenAI service provides direct access to OpenAI models.  
  * *Cons:* The platform can be less intuitive for teams not already invested in the Microsoft ecosystem. Sometimes perceived as less flexible for open-source-first development.

### **Argument**

GCP is the best choice for this project due to its **superior price-performance and integration specifically for generative AI workloads**.

1. **Leading AI Services:** Vertex AI provides a unified, developer-friendly platform for accessing Google's powerful Gemini models and a wide array of other foundation models. This tight integration simplifies the development of our RAG pipeline.  
2. **Cost-Effective Serverless:** Cloud Run is a highly efficient and cost-effective solution for our containerized Chainlit application. Its scale-to-zero capability is perfect for an application that may start with intermittent traffic.  
3. **Unified Ecosystem:** GCP's services feel cohesively designed. The integration between Cloud Run, Cloud SQL, and Vertex AI is seamless, reducing the "glue code" and operational complexity required to connect different parts of the stack.  
4. **Predictable and Competitive Pricing:** GCP's pricing for compute and AI is often more straightforward and competitive than its rivals, especially with features like Sustained Use Discounts that are applied automatically. This aligns with our goal of maintaining low, predictable costs.

While AWS has a larger service catalog and Azure dominates the Microsoft-centric enterprise, GCP's strategic focus on AI, data, and open-source makes it the most aligned and cost-effective platform for building this specific application.

### **Implications**

* **Technology Stack:** The team will focus on GCP-native services and SDKs.  
* **Infrastructure as Code:** Terraform will be used to provision and manage all GCP resources.  
* **Developer Skills:** Team members will need to be proficient with GCP services like Cloud Run, IAM, and Cloud SQL.  
* **Vendor Lock-in:** While a consideration, the use of open technologies like Docker containers and PostgreSQL mitigates this risk. The core application logic remains portable even if the managed services change.

### **Related**

* **ADR:** Database Choice for CWE Chatbot  
* **Principles:** Serverless First, Cost-Efficiency, Simplicity.