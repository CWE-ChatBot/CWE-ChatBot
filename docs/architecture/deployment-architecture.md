# Deployment Architecture

This section outlines the strategy for deploying the CWE ChatBot, including the chosen platforms, CI/CD pipeline, environment management, and rollback procedures.

## Deployment Strategy

The CWE ChatBot will leverage Google Cloud Platform's serverless capabilities for highly scalable and efficient deployments.

  * **Frontend & Backend Deployment:** The unified **Chainlit application (Python)**, serving both the UI and core backend logic, will be deployed as a containerized service to **Google Cloud Run**. This provides automatic scaling, serverless execution, and a publicly accessible endpoint.
  * **Supporting Services Deployment:** Logical microservices such as the `NLP/AI Processor` (if separated) and the `CWE Data Ingestion Service` will also be deployed to **Google Cloud Run** or **Google Cloud Functions**, depending on their execution pattern (long-running vs. event-driven/scheduled).
  * **Build Command:** Docker will be used as the primary containerization technology. The `Dockerfile` within each app/service directory will define its build process.
  * **Deployment Method:** We will aim for **Continuous Deployment (CD)** to our staging environment, and **Continuous Delivery (CD)** with a manual approval gate for production releases.

## CI/CD Pipeline

A robust Continuous Integration/Continuous Delivery (CI/CD) pipeline will automate the process of building, testing, and deploying the application.

  * **CI/CD Platform:** **GitHub Actions** will be used for orchestrating the overall pipeline due to its tight integration with our code repository. **Google Cloud Build** will be leveraged for efficient and secure Docker image builds and deployment to GCP resources.
  * **Pipeline Configuration:** Configuration files (e.g., `.github/workflows/*.yml`) will reside in the `.github/workflows/` directory of the monorepo.
  * **Conceptual Workflow:**
    1.  **Code Commit/Pull Request:** Developer pushes code changes or opens a Pull Request.
    2.  **Continuous Integration (CI):** GitHub Actions triggers:
          * Automated tests (unit, integration) using Pytest (NFR47).
          * Code linting and static analysis (NFR5, NFR48).
          * Security scanning (SAST) (NFR47).
    3.  **Image Build:** On successful CI and merge to `main`, Google Cloud Build triggers to:
          * Build Docker images for affected services/apps.
          * Push images to Google Artifact Registry.
    4.  **Automated Deployment to Staging:** GitHub Actions/Cloud Build deploys the new images to the dedicated **Staging** Cloud Run services.
    5.  **Dynamic Application Security Testing (DAST):** Automated DAST scans run against the newly deployed staging environment (NFR47).
    6.  **Manual Approval (for Production):** A manual gate (e.g., in GitHub Actions or a dedicated release tool) requires approval for deployment to Production.
    7.  **Production Deployment:** Upon approval, the new images are deployed to the **Production** Cloud Run services.
    8.  **Scheduled Data Ingestion:** A separate CI/CD flow or Cloud Scheduler job will trigger the `cwe_data_ingestion` service periodically (e.g., weekly, aligning with NFR18).

## Environments

Distinct environments will be used to ensure proper testing and separation of development stages.

  * **Development:** Local developer machines, used for coding, local testing, and rapid iteration.
  * **Staging:** A dedicated GCP project or set of resources, mirroring the production environment. Used for integration testing, user acceptance testing (UAT), DAST, and pre-release validation.
  * **Production:** A fully isolated and hardened GCP project, hosting the live application accessible by end-users.

## Availability & DoS Protection

* **Rate Limiting:** The system will implement per-user rate limiting on all public endpoints via Google Cloud Armor to mitigate API Flooding (**D-2**) and Financial DoS (**D-3**).  
* **Billing Alerts:** GCP billing alerts will be configured via Terraform to provide early warning of potential FDoS attacks (**D-3**).  
* **Query Complexity:** The application logic will include timeouts and complexity analysis on AI-driven queries to prevent resource exhaustion (**D-1**).
* 
## Rollback Strategy

A clear rollback strategy is essential to quickly recover from critical issues post-deployment (NFR42).

  * **Primary Method:** **Google Cloud Run Revision Management.** Cloud Run automatically creates a new revision for each deployment. Rolling back is as simple as routing traffic to a previously known stable revision with a single command or UI action. This provides near-instantaneous rollback capabilities.
  * **Trigger Conditions:** Critical errors detected in post-deployment monitoring (e.g., high error rates, performance degradation, major functional regressions, security alerts).
  * **Recovery Time Objective (RTO):** Aim for an RTO of less than 5 minutes for critical issues by leveraging Cloud Run's rapid rollback feature.
