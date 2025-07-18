# LLM Framework Choice for CWE Mapping Chatbot

Contents:

- [LLM Framework Choice for CWE Mapping Chatbot](#llm-framework-choice-for-cwe-mapping-chatbot)
  - [Summary](#summary)
    - [Issue](#issue)
    - [Decision](#decision)
    - [Status](#status)
  - [Details](#details)
    - [Assumptions](#assumptions)
    - [Constraints](#constraints)
    - [Positions](#positions)
    - [Argument](#argument)
    - [Implications](#implications)
  - [Related](#related)
    - [Related decisions](#related-decisions)
    - [Related requirements](#related-requirements)
    - [Related artifacts](#related-artifacts)
    - [Related principles](#related-principles)
  - [Notes](#notes)

## Summary

### Issue

We need to select a Python-based framework for the chatbot user interface in our CWE mapping solution. The framework must support rapid development, be agnostic to LLM backends, integrate into a web and mobile environment, and allow enterprise security features to be layered around it.

### Decision

We are choosing **Chainlit** as the primary framework for building the conversational UI of our LLM-powered CWE mapping assistant.

### Status

Decided. We remain open to new frameworks as they emerge but will proceed with Chainlit for the initial MVP and production rollout.

## Details

### Assumptions

* The primary interface is a chat-style UI accessed via web and mobile browsers.
* LLM backends may change (OpenAI, on‑prem models, etc.), so the UI layer must be model-agnostic.
* Enterprise-grade security (SSO, RBAC, audit logging) will be implemented externally or via minimal built-in features.
* Standard UI components (text inputs, chat bubbles, tables) sufficiently meet requirements—no custom interactive graphs are needed initially.
* Retrieval-augmented workflows (e.g., looking up CWE entries) will be handled in code behind the UI.

### Constraints

* Must support responsive access on both desktop and mobile browsers without a native app.
* Should minimize custom front-end development effort to accelerate time-to-first-demo.
* Must be able to host behind corporate authentication (e.g., OAuth/OIDC proxy) and integrate with internal monitoring.
* UI framework licenses must be open-source or compatible with our enterprise policies.

### Positions

We considered the following options:

* **Streamlit**
* **Gradio**
* **Chainlit**
* **Flask/FastAPI** with custom front-end
* **Rasa** for structured dialogue management

### Argument

* **Streamlit**: Excellent for rapid dashboards and simple chat prototypes, but lacks built-in auth and is less suited for large-scale conversational apps. Custom session handling and scaling require extra work.
* **Gradio**: Very fast to prototype with built-in chat components and basic password gating. Limited in layout customization and long-term scalability for enterprise security features.
* **Chainlit**: Purpose‑built for LLM chat apps, offers chat UI, streaming, user feedback, built-in auth hooks, and observability. Highly flexible for integrating retrieval workflows and multiple LLM backends. Responsive on web/mobile and easily themed.
* **Flask/FastAPI + Custom Front‑End**: Maximum flexibility and full control over auth and UI, but far slower to develop, requiring separate front-end build and session management. Higher maintenance burden.
* **Rasa**: Strong structured dialog and NLU, but overkill for an LLM‑centric Q\&A assistant and does not ship with a rich web UI. Integration adds complexity without commensurate benefit.

Based on balancing development speed, enterprise readiness, and long-term maintainability, **Chainlit** best meets our needs.

### Implications

* Engineers will adopt Chainlit and learn its event‑driven chat API (e.g., `@cl.on_message`).
* We can leverage Chainlit’s built-in authentication and feedback mechanisms, reducing custom development for security and observability.
* The UI will be a single-page chat interface accessible on web and mobile browsers, hosted behind corporate SSO.
* Future integration of additional features (file uploads, admin review panels, RAG workflows) aligns with Chainlit’s extensibility.
* If requirements shift (e.g., need for a non-chat dashboard), we may augment Chainlit with FastAPI endpoints or a separate front-end.

## Related

### Related decisions

* Deployment architecture (containerization, load balancing) will accommodate Chainlit’s web service model.
* Logging and monitoring standards will include Chainlit’s built-in telemetry plus external observability tools.

### Related requirements

* Support for LLM-agnostic backends.
* Responsive web/mobile UI.
* Integration with enterprise SSO and audit logging.

### Related artifacts

* Chainlit configuration files (e.g., `chainlit.yaml`).
* Template chat handlers (e.g., `app.py` with `@cl.on_message`).

### Related principles

* **Rapid Prototyping**: Favor frameworks that minimize boilerplate for initial delivery.
* **Separation of Concerns**: Keep LLM logic, retrieval pipelines, and UI layers decoupled.
* **Enterprise Security**: Enforce authentication and auditing at the network or framework level.

## Notes

* Stay up to date on Chainlit’s roadmap, as new features (advanced UI widgets, analytics integrations) may further benefit our use case.
* Evaluate Chainlit’s performance under expected load and plan horizontal scaling strategy.
