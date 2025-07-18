
## Architectural Decision Records (ADRs): What and Why

This README provides an overview of Architectural Decision Records (ADRs), explaining what they are and why they are a valuable practice in software development.


## Laws of Software Architecture

[Fundamentals of Software Architecture](https://www.oreilly.com/library/view/fundamentals-of-software/9781492043447/), Mark Richards & Neal Ford, defines some fundamental Laws of Software Architecture.

### First Law of Software Architecture

**"Everything in software architecture is a trade-off."**

- Corollary 1:  If an architect thinks they have discovered something that isn’t a trade-off, more likely they just haven’t identified the trade-off yet.


### Second Law of Software Architecture

**"Why is more important than how."**


### What are ADRs?

An Architectural Decision Record (ADR) is a concise document that captures a significant architectural choice made about a software system. It records the context, the decision itself, and the consequences. Think of it as a snapshot in time explaining a key "why" behind the system's design.

ADRs are typically lightweight and immutable once accepted, forming an append-only log of the project's architectural evolution.

ADRs should capture the **tradeoff considerations**, and the **why** per the Laws of Software Architecture.

### Why use ADRs?

Implementing ADRs offers several key benefits for software development teams:

* **Knowledge Capture and Transfer:** ADRs document the reasoning behind significant decisions, preventing the loss of crucial context as team members join or leave. This is vital for onboarding new members and understanding historical choices. 
* **Improved Communication and Alignment:** By clearly articulating decisions and their rationale, ADRs ensure that all stakeholders understand the motivations and implications of architectural choices, fostering alignment across teams.
* **Preventing Relitigation:** A documented decision with its context and consequences reduces the likelihood of the same discussions and debates recurring.
* **Facilitating Audits and Compliance:** ADRs provide a historical log of decisions, which can be essential for audits, compliance requirements, and understanding the system's evolution.
* **Supporting Asynchronous Decision Making:** ADRs allow for review and feedback outside of synchronous meetings, streamlining the decision-making process.
* **Providing Context for Code:** ADRs explain *why* the code is the way it is, offering valuable insight beyond the implementation details themselves.

In essence, ADRs serve as a collective memory for architectural decisions, ensuring clarity, consistency, and maintainability throughout the software lifecycle.

**References:**

* [Using architectural decision records to streamline technical decision-making for a software development project](https://docs.aws.amazon.com/prescriptive-guidance/latest/architectural-decision-records/welcome.html), March 2022
* [Fundamentals of Software Architecture](https://www.oreilly.com/library/view/fundamentals-of-software/9781492043447/), Mark Richards & Neal Ford
* [Architecture Decision Records (ADRs)](https://adr.github.io/)
* [Can LLMs Generate Architectural Design Decisions? - An Exploratory Empirical study](https://arxiv.org/html/2403.01709v1), Mar 2024
* Example ADR https://github.com/joelparkerhenderson/architecture-decision-record/tree/main/locales/en/examples/programming-languages




 


 




