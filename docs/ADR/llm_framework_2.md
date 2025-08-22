### **Addendum: Re-evaluation of Chainlit Framework Choice**

**Date:** August 14, 2025

**Status:** Supersedes previous status with new context, but affirms the original decision.

#### **1. Context**

This addendum addresses new information regarding the maintenance status of the Chainlit project. As of May 2025, the project is no longer actively maintained by the original team and has transitioned to community-led maintenance. This change prompted a re-evaluation of our decision documented in the original ADR.

#### **2. Analysis of Impact**

The transition to community maintenance introduces a potential risk regarding the long-term velocity of development, official support, and the timeliness of security patches. However, the framework's current feature set is stable and complete for our immediate project goals.

#### **3. Decision**

We will **continue to use Chainlit** for the initial development and MVP of the CWE Mapping Chatbot.

#### **4. Rationale**

* **Sufficient for MVP:** The current state of Chainlit is mature and provides all necessary functionality for our initial requirements. The immediate benefits have not changed.
* **Development Velocity:** Migrating to an alternative framework at this stage would introduce significant delays and rework, negating the primary advantage of rapid prototyping that led to Chainlit's selection.
* **Mitigatable Risk:** The risk associated with community maintenance is primarily long-term. We can mitigate this by actively monitoring the project's health (e.g., community activity, response to issues, release cadence).

We will proceed with Chainlit as planned, accepting the new long-term risk in favor of maintaining project momentum. We will formally re-evaluate this choice if the community maintenance proves insufficient for our security or feature needs in the future.