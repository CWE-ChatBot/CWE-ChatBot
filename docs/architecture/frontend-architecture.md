# Frontend Architecture

This section details the frontend-specific architectural considerations and patterns for the CWE ChatBot, focusing on leveraging Chainlit's capabilities and extending them for custom UI/UX requirements.

## Component Architecture

The UI will be built upon Chainlit's integrated component system, which utilizes React internally. Custom components will be developed to extend Chainlit's native functionality, adhering to defined styling and interaction patterns.

  * **Component Organization:** Custom React components or Chainlit elements will be organized in a clear directory structure, such as `app/frontend/src/components` (if custom React components are served by Chainlit's static files) or within Python files if leveraging Chainlit's direct UI element definitions (`cl.Message`, `cl.AskUserMessage`, `cl.Action`).

  * **Component Template (Conceptual - Python/Chainlit Paradigm):** This illustrates how custom UI logic or content might be defined and sent within the Chainlit backend to be rendered in the frontend.

    ```python
    # In your main Chainlit app.py or a custom module
    import chainlit as cl
    from chainlit.types import AskFileMessage, AskUserMessage, Audio, Image, Text, Pdf, Video, Action, Element, Task, TaskList

    @cl.step(type="ui_component_interaction") # Example of a custom step type
    async def display_custom_settings_ui(user_id: str):
        # This is a conceptual representation. In reality, you'd send cl.Message
        # with elements that trigger custom React components, or use Chainlit's native elements.
        settings_card = Text(
            name="user_settings_card",
            content=f"""
            ## User Settings for {user_id}
            - **Role:** Developer
            - **LLM Config:** Custom API
            
            [Edit Role](link/to/role/edit) | [Manage LLM API Key](link/to/key/manage)
            """,
            language="markdown"
        )
        await cl.Message(
            content="Here are your current settings:",
            elements=[settings_card],
            actions=[cl.Action(name="refresh_settings", label="Refresh Settings")]
        ).send()

    # @cl.action("edit_role") - would trigger a backend action from frontend interaction
    # async def handle_edit_role(): ...
    ```

  * **Naming Conventions:** Consistent PascalCase for React component names (if custom React components are used) and snake\_case for Python module/function names related to Chainlit UI elements.

## State Management Architecture

Chainlit provides built-in mechanisms for managing user session state. For any global UI state beyond session context, standard Python patterns or Chainlit's capabilities will be leveraged.

  * **Store Structure:** Chainlit primarily manages state per user session via `cl.user_session`. This object is directly accessible within Chainlit message handlers and functions.

  * **State Management Patterns:**

      * **Chainlit Session State (`cl.user_session`):** For storing user-specific data that persists across messages within a session (e.g., user role, current conversation context, preferences). This aligns with NFR35 (Session Context Preservation).
      * **Local Python Variables:** For transient state within a single function call.
      * **Database Persistence:** For state that needs to persist across sessions or be shared/audited (e.g., `User` preferences, `Conversation` history, stored in PostgreSQL).

    <!-- end list -->

    ```python
    # Example of Chainlit session state usage
    import chainlit as cl

    @cl.on_chat_start
    async def start():
        # Initialize user-specific session state at the start of a conversation
        cl.user_session.set("user_role", "general") # Default role
        await cl.Message(content="What is your role today? (Developer, PSIRT Member, etc.)").send()

    @cl.on_message
    async def update_role(message: cl.Message):
        if "my role is" in message.content.lower():
            if "developer" in message.content.lower():
                cl.user_session.set("user_role", "Developer")
                await cl.Message(content="Understood, I will tailor responses for a Developer.").send()
            # ... handle other roles
        current_role = cl.user_session.get("user_role")
        await cl.Message(content=f"Current role in session: {current_role}").send()
    ```

## Routing Architecture

Chainlit intrinsically handles the routing for the main conversational interface. For any supplementary web pages (e.g., a dedicated settings dashboard), these would either be separate routes managed by Chainlit or a minimal web framework integrated within the Chainlit application.

  * **Route Organization:**
      * The primary chatbot UI is served directly by Chainlit's internal routing.
      * Custom web pages (e.g., `/settings`, `/profile`) would be managed as part of the main Chainlit Python application using standard web framework patterns (e.g., Flask/FastAPI routes within the Chainlit app if extended, or external static files served by Chainlit).
  * **Protected Route Pattern:** Authentication and authorization will be handled by Chainlit's built-in authentication hooks (NFR34). These hooks enable securing routes or specific functionalities based on user login status and roles.

## Internal Service Interaction Patterns (within Chainlit Backend)

This layer defines how the Python Chainlit application and its logical components communicate with each other, and with external APIs like LLMs.

  * **API Client Setup:** For interacting with external LLM APIs (FR28), embedding models, or other external services, standard Python HTTP clients (`httpx` for async, `requests` for sync) will be used. These clients will be configured with necessary authentication headers (e.g., API keys, OAuth tokens) and robust error handling.
    ```python
    # Python example for calling an external LLM API from the Chainlit backend
    import httpx
    import os

    async def call_byo_llm_api(endpoint: str, api_key: str, prompt: str, model_name: str):
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": model_name,
            "messages": [{"role": "user", "content": prompt}]
        }
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(endpoint, headers=headers, json=payload, timeout=60.0)
                response.raise_for_status() # Raises HTTPStatusError for bad responses (4xx/5xx)
                return response.json()["choices"][0]["message"]["content"]
        except httpx.RequestError as exc:
            print(f"An error occurred while requesting {exc.request.url!r}: {exc}")
            raise # Re-raise to be handled by higher level
        except httpx.HTTPStatusError as exc:
            print(f"Error response {exc.response.status_code} while requesting {exc.request.url!r}: {exc.response.text}")
            raise # Re-raise
    ```
  * **Service Example:** Interactions between logical components (e.g., `Chatbot Application` calling `NLP/AI Service` or `User Management Service`) will be achieved through direct Python function calls, class instantiations, or dependency injection patterns, optimizing for performance within the unified Python backend.
