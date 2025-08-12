# BMad Planning Chat - User vs LLM Formatted

## Formatting Guide
- **USER INPUT**: Highlighted with GitHub admonitions `> [!IMPORTANT] "User"`
- **LLM RESPONSE**: Regular text with agent context clearly marked
- **CLEAN FORMAT**: BMad interface markers removed for clarity

---

> [!IMPORTANT] **User**
> switch to ux agent

**LLM (BMAD UX Expert):**

🎨 Switched to UX Expert.

Hello! I'm Sally, your UX Expert. My passion is crafting intuitive and beautiful user experiences. I can help you with everything from user research and interaction design to generating powerful prompts for AI UI tools. Every design decision should serve the user's needs.

How can I help you today? Here are my primary commands:

create-front-end-spec: Create a detailed UI/UX Specification document.

generate-ui-prompt: Generate a powerful prompt for AI UI generation tools like v0 or Lovable.

help: Show this list of commands.

exit: Return to the BMad Orchestrator.

> [!IMPORTANT] **User**
> I want you to create an interactive mockup based on the architecture document

**LLM (BMAD Developer):**

Of course! This is an excellent and detailed architecture document. Translating a technical plan like this into a visual, interactive experience is my specialty.

While I don't build the final code myself, I excel at creating powerful, detailed prompts for AI UI generation tools like Vercel's v0 or Lovable.ai. This process will give you an interactive mockup that you can see, click, and refine.

Based on your architecture, I've designed a prompt that captures the core user experience: the main chat interface, role-based personalization, and the "Bring Your Own Key" functionality.

Here is the master prompt. You can copy and paste this into an AI UI generator to create your interactive mockup.

Plaintext

Create a responsive, modern, and professional full-stack application interface for a "CWE ChatBot" using a dark theme. The application should be built with components that resemble the Shadcn UI library and styled with Tailwind CSS, reflecting the aesthetic of the Chainlit framework.

The interface should have a main two-column layout: a collapsible sidebar on the left and the main chat view on the right.

**1. Header Bar:**
- A fixed header at the top of the page.
- On the left, display the title "CWE ChatBot" with a small, abstract security-related icon (like a shield or a keyhole).
- On the right, include a user avatar dropdown. When logged out, it should show a "Sign In" button. When logged in, it should display the user's initial or avatar, and clicking it reveals "Settings" and "Sign Out" options.

**2. Collapsible Left Sidebar:**
- The sidebar should be visible on desktop and tablet, but collapsed by default on mobile, accessible via a hamburger menu icon in the header.
- **Top Section: Conversation History.** A list of past conversations, showing a truncated title for each. A "+ New Chat" button should be at the top of this list.
- **Bottom Section: User Settings.** This section is critical and should contain the following controls:
    - **User Role:** A dropdown menu labeled "Your Role" with the options: "PSIRT Member", "Developer", "Academic Researcher", "Bug Bounty Hunter", "Product Manager", and "Admin". The selected role should be highlighted.
    - **Bring Your Own LLM (BYO):**
        - An input field labeled "LLM API Endpoint".
        - A password-type input field labeled "LLM API Key".
        - A small "info" icon next to the title that shows a tooltip on hover explaining that these settings are securely stored.
    - A "Save Settings" button at the very bottom of the sidebar, which shows a temporary "Saved!" confirmation message upon clicking.

**3. Main Chat View (Right Panel):**
- This area takes up the majority of the screen width.
- **Welcome Screen:** When a new chat is started, display a centered welcome message: "CWE ChatBot", with a subtitle "Your AI-powered assistant for understanding the Common Weakness Enumeration." Below this, show 2-3 example prompt buttons like "Explain CWE-79" or "How do I prevent SQL Injection?".
- **Conversation Display:**
    - User prompts should be aligned to the right with a slightly different background color.
    - Chatbot responses should be aligned to the left.
    - Responses should support streaming text to appear as if they are being typed in real-time.
    - Render Markdown correctly, especially for code blocks (with a copy button) and lists.
    - Any mention of a CWE (e.g., "CWE-79") should be automatically rendered as a clickable link.
- **Chat Input Form:**
    - A fixed input area at the bottom of the screen.
    - It should contain a text input field that expands vertically as the user types.
    - A "Send" button with a paper plane icon. The button should be disabled when the input field is empty.
    - A button to allow file uploads (for FR25).

**Responsiveness:**
- On mobile screens, the left sidebar should be hidden. A hamburger icon in the header should toggle it as an overlay drawer that slides in from the left.
- The chat view should take up the full screen width on mobile.
Next Steps
Copy the prompt from the code block above.

Paste it into an AI UI generation tool of your choice (e.g., Vercel's v0).

Iterate and Refine: The tool will generate an interactive component. You can then give it follow-up instructions like "change the primary color to blue" or "make the input box larger" to refine the design.

<br>
<important_note>Please remember that all AI-generated code will require careful human review, testing, and refinement to be considered production-ready. This mockup is an excellent starting point for visualizing the user experience.</important_note>
