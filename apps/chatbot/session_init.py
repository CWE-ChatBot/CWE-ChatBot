#!/usr/bin/env python3
"""
Session initialization helper for Chainlit chat sessions.

This pulls almost all logic out of @cl.on_chat_start in main.py
to reduce cyclomatic complexity and make the startup path testable.

Responsibilities:
- Startup sanity and auth gating
- CSRF token creation and session state wiring
- Persona + OAuth enrichment of UserContext
- UI bootstrapping (settings panel, hint bubble)
- One-time welcome/onboarding messages
"""

import time
from typing import Any, List

import chainlit as cl
from chainlit.input_widget import InputWidget, Select, Switch
from src.security import CSRFManager
from src.security.secure_logging import get_secure_logger
from src.ui import UISettings
from src.user_context import UserPersona
from src.utils.session import get_user_context

logger = get_secure_logger(__name__)


class SessionInitializer:
    """
    Orchestrates first-connection experience.

    main.py's @cl.on_chat_start becomes a tiny wrapper that calls `await run()`.
    """

    def __init__(
        self,
        *,
        app_config: Any,
        conversation_manager: Any,
        requires_authentication_fn,
        is_user_authenticated_fn,
    ) -> None:
        self.app_config = app_config
        self.cm = conversation_manager
        self._requires_authentication = requires_authentication_fn
        self._is_user_authenticated = is_user_authenticated_fn

    async def run(self) -> None:
        """
        Entry point called by main.start().

        High-level:
        1. Abort early if system isn't ready
        2. Enforce auth policy (if needed)
        3. Prepare session state (CSRF, persona, OAuth -> UserContext, UI settings)
        4. Render UI + onboarding content if first time this session
        """
        if not await self._check_startup_ready():
            return

        if not await self._check_auth():
            return

        persona = await self._prepare_session_state()

        # Avoid duplicate onboarding on reconnect (WebSocket reconnect every ~150s)
        if cl.user_session.get("welcome_sent"):
            logger.debug(
                "SessionInitializer.run(): welcome already sent, skipping onboarding"
            )
            return

        await self._render_settings_panel()
        await self._maybe_send_ui_hint()
        await self._send_welcome_sequence(persona)

        # Mark that we've done first-time onboarding for this Chainlit session
        cl.user_session.set("welcome_sent", True)
        logger.debug("SessionInitializer.run(): onboarding marked as sent")

    async def _check_startup_ready(self) -> bool:
        """
        Verify ConversationManager + init_ok are healthy enough to serve.
        Mirrors the early-escape in original start().
        """
        if not self.cm:
            # This matches the old failure message
            await cl.Message(
                content=(
                    "Startup error: configuration missing or database unavailable. "
                    "Please check environment (GEMINI_API_KEY/DB)."
                )
            ).send()
            logger.error(
                "SessionInitializer: conversation_manager missing or init not OK"
            )
            return False
        return True

    async def _check_auth(self) -> bool:
        """
        Enforce OAuth requirement if configured.
        Sends the '🔒 Authentication required...' message if blocked.
        """
        if self._requires_authentication() and not self._is_user_authenticated():
            await cl.Message(
                content=(
                    "🔒 Authentication required. Please authenticate using Google or "
                    "GitHub to access the CWE ChatBot."
                ),
                author="System",
            ).send()
            logger.info("SessionInitializer: blocked unauthenticated user")
            return False
        return True

    async def _prepare_session_state(self) -> str:
        """
        Sets up per-session runtime state:
        - CSRF token
        - Default UI settings in cl.user_session
        - Persona sync from chat_profile → UserContext
        - OAuth enrichment of UserContext (email/name/avatar/etc.)
        - Activity timestamp + auth metadata
        Returns the resolved persona string.
        """
        # --- CSRF token generation / storage ---
        try:
            csrf_manager = CSRFManager()
            csrf_token = csrf_manager.generate_token()
            csrf_manager.set_session_token(csrf_token)
            logger.debug("SessionInitializer: CSRF token generated and stored")
        except Exception as e:
            # Non-fatal: continue serving
            logger.warning(f"SessionInitializer: CSRF token generation failed: {e}")

        # --- Default UI settings for this session ---
        default_settings = UISettings()
        cl.user_session.set("ui_settings", default_settings.dict())

        # --- Persona selection from Chainlit chat profile ---
        selected_profile = cl.user_session.get("chat_profile")
        persona = (
            selected_profile
            if isinstance(selected_profile, str)
            and selected_profile in UserPersona.get_all_personas()
            else UserPersona.DEVELOPER.value
        )

        # --- Sync persona + OAuth info into persistent-ish UserContext ---
        # NOTE: get_user_context() creates/returns the per-session UserContext
        user_context = get_user_context()

        # keep persona aligned
        if user_context.persona != persona:
            user_context.persona = persona

        # OAuth enrichment (if enabled + user is authenticated)
        if self._requires_authentication() and self._is_user_authenticated():
            user = cl.user_session.get("user")
            if user and hasattr(user, "metadata") and user.metadata:
                try:
                    user_context.set_oauth_data(
                        provider=user.metadata.get("provider"),
                        email=user.metadata.get("email"),
                        name=user.metadata.get("name"),
                        avatar_url=user.metadata.get("avatar_url"),
                    )
                    # Track activity
                    user_context.update_activity()

                    # Mirror a few useful auth facts into Chainlit session
                    cl.user_session.set("auth_timestamp", time.time())
                    cl.user_session.set("auth_provider", user.metadata.get("provider"))
                    cl.user_session.set("auth_email", user.metadata.get("email"))

                    logger.info(
                        "SessionInitializer: OAuth data integrated for "
                        f"{user.metadata.get('email')}"
                    )
                except Exception as e:
                    # We intentionally surface the same warning message as the original code.
                    logger.log_exception(
                        "SessionInitializer: OAuth integration error", e
                    )
                    await cl.Message(
                        content=(
                            "⚠️ Authentication integration error. Some features may not "
                            "work properly. Please try refreshing the page."
                        ),
                        author="System",
                    ).send()
        else:
            # OAuth disabled / open-access mode
            logger.info(
                f"SessionInitializer: OAuth disabled or not required, persona={persona}"
            )

        return persona

    async def _render_settings_panel(self) -> None:
        """
        Renders the Chainlit settings UI (detail level / examples / mitigations).
        Matches the behavior of the original try/except block.
        """
        try:
            ui_settings = cl.user_session.get("ui_settings") or UISettings().dict()

            widgets: List[InputWidget] = [
                Select(
                    id="detail_level",
                    label="Detail Level",
                    items={
                        "basic": "basic",
                        "standard": "standard",
                        "detailed": "detailed",
                    },
                    initial=ui_settings["detail_level"],
                    description="How much detail to include",
                ),
                Switch(
                    id="include_examples",
                    label="Include Code Examples",
                    initial=ui_settings["include_examples"],
                ),
                Switch(
                    id="include_mitigations",
                    label="Include Mitigations",
                    initial=ui_settings["include_mitigations"],
                ),
            ]
            settings_panel = cl.ChatSettings(widgets)
            await settings_panel.send()
            logger.debug("SessionInitializer: settings panel sent")
        except Exception as e:
            logger.log_exception(
                "SessionInitializer: Failed to render settings panel", e
            )

    async def _maybe_send_ui_hint(self) -> None:
        """
        Sends the one-time "💡 tip" message explaining persona selector + gear icon.
        Preserves the original guard via user_session['ui_hint_shown'].
        """
        try:
            if not cl.user_session.get("ui_hint_shown"):
                tip = (
                    "Use the Persona selector in the top bar to switch roles, "
                    "and the gear next to the input to adjust detail level, "
                    "examples, and mitigations."
                )
                await cl.Message(content=f"💡 {tip}", author="System").send()
                cl.user_session.set("ui_hint_shown", True)
                logger.debug("SessionInitializer: UI hint sent")
        except Exception as e:
            logger.log_exception("SessionInitializer: Failed to send UI hint", e)

    async def _send_welcome_sequence(self, persona: str) -> None:
        """
        Sends:
        - Persona-aware welcome text
        - Persona guide block
        - Example query actions (persona-dependent)
        """
        # --- Welcome message (personalized if OAuth is active and user is authenticated) ---
        welcome_string = self._build_welcome_text()
        await cl.Message(content=welcome_string).send()

        # --- Persona guide content as inline expandable element ---
        persona_info = self._build_persona_info_text()
        persona_element = cl.Text(
            name="Persona Guide", content=persona_info, display="inline"
        )

        # --- Example query call-to-action ---
        examples_intro = (
            "**🚀 Step 3: Try Example Queries**\n\n"
            "Click any button below to ask a common security question, "
            "or type your own question in the chat:"
        )

        actions = self._build_example_actions(persona)

        await cl.Message(
            content=examples_intro,
            actions=actions,
            elements=[persona_element],
        ).send()

    def _build_welcome_text(self) -> str:
        """
        Recreates the behavior of the original welcome message block,
        including OAuth-aware variants.
        """
        if self._requires_authentication():
            user = cl.user_session.get("user")
            if user and hasattr(user, "metadata") and user.metadata:
                user_name = (
                    user.metadata.get("name")
                    or (user.metadata.get("email", "").split("@")[0])
                )
                provider = (user.metadata.get("provider", "OAuth") or "OAuth").title()
                greeting = (
                    f"Welcome back, {user_name}! 🛡️\n\n"
                    f"*Authenticated via {provider}*\n\n"
                    "🔐 *Your session is secure and your persona preferences will be saved.*"
                )
            else:
                greeting = "Welcome to the CWE ChatBot! 🛡️\n\n*Authentication enabled*"
        else:
            greeting = (
                "Welcome to the CWE ChatBot! 🛡️\n\n"
                "*Running in open access mode (OAuth disabled)*"
            )

        body = (
            "\n\nI'm here to help you with Common Weakness Enumeration (CWE) information. "
            "Let me guide you through getting started:\n\n"
            "**🎯 Step 1: Choose Your Role**\n"
            "Use the Persona selector in the top bar to select your cybersecurity role for tailored responses.\n\n"
            "**⚙️ Step 2: Customize Settings**\n"
            "Click the gear icon next to the input to adjust:\n"
            "• **Detail Level**: Basic (summaries), Standard (balanced), or Detailed (comprehensive)\n"
            "• **Examples**: Toggle code examples and demonstrations\n"
            "• **Mitigations**: Include/exclude prevention guidance"
        )
        return f"{greeting}{body}"

    def _build_persona_info_text(self) -> str:
        """
        Same persona guide list from the original start().
        """
        return (
            "**Available Personas:**\n\n"
            "• **PSIRT Member** 🛡️ - Impact assessment and security advisory creation\n"
            "• **Developer** 💻 - Remediation steps and secure coding examples\n"
            "• **Academic Researcher** 🎓 - Comprehensive analysis and CWE relationships\n"
            "• **Bug Bounty Hunter** 🔍 - Exploitation patterns and testing techniques\n"
            "• **Product Manager** 📊 - Business impact and prevention strategies\n"
            "• **CWE Analyzer** 🔬 - CVE-to-CWE mapping analysis with confidence scoring\n"
            "• **CVE Creator** 📝 - Structured CVE vulnerability descriptions\n\n"
            "Each persona provides responses tailored to your specific needs and expertise level."
        )

    def _build_example_actions(self, persona: str) -> List[cl.Action]:
        """
        Recreates the persona-dependent example button sets from main.start().

        NOTE: we keep the payload text identical to preserve downstream behavior,
        because handle_example_query_action() depends on these payloads.
        """
        if persona == "CWE Analyzer":
            return [
                cl.Action(
                    name="example_nvidia_cve",
                    label="🔬 Analyze NVIDIA vulnerability",
                    payload={
                        "query": (
                            "NVIDIA Base Command Manager contains a missing "
                            "authentication vulnerability in the CMDaemon component. "
                            "A successful exploit of this vulnerability might lead to code "
                            "execution, denial of service, escalation of privileges, "
                            "information disclosure, and data tampering."
                        )
                    },
                ),
                cl.Action(
                    name="example_phpgurukul_cve",
                    label="🔬 Analyze PHPGurukul SQL injection",
                    payload={
                        "query": (
                            "A vulnerability has been found in PHPGurukul Boat "
                            "Booking System 1.0 and classified as critical. Affected "
                            "by this vulnerability is an unknown functionality of the "
                            "file book-boat.php?bid=1 of the component Book a Boat Page. "
                            "The manipulation of the argument nopeople leads to sql "
                            "injection. The attack can be launched remotely. The exploit "
                            "has been disclosed to the public and may be used."
                        )
                    },
                ),
                cl.Action(
                    name="example_wordpress_xss",
                    label="🔬 Analyze WordPress XSS vulnerability",
                    payload={
                        "query": (
                            "The Advanced Schedule Posts WordPress plugin through "
                            "2.1.8 does not sanitise and escape a parameter before "
                            "outputting it back in the page, leading to a Reflected "
                            "Cross-Site Scripting which could be used against high "
                            "privilege users such as admins."
                        )
                    },
                ),
            ]

        if persona == "CVE Creator":
            return [
                cl.Action(
                    name="example_tomcat_cve",
                    label="📝 Apache Tomcat DoS (CVE-2023-24998 fix incomplete)",
                    payload={
                        "query": (
                            "Fix for CVE-2023-24998 was incomplete\n"
                            "Severity: Moderate\n"
                            "Vendor: The Apache Software Foundation\n"
                            "Versions Affected:\n"
                            "Apache Tomcat 11.0.0-M2 to 11.0.0-M4\n"
                            "Apache Tomcat 10.1.5 to 10.1.7\n"
                            "Apache Tomcat 9.0.71 to 9.0.73\n"
                            "Apache Tomcat 8.5.85 to 8.5.87\n"
                            "Description:\n"
                            "The fix for CVE-2023-24998 was incomplete. If non-default "
                            "HTTP connector settings were used such that the "
                            "maxParameterCount could be reached using query string "
                            "parameters and a request was submitted that supplied "
                            "exactly maxParameterCount parameters in the query string, "
                            "the limit for uploaded request parts could be bypassed "
                            "with the potential for a denial of service to occur.\n"
                            "Mitigation:\n"
                            "Users of the affected versions should apply one of the "
                            "following mitigations:\n"
                            "Upgrade to Apache Tomcat 11.0.0-M5 or later\n"
                            "Upgrade to Apache Tomcat 10.1.8 or later\n"
                            "Upgrade to Apache Tomcat 9.0.74 or later\n"
                            "Upgrade to Apache Tomcat 8.5.88 or later"
                        )
                    },
                ),
                cl.Action(
                    name="example_rocketmq_rce",
                    label="📝 Apache RocketMQ RCE (missing auth)",
                    payload={
                        "query": (
                            "Affected versions:\n\n"
                            "- Apache RocketMQ through 5.1.0\n\n"
                            "Description:\n\n"
                            "For RocketMQ versions 5.1.0 and below, under certain "
                            "conditions, there is a risk of remote command execution.\n\n"
                            "Several components of RocketMQ, including NameServer, "
                            "Broker, and Controller, are leaked on the extranet and "
                            "lack permission verification, an attacker can exploit this "
                            "vulnerability by using the update configuration function "
                            "to execute commands as the system users that RocketMQ is "
                            "running as. Additionally, an attacker can achieve the same "
                            "effect by forging the RocketMQ protocol content.\n\n"
                            "To prevent these attacks, users are recommended to "
                            "upgrade to version 5.1.1 above for using RocketMQ 5.x or "
                            "4.9.6 above for using RocketMQ 4.x ."
                        )
                    },
                ),
                cl.Action(
                    name="example_netfilter_overflow",
                    label="📝 Linux netfilter stack overflow (nft_payload)",
                    payload={
                        "query": (
                            "> The vulnerability consists of a stack buffer overflow "
                            "due to an integer underflow vulnerability inside the "
                            "nft_payload_copy_vlan function, which is invoked with "
                            "nft_payload expressions as long as a VLAN tag is present "
                            "in the current skb.\n"
                            "(full technical analysis continues...)"
                        )
                    },
                ),
            ]

        # Default persona (Developer / PSIRT / etc.)
        return [
            cl.Action(
                name="example_cwe79",
                label="🛡️ What is CWE-79 and how do I prevent it?",
                payload={"query": "What is CWE-79 and how do I prevent it?"},
            ),
            cl.Action(
                name="example_sql_injection",
                label="💉 Show me SQL injection prevention techniques",
                payload={"query": "Show me SQL injection prevention techniques"},
            ),
            cl.Action(
                name="example_xss_types",
                label="🔍 Explain the types of XSS",
                payload={"query": "Explain the types of XSS"},
            ),
        ]
