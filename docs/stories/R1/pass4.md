here’s a concrete, dev-ready plan with targeted diffs/snippets you can hand to an engineer. I grouped by the feedback buckets (P1→P3), showed file paths, and included test hooks + rollout notes.

P1 — High-priority refactors
1) Unify state on cl.user_session (remove UserContextManager)
A. Repo changes

Delete: apps/chatbot/src/user_context_manager.py (or wherever it lives)

Add: apps/chatbot/src/utils/session.py

# apps/chatbot/src/utils/session.py
from __future__ import annotations
import chainlit as cl
from typing import Optional
from apps.chatbot.src.user_context import UserContext

SESSION_KEY = "user_context"

def get_user_context() -> UserContext:
    ctx: Optional[UserContext] = cl.user_session.get(SESSION_KEY)
    if ctx is None:
        ctx = UserContext()
        cl.user_session.set(SESSION_KEY, ctx)
    return ctx

def set_user_context(ctx: UserContext) -> None:
    cl.user_session.set(SESSION_KEY, ctx)

B. ConversationManager uses one source of truth
# apps/chatbot/src/conversation.py (only the relevant parts)
from apps.chatbot.src.utils.session import get_user_context
# remove any imports of UserContextManager

class ConversationManager:
    async def process_user_message_streaming(self, session_id: str, message_content: str, message_id: str):
        context = get_user_context()
        # ... rest unchanged except: never touch any global manager

C. (Temporary) guard to catch stragglers

Search for UserContextManager and remove. If you want to fail fast:

# apps/chatbot/src/user_context_manager.py
raise RuntimeError("UserContextManager has been removed. Use utils.session.get_user_context().")

D. Tests

Update any tests importing UserContextManager.

New unit test: tests/unit/test_session_context.py

from apps.chatbot.src.utils.session import get_user_context, set_user_context
def test_session_context_smoke(monkeypatch):
    store = {}
    class Dummy:
        def get(self, k): return store.get(k)
        def set(self, k, v): store[k] = v
    monkeypatch.setattr("chainlit.user_session", Dummy())  # type: ignore
    ctx = get_user_context()
    assert ctx is not None
    ctx.persona = "Developer"
    set_user_context(ctx)
    assert get_user_context().persona == "Developer"

2) Consolidate query preprocessing via QueryProcessor
A. Make QueryProcessor the single entry

(If you already have it, align the API; otherwise create it.)

# apps/chatbot/src/processing/query_processor.py
from __future__ import annotations
from typing import Any, Dict
from apps.chatbot.src.input_security import InputSanitizer
from apps.chatbot.src.processing.followup_processor import FollowupProcessor

class QueryProcessor:
    def __init__(self):
        self.sanitizer = InputSanitizer()
        self.followups = FollowupProcessor()

    def process_with_context(self, raw: str, session_hint: Dict[str, Any]) -> Dict[str, Any]:
        san = self.sanitizer.sanitize_input(raw)
        intent = self.followups.detect(raw, session_hint)  # returns dict with is_followup, intent, targets
        return {
            "sanitized_query": san.text,
            "query_type": san.query_type,           # e.g., 'cwe_lookup'/'general' etc.
            "security_check": san.security_check,   # {is_safe: bool, reasons: [...]}
            "followup": intent,
            "tokens": san.tokens,
        }

B. ConversationManager delegates to it
# apps/chatbot/src/conversation.py
from apps.chatbot.src.processing.query_processor import QueryProcessor
from apps.chatbot.src.utils.session import get_user_context
# keep SecurityValidator for *response* validation

class ConversationManager:
    def __init__(self, ...):
        self.query_processor = QueryProcessor()
        # self.input_sanitizer = ...  # remove direct use

    async def process_user_message_streaming(...):
        context = get_user_context()
        processed = self.query_processor.process_with_context(
            message_content, context.get_session_context_for_processing()
        )
        if not processed["security_check"]["is_safe"]:
            return await self._respond_blocked(processed)  # graceful fallback

        q = processed["sanitized_query"]
        # pass persona prefs unchanged
        result = await self.query_handler.process_query(q, context.get_persona_preferences())
        # ... continue with generation

C. Tests

tests/unit/test_query_processor.py covers: sanitization path, follow-up detection path, and security flags.

3) Fix brittle imports & packaging
A. Layout
repo/
├─ pyproject.toml
├─ apps/chatbot/src/
│  └─ apps/chatbot/src/__init__.py
│  └─ apps/chatbot/src/query_handler.py
│  └─ apps/chatbot/src/cwe_ingestion/   # move ingestion here as a subpackage
│     ├─ __init__.py
│     ├─ pg_chunk_store.py
│     └─ embedder.py

B. pyproject.toml (minimal)
[project]
name = "cwe-chatbot"
version = "0.1.0"
requires-python = ">=3.10"
dependencies = [
  "chainlit>=0.7,<0.9",
  "pydantic>=2",
  "python-dotenv",
  "psycopg[binary]>=3",
  # ... your other deps
]

[tool.setuptools.packages.find]
where = ["apps/chatbot/src"]
include = ["apps.chatbot*"]


Dev: pip install -e . from repo root.

C. Replace path hacks

Before:

# query_handler.py
import sys, os
sys.path.append(os.getenv("CWE_INGESTION_PATH", "..."))
from pg_chunk_store import PostgresChunkStore


After:

# apps/chatbot/src/query_handler.py
from apps.chatbot.src.cwe_ingestion.pg_chunk_store import PostgresChunkStore

D. CI/Lint

Ensure PYTHONPATH not required.

Run ruff/mypy to flush stragglers.

P2 — Medium-priority simplifications
1) Merge RoleManager into UserContext (or keep a tiny service)
A. Fold persona logic into UserContext
# apps/chatbot/src/user_context.py
from dataclasses import dataclass, field
from enum import Enum
import time
import chainlit as cl
import logging

logger = logging.getLogger(__name__)

class UserPersona(str, Enum):
    PSIRT = "PSIRT Member"
    DEVELOPER = "Developer"
    ACADEMIC = "Academic Researcher"
    BUG_BOUNTY = "Bug Bounty Hunter"
    PRODUCT_MANAGER = "Product Manager"
    CWE_ANALYZER = "CWE Analyzer"
    CVE_CREATOR = "CVE Creator"

    @classmethod
    def is_valid_persona(cls, val: str) -> bool:
        return val in {p.value for p in cls}

@dataclass
class UserContext:
    persona: str = UserPersona.DEVELOPER.value
    last_cwes_discussed: list[str] = field(default_factory=list)
    last_activity_ts: float = field(default_factory=lambda: time.time())

    def set_persona(self, persona_value: str) -> bool:
        if UserPersona.is_valid_persona(persona_value):
            self.persona = persona_value
            self.update_activity()
            logger.info("Persona set to %s", persona_value)
            return True
        logger.warning("Invalid persona attempted: %s", persona_value)
        return False

    def update_activity(self) -> None:
        self.last_activity_ts = time.time()

    def get_session_context_for_processing(self) -> dict:
        return {"persona": self.persona, "last_cwes": self.last_cwes_discussed[-5:]}

    def get_role_actions_for_chainlit(self) -> list:
        return [
            cl.Action(
                name=f"select_role_{p.name.lower()}",
                value=p.value,
                label=p.value,
                description=self._persona_desc(p),
            )
            for p in UserPersona
        ]

    def _persona_desc(self, p: UserPersona) -> str:
        return {
            UserPersona.DEVELOPER: "Code-level fixes & examples",
            UserPersona.PSIRT: "Impact, advisories, risk",
            UserPersona.ACADEMIC: "Theory & taxonomy",
            UserPersona.BUG_BOUNTY: "Exploitability & tips",
            UserPersona.PRODUCT_MANAGER: "Risk & prioritization",
            UserPersona.CWE_ANALYZER: "CWE taxonomy deep-dives",
            UserPersona.CVE_CREATOR: "CVE narrative & evidence",
        }[p]

B. Remove/retire RoleManager

Delete file or leave shim that forwards to UserContext with deprecation warnings.

Update imports in main.py, conversation.py, etc.

C. Test

tests/unit/test_user_context_persona.py: set/get persona, invalid persona, actions count == number of enum members.

2) Unify streaming vs. non-streaming
# apps/chatbot/src/conversation.py
class ConversationManager:
    async def _process_message_core(self, message_content: str) -> dict:
        ctx = get_user_context()
        processed = self.query_processor.process_with_context(
            message_content, ctx.get_session_context_for_processing()
        )
        if not processed["security_check"]["is_safe"]:
            return {"status": "blocked", "reasons": processed["security_check"]["reasons"]}

        q = processed["sanitized_query"]
        retrieval = await self.query_handler.process_query(q, ctx.get_persona_preferences())
        gen = await self.response_generator.generate(retrieval, ctx.persona, processed)
        return {
            "status": "ok",
            "retrieval": retrieval,
            "response": gen["text"],
            "meta": gen.get("meta", {}),
        }

    async def process_user_message(self, session_id: str, message_content: str):
        result = await self._process_message_core(message_content)
        return result  # non-stream path returns dict

    async def process_user_message_streaming(self, session_id: str, message_content: str, message_id: str):
        result = await self._process_message_core(message_content)
        # Stream or send once based on result
        # ...


Tests: tests/integration/test_conversation_paths.py asserts identical payload structure.

P3 — Low-priority quality improvements
1) Improve security regexes
# apps/chatbot/src/input_security.py
import re

DANGEROUS_CMDS = r"(?:rm|wget|curl|bash|sh|nc|ncat|powershell|cmd|scp|ftp|tftp|python|perl)"
# Anchor to line starts or semicolon chain, require a command-like token
CMD_INJECTION = re.compile(
    rf"""(?mi)
    (?: ^\s*(?:sudo\s+)?{DANGEROUS_CMDS}\b )     # begin of line command
    |
    (?: [;&|]\s*(?:sudo\s+)?{DANGEROUS_CMDS}\b ) # command chaining
    """,
    re.VERBOSE,
)

PIPE_ABUSE = re.compile(r"(?m)(?:^|\s)\|\s*(?:sh|bash)\b", re.IGNORECASE)

def looks_like_teaching_example(text: str) -> bool:
    # allow-list heuristics for explainer content
    return bool(re.search(r"(example|demo|explain|what is|how does).{0,40}(command|pipe|shell)", text, re.I))

class InputSanitizer:
    def sanitize_input(self, text: str):
        # ...
        injection_hits = bool(CMD_INJECTION.search(text) or PIPE_ABUSE.search(text))
        if injection_hits and not looks_like_teaching_example(text):
            # flag, not block (unless strict mode)
            pass


Unit test for both true positives and teaching allow-list cases.

2) Persona strategy pattern
A. Policy interface + handlers
# apps/chatbot/src/personas/policy.py
from __future__ import annotations
from typing import Dict, Any, List

class PersonaPolicy:
    name: str = "Generic"
    def preprocess(self, q: str, ctx: Dict[str, Any]) -> Dict[str, Any]:
        return {}
    def prompt_hints(self, ctx: Dict[str, Any]) -> List[str]:
        return []
    def file_ingest_rules(self) -> Dict[str, Any]:
        return {"allow_pdf": True, "allow_text": True, "max_mb": 10}

# apps/chatbot/src/personas/cve_creator.py
from .policy import PersonaPolicy
class CveCreatorPolicy(PersonaPolicy):
    name = "CVE Creator"
    def preprocess(self, q, ctx):
        return {"prefer_evidence": True}
    def file_ingest_rules(self):
        return {"allow_pdf": True, "allow_text": True, "max_mb": 20, "require_evidence": False}

B. Policy registry + selection
# apps/chatbot/src/personas/registry.py
from typing import Dict
from .policy import PersonaPolicy
from .cve_creator import CveCreatorPolicy

_POLICIES: Dict[str, PersonaPolicy] = {
    "CVE Creator": CveCreatorPolicy(),
}

def get_policy(name: str) -> PersonaPolicy:
    return _POLICIES.get(name) or PersonaPolicy()

C. Wire into processing/generation
# conversation.py or response_generator.py
from apps.chatbot.src.personas.registry import get_policy

policy = get_policy(ctx.persona)
policy_hints = policy.preprocess(q, ctx.get_session_context_for_processing())
# use hints to tweak retrieval/generation without if/else chains

3) Config loading simplification
# apps/chatbot/src/config.py
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    DATABASE_URL: str
    GEMINI_API_KEY: str
    LOG_LEVEL: str = "INFO"
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

settings = Settings()


Usage:

from apps.chatbot.src.config import settings
db_url = settings.DATABASE_URL


Delete app_config.py importlib gymnastics.

4) Standardize secure logging
# apps/chatbot/src/utils/logging.py
import logging, re, sys

class RedactSecrets(logging.Filter):
    PATTERNS = [
        (re.compile(r"(api[_-]?key\s*=\s*)([A-Za-z0-9_\-]{12,})", re.I), r"\1[REDACTED]"),
        (re.compile(r"(Authorization:\s*Bearer\s+)[A-Za-z0-9_\-\.]+", re.I), r"\1[REDACTED]"),
    ]
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            msg = record.msg
            for pat, rep in self.PATTERNS:
                msg = pat.sub(rep, msg)
            record.msg = msg
        return True

def get_secure_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.addFilter(RedactSecrets())
        formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s - %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger


Replace:

# before
import logging
logger = logging.getLogger(__name__)
# after
from apps.chatbot.src.utils.logging import get_secure_logger
logger = get_secure_logger(__name__)

Rollout plan (safe sequence)

P1.1 Unify session (delete manager, add utils/session.py, update imports)

P1.3 Packaging/imports (move ingestion package, update imports, pip install -e .)

P1.2 QueryProcessor centralization (ConversationManager delegating)

P2.2 Unified streaming/non-streaming (introduce _process_message_core)

P2.1 Merge RoleManager into UserContext (or replace with shim)

P3 improvements (regex, persona strategy, config, logging)

Each step: green tests before moving on.

Test additions (quick list)

tests/unit/test_session_context.py — session helper

tests/unit/test_query_processor.py — sanitization + follow-up + safety flag

tests/unit/test_user_context_persona.py — persona set/validate/actions

tests/unit/test_input_security_regex.py — command injection vs teaching queries

tests/unit/test_persona_policies.py — policy registry returns defaults, CVE Creator hints shape

tests/integration/test_conversation_paths.py — streaming vs non-streaming parity

tests/integration/test_imports_package_layout.py — importing PostgresChunkStore without sys.path hacks

Quick “search & replace” checklist

 Remove all imports/refs to UserContextManager

 Remove sys.path / CWE_INGESTION_PATH logic

 Replace raw logging.getLogger with get_secure_logger

 Replace any direct InputSanitizer calls in ConversationManager with QueryProcessor

 Replace RoleManager usage with UserContext.set_persona() and get_role_actions_for_chainlit()