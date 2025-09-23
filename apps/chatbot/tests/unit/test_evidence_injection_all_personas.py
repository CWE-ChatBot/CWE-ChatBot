import pytest


PERSONAS = [
    "PSIRT Member",
    "Developer",
    "Academic Researcher",
    "Bug Bounty Hunter",
    "Product Manager",
    "CWE Analyzer",
    "CVE Creator",
]


class DummyUserSession:
    def __init__(self):
        self._store = {}

    def get(self, k):
        return self._store.get(k)

    def set(self, k, v):
        self._store[k] = v


class DummyMessage:
    def __init__(self, content=""):
        self.content = content
        self.elements = []

    async def send(self):
        return None

    async def update(self):
        return None

    async def stream_token(self, _):
        return None


class DummyQH:
    def __init__(self, *_, **__):
        pass

    async def process_query(self, *_args, **_kwargs):
        # Return a single dummy CWE chunk
        return [
            {
                "document": "CWE-79 details ...",
                "metadata": {"cwe_id": "CWE-79", "name": "XSS", "section": "Description"},
                "scores": {"hybrid": 0.5},
            }
        ]

    def health_check(self):
        return {"database": True, "embedder": True}


class DummyRG:
    def __init__(self, *_args, **_kwargs):
        pass

    async def generate_response(self, query, retrieved_chunks, user_persona):
        # Simple echo to allow validation step to proceed
        return f"ok: {user_persona}: {query[:10]} ({len(retrieved_chunks)} chunks)"


@pytest.mark.asyncio
@pytest.mark.parametrize("persona", PERSONAS)
async def test_evidence_pseudo_chunk_injected_for_every_persona(monkeypatch, persona):
    # Patch Chainlit primitives
    import chainlit as cl

    cl_session = DummyUserSession()
    monkeypatch.setattr(cl, "user_session", cl_session, raising=True)
    monkeypatch.setattr(cl, "Message", DummyMessage, raising=True)

    # Patch heavy dependencies by stubbing their modules before import
    import sys, types

    qh_mod = types.ModuleType("src.query_handler")
    setattr(qh_mod, "CWEQueryHandler", DummyQH)
    sys.modules["src.query_handler"] = qh_mod

    rg_mod = types.ModuleType("src.response_generator")
    setattr(rg_mod, "ResponseGenerator", DummyRG)
    sys.modules["src.response_generator"] = rg_mod

    # Import after module stubs are in place
    from src.conversation import ConversationManager

    # Create manager (uses DummyQH/DummyRG)
    cm = ConversationManager(database_url="postgresql://user:pass@host/db", gemini_api_key="dummy")

    # Seed a session context and persona
    session_id = "sess-test"
    ctx = cm._get_or_create_user_context(session_id)
    ctx.persona = persona

    # Provide uploaded evidence via session
    cl_session.set("uploaded_file_context", "Evidence: reflected XSS in search param")

    # Spy on generate_response to capture retrieval passed from core path
    calls = {}

    async def spy_generate_response(query, retrieved_chunks, user_persona):
        calls["retrieved_chunks"] = list(retrieved_chunks)
        return await DummyRG().generate_response(query, retrieved_chunks, user_persona)

    monkeypatch.setattr(cm.response_generator, "generate_response", spy_generate_response, raising=True)

    # Execute streaming path (wrapper around core)
    result = await cm.process_user_message_streaming(session_id, "Explain the risk of XSS", "msg-1")

    # Ensure response returned and our spy captured retrieval
    assert "response" in result
    retrieved = calls.get("retrieved_chunks")
    assert retrieved is not None, "generate_response should have been called with retrieval"

    # Evidence pseudo-chunk is appended; look for marker
    sources = [ch.get("metadata", {}).get("cwe_id") for ch in retrieved]
    assert "EVIDENCE" in sources, "Expected user evidence pseudo-chunk to be injected for all personas"
