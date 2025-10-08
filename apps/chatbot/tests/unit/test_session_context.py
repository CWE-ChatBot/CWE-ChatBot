from src.utils.session import get_user_context, set_user_context


def test_session_context_smoke(monkeypatch):
    store = {}

    class Dummy:
        def get(self, k):
            return store.get(k)

        def set(self, k, v):
            store[k] = v

    # Patch chainlit.user_session to a dummy in-memory store
    import chainlit

    monkeypatch.setattr(chainlit, "user_session", Dummy(), raising=True)

    ctx = get_user_context()
    assert ctx is not None
    ctx.persona = "Developer"
    set_user_context(ctx)
    assert get_user_context().persona == "Developer"
