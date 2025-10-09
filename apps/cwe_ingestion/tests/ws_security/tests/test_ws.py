import pytest
from helpers.ws import try_ws_connect

pytestmark = pytest.mark.order(1)


@pytest.mark.asyncio
async def test_ws_same_origin_allows(ws_url, base_url):
    res = await try_ws_connect(ws_url, base_url)
    assert res["ok"], f"Expected same-origin WS to connect, got error: {res['error']}"


@pytest.mark.asyncio
async def test_ws_cross_origin_denies(ws_url, evil_origin):
    res = await try_ws_connect(ws_url, evil_origin)
    assert not res["ok"], "Expected cross-origin WS to be blocked by LB/Armor"
