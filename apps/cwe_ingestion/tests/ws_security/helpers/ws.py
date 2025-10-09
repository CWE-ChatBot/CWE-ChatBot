import asyncio
from typing import Any, Dict, Optional

import websockets
from websockets.exceptions import InvalidStatusCode


async def ws_connect(
    url: str,
    origin: str,
    headers: Optional[Dict[str, str]] = None,
    cookies: Optional[str] = None,
    timeout: float = 10.0,
):
    extra_headers = dict(headers) if headers else {}
    if origin:
        extra_headers["Origin"] = origin
    if cookies:
        extra_headers["Cookie"] = cookies
    return await asyncio.wait_for(
        websockets.connect(url, extra_headers=extra_headers), timeout=timeout
    )


async def try_ws_connect(url: str, origin: str, **kwargs) -> Dict[str, Any]:
    """Attempt to connect. Return {ok: bool, error: str|None}"""
    try:
        async with await ws_connect(url, origin, **kwargs) as ws:
            # small ping to verify it stays up briefly
            try:
                await ws.ping()
            except Exception:
                pass
            return {"ok": True, "error": None}
    except InvalidStatusCode as e:
        return {"ok": False, "error": f"InvalidStatusCode:{e.status_code}"}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}:{e}"}
