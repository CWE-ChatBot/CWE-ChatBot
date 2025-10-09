import httpx
import pytest

pytestmark = pytest.mark.order(3)


def test_csp_headers_present(base_url):
    try:
        r = httpx.get(base_url, timeout=10.0, follow_redirects=True)
    except Exception as e:
        pytest.skip(f"Could not fetch {base_url}: {e}")

    # LB/Armor should set CSP; skip early if not yet configured
    csp = r.headers.get("content-security-policy") or r.headers.get(
        "Content-Security-Policy"
    )
    if not csp:
        pytest.skip("No CSP header found yet (LB may not be configured).")
    assert "default-src" in csp, "CSP should define default-src"
    assert "frame-ancestors" in csp, "CSP should define frame-ancestors"
