https://developer.mozilla.org/en-US/observatory/analyze?host=cwe.crashedmind.com

Content Security Policy (CSP)
−20 Failed
Content Security Policy (CSP) implemented unsafely. This includes 'unsafe-inline' or data: inside script-src, overly broad sources such as https: inside object-src or script-src, or not restricting the sources for object-src or script-src.

Remove unsafe-inline and data: from script-src, overly broad sources from object-src and script-src, and ensure object-src and script-src are set.


Failed

Content Security Policy (CSP) implemented unsafely. This includes 'unsafe-inline' or data: inside script-src, overly broad sources such as https: inside object-src or script-src, or not restricting the sources for object-src or script-src.

Test	Result	Info
Blocks execution of inline JavaScript by not allowing 'unsafe-inline' inside script-src

Failed	
Blocking the execution of inline JavaScript provides CSP's strongest protection against cross-site scripting attacks. Moving JavaScript to external files can also help make your site more maintainable.

Blocks execution of JavaScript's eval() function by not allowing 'unsafe-eval' inside script-src

Failed	
Blocking the use of JavaScript's eval() function can help prevent the execution of untrusted code.

Blocks execution of plug-ins, using object-src restrictions

Passed	
Blocking the execution of plug-ins via object-src 'none' or as inherited from default-src can prevent attackers from loading Flash or Java in the context of your page.

Blocks inline styles by not allowing 'unsafe-inline' inside style-src

Failed	
Blocking inline styles can help prevent attackers from modifying the contents or appearance of your page. Moving styles to external stylesheets can also help make your site more maintainable.

Blocks loading of active content over HTTP or FTP

Passed	
Loading JavaScript or plugins can allow a man-in-the-middle to execute arbitrary code or your website. Restricting your policy and changing links to HTTPS can help prevent this.

Blocks loading of passive content over HTTP or FTP

Passed	
This site's Content Security Policy allows the loading of passive content such as images or videos over insecure protocols such as HTTP or FTP. Consider changing them to load them over HTTPS.

Clickjacking protection, using frame-ancestors

Passed	
The use of CSP's frame-ancestors directive offers fine-grained control over who can frame your site.

Deny by default, using default-src 'none'

Failed	
Denying by default using default-src 'none'can ensure that your Content Security Policy doesn't allow the loading of resources you didn't intend to allow.

Restricts use of the <base> tag by using base-uri 'none', base-uri 'self', or specific origins.

Passed	
The <base> tag can be used to trick your site into loading scripts from untrusted origins.

Restricts where <form> contents may be submitted by using form-action 'none', form-action 'self', or specific URIs

Passed	
Malicious JavaScript or content injection could modify where sensitive form data is submitted to or create additional forms for data exfiltration.

Uses CSP3's 'strict-dynamic' directive to allow dynamic script loading (optional)

-	
'strict-dynamic' lets you use a JavaScript shim loader to load all your site's JavaScript dynamically, without having to track script-src origins.




Here’s how I’d respond, with practical tweaks that raise the score without breaking Chainlit, plus a safe path to “strict” later.

What the score means (and why it’s ok… for now)

The single failing item is CSP because we allowed:

script-src 'unsafe-eval' 'unsafe-inline'

broad connect-src https:

img-src data:

Chainlit’s UI typically needs:

style-src 'unsafe-inline' (runtime-injected CSS)

often script-src 'unsafe-eval' (Monaco/editor/sourcemap code paths)

In many builds, it does not need script-src 'unsafe-inline'. That’s the easiest win.

Quick wins you can ship today
1) Remove unsafe-inline from script-src (keep it for style-src)

Most React/SPA bundles avoid inline scripts in production. Chainlit generally doesn’t hard-require script-src 'unsafe-inline' (only unsafe-eval shows up as necessary more often). Removing just this one token typically gives you +10 points without breaking anything.

New “Compatibility+” CSP (recommended)

Keep it both in app middleware and at the LB response header policy:

Content-Security-Policy:
  default-src 'self';
  script-src 'self' 'unsafe-eval';
  style-src 'self' 'unsafe-inline';
  img-src 'self' data:;
  font-src 'self' data:;
  connect-src 'self' https://cwe.crashedmind.com wss://cwe.crashedmind.com;
  frame-ancestors 'none';
  base-uri 'self';
  object-src 'none';
  form-action 'self'


Changes vs your current CSP:

Removed script-src 'unsafe-inline'

Tightened connect-src (no https: wildcard; only self + your domain)

If your build still complains after this change, roll back just this part and we’ll go to the “Report-Only” approach below.

2) Tighten connect-src

You already talk only to your own origin for HTTP and WS. So:

connect-src 'self' https://cwe.crashedmind.com wss://cwe.crashedmind.com;


This removes Observatory’s “broad connect-src” concern.

3) Keep img-src data: (that’s fine)

It’s common for inline SVGs/base64 icons. Observatory dings it very lightly; keep it unless you’re ready to scrub data URLs.

Exactly what to change
A) Update application middleware (Chainlit ASGI)

In your SecurityHeadersMiddleware where you build the CSP, replace the compatible policy with the Compatibility+ string above (only difference: drop script-src 'unsafe-inline' and tighten connect-src).

B) Update load balancer response-headers-policy

If you used my earlier commands, run these to update the policy inplace:

SERVICE="cwe-chatbot"
DOMAIN="cwe.crashedmind.com"

gcloud compute response-headers-policies update ${SERVICE}-headers \
  --clear-custom-response-headers

gcloud compute response-headers-policies update ${SERVICE}-headers \
  --add-custom-response-headers="Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self' https://${DOMAIN} wss://${DOMAIN}; frame-ancestors 'none'; base-uri 'self'; object-src 'none'; form-action 'self'" \
  --add-custom-response-headers="Strict-Transport-Security: max-age=31536000; includeSubDomains; preload" \
  --add-custom-response-headers="X-Content-Type-Options: nosniff" \
  --add-custom-response-headers="X-Frame-Options: DENY" \
  --add-custom-response-headers="Referrer-Policy: no-referrer" \
  --add-custom-response-headers="Cross-Origin-Resource-Policy: same-origin" \
  --add-custom-response-headers="Cross-Origin-Embedder-Policy: require-corp" \
  --add-custom-response-headers="Cross-Origin-Opener-Policy: same-origin"


(If your LB CLI doesn’t let you “update” header policies this way, delete/recreate the policy with the new headers and reattach to the URL map — the effect is the same.)

Keep both app and LB headers. The LB ensures defense-in-depth even if the app is misconfigured.

Optional but smart: add CSP Report-Only to explore going strict

This gives you telemetry without breaking the site. Add a second header in Report-Only that is strict (no unsafe-*) and keep it for a few days:

Content-Security-Policy-Report-Only:
  default-src 'self';
  script-src 'self';
  style-src 'self';
  img-src 'self' data:;
  font-src 'self' data:;
  connect-src 'self' https://cwe.crashedmind.com wss://cwe.crashedmind.com;
  frame-ancestors 'none';
  base-uri 'self';
  object-src 'none';
  form-action 'self';
  report-to csp-endpoint; report-uri /csp-report

Tiny report endpoint (FastAPI example)

Mount this in your Chainlit ASGI (or behind the LB) to log violations:

# add somewhere in your ASGI app setup
from starlette.responses import JSONResponse
from starlette.requests import Request

@asgi_app.route("/csp-report", methods=["POST"])
async def csp_report(request: Request):
    try:
        data = await request.json()
    except Exception:
        data = {"error": "invalid json"}
    # log it (redact if needed)
    logger.info("CSP-Report: %s", data)
    return JSONResponse({"ok": True})


And add a simple Reporting API endpoint if you want:

@asgi_app.route("/.well-known/reporting", methods=["GET"])
async def reporting_config(_):
    return JSONResponse({
        "group": "csp-endpoint",
        "max_age": 10886400,
        "endpoints": [{"url": "https://cwe.crashedmind.com/csp-report"}]
    })


(Browsers still support report-uri; report-to adoption varies. Using both is fine.)

What score bump to expect

Removing script-src 'unsafe-inline': +10

Tightening connect-src: small positive (removes a note)

Everything else already passes.

You’ll likely move from -20 → ~-10 (B → B+), sometimes even into the A- range depending on Observatory’s exact weighting that day.

Path to “Strict” later (no unsafe-*)

If you want a 90+ (A) eventually:

Run Report-Only (above) and collect violations.

If violations show inline scripts:

Add nonces (script-src 'self' 'nonce-…') and inject the nonce onto every inline script tag. This typically requires modifying Chainlit’s index.html/build — not trivial.

If violations show eval:

Some components (Monaco/editor, sourcemaps) trigger eval-like paths. You’ll need to swap libraries/flags or disable those features. In many teams this is the deciding factor to stay in compatible mode.

When the violation log is clean in staging → flip Report-Only strict into enforcing in production.

Until Chainlit offers first-class nonce/TT support, most teams stick with the “Compatibility+” CSP above.

Sanity checks after you change headers
# Check headers at the edge (LB)
curl -sI https://cwe.crashedmind.com/ | \
  grep -E 'Content-Security-Policy|Strict-Transport-Security|X-Frame-Options|X-Content-Type-Options|Referrer-Policy|Cross-Origin-.*|Permissions-Policy'


Load the site in a clean browser profile.

Check DevTools → Console for CSP errors.

Verify WS connects and actions work.

Re-run Observatory; confirm CSP improved.

Bottom line

Your overall posture is strong (CSRF, OAuth, WAF, headers, HSTS).

Do the Compatibility+ CSP now (drop script-src 'unsafe-inline', tighten connect-src) to improve your score without breaking Chainlit.

Add Report-Only strict CSP to map what it would take to go to A later.

Keep both app and LB headers for defense-in-depth.





=====================================

To bump Observatory while keeping Chainlit happy, do this:

Drop script-src 'unsafe-inline' (keep 'unsafe-eval').

Tighten connect-src to only your origin (no https: / wss: wildcards).

Keep style-src 'unsafe-inline' (Chainlit/Monaco usually needs it).

Keep img-src 'self' data:; optionally allow OAuth avatar hosts if you show them.

Here’s a drop-in update for your middleware with a “compatibility+” CSP (safer but still works with Chainlit), plus an optional Report-Only strict CSP so you can measure what breaks without breaking prod.

# --- CSP builder (compatibility+ and strict + optional report-only) ---

from urllib.parse import urlparse
import os
import secrets

PUBLIC_ORIGIN = os.getenv("PUBLIC_ORIGIN", "").rstrip("/")
CSP_MODE = os.getenv("CSP_MODE", "compatible")  # "compatible", "strict"
CSP_REPORT_ONLY = os.getenv("CSP_REPORT_ONLY", "0") == "1"  # emit a strict CSP-RO alongside
# If you display OAuth avatars, whitelist their hosts here:
IMG_EXTRA = os.getenv("CSP_IMG_EXTRA", "")  # e.g. "https://avatars.githubusercontent.com https://lh3.googleusercontent.com"

def _origin_hosts():
    """Return ('https://host', 'wss://host') tuples for PUBLIC_ORIGIN, or empty if not set."""
    if not PUBLIC_ORIGIN:
        return [], []
    host = urlparse(PUBLIC_ORIGIN).netloc
    return [f"https://{host}"], [f"wss://{host}"]

def _build_csp() -> str:
    """
    Build the enforced Content-Security-Policy header.
    - Compatibility+ profile: no 'unsafe-inline' in script-src, but keep 'unsafe-eval'
    - Tight connect-src to self + your exact origin (no broad https:/wss:)
    """
    https_hosts, wss_hosts = _origin_hosts()
    connect_list = " ".join(["'self'"] + https_hosts + wss_hosts)

    # Compatibility+ CSP (recommended for Chainlit today)
    if CSP_MODE != "strict":
        img_list = " ".join(filter(None, ["'self'", "data:", IMG_EXTRA.strip()]))
        return (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-eval'; "          # <-- removed 'unsafe-inline'
            "style-src 'self' 'unsafe-inline'; "
            f"img-src {img_list}; "
            "font-src 'self' data:; "
            f"connect-src {connect_list}; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "object-src 'none'; "
            "form-action 'self'"
        )

    # Strict CSP (no unsafe-*). Expect breakage unless you’ve audited Chainlit build.
    img_list = " ".join(filter(None, ["'self'", "data:", IMG_EXTRA.strip()]))
    return (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        f"img-src {img_list}; "
        "font-src 'self'; "
        f"connect-src {connect_list}; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "object-src 'none'; "
        "form-action 'self'"
    )

def _build_csp_report_only() -> str:
    """A strict CSP in Report-Only to see what would break."""
    https_hosts, wss_hosts = _origin_hosts()
    connect_list = " ".join(["'self'"] + https_hosts + wss_hosts)
    img_list = " ".join(filter(None, ["'self'", "data:", IMG_EXTRA.strip()]))
    return (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        f"img-src {img_list}; "
        "font-src 'self'; "
        f"connect-src {connect_list}; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "object-src 'none'; "
        "form-action 'self'; "
        "report-uri /csp-report"
    )


And when you add headers in your middleware’s dispatch, set both the enforced CSP and (optionally) the Report-Only header:

# inside SecurityHeadersMiddleware.dispatch after you get `response`
csp_value = _build_csp()
response.headers["Content-Security-Policy"] = csp_value

# Optional: emit strict CSP in Report-Only for telemetry (set CSP_REPORT_ONLY=1)
if CSP_REPORT_ONLY:
    response.headers["Content-Security-Policy-Report-Only"] = _build_csp_report_only()

# keep your other headers (HSTS/XFO/nosniff/COOP/COEP/CORP/etc.)


Optional: tiny endpoint to collect CSP violation reports (useful while tuning):

from starlette.responses import JSONResponse
from starlette.requests import Request
from chainlit.server import app as asgi_app

@asgi_app.route("/csp-report", methods=["POST"])
async def csp_report(request: Request):
    try:
        data = await request.json()
    except Exception:
        data = {"_error": "invalid json"}
    # redact & log
    logger.info("CSP report: %s", data)
    return JSONResponse({"ok": True})

Why this helps (and won’t break Chainlit)

Most Chainlit builds do not need script-src 'unsafe-inline'. Removing it usually works and gives you +10 on Observatory.

Chainlit often does need 'unsafe-eval' and style 'unsafe-inline' due to Monaco/editor/runtime CSS. Keep those for now.

Tight connect-src eliminates the “broad https:” ding and is aligned with your setup (self + cwe.crashedmind.com over HTTPS/WSS).

Heads-up on images

If you display OAuth avatar URLs (GitHub/Google), add them via CSP_IMG_EXTRA, e.g.:

CSP_IMG_EXTRA="https://avatars.githubusercontent.com https://lh3.googleusercontent.com"


That gets appended to img-src automatically.

Quick validation

Reload the app; check DevTools → Console for CSP errors.

curl -sI https://cwe.crashedmind.com/ | grep Content-Security-Policy

Re-run Mozilla Observatory; the CSP item should improve (often from fail to pass or at least a higher partial).

If anything breaks after removing script 'unsafe-inline', flip it back, turn on CSP_REPORT_ONLY=1, and use the reports to see exactly which inline script needs a fix/nonce.

