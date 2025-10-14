here are three clean commits with focused scopes and copy-pasteable diffs.

Commit 1 — DB hardening & safe logging

Message (subject + body):

db: harden connection logging and make pool warm-up opt-in

- Stop logging password length/tail to avoid partial-secret leakage.
- Default DB_WARM_POOL to false to prevent over-connection in serverless.
- Allow sizing via DB_WARM_POOL_SIZE when explicitly enabled.


Diff:

diff --git a/src/db.py b/src/db.py
index 6c7d1ab..e1f0c22 100644
--- a/src/db.py
+++ b/src/db.py
@@ -30,12 +30,10 @@ def _build_url_from_env() -> URL:
     pwd = os.environ["DB_PASSWORD"].strip()  # Always strip newline/whitespace
     sslmode = os.getenv("DB_SSLMODE", "require")

-    # Log sanity checks (no secrets leaked)
-    logger.info(
-        f"DB connect params: host={host}:{port}, db={db}, user={user}, sslmode={sslmode}, pw_len={len(pwd)}, tail={repr(pwd[-2:]) if len(pwd) >= 2 else repr(pwd)}"
-    )
+    # Log params without any password footprint
+    logger.info("DB connect params: host=%s:%s, db=%s, user=%s, sslmode=%s",
+                host, port, db, user, sslmode)

     return URL.create(
         drivername="postgresql+psycopg",
         username=user,
         password=pwd,  # SQLAlchemy will quote/escape properly
         host=host,
         port=port,
         database=db,
     )
@@ -104,8 +102,9 @@ def engine() -> Any:
     # Note: Planner hints (enable_seqscan, hnsw.ef_search, etc.) are now applied
     # via transaction-scoped SET LOCAL in pg_chunk_store.py for better control

-    # Warm the pool if enabled (default: true)
-    if os.getenv("DB_WARM_POOL", "true").lower() == "true":
-        warm_pool(eng, size=3)
+    # Warm the pool iff explicitly enabled (opt-in; safer for serverless)
+    if os.getenv("DB_WARM_POOL", "false").lower() == "true":
+        warm_pool(eng, size=int(os.getenv("DB_WARM_POOL_SIZE", "3")))

     return eng

Commit 2 — Engine disposal & shutdown cleanup

Message (subject + body):

db/main: fix engine disposal and ensure graceful shutdown closes pools

- src/db.close() now disposes the cached engine instead of creating a new one.
- main.on_stop() calls db.close() to release SQLAlchemy connections.


Diff:

diff --git a/src/db.py b/src/db.py
index e1f0c22..4a2b7cd 100644
--- a/src/db.py
+++ b/src/db.py
@@ -116,12 +116,17 @@ def engine() -> Any:
     return eng


 def close() -> None:
     """
     Dispose the engine and close all pooled connections.
 
     Call this during graceful shutdown to clean up database connections.
     """
-    # Clear the lru_cache to get the actual engine instance
-    eng = engine.__wrapped__()
-    if eng is not None:
-        logger.info("Disposing database engine and closing all connections")
-        eng.dispose()
-        engine.cache_clear()
+    try:
+        # Get the cached instance instead of constructing a new one
+        eng = engine()
+    except Exception:
+        eng = None
+    if eng is not None:
+        logger.info("Disposing database engine and closing all connections")
+        try:
+            eng.dispose()
+        finally:
+            engine.cache_clear()

diff --git a/main.py b/main.py
index 3b1d6c0..9c31a1e 100644
--- a/main.py
+++ b/main.py
@@ -1128,15 +1128,26 @@ async def on_stop() -> None:
     """Gracefully close resources when the app stops."""
     try:
         if conversation_manager and getattr(
             conversation_manager, "query_handler", None
         ):
             qh = conversation_manager.query_handler
             close_fn = getattr(qh, "close", None)
             if callable(close_fn):
                 close_fn()
                 logger.info("Closed retriever/database resources")
+        # Dispose global SQLAlchemy engine if present
+        try:
+            from src.db import close as db_close
+            db_close()
+            logger.info("Disposed SQLAlchemy engine")
+        except Exception as e:
+            logger.warning(f"Engine dispose failed: {e}")
     except Exception as e:
         logger.log_exception("Shutdown cleanup failed", e)

Commit 3 — LLM robustness: normalize finish_reason

Message (subject + body):

llm: normalize Gemini finish_reason and warn on truncation

SDKs surface finish reasons as enums/ints/strings; normalize to string
and warn when completion is non-STOP to help detect truncation/trips.


Diff:

diff --git a/src/llm_provider.py b/src/llm_provider.py
index 9a3c7ab..b1dfe54 100644
--- a/src/llm_provider.py
+++ b/src/llm_provider.py
@@ -86,16 +86,22 @@ class GoogleProvider(LLMProvider):
         try:
             resp = await cast(Any, self._model).generate_content_async(
                 prompt,
                 generation_config=cast(Any, self._gen_cfg),
                 safety_settings=cast(Any, self._safety),
             )
             # Log response details for debugging truncation issues
             response_text = resp.text or ""
-            finish_reason = getattr(
-                resp.candidates[0] if resp.candidates else None,
-                "finish_reason",
-                "UNKNOWN",
-            )
-            logger.info(
-                f"Gemini generation completed: {len(response_text)} chars, finish_reason={finish_reason}"
-            )
-            if finish_reason not in ["STOP", 1]:  # STOP=1 is normal completion
-                logger.warning(
-                    f"Non-normal finish_reason: {finish_reason} - response may be truncated"
-                )
+            finish_reason = None
+            if getattr(resp, "candidates", None):
+                finish_reason = getattr(resp.candidates[0], "finish_reason", None)
+            # Normalize enums/ints/strings to an upper-case string for comparison
+            finish_norm = str(finish_reason).upper() if finish_reason is not None else "UNKNOWN"
+            logger.info(
+                "Gemini generation completed: %d chars, finish_reason=%s",
+                len(response_text), finish_reason
+            )
+            # Accept common STOP variants; warn on anything else (possible truncation)
+            if finish_norm not in {"STOP", "FINISH_REASON_STOP", "1"}:
+                logger.warning(
+                    "Non-normal finish_reason: %s - response may be truncated",
+                    finish_reason,
+                )
             return response_text
         except Exception as e:
             logger.error(f"Gemini generation failed with error: {e}")
             logger.error(f"Error type: {type(e).__name__}")
             raise e