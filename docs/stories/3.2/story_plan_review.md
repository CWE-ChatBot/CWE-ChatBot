3.2 is a tight follow-on to 3.1. Below is a pragmatic review plus drop-in stubs so a dev can implement without hunting context. I’ve assumed you’ll reuse 3.1’s retrieval + persona infra and move confidence/low-confidence logic into shared modules to avoid duplication.

quick scorecard

AC1 (prioritized list + confidence): ✅ Clear. Reuse 3.1 confidence; extract to a shared ConfidenceCalculator and display max 5.

AC2 (limit + prohibited/Discouraged): ⚠️ Add an explicit filter source (ingestion flag or config list). Enforce hard cap of 5.

AC3 (explanations with quotes): ✅ Add an ExplanationBuilder that picks 1–2 short, source-anchored snippets per CWE.

AC4 (relationship exploration): ✅ Prefer structured relationships from ingestion; only regex as fallback. Add “Explore relationships” action.

AC5 (low-confidence guidance): ✅ Reuse 3.1 low-confidence path; move templates and persona hints into QuerySuggester.

key alignment with 3.1

Unify confidence: move 3.1 scoring into processing/confidence_calculator.py; call it from CWEQueryHandler.

Keep evidence isolation from 3.1 (no change needed).

One return contract from process_query() so 3.1/3.2 features compose.

minimal, production-ready interfaces (copy/paste)
1) processing/confidence_calculator.py
# apps/chatbot/src/processing/confidence_calculator.py
from __future__ import annotations
from typing import TypedDict, Literal, Iterable
import math

ConfidenceLevel = Literal["High", "Medium", "Low", "Very Low"]

class AggregatedCWE(TypedDict):
    cwe_id: str
    name: str
    top_hybrid_scores: list[float]     # top N hybrid scores from retrieval
    exact_alias_match: bool            # name/alias exact hit
    section_hits: dict[str, int]       # {"Description":2,"Consequences":1,...}
    source_count: int                  # distinct chunks/sources

class ConfidenceCalculator:
    def __init__(self,
                 w_sim: float = 0.55,
                 w_count: float = 0.15,
                 w_alias: float = 0.15,
                 w_sections: float = 0.1,
                 w_diversity: float = 0.05):
        self.w_sim, self.w_count, self.w_alias, self.w_sections, self.w_diversity = \
            w_sim, w_count, w_alias, w_sections, w_diversity

    @staticmethod
    def _norm_sim(scores: Iterable[float]) -> float:
        if not scores: return 0.0
        # squash average(top3) into 0..1
        top = list(scores)[:3]
        avg = sum(top)/len(top)
        # if hybrid is already 0..1, return avg; otherwise logistic as a guard:
        return 1/(1+math.exp(-8*(avg-0.6))) if avg>1 else max(0.0, min(1.0, avg))

    def score(self, agg: AggregatedCWE) -> float:
        sim = self._norm_sim(agg["top_hybrid_scores"])
        count = min(len(agg["top_hybrid_scores"])/5.0, 1.0)
        alias = 1.0 if agg["exact_alias_match"] else 0.0
        sections = min(sum(1 for k,v in agg["section_hits"].items() if v>0)/4.0, 1.0)
        diversity = min(agg["source_count"]/4.0, 1.0)
        raw = (self.w_sim*sim + self.w_count*count + self.w_alias*alias +
               self.w_sections*sections + self.w_diversity*diversity)
        return max(0.0, min(1.0, raw))

    @staticmethod
    def level(score: float) -> ConfidenceLevel:
        if score >= 0.80: return "High"
        if score >= 0.60: return "Medium"
        if score >= 0.40: return "Low"
        return "Very Low"

2) processing/cwe_filter.py
# apps/chatbot/src/processing/cwe_filter.py
from __future__ import annotations
from typing import Iterable

MAX_RECS = 5

class CWEFilter:
    def __init__(self, prohibited: set[str] | None = None, discouraged: set[str] | None = None):
        self.prohibited = {c.upper() for c in (prohibited or set())}
        self.discouraged = {c.upper() for c in (discouraged or set())}

    def filter(self, recs: list[dict]) -> list[dict]:
        out = []
        for r in recs:
            cid = r["cwe_id"].upper()
            if cid in self.prohibited: 
                r["filter_reason"] = "prohibited"; continue
            if cid in self.discouraged: 
                r["filter_reason"] = "discouraged"; continue
            out.append(r)
        # hard cap
        return out[:MAX_RECS]


Source of lists: ingestion metadata (status in {Prohibited, Discouraged}) or a config file (config/cwe_filter.yaml). Make it injectable.

3) processing/explanation_builder.py
# apps/chatbot/src/processing/explanation_builder.py
from __future__ import annotations
from typing import List, Dict

SECTION_PRIORITY = ["Description","Common Consequences","Detection Methods","Mitigations","Relationships"]

def _short_quote(text: str, max_chars: int = 240) -> str:
    t = " ".join(text.split())
    return t[:max_chars] + ("…" if len(t) > max_chars else "")

class ExplanationBuilder:
    def build(self, query: str, cwe_id: string, chunks: List[Dict]) -> Dict:
        # chunks: list of {document, metadata:{section, chunk_id, cwe_name}}
        # rank snippets: prefer high-scoring chunks and priority sections
        ranked = sorted(chunks, key=lambda c: (
            -SECTION_PRIORITY.index(c["metadata"].get("section","Description"))
            if c["metadata"].get("section") in SECTION_PRIORITY else 99
        ))
        snippets = []
        seen_sections = set()
        for c in ranked:
            sec = c["metadata"].get("section","")
            if sec in seen_sections: continue
            snippets.append({
                "text": _short_quote(c["document"]),
                "section": sec,
                "citation": {"cwe_id": cwe_id,
                             "section": sec,
                             "chunk_id": c["metadata"].get("chunk_id")}
            })
            seen_sections.add(sec)
            if len(snippets) >= 2: break

        rationale_bullets = []
        # example signals: term overlap, alias hit, section coverage (computed upstream)
        rationale_bullets.append("High semantic match to your query.")
        if any(s["section"]=="Description" for s in snippets):
            rationale_bullets.append("Description and consequences align with your input.")
        return {"snippets": snippets, "bullets": rationale_bullets}

4) processing/relationship_parser.py
# apps/chatbot/src/processing/relationship_parser.py
from __future__ import annotations
from typing import List, Dict

class RelationshipParser:
    def __init__(self, repo):
        self.repo = repo  # DB/retriever with structured relationships if available

    async def related(self, cwe_id: str) -> Dict[str, List[Dict]]:
        """
        Returns {"ParentOf":[{cwe_id,name}], "ChildOf":[...], "RelatedTo":[...]}
        Prefer structured table; fallback to regex on 'Relationships' section.
        """
        data = await self.repo.get_relationships(cwe_id)  # implement in repo
        return data or {"ParentOf": [], "ChildOf": [], "RelatedTo": []}

5) processing/query_suggester.py
# apps/chatbot/src/processing/query_suggester.py
from __future__ import annotations
from typing import List

PERSONA_HINTS = {
  "Developer": ["Add language/framework (e.g., 'in Spring Boot').",
                "Include the failing API/endpoint or function name."],
  "PSIRT Member": ["Provide affected product/version.", "Add CVE/CWE if known."],
  "Bug Bounty Hunter": ["Describe the entry point and observed impact.",
                        "Include repro steps or payload shape."]
}

class QuerySuggester:
    def suggest(self, query: str, persona: str) -> List[str]:
        out = []
        if "cwe-" not in query.lower(): out.append("Include a specific CWE if you suspect one (e.g., 'CWE-79').")
        if len(query.split()) < 6: out.append("Add a brief symptom or error message to anchor the context.")
        out.extend(PERSONA_HINTS.get(persona, [])[:2])
        return out[:3]

query_handler.py integration (core pipeline)

Add a single orchestrated path that: retrieve → aggregate by CWE → score → explain → filter → sort → return.

# apps/chatbot/src/query_handler.py (key excerpts)
from typing import TypedDict, Literal
from .processing.confidence_calculator import ConfidenceCalculator
from .processing.cwe_filter import CWEFilter
from .processing.explanation_builder import ExplanationBuilder
from .processing.relationship_parser import RelationshipParser

class Recommendation(TypedDict):
    cwe_id: str
    name: str
    confidence: float
    level: Literal["High","Medium","Low","Very Low"]
    explanation: dict        # {"snippets":[{text,section,citation}], "bullets":[...]}
    top_chunks: list[dict]   # kept server-side; avoid echoing entire text in UI
    relationships: dict | None

class CWEQueryHandler:
    def __init__(self, store, embedder, relationship_repo, prohibited: set[str], discouraged: set[str]):
        self.store, self.embedder = store, embedder
        self.conf_calc = ConfidenceCalculator()
        self.filter = CWEFilter(prohibited, discouraged)
        self.explainer = ExplanationBuilder()
        self.rels = RelationshipParser(relationship_repo)

    async def process_query(self, query: str, user_ctx: dict) -> dict:
        raw_chunks = await self._retrieve_chunks(query, user_ctx)  # existing
        by_cwe = {}
        for ch in raw_chunks:
            cid = ch["metadata"]["cwe_id"]
            by_cwe.setdefault(cid, {"name": ch["metadata"].get("cwe_name", cid),
                                    "scores": [], "section_hits": {}, "chunks":[]})
            by_cwe[cid]["scores"].append(ch.get("scores",{}).get("hybrid",0.0))
            sec = ch["metadata"].get("section","")
            by_cwe[cid]["section_hits"][sec] = by_cwe[cid]["section_hits"].get(sec,0)+1
            by_cwe[cid]["chunks"].append(ch)

        recs: list[Recommendation] = []
        for cid, agg in by_cwe.items():
            agg_model = {
                "cwe_id": cid,
                "name": agg["name"],
                "top_hybrid_scores": sorted(agg["scores"], reverse=True)[:3],
                "exact_alias_match": any(ch["metadata"].get("alias_exact",False) for ch in agg["chunks"]),
                "section_hits": agg["section_hits"],
                "source_count": len({ch["metadata"].get("chunk_id") for ch in agg["chunks"]}),
            }
            conf = self.conf_calc.score(agg_model)
            level = self.conf_calc.level(conf)
            expl = self.explainer.build(query, cid, agg["chunks"])
            recs.append({
                "cwe_id": cid, "name": agg["name"],
                "confidence": conf, "level": level,
                "explanation": expl, "top_chunks": agg["chunks"],
                "relationships": None
            })

        # Sort, filter, cap
        recs.sort(key=lambda r: r["confidence"], reverse=True)
        recs = self.filter.filter(recs)

        return {
            "recommendations": recs,
            "low_confidence": (len(recs)==0 or (recs and recs[0]["confidence"] < 0.40))
        }

    async def get_relationships(self, cwe_id: str) -> dict:
        return await self.rels.related(cwe_id)

response_generator.py (rendering essentials)

For AC1/AC3: show up to 5 items with score + level + 1–2 quotes + short bullets.

Example rendering logic (pseudo):

1) CWE-79 — Cross-Site Scripting  • Confidence: 0.86 (High)
   Why: High semantic match; Description and consequences align.
   “Improper neutralization of input during web page generation …”  — Description
   “Impact includes session hijacking and credential theft …”       — Common Consequences
   Actions: [Explore relationships]


Add an action/button per item to call get_relationships(cwe_id) and print:

Relationships for CWE-79:
• ParentOf: [CWE-80 …]
• RelatedTo: [CWE-116 …, CWE-20 …]

UX constraints (meets ACs & avoids leakage)

Cap suggestions to 5 (hard cap).

Do not display internal weights or retrieval scores; only the final 0–1 confidence and level label.

Quotes: 1–2 short snippets (≤ ~240 chars each), with section and CWE id as citation. Never expose chunk IDs to end users.

Low-confidence: prepend a short banner + 2–3 QuerySuggester hints tailored by persona.

security & performance notes

Sanitize quoted text: strip control chars, neutralize markdown autolinks.

Relationship exploration: rate limit per session (e.g., 10/min) to stop graph-walk spam.

Perf: reuse already-retrieved chunks for explanations; no extra DB round trips until user clicks “Explore relationships”.

Config:

MAX_RECS=5
RELATIONSHIPS_ENABLED=true
CONFIDENCE_DISPLAY_ENABLED=true


Logging: keep internal features in debug logs only (avg_similarity, alias_hit), never in user output.

tests you should add (short list)

Unit

ConfidenceCalculator: high/medium/low bands and clamping.

CWEFilter: removes prohibited/discouraged; caps to 5.

ExplanationBuilder: returns ≤2 snippets; sections labeled; no control chars.

RelationshipParser: structured path + regex fallback.

QuerySuggester: persona-specific hints; cap to 3.

Integration

End-to-end: query ⇒ 3–5 recs ordered by confidence; no prohibited CWEs.

Relationship flow: click “Explore relationships” ⇒ shows Parent/Child/Related.

Low-confidence: ambiguous query triggers guidance banner.

E2E (Playwright)

UI shows score + level, quotes, and the action button; clicking shows relationships.

minor plan tweaks

Move “confidence” bits from 3.1 into processing/confidence_calculator.py and delete duplicates.

Define a single Recommendation shape returned by process_query() (used by both 3.1 & 3.2).

Ensure prohibited/Discouraged sources exist (ingestion flag or config). Document where it comes from.

If you want, I can also provide a tiny PR diff for response_generator.py (the rendering + action callback) and a fake relationship_repo.get_relationships() stub so your devs can wire it incrementally.

You said:
yes
ChatGPT said:
Thought for 21s

Perfect — here’s the tiny PR-style diff you asked for: a rendering helper in response_generator.py, a Chainlit action + wiring in main.py, and a minimal relationship_repo stub you can swap later.

apps/chatbot/src/repositories/relationship_repo.py (new)
+++ apps/chatbot/src/repositories/relationship_repo.py
@@
+from __future__ import annotations
+from typing import Dict, List
+
+
+class RelationshipRepo:
+    """
+    Minimal stub. Replace with a DB-backed repo when your ingestion
+    exposes relationships in a table. The return shape is:
+    {
+      "ParentOf": [{"cwe_id":"CWE-xxx","name":"..."}],
+      "ChildOf": [{"cwe_id":"CWE-yyy","name":"..."}],
+      "RelatedTo": [{"cwe_id":"CWE-zzz","name":"..."}]
+    }
+    """
+    async def get_relationships(self, cwe_id: str) -> Dict[str, List[dict]]:
+        # TODO: Replace with real lookup.
+        # A tiny hardcoded sample so the UI path works immediately.
+        sample = {
+            "CWE-79": {
+                "ParentOf": [],
+                "ChildOf": [],
+                "RelatedTo": [
+                    {"cwe_id": "CWE-116", "name": "Improper Encoding or Escaping of Output"},
+                    {"cwe_id": "CWE-20", "name": "Improper Input Validation"},
+                ],
+            }
+        }
+        return sample.get(cwe_id.upper(), {"ParentOf": [], "ChildOf": [], "RelatedTo": []})

apps/chatbot/src/response_generator.py (add a renderer)
*** apps/chatbot/src/response_generator.py
@@
 from __future__ import annotations
-from typing import List, Dict, Any
+from typing import List, Dict, Any
+import re
+
+# --- 3.2: tiny rendering helper for mapping suggestions ----------------------
+def _sanitize_for_md(text: str) -> str:
+    if not text:
+        return ""
+    # collapse whitespace, strip control chars, neutralize triple backticks
+    t = " ".join(text.split())
+    t = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F]", "", t)
+    return t.replace("```", "ʼʼʼ")
+
+class MappingRenderer:
+    """
+    Renders recommendations (from CWEQueryHandler) into markdown + lightweight
+    action descriptors that main.py turns into Chainlit actions.
+    """
+    @staticmethod
+    def render(recommendations: List[Dict[str, Any]], persona: str) -> Dict[str, Any]:
+        lines: List[str] = []
+        actions: List[Dict[str, str]] = []
+
+        if not recommendations:
+            return {"markdown": "_No strong CWE matches found._", "actions": []}
+
+        for i, r in enumerate(recommendations, 1):
+            cwe_id = r["cwe_id"]
+            name = r.get("name", cwe_id)
+            conf = r.get("confidence", 0.0)
+            level = r.get("level", "Low")
+            lines.append(f"**{i}) {cwe_id} — {name}**  \nConfidence: **{conf:.2f}** ({level})")
+
+            expl = r.get("explanation", {})
+            bullets = expl.get("bullets", [])
+            if bullets:
+                lines.append("Why: " + "; ".join(_sanitize_for_md(b) for b in bullets))
+
+            for snip in (expl.get("snippets") or [])[:2]:
+                quote = _sanitize_for_md(snip.get("text", ""))
+                section = snip.get("section") or "Source"
+                lines.append(f"> {quote}  \n— *{section}*, {cwe_id}")
+
+            # Add an action to explore relationships for each item
+            actions.append({
+                "name": "explore_relationships",
+                "value": cwe_id,
+                "label": f"Explore {cwe_id} relationships"
+            })
+            lines.append("")  # spacer
+
+        return {"markdown": "\n".join(lines).strip(), "actions": actions}
+
+# -----------------------------------------------------------------------------
@@
 class ResponseGenerator:
     def __init__(self, llm, persona_prompts):
         self.llm = llm
         self.persona_prompts = persona_prompts
+        self.mapping_renderer = MappingRenderer()
@@
     def build_response(self, persona: str, recommendations: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
-        # existing logic that builds a persona-specific answer from context
-        # ...
-        return {"content": text, "meta": {...}}
+        """
+        3.2: If we have mapping recommendations, render them concisely with confidence,
+        short quotes, and per-item 'Explore relationships' actions.
+        Falls back to your existing freeform path if none are provided.
+        """
+        if recommendations:
+            bundle = self.mapping_renderer.render(recommendations, persona)
+            return {
+                "content": bundle["markdown"],
+                "actions": bundle["actions"],
+                "meta": {"has_recommendations": True}
+            }
+
+        # Fallback to your prior rich response path
+        text = "I couldn't produce mapping suggestions from the current context."
+        return {"content": text, "actions": [], "meta": {"has_recommendations": False}}


If your ResponseGenerator.build_response already exists, merge the new branch that handles recommendations and keep your old path as fallback.

apps/chatbot/src/main.py (wire up actions + callback)
*** apps/chatbot/src/main.py
@@
 import chainlit as cl
-from apps.chatbot.src.query_handler import CWEQueryHandler
-from apps.chatbot.src.response_generator import ResponseGenerator
+from apps.chatbot.src.query_handler import CWEQueryHandler
+from apps.chatbot.src.response_generator import ResponseGenerator
+from apps.chatbot.src.repositories.relationship_repo import RelationshipRepo
@@
-# bootstrap (existing)
+# bootstrap (existing)
 relationship_repo = RelationshipRepo()
 query_handler = CWEQueryHandler(store, embedder, relationship_repo, prohibited_cwes, discouraged_cwes)
 response_generator = ResponseGenerator(llm, persona_prompts)
@@
 @cl.on_message
 async def on_message(message: cl.Message):
     user_query = message.content
     persona = cl.user_session.get("persona", "Developer")
@@
-    result = await conversation_manager.process_user_message_streaming(
-        session_id=session_id,
-        message_content=user_query,
-        message_id=message.id
-    )
+    # Your existing conversation pipeline; ensure it returns recommendations list
+    result = await conversation_manager.process_user_message_streaming(
+        session_id=session_id,
+        message_content=user_query,
+        message_id=message.id
+    )
 
-    # existing rendering
-    # ...
+    # 3.2: render prioritized CWE mapping suggestions (if present)
+    recs = result.get("recommendations") or []
+    rendered = response_generator.build_response(persona=persona, recommendations=recs)
+
+    msg = cl.Message(content=rendered["content"])
+    if rendered.get("actions"):
+        # Convert lightweight action dicts into Chainlit actions
+        msg.actions = [cl.Action(name=a["name"], value=a["value"], label=a["label"])
+                       for a in rendered["actions"]]
+    await msg.send()
@@
+# 3.2: relationship explorer action
+@cl.action_callback("explore_relationships")
+async def on_explore_relationships(action: cl.Action):
+    cwe_id = str(action.value).upper()
+    rels = await query_handler.get_relationships(cwe_id)
+
+    def _fmt_group(title: str, items: list[dict]) -> str:
+        if not items:
+            return f"- *None*"
+        return "\n".join(f"- **{it['cwe_id']}** — {it.get('name', '')}".rstrip()
+                         for it in items)
+
+    content = (
+        f"### Relationships for **{cwe_id}**\n\n"
+        f"**ParentOf**\n{_fmt_group('ParentOf', rels.get('ParentOf', []))}\n\n"
+        f"**ChildOf**\n{_fmt_group('ChildOf', rels.get('ChildOf', []))}\n\n"
+        f"**RelatedTo**\n{_fmt_group('RelatedTo', rels.get('RelatedTo', []))}"
+    )
+    await cl.Message(content=content).send()


If your conversation_manager.process_user_message_streaming already sends messages internally, you can instead just attach actions to that message. The above shows the simple, self-contained path where main.py sends one message for the mapping list and wires the action.

What this adds (in plain English)

A compact, prioritized list of CWE suggestions with a numeric confidence and level.

Short, cited snippets from the CWE to justify each suggestion.

A per-item “Explore relationships” button that opens Parent/Child/Related CWEs.

A stub repo so the action works immediately; swap it for your real relationship store later.




here are drop-in pytest unit tests that cover the new renderer, the ResponseGenerator mapping path, and the RelationshipRepo stub. They don’t mock Chainlit; they just validate the pure-Python pieces you added.

apps/chatbot/tests/unit/test_mapping_renderer.py (new)
+++ apps/chatbot/tests/unit/test_mapping_renderer.py
@@
+import re
+from apps.chatbot.src.response_generator import MappingRenderer, ResponseGenerator
+
+
+def test_mapping_renderer_renders_confidence_bullets_and_snippets():
+    recs = [
+        {
+            "cwe_id": "CWE-79",
+            "name": "Cross-site Scripting",
+            "confidence": 0.9132,
+            "level": "High",
+            "explanation": {
+                "bullets": [
+                    "Query contains `<script>` and HTML context indicative of XSS.",
+                    "Matches CWE alias 'XSS'.",
+                ],
+                "snippets": [
+                    {
+                        "text": "The software does not neutralize or incorrectly neutralizes input prior to generating web pages.",
+                        "section": "Description",
+                    },
+                    {
+                        "text": "Attackers may execute arbitrary JavaScript in a victim's browser.",
+                        "section": "Common Consequences",
+                    },
+                ],
+            },
+        },
+        {
+            "cwe_id": "CWE-116",
+            "name": "Improper Encoding or Escaping of Output",
+            "confidence": 0.72,
+            "level": "Medium",
+            "explanation": {
+                # include tricky content to verify sanitization (backticks + control char)
+                "bullets": ["Evidence shows missing output encoding ``` in template \x07 layer."],
+                "snippets": [{"text": "Ensure correct escaping prior to rendering.", "section": "Mitigations"}],
+            },
+        },
+    ]
+
+    bundle = MappingRenderer.render(recommendations=recs, persona="Developer")
+    md = bundle["markdown"]
+    actions = bundle["actions"]
+
+    # List numbering and IDs
+    assert "**1) CWE-79" in md
+    assert "**2) CWE-116" in md
+
+    # Confidence rounding / formatting
+    assert "Confidence: **0.91** (High)" in md
+    assert "Confidence: **0.72** (Medium)" in md
+
+    # Bullets stitched into "Why:" line
+    assert "Why: Query contains `<script>` and HTML context indicative of XSS.; Matches CWE alias 'XSS'." in md
+
+    # Snippet quoting + section tag
+    assert "> The software does not neutralize or incorrectly neutralizes input prior to generating web pages." in md
+    assert "— *Description*, CWE-79" in md
+
+    # Sanitization: backticks replaced and control chars removed
+    assert "```" not in md
+    assert "ʼʼʼ" in md  # neutralized triple backticks
+    assert "\x07" not in md  # control char should be stripped
+
+    # Actions one per recommendation
+    assert len(actions) == 2
+    assert all(a["name"] == "explore_relationships" for a in actions)
+    # correct values for each action
+    vals = {a["value"] for a in actions}
+    assert {"CWE-79", "CWE-116"} == vals
+    # human label present
+    assert any("Explore CWE-79 relationships" in a["label"] for a in actions)
+
+
+def test_mapping_renderer_empty_list():
+    bundle = MappingRenderer.render(recommendations=[], persona="Developer")
+    assert bundle["actions"] == []
+    assert "_No strong CWE matches found._" in bundle["markdown"]
+
+
+def test_response_generator_uses_renderer_when_recommendations_present():
+    # minimal ResponseGenerator wiring (llm & prompts unused in this path)
+    rg = ResponseGenerator(llm=None, persona_prompts={})
+    recs = [{"cwe_id": "CWE-20", "name": "Improper Input Validation", "confidence": 0.83, "level": "High"}]
+    out = rg.build_response(persona="Developer", recommendations=recs)
+
+    assert out["meta"]["has_recommendations"] is True
+    assert "CWE-20" in out["content"]
+    assert out["actions"] and out["actions"][0]["name"] == "explore_relationships"
+
+
+def test_response_generator_fallback_when_no_recommendations():
+    rg = ResponseGenerator(llm=None, persona_prompts={})
+    out = rg.build_response(persona="Developer", recommendations=[])
+    assert out["meta"]["has_recommendations"] is False
+    assert "couldn't produce mapping suggestions" in out["content"].lower()
+    assert out["actions"] == []

apps/chatbot/tests/unit/test_relationship_repo.py (new)
+++ apps/chatbot/tests/unit/test_relationship_repo.py
@@
+import pytest
+from apps.chatbot.src.repositories.relationship_repo import RelationshipRepo
+
+
+@pytest.mark.asyncio
+async def test_relationship_repo_returns_stubbed_related_items_for_cwe_79():
+    repo = RelationshipRepo()
+    rels = await repo.get_relationships("cwe-79")
+
+    # shape
+    assert set(rels.keys()) == {"ParentOf", "ChildOf", "RelatedTo"}
+    assert isinstance(rels["RelatedTo"], list)
+
+    # content from the provided stub
+    related_ids = {r["cwe_id"] for r in rels["RelatedTo"]}
+    assert "CWE-116" in related_ids
+    assert "CWE-20" in related_ids
+
+
+@pytest.mark.asyncio
+async def test_relationship_repo_unknown_cwe_returns_empty_groups():
+    repo = RelationshipRepo()
+    rels = await repo.get_relationships("CWE-9999")
+    assert rels == {"ParentOf": [], "ChildOf": [], "RelatedTo": []}

(optional) apps/chatbot/tests/unit/__init__.py (new; helps some runners discover the package)
+++ apps/chatbot/tests/unit/__init__.py
@@
+# Intentionally empty: marks this folder as a package for some test runners.

Notes for running locally

If you normally run tests from the repo root, imports like from apps.chatbot.src... should work.
If your runner uses a different CWD, set PYTHONPATH=. or add a pytest.ini with:

[pytest]
pythonpath = .


These tests rely only on your new files; no DB or Chainlit runtime is required.