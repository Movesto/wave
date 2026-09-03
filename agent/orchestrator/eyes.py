"""The Eyes -- structure (local tree-sitter map) + comprehension (GLM, local fallback).

Two responsibilities, both COMPREHENSION only. Neither pass ever returns a vulnerability verdict -- that
is the local detector's job (detection/exploit stay local, always). The Eyes only build the *map* the
detector reasons over:

  1. structure   -- codemap.py: entry points, call graph, entry->sink reachability (exact, local, cheap).
  2. comprehend  -- for each entry point, a semantic note: what it does, what input it takes, and which
                    operations inside it are powerful enough to matter (candidate sinks + line). This is
                    where a strong reader earns its keep -- the tree-sitter map sees calls, not meaning.
  3. audit       -- the map's blind spots. tree-sitter's call graph cannot see dynamic dispatch, eval,
                    reflection, or framework routing. We pre-scan for those patterns LOCALLY (cheap,
                    exact) and ask the reader to interpret the specific spots the parser would miss.

The comprehension model is GLM-5.2 (OpenRouter, free tier, provider does not train/retain) WHEN it is
reachable; the free pool 429s intermittently, so every call falls back to the local model. GLM is an
enhancement, never a dependency -- the pipeline is identical in shape either way.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from . import codemap

_GLM_ID = "z-ai/glm-5.2:free"
_GLM_BASE = "https://openrouter.ai/api/v1"

# Patterns the tree-sitter call graph structurally cannot resolve -> hand these spots to the reader.
_DYNAMIC = [
    (re.compile(r"\beval\s*\(|\bnew\s+Function\s*\(|\bFunction\s*\("), "eval / dynamic code"),
    (re.compile(r"\b(require|import)\s*\(\s*[A-Za-z_$\[]"), "dynamic import (variable module)"),
    (re.compile(r"\b__import__\s*\(|\bimportlib\.|\bgetattr\s*\(|\bsetattr\s*\(|\bglobals\s*\(\)"), "reflection"),
    (re.compile(r"\bexec\s*\(|\bcompile\s*\("), "exec / compile"),
    (re.compile(r"\[\s*[A-Za-z_]\w*\s*\]\s*\("), "dynamic dispatch (obj[name]())"),
    (re.compile(r"@\w+\.(route|get|post|put|delete|patch)\b|\.(get|post|put|use|all)\s*\(\s*['\"]"), "route registration"),
]
_SKIP = codemap._SKIP


def _env_key():
    import os
    if os.environ.get("OPENROUTER_API_KEY"):
        return os.environ["OPENROUTER_API_KEY"]
    for name in (".env",):
        p = Path.cwd() / name
        if p.is_file():
            for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if line.startswith("OPENROUTER_API_KEY"):
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
    return None


def make_glm():
    """A GLM-5.2 comprehension model, or None if no key is configured. Detection never uses this."""
    key = _env_key()
    if not key:
        return None
    from .model import Model
    return Model(model_id=_GLM_ID, api_base=_GLM_BASE, api_key=key)


def _json_block(text):
    """Pull the first JSON object/array out of a model reply (it may be fenced or wrapped in prose)."""
    if not text:
        return None
    text = text.split("</think>")[-1]
    m = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
    cand = m.group(1) if m else text
    for open_c, close_c in (("{", "}"), ("[", "]")):
        i, j = cand.find(open_c), cand.rfind(close_c)
        if 0 <= i < j:
            try:
                return json.loads(cand[i:j + 1])
            except Exception:
                pass
    return None


_COMPREHEND_SYS = (
    "You are a code-comprehension assistant helping map a codebase for a downstream security verifier. "
    "You do NOT decide whether anything is vulnerable -- a separate tool proves that by execution. Your "
    "only job is to describe a function accurately and point at the operations that could matter. "
    "Reply with ONE JSON object and nothing else:\n"
    '{"purpose": "<one sentence>", "untrusted_input": "<which args/fields an external caller controls, or '
    'none>", "candidate_sinks": [{"op": "<the powerful operation, e.g. child_process.exec / regex building '
    'HTML / fs.readFile>", "line": <int>, "reaches_input": <true|false>}]}\n'
    "candidate_sinks = places where a value could flow into command execution, code eval, a filesystem "
    "path, an HTTP request, SQL, or HTML output. Empty list if there are none. Be precise about lines."
)


_LEDGER_SYS = (
    "You are a security code-comprehension assistant. You are given a MAP of a whole repository: every "
    "file, what it imports and does, its functions/classes (signatures only), and inline PINS marking HTTP "
    "routes [ROUTE] and candidate sinks [SINK:<class>] for the 9 injection classes (SQLi, NoSQLi, cmd, "
    "eval, path, ssrf, xss, deser, redirect). You do NOT decide whether anything is vulnerable -- a "
    "separate tool proves that by execution. Your job: read the WHOLE map and produce an ATTACK-SURFACE "
    "LEDGER telling the downstream verifier where to look first. Reply with ONE JSON object, nothing else:\n"
    '{"entry_points": [{"name": "<route or function>", "file": "<path>", "auth": '
    '"<none|session|jwt|admin|unknown>", "input": "<what external input it takes>"}], '
    '"high_risk_ops": [{"file": "<path>", "op": "<financial logic / file upload / role check / raw SQL / '
    'exec / deserialize / etc>", "why": "<one clause>"}], '
    '"ranked_targets": [{"file": "<path>", "classes_first": ["SQLi", "..."], "reason": "<one clause>"}]}\n'
    "Rank targets by attack-surface value: input-reachable sinks first, the 9 injection classes before "
    "broader logic. Base everything ONLY on the map -- never invent a file, route, or line not in it."
)


def _cap_map(map_text, cap):
    if len(map_text) <= cap:
        return map_text, False
    return (map_text[:cap] + "\n\n[... map truncated to fit the model's context; PINNED targets and the "
            "infrastructure section above are ordered first ...]"), True


def _parse_ledger(raw, via, truncated):
    data = _json_block(raw) or {}
    notes = "" if data else (raw or "").split("</think>")[-1].strip()
    return {"via": via, "truncated": truncated,
            "entry_points": data.get("entry_points") or [],
            "high_risk_ops": data.get("high_risk_ops") or [],
            "ranked_targets": data.get("ranked_targets") or [],
            "notes": notes}


def build_ledger(map_text, local_model=None, use_glm=True, max_new_tokens=3000,
                 glm_char_cap=120000, local_char_cap=24000):
    """Stage 1b -- the model reads the whole-repo MAP and returns an Attack-Surface Ledger.

    Comprehension only (never a verdict). The context cap is PATH-DEPENDENT: GLM is a cloud model with a
    ~128k-token window, so it gets (nearly) the whole map (glm_char_cap); the local 27B has a 16k window,
    so its fallback gets a small PINNED-first slice (local_char_cap). Sizing both to the local window --
    the old bug -- threw away 60% of a real 60k-char map before GLM ever saw it.

    Path split, measured: GLM (the intended primary) emits the structured JSON cleanly. The local MTP 27B
    reasons *well* but writes free-form prose and ignores json_mode/think=False via ollama (see
    reference_ollama_num_ctx). So when no JSON parses we DON'T discard the analysis: we return it as
    `notes` (unstructured but useful), lists empty. Honest graceful degradation, not a silent empty ledger."""
    glm = make_glm() if use_glm else None
    if glm is not None:                                    # PRIMARY: cloud, big window -> (almost) whole map
        body, trunc = _cap_map(map_text, glm_char_cap)
        try:
            out = glm.generate(_LEDGER_SYS, "REPO MAP:\n\n" + body, max_new_tokens=max_new_tokens,
                               temperature=0.2, json_mode=True)
            if out.strip():
                return _parse_ledger(out, "glm", trunc)
        except Exception:
            pass                                            # 429 / transient -> fall through to local
    if local_model is not None:                            # FALLBACK: local, small window
        body, trunc = _cap_map(map_text, local_char_cap)
        out = local_model.generate(_LEDGER_SYS, "REPO MAP:\n\n" + body, max_new_tokens=max_new_tokens,
                                   temperature=0.2, think=False, json_mode=True)
        return _parse_ledger(out, "local", trunc)
    return _parse_ledger("", "none", len(map_text) > glm_char_cap)


class Eyes:
    def __init__(self, cmap, root, glm=None, local=None):
        self.map = cmap
        self.root = Path(root)
        self.glm = glm
        self.local = local

    def _ask(self, system, user, max_new_tokens=2000):
        """GLM first (comprehension may use cloud); on any failure fall back to the local model. The local
        fallback runs with thinking OFF and a generous budget -- the MTP model still reasons briefly even
        with think=False, so a tight cap gets cut mid-reasoning and returns empty content."""
        if self.glm is not None:
            try:
                out = self.glm.generate(system, user, max_new_tokens=max_new_tokens,
                                        temperature=0.2, json_mode=True)
                if out.strip():                              # empty (429/truncated) -> fall through to local
                    return out, "glm"
            except Exception as e:
                self._glm_err = str(e)[:120]
        if self.local is not None:
            return self.local.generate(system, user, max_new_tokens=max_new_tokens,
                                       temperature=0.2, think=False, json_mode=True), "local"
        return "", "none"

    def _slice(self, func, pad=2):
        try:
            lines = Path(func.file).read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return ""
        a = max(0, func.line - 1 - pad)
        b = min(len(lines), (func.end or func.line + 80) + pad)
        b = min(b, a + 160)                                  # cap the slice so a giant function can't blow context
        return "\n".join(f"{a + i + 1:>4} {ln}" for i, ln in enumerate(lines[a:b]))

    def comprehend_entry(self, func):
        src = self._slice(func)
        if not src.strip():
            return None
        chain = self.map.chain_to_entry(func.name)
        user = (f"File: {Path(func.file).name}   Entry point: {func.name}()   "
                f"Call chain: {' -> '.join(chain) if chain else func.name}\n\n{src}")
        raw, via = self._ask(_COMPREHEND_SYS, user)
        data = _json_block(raw) or {}
        return {"entry": func.name, "file": func.file, "line": func.line, "via": via,
                "purpose": (data.get("purpose") or "").strip(),
                "untrusted_input": (data.get("untrusted_input") or "").strip(),
                "candidate_sinks": data.get("candidate_sinks") or []}

    def prescan_dynamic(self):
        """Local, exact: find the spots the tree-sitter call graph cannot resolve (eval/reflection/etc.)."""
        hits = []
        for f in codemap._iter_files(str(self.root)):
            try:
                lines = Path(f).read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for i, ln in enumerate(lines, 1):
                s = ln.split("//")[0].split("#")[0]
                for rx, kind in _DYNAMIC:
                    if rx.search(s):
                        hits.append({"file": str(f), "line": i, "kind": kind, "code": ln.strip()[:160]})
                        break
        return hits


def build(target, local_model=None, budget=10, use_glm=True):
    """Full Eyes pass over `target` -> the enriched map dict handed to the detector.

    {entry_points, comprehension:[...], dynamic_blind_spots:[...], stats:{...}}
    """
    cmap = codemap.build(target)
    glm = make_glm() if use_glm else None
    eyes = Eyes(cmap, root=target, glm=glm, local=local_model)

    eps = cmap.entry_points()
    # de-dup by (name,file); prioritize decorated routes + exports, cap at budget
    seen, ordered = set(), []
    for e in sorted(eps, key=lambda f: (not f.decorators, f.name)):
        k = (e.name, e.file, e.line)
        if k not in seen:
            seen.add(k)
            ordered.append(e)
    comp = []
    for e in ordered[:budget]:
        c = eyes.comprehend_entry(e)
        if c:
            comp.append(c)
    dyn = eyes.prescan_dynamic()
    via = comp[0]["via"] if comp else ("glm" if glm else "local")
    return {"target": str(target),
            "entry_points": [{"name": e.name, "file": e.file, "line": e.line,
                              "exported": e.exported, "decorators": e.decorators} for e in ordered],
            "comprehension": comp,
            "dynamic_blind_spots": dyn,
            "stats": {"functions": sum(len(v) for v in cmap.funcs.values()),
                      "calls": len(cmap.calls), "entry_points": len(ordered),
                      "comprehended": len(comp), "dynamic_hits": len(dyn), "reader": via}}
