"""Stage 2 -- the DETECTOR: clean-room asymmetric falsification.

The notebook (Stage 1b) GENERATED believed findings with the model primed to FIND. Running N more primed
passes just launders that bias (the field's warning, and our own open risk). Instead we DECORRELATE by
CONTEXT ASYMMETRY: a FRESH single-shot call, shown ONLY the raw code slice around the finding, tasked
SOLELY to DISPROVE it (low temperature). A finding that survives an honest attempt to knock it down is
worth the expensive proof loop; one the model can refute with a cited guard / cast / allow-list / constant
is dropped. Same weights, opposite framing, no shared context -- strictly better than re-rolling the primed
prompt, and free (sequential, one GPU).

Honest limits: `survives` != `confirmed` -- Stage 3 proves by execution; this only FILTERS. And it is the
same model, so shared TRAINING bias survives the context reset (it kills priming/anchoring, not blind
spots). A refuted finding could be a real vuln the model wrongly cleared (a false refute = a missed bug),
so refutations are LOGGED with their cited reason for a human to scan.

Input: the persistent notebook (wave_notebook.jsonl from `eyes --notes`). Output: wave_candidates.jsonl
(survivors, ranked) -- the Stage 3 proof loop's worklist. Resumable via wave_detect.jsonl.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from .repomap import _rel  # noqa: F401  (kept for symmetry with notebook; path handling below uses it indirectly)

# severity for ranking survivors (the proof loop works the most dangerous first)
_SEV = {"cmd": 9, "eval": 9, "deser": 8, "ssti": 8, "sqli": 8, "memory": 8, "nosqli": 7, "ssrf": 6,
        "path": 6, "protopollution": 6, "proto": 6, "prototype": 6, "format": 6, "xss": 4, "authz": 5,
        "redirect": 3, "other": 1}

_FALSIFY_SYS = (
    "You are a skeptical security reviewer. Another analyst flagged a POSSIBLE vulnerability in the code "
    "below. Your ONLY job is to DISPROVE it: find the concrete reason, VISIBLE IN THIS CODE, that it is "
    "NOT exploitable -- input validation / sanitization / escaping / parameterization before the sink, a "
    "type cast or schema that constrains the input, an allow-list, the sink being unreachable from "
    "untrusted input, or the value being a constant that is not attacker-controlled. Judge using ONLY the "
    "code shown; do NOT assume a guard exists elsewhere. "
    "Output ONE JSON object and NOTHING else, with the keys in THIS ORDER: "
    '{"reason": "<work through the code, then state your decision>", "verdict": "refuted"|"survives"}. '
    "Write `reason` FIRST -- do your full analysis there -- and write `verdict` LAST, as the single "
    "conclusion that FOLLOWS FROM that analysis. The verdict MUST agree with how the reason ends: if the "
    'reason concludes the code is safe / not exploitable / the input cannot reach the sink -> "refuted"; '
    'if the reason concludes you could NOT prove it safe from this code -> "survives". "refuted" = you '
    'found a concrete safe-making reason HERE. "survives" = you could NOT disprove it from this code. Be '
    "strict but honest: do not refute just because a guard *might* exist elsewhere, and NEVER emit a "
    "verdict that contradicts your own reason.")


def _load_findings(notebook_path):
    """Flatten the notebook's per-file findings into deduped candidate records."""
    out, seen = [], set()
    for line in Path(notebook_path).read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            note = json.loads(line)
        except Exception:
            continue
        for f in note.get("findings", []):
            if not isinstance(f, dict):
                continue
            try:
                ln = int(f.get("line") or 0)
            except (TypeError, ValueError):
                ln = 0
            cls = str(f.get("class") or "other").lower()
            key = (note.get("file", ""), ln, cls)
            if key in seen:
                continue
            seen.add(key)
            out.append({"file": note.get("file", ""), "line": ln, "class": cls,
                        "sink": str(f.get("sink") or ""), "input": str(f.get("input") or ""),
                        "why": str(f.get("why") or ""), "confidence": str(f.get("confidence") or "")})
    return out


def _rank_key(f):
    return (_SEV.get(f["class"], 1), 1 if f["confidence"].lower() == "high" else 0)


def _slice(root, rel, line, pad=30):
    try:
        lines = (Path(root) / rel).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    a = max(0, line - 1 - pad)
    b = min(len(lines), line + pad)
    return "\n".join(f"{a + i + 1}: {ln}" for i, ln in enumerate(lines[a:b]))


# the trailing verdict field -- last match wins (the reason may quote the schema/the word "verdict")
_VERDICT_RE = re.compile(r'"verdict"\s*:\s*"\s*(refuted|survives)\s*"', re.I)


def _parse(txt):
    """Best-effort {verdict, reason} from the model's reply. Prefer strict JSON (after any </think>). A
    long, unescaped `reason` string is the common breakage that makes json.loads fail -- when it does,
    salvage the verdict by regex (taking the LAST match, since verdict is emitted last) so a real
    decision is never lost to the default. The reason ordering is enforced by _FALSIFY_SYS so that the
    verdict trails -- and therefore reflects -- the analysis, never a label committed before reasoning."""
    after = (txt or "").split("</think>")[-1]
    for scope in (after, txt or ""):
        i, j = scope.find("{"), scope.rfind("}")
        if 0 <= i < j:
            try:
                d = json.loads(scope[i:j + 1])
                if isinstance(d, dict):
                    return d
            except Exception:
                pass
    scope = after or (txt or "")                           # strict JSON failed -> salvage the verdict
    ms = _VERDICT_RE.findall(scope)
    return {"verdict": ms[-1].lower()} if ms else {}


def falsify(model, root, finding):
    """Clean-room disprove attempt on one finding. Returns {verdict, reason}. Unparseable/failed -> the
    finding SURVIVES (we never drop a lead on a model glitch -- the safe failure direction)."""
    code = _slice(root, finding["file"], finding["line"])
    if not code.strip():
        return {"verdict": "survives", "reason": "could not read the code slice"}
    claim = (f"FLAGGED: {finding['class']} at line {finding['line']}. sink: {finding['sink']}. "
             f"untrusted input: {finding['input'] or 'unclear'}.")
    user = f"{claim}\n\nCODE:\n{code}\n\nTry to disprove this finding."
    try:
        # verdict is emitted LAST now (reason-first, so it reflects the concluded analysis) -- give a
        # generous budget so a verbose reason can't run out of room before the verdict lands.
        txt = model.generate(_FALSIFY_SYS, user, max_new_tokens=1800, temperature=0.1, think=False,
                             json_mode=True)
    except Exception as e:
        return {"verdict": "survives", "reason": f"falsifier call failed: {str(e)[:120]}"}
    d = _parse(txt)
    v = str(d.get("verdict", "")).lower()
    if v not in ("refuted", "survives"):
        v = "survives"                                     # unparseable -> keep the lead
    return {"verdict": v, "reason": str(d.get("reason") or "")}


def run(model, root, notebook_path=None, budget=40, out_dir=None, resume=True, jobs=1):
    """Falsify the notebook's findings (highest severity+confidence first, up to budget). Writes the
    per-finding verdicts to wave_detect.jsonl (resumable) and the SURVIVORS (ranked) to
    wave_candidates.jsonl -- the Stage 3 worklist. `jobs`>1 falsifies CONCURRENTLY (cloud model only).
    Returns (survivors, refuted)."""
    from .parallel import fan_out, is_cloud_model
    out_dir = Path(out_dir or root)
    notebook_path = notebook_path or (out_dir / "wave_notebook.jsonl")
    if not Path(notebook_path).exists():
        raise SystemExit(f"no notebook at {notebook_path} -- run `eyes --notes` first")
    findings = sorted(_load_findings(notebook_path), key=_rank_key, reverse=True)

    detect_log = out_dir / "wave_detect.jsonl"
    done = {}
    if resume and detect_log.exists():
        for line in detect_log.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                d = json.loads(line)
                done[(d["file"], d["line"], d["class"])] = d
            except Exception:
                pass

    todo = []
    for f in findings:
        if (f["file"], f["line"], f["class"]) in done:
            continue
        if len(todo) >= budget:
            break
        todo.append(f)
    n_todo = len(todo)
    if jobs > 1 and not is_cloud_model(model):
        print("[detect] --jobs>1 needs a cloud model -- falsifying serially", flush=True)
        jobs = 1

    def _compute(f, i):
        print(f"[detect] {i}/{n_todo} falsify {f['class']}@{f['file']}:{f['line']} ...", flush=True)
        try:
            return falsify(model, root, f)                  # falsify already fails SAFE (survives) on a glitch
        except Exception as e:
            return {"verdict": "survives", "reason": f"falsify error, kept as a lead: {type(e).__name__}: {e}"}

    with detect_log.open("a", encoding="utf-8") as fh:
        def _commit(f, res, i):
            rec = {**f, **res}
            fh.write(json.dumps(rec) + "\n")
            fh.flush()
            done[(f["file"], f["line"], f["class"])] = rec
            mark = "SURVIVES" if res["verdict"] == "survives" else "refuted"
            print(f"[detect]   -> {mark} ({f['class']}@{f['file']}:{f['line']}): {res['reason'][:80]}", flush=True)
        fan_out(todo, _compute, _commit, jobs)

    results = [done[(f["file"], f["line"], f["class"])] for f in findings
               if (f["file"], f["line"], f["class"]) in done]
    survivors = sorted([r for r in results if r["verdict"] == "survives"], key=_rank_key, reverse=True)
    refuted = [r for r in results if r["verdict"] == "refuted"]
    cand = out_dir / "wave_candidates.jsonl"
    cand.write_text("\n".join(json.dumps(r) for r in survivors) + ("\n" if survivors else ""),
                    encoding="utf-8")
    return survivors, refuted, {"candidates": str(cand), "log": str(detect_log)}
