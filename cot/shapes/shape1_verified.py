# ============================================================
# cot/shapes/shape1_verified.py
#
# Verified vuln-trace regeneration. Unlike the other shapes, a
# generated trace is KEPT only if it passes the oracle gates
# (cot/gates.py) against the patch-localization Region
# (cot/oracle.py). Failures are DROPPED and logged with the failing
# gate — no more keeping speculative/hallucinated traces.
#
# Works with the standard cot/runner.py: build_prompt does the
# (blind) generation prompt; verify runs the gates and returns the
# record or None. Rejection reasons are appended to
# data/cot/pilot/shape1_verified.rejections.jsonl.
#
# Pair with a strong teacher: WAVE_GENERATOR_BACKEND=anthropic.
# Target slices (from the cot_v4 eval): real React/TS vuln, R2Vul
# py/js vuln, crypto/auth CWEs. Set via WAVE_VERIFIED_LANGS
# (comma-separated; default: typescript,react).
# ============================================================
import json
import os
import re
from typing import Optional

from ..fix_pairs import iter_fix_pairs
from ..oracle import locate_vuln, Region
from ..gates import all_gates_pass
from ..config import PILOT_DIR
from .common import detect_language

name = "shape1_verified"

_REJECT_LOG = PILOT_DIR / "shape1_verified.rejections.jsonl"


def _target_languages() -> set[str]:
    raw = os.environ.get("WAVE_VERIFIED_LANGS", "typescript,react")
    return {x.strip() for x in raw.split(",") if x.strip()}


def _target_types():
    """WAVE_VERIFIED_TYPES=sql_injection,xss,... restricts to those types
    (e.g. the weak ones from the eval). Empty = all types, balanced."""
    raw = os.environ.get("WAVE_VERIFIED_TYPES", "").strip()
    return {x.strip() for x in raw.split(",") if x.strip()} or None


def _existing_codes() -> set:
    """vuln_code already generated (dedup by content, robust to id scheme)."""
    import json
    codes = set()
    p = PILOT_DIR / "shape1_verified.jsonl"
    if p.exists():
        for line in open(p, encoding="utf-8"):
            try:
                r = json.loads(line)
                m = re.search(r"<SCAN>\s*(.*?)\s*</SCAN>", r["messages"][0]["content"], re.S)
                if m:
                    codes.add(m.group(1).strip())
            except Exception:
                pass
    return codes


def prepare_tasks(limit: int) -> list[dict]:
    """Type-bucketed, balanced verifiable vuln tasks. Buckets candidates by vuln
    TYPE (XSS/SQLi/cmd-injection/...) and round-robins across buckets so coverage
    is balanced and rare/weak types get a fair share — instead of whatever the
    languages happened to contain. Only keeps hunks the oracle can locate (so the
    trace is checkable) and skips codes already generated."""
    import hashlib
    from collections import defaultdict
    langs = _target_languages()
    types_filter = _target_types()
    have = _existing_codes()
    buckets = defaultdict(list)
    seen: set[str] = set()
    scanned = 0
    for fp in iter_fix_pairs(languages=langs):
        scanned += 1
        if scanned > 40000:
            break
        vt = fp.get("vuln_type", "other")
        if types_filter and vt not in types_filter:
            continue
        code = fp["vuln_code"].strip()
        if code in seen or code in have:
            continue
        seen.add(code)
        region = locate_vuln(fp["vuln_code"], fp.get("fixed_code"), fp.get("cwe"), fp.get("language"))
        if not region.known():
            continue
        h = hashlib.sha256(code.encode("utf-8")).hexdigest()[:10]
        buckets[vt].append({
            "task_id": f"shape1_verified:{vt}:{fp['language']}:{h}",
            "vuln_code": fp["vuln_code"],
            "language": fp["language"],
            "cwe": fp.get("cwe"),
            "vuln_type": vt,
            "region": region,
        })
        if sum(len(v) for v in buckets.values()) >= limit * 4:
            break

    # Round-robin across type buckets -> balanced coverage.
    out: list[dict] = []
    types_present = list(buckets)
    while len(out) < limit and any(buckets.values()):
        advanced = False
        for vt in types_present:
            if buckets[vt]:
                out.append(buckets[vt].pop(0))
                advanced = True
                if len(out) >= limit:
                    break
        if not advanced:
            break
    return out


SYSTEM = (
    "You produce chain-of-thought training data for a vulnerability scanner. "
    "Given a code snippet that contains a real, confirmed vulnerability, trace the "
    "data flow from the untrusted SOURCE to the dangerous SINK and emit a structured "
    "verdict. Reason about the CONCRETE code in front of you — name the actual "
    "identifiers and the line of the sink. Do NOT hedge or hypothesize; if you cannot "
    "point to a concrete source->sink flow, say so plainly rather than inventing one."
)


def build_prompt(task: dict) -> tuple[Optional[str], str]:
    code = task["vuln_code"]
    lang = task["language"]
    cwe_hint = task.get("cwe")
    region: Region = task.get("region")
    parts = [
        f"Language: {lang}",
        "This snippet contains a confirmed vulnerability (it was later patched).",
    ]
    if cwe_hint:
        parts.append(f"Category hint (do not just restate it): {cwe_hint}")
    # Guided generation: anchor a (possibly weak) teacher to the real fix location
    # so it traces toward the actual sink. The gates still verify the output, so a
    # hinted-but-correct trace is legitimate training data.
    if region is not None and region.known():
        loc = ", ".join(str(n) for n in sorted(region.lines)[:6])
        keys = ", ".join(sorted(region.identifiers)[:8])
        parts.append(
            f"The fix changed line(s) {loc}. The dangerous sink involves: {keys}. "
            f"Trace the data flow from the untrusted source INTO that sink — do not "
            f"point anywhere else."
        )
    parts.append(f"\nCODE:\n```{lang}\n{code}\n```\n")
    parts.append(
        "Task: trace the real data flow from the untrusted source to the dangerous "
        "sink, naming the specific identifiers and the sink's line number. Then emit:\n"
        "<think>\n[concrete source->sink reasoning — no hedging]\n</think>\n\n"
        "status: confirmed\n"
        "cwe: CWE-<n>\n"
        "severity: HIGH | MEDIUM | LOW\n"
        "line: <line number of the sink>\n"
        "trace: <one-line source->sink summary naming specific identifiers>\n"
        "fix: <short concrete fix>"
    )
    return SYSTEM, "\n".join(parts)


def build_correction(task: dict, prev_text: str, fails: list[str]) -> str:
    """Turn the specific gate failures into a targeted correction prompt, grounded
    in the patch oracle. Fed back to the teacher so it FIXES the trace instead of
    us discarding the work."""
    region: Region = task["region"]
    loc = ", ".join(str(n) for n in sorted(region.lines)[:6]) if region else "?"
    keys = ", ".join(sorted(region.identifiers)[:8]) if region else "?"
    instr = []
    for f in fails:
        if f.startswith("correspondence"):
            instr.append("You referenced identifiers that are NOT in the snippet. Use only "
                         "identifiers that literally appear in the code.")
        elif f.startswith("localization"):
            instr.append(f"Your sink is in the wrong place. The real vulnerability is at "
                         f"line(s) {loc}, involving: {keys}. Point your line: and trace: there.")
        elif "hedg" in f:
            instr.append("Remove all hedging ('could be', 'if it were', 'may', 'presumably'). "
                         "Describe the vulnerability that IS present, concretely.")
        elif "flow" in f:
            instr.append("Your trace must show a concrete data flow with arrows: "
                         "source -> intermediate -> sink.")
        elif "no concrete identifier" in f:
            instr.append("Your trace: line must name at least one specific identifier from the code.")
    fixes = "\n".join(f"- {x}" for x in instr) or "- Make the trace concrete and code-anchored."
    return (
        "Your previous analysis was REJECTED by the verifier. Fix it.\n\n"
        f"CODE:\n```{task['language']}\n{task['vuln_code']}\n```\n\n"
        f"YOUR REJECTED ANSWER:\n{prev_text[:900]}\n\n"
        f"PROBLEMS TO FIX:\n{fixes}\n\n"
        f"The vulnerability is REAL and located at line(s) {loc} ({keys}). "
        "Re-emit the FULL corrected answer in the exact format "
        "(<think> ... </think>, then status/cwe/severity/line/trace/fix)."
    )


def generate_verified(task: dict, max_attempts: int = 3):
    """Generate a trace, then feed gate failures back to the teacher up to
    max_attempts times. Returns (record_or_None, attempts_used, last_fails)."""
    from ..gates import all_gates_pass
    from ..generator import call_generator
    system, user = build_prompt(task)
    text = call_generator(user, system=system)["text"]
    ok, fails, _ = all_gates_pass(text, task["vuln_code"], task["region"])
    attempts = 1
    while not ok and attempts < max_attempts:
        corr = build_correction(task, text, fails)
        text = call_generator(corr, system=system)["text"]
        ok, fails, _ = all_gates_pass(text, task["vuln_code"], task["region"])
        attempts += 1
    if ok:
        return verify(task, text), attempts, []
    return None, attempts, fails


def _log_rejection(task: dict, fails: list[str]) -> None:
    try:
        with open(_REJECT_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps({
                "task_id": task["task_id"], "language": task["language"],
                "cwe": task.get("cwe"), "fails": fails,
            }, ensure_ascii=False) + "\n")
    except Exception:
        pass


def verify(task: dict, generated_text: str) -> Optional[dict]:
    region: Region = task["region"]
    passed, fails, _results = all_gates_pass(generated_text, task["vuln_code"], region)
    if not passed:
        _log_rejection(task, fails)
        return None
    # passed all gates -> keep, normalized to the shape1 verdict format
    cwe_m = re.search(r"CWE-\d+", generated_text)
    return {
        "messages": [
            {"role": "user", "content": f"<SCAN>\n{task['vuln_code']}\n</SCAN>"},
            {"role": "assistant", "content": generated_text.strip()},
        ],
        "_meta": {
            "shape": "shape1",
            "source": "verified",
            "language": task["language"],
            "label": "vuln",
            "cwes": [cwe_m.group(0)] if cwe_m else [],
            "ground_truth_cwe": task.get("cwe") or (region.cwe if region else None),
            "vuln_type": task.get("vuln_type"),
            "oracle": region.source if region else "none",
        },
    }
