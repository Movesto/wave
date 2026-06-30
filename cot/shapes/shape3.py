# ============================================================
# cot/shapes/shape3.py
#
# Shape 3 — Cross-file completion.
#
# Take a Shape 2 caller and pair it with the actual helper
# definition. Disposition mix:
#   ~50% confirm: helper is unsafe -> final status: confirmed
#   ~50% dismiss: helper sanitizes  -> final status: safe
#   ~15% multi-hop: the helper itself calls ANOTHER unseen
#       function. Trace must mention the new open_ref. Final
#       status is still confirmed/safe based on the visible def.
#
# We reuse Shape 2's SEED_PATTERNS so this stays consistent.
# Generator writes both the caller AND the definition, plus a
# trace that spans them. Verifier checks the disposition matches
# and (for multi-hop) that a new symbol is mentioned.
# ============================================================
import random
from typing import Optional

from .common import parse_verdict, normalize_safe_assistant
from .shape2 import SEED_PATTERNS
from .exemplars import format_shape3_exemplars
from ..specificity import score_assistant, gate


name = "shape3"

random.seed(44)


def prepare_tasks(limit: int) -> list[dict]:
    """Deterministic across limits: prepare_tasks(N)[:M] == prepare_tasks(M)."""
    rng = random.Random(44)
    tasks = []
    pool = list(SEED_PATTERNS)
    MAX_POOL = max(limit, 64)
    i = 0
    while len(tasks) < MAX_POOL:
        seed = pool[i % len(pool)]
        category, helper_fn, file_path, language, input_source, arg_name = seed

        # Disposition: confirm vs dismiss (50/50). Then 40% chance of multi-hop
        # (was 15% in v1 — v1 eval showed model wholly ignoring multi-hop task,
        # so we boost frequency until the LoRA learns to surface follow_up_refs).
        is_confirm = (i % 2 == 0)
        is_multi_hop = (rng.random() < 0.40)

        tasks.append({
            "task_id": f"shape3:{'confirm' if is_confirm else 'dismiss'}{'_hop' if is_multi_hop else ''}:{helper_fn}:{i}",
            "category": category,
            "helper_fn": helper_fn,
            "file_path": file_path,
            "language": language,
            "input_source": input_source,
            "arg_name": arg_name,
            "disposition": "confirm" if is_confirm else "dismiss",
            "multi_hop": is_multi_hop,
        })
        i += 1
    rng.shuffle(tasks)
    return tasks[:limit]


SYSTEM = (
    "You generate chain-of-thought training data for a vulnerability scanner. "
    "Specifically, you produce examples where the model can now see BOTH a "
    "caller and the previously-imported helper, and must continue the trace "
    "to a final verdict. The trace should span both files."
)


def build_prompt(task: dict) -> tuple[Optional[str], str]:
    lang = task["language"]
    helper = task["helper_fn"]
    fp = task["file_path"]
    cat = task["category"]
    input_src = task["input_source"]
    arg = task["arg_name"]
    disp = task["disposition"]
    multi = task["multi_hop"]

    if disp == "confirm":
        helper_guidance = (
            f"The helper {helper} is UNSAFE: it passes {arg} into a dangerous "
            f"sink (e.g., string-concat SQL / shell exec / unsafe deserialize / "
            f"unvalidated URL fetch, whichever is realistic for {cat}). No "
            f"sanitization. The final verdict must be `confirmed`."
        )
    else:
        helper_guidance = (
            f"The helper {helper} is SAFE: it validates/sanitizes/parameterizes "
            f"{arg} before using it (parameterized query / allowlist / escaping / "
            f"path-resolve-and-check, whichever fits {cat}). The final verdict "
            f"must be `safe`. Because it is safe, set cwe: none and severity: none."
        )

    multi_hop_extra = ""
    if multi:
        multi_hop_extra = (
            "\n\nADDITIONAL: Make the helper call ONE MORE function from yet another "
            "file (e.g., from utils/sanitizer.py). The trace should mention this new "
            "unseen call as a follow-up open_ref to investigate later — but the "
            "FINAL status is still based on what's visible (confirmed/safe per above)."
        )

    exemplar_block = format_shape3_exemplars(count=1)
    instruction = f"""{exemplar_block}

You are constructing a Shape-3 training example: cross-file completion.

PARAMETERS:
  language: {lang}
  vulnerability category: {cat}
  helper function name: {helper}
  helper file path: {fp}
  user input source: {input_src}
  argument passed into helper: {arg}
  disposition: {disp}
  multi-hop: {multi}

{helper_guidance}{multi_hop_extra}

TASK 1 — Write a caller snippet ({lang}, 6–14 lines) that imports {helper} from
{fp}, receives user input from {input_src}, and passes it into {helper}({arg}).
Do NOT define {helper} inline.

TASK 2 — Write the helper definition ({lang}, 5–14 lines) per the guidance above.

TASK 3 — Write a <think> trace that:
  - Tracks user input from the source in the caller
  - Follows it into {helper}({arg})
  - NOW examines {helper}'s actual body
  - Concludes per the disposition above
  {'- Notes the additional unseen call as a follow-up open_ref' if multi else ''}

TASK 4 — Emit the result in EXACTLY this format:

<<<CALLER_CODE file="app.{('py' if lang == 'python' else 'tsx' if lang == 'react' else 'ts' if lang == 'typescript' else 'js')}">>>
[caller snippet]
<<<END_CALLER_CODE>>>

<<<HELPER_CODE file="{fp}">>>
[helper definition]
<<<END_HELPER_CODE>>>

<think>
[your trace — 5–12 short sentences, code-anchored, spanning both files]
</think>

status: {'confirmed' if disp == 'confirm' else 'safe'}
cwe: CWE-XX | none
severity: HIGH | MEDIUM | LOW | none
trace: <one-line cross-file data flow summary>
fix: <short fix or "n/a — code is safe">
{'follow_up_refs:' if multi else ''}
{'  - <new_symbol> (<new_file>)' if multi else ''}
"""
    return SYSTEM, instruction


def _extract_block(generated: str, tag: str) -> Optional[str]:
    import re as _re
    pattern = rf"<<<{tag}(?:\s[^>]*)?>>>\s*\n(.*?)\n<<<END_{tag}>>>"
    m = _re.search(pattern, generated, _re.DOTALL)
    if not m:
        return None
    code = m.group(1).strip()
    return code or None


def verify(task: dict, generated_text: str) -> Optional[dict]:
    parsed = parse_verdict(generated_text)
    if not parsed["status"] or not parsed["think"]:
        return None

    expected = "confirmed" if task["disposition"] == "confirm" else "safe"
    if parsed["status"] != expected:
        return None

    caller = _extract_block(generated_text, "CALLER_CODE")
    helper = _extract_block(generated_text, "HELPER_CODE")
    if not caller or not helper or len(caller) < 60 or len(helper) < 40:
        return None

    # For multi-hop, require a follow_up_refs section that names something new.
    if task["multi_hop"]:
        import re as _re
        m = _re.search(r"follow_up_refs\s*:\s*\n((?:\s*-\s*[^\n]+\n?)+)", generated_text, _re.IGNORECASE)
        if not m or not m.group(1).strip():
            return None  # multi-hop case must surface a new ref

    # Build the user message: caller + helper visible inline with file markers.
    user_content = (
        f"<SCAN>\n"
        f"// caller\n"
        f"{caller}\n\n"
        f"// {task['file_path']}\n"
        f"{helper}\n"
        f"</SCAN>"
    )
    if task["language"] == "python":
        user_content = user_content.replace("// ", "# ")

    # Strip code blocks from assistant payload (they belong in the user message).
    import re as _re
    asst = _re.sub(r"<<<CALLER_CODE.*?<<<END_CALLER_CODE>>>\s*", "", generated_text, flags=_re.DOTALL)
    asst = _re.sub(r"<<<HELPER_CODE.*?<<<END_HELPER_CODE>>>\s*", "", asst, flags=_re.DOTALL).strip()

    if expected == "safe":
        asst = normalize_safe_assistant(asst)

    # Specificity gate — opt-in via WAVE_SPECIFICITY_GATE=true.
    import os as _os
    spec_meta = None
    if _os.environ.get("WAVE_SPECIFICITY_GATE", "false").lower() in ("1", "true", "yes"):
        combined_code = caller + "\n" + helper
        spec_meta = score_assistant(asst, combined_code, task["language"])
        if not gate(spec_meta["score"]):
            return None

    record = {
        "messages": [
            {"role": "user", "content": user_content},
            {"role": "assistant", "content": asst},
        ],
        "_meta": {
            "shape": "shape3",
            "language": task["language"],
            "category": task["category"],
            "disposition": task["disposition"],
            "multi_hop": task["multi_hop"],
            "label": expected,
            "cwes": [parsed["cwe"]] if (parsed["cwe"] and expected != "safe") else [],
            "specificity": spec_meta["score"] if spec_meta else None,
        },
    }
    return record
