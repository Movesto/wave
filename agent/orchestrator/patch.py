"""Stage 4 -- PATCH + REVERIFY: fix a confirmed finding, then re-run the SAME proof.

The model TRANSLATES a fix (rewrites the vulnerable function, signature + behavior preserved); the SAME
oracle that confirmed the finding re-runs on the PATCHED code and must now FAIL to reproduce it -- that is
the proof the patch holds, not the model's say-so. Two gates:
  Gate A (security): re-run the prover -> the exploit no longer fires (rung1 canary no longer `proven`, or
          the investigate loop no longer `confirmed`). Still fires -> patch REJECTED.
  Gate B (functional): the patched file still loads (py_compile / `node --check`) -- a patch that breaks
          the file is not a fix.

Language-agnostic: the model writes the fix in the file's language; the oracle (rung1 for Python, the
investigate sandbox otherwise) re-proves. NON-DESTRUCTIVE by default -- the original source is restored and
the patch is saved to wave_patches.jsonl; `--write` keeps a patch that passed both gates.

Input: wave_findings.jsonl (only `confirmed` findings are patched; `anomalous_state` is human-review, left
alone). Output: wave_patches.jsonl (per-finding: patch text + gate results + status).
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from . import briefs, codemap, prove, repro, rung1
from . import investigate as invmod
from .model import code_block

_SYSTEM = (
    "You are a security engineer. You are given ONE function that contains a CONFIRMED vulnerability. "
    "Rewrite ONLY this function to FIX the vulnerability while preserving its exact signature and normal "
    "behavior (same inputs -> same legitimate outputs). Use the safe API for the class: parameterized "
    "queries for SQLi, an argv list / shlex.quote (never a shell string) for command injection, path "
    "normalization + a base-dir containment check for path traversal, an allow-list / scheme+host check "
    "for SSRF, output encoding for XSS. Do NOT add commentary. Output the FULL fixed function in a single "
    "fenced code block and nothing else.")


def _reindent(src, base):
    """Shift `src` so its first line sits at `base` columns (the model emits at col 0; the slice may be an
    indented method)."""
    lines = src.splitlines()
    if not lines:
        return src
    cur = len(lines[0]) - len(lines[0].lstrip())
    delta = base - cur
    if delta == 0:
        return src
    out = []
    for ln in lines:
        if not ln.strip():
            out.append(ln)
        elif delta > 0:
            out.append(" " * delta + ln)
        else:
            out.append(ln[min(-delta, len(ln) - len(ln.lstrip())):])
    return "\n".join(out)


def _apply(file, slice_src, new_src):
    """Replace `slice_src` with `new_src` (indentation-matched) in `file`. Returns the ORIGINAL text for
    restore, or None if the slice isn't found."""
    code = Path(file).read_text(encoding="utf-8", errors="replace")
    if not slice_src or slice_src not in code:
        return None
    first = slice_src.splitlines()[0]
    base = len(first) - len(first.lstrip())
    Path(file).write_text(code.replace(slice_src, _reindent(new_src, base), 1), encoding="utf-8")
    return code


def gen_patch(model, c, attempts=3):
    """Model rewrites the vulnerable function. Returns the fixed source (a fenced code block) or None.
    Retries a few times: a reasoning model occasionally spends its whole budget inside <think> and emits no
    fenced block (the NO-PATCH flake) -- the same non-determinism craft() guards against with a retry. On a
    retry we insist on code-only output so <think> can't crowd out the block."""
    user = (f"Vulnerability: {c.cwe} ({c.family}). Sink: {c.sink}. A probe reached the sink unsafely.\n\n"
            f"Fix this function (keep its signature):\n```\n{c.slice}\n```")
    for i in range(attempts):
        u = user if i == 0 else (user + "\n\nOutput ONLY the fixed function as ONE fenced ``` code block -- "
                                 "no explanation, no reasoning text before or after the block.")
        patch = code_block(model.generate(_SYSTEM, u, max_new_tokens=2800))
        if patch:
            return patch
    return None


def _gate_b(file):
    """Functional smoke: the patched file still parses/loads. py_compile for Python; `node --check` for
    JS/TS when node is available (else skipped). Returns (ok, note)."""
    p = str(file)
    if p.endswith(".py"):
        import py_compile
        try:
            py_compile.compile(p, doraise=True)
            return True, "py_compile ok"
        except py_compile.PyCompileError as e:
            return False, f"py_compile failed: {str(e).splitlines()[0][:120]}"
    if briefs._is_js(p):
        try:
            r = subprocess.run(["node", "--check", p], capture_output=True, text=True, timeout=30)
            return (r.returncode == 0), ("node --check ok" if r.returncode == 0
                                         else f"node --check failed: {(r.stderr or '')[:120]}")
        except Exception:
            return True, "node --check skipped (node unavailable)"
    return True, "no parser for this language -- skipped"


def _gate_a(model, target, c, rec, have_docker, max_steps):
    """Re-run the SAME proof on the patched code. Returns (status, note), status in:
      'still'    -- the exploit RE-FIRED on the patched code (rung1 proven / investigate confirmed) -> the
                    patch FAILED.
      'cleared'  -- the proof re-ran and the exploit DEMONSTRABLY no longer fires (rung1 safe / investigate
                    refuted) -> the patch holds.
      'unproven' -- we could NOT re-witness either way (rung1 unknown / investigate believed|blocked|
                    anomalous, or no docker) -> the patch is UNVERIFIED, must NOT be called fixed.
    Only 'cleared' certifies a fix. A non-re-witness never counts as fixed (the false-'fixed' bug: a flaky
    reverify that merely fails to re-confirm is not evidence the fix works)."""
    # Reverify with the SAME oracle that actually PROVED the finding. Using rung1 for a finding that was
    # proven by investigate (because rung1 couldn't drive it in the first place) just re-produces "0 sink
    # hits -> unknown" regardless of whether the patch works -- the wrong test. So rung1 only if rung1 proved it.
    oracle = str(rec.get("oracle", ""))
    if oracle.startswith("rung1"):
        mr = rung1.micro_exec(c, rt=None)                   # deterministic -- re-run the exact canary
        status = {"proven": "still", "safe": "cleared"}.get(mr.verdict, "unproven")
        return status, f"rung1 -> {mr.verdict}: {mr.reason[:100]}"
    if not have_docker:
        return "unproven", "cannot reverify the fix (docker unavailable) -- patch UNVERIFIED, not fixed"
    mode = briefs._proof_mode(c)                             # match prove's proof-shape routing
    scaffold = repro.build(c, target, mode=("render" if mode == "render" else "call"))
    img = briefs._image_for(c.file)
    if briefs._is_js(c.file):                                # tsx+node_modules; browser only for DOM render
        from . import js_env
        if mode == "render":
            js_env.ensure_deps(target)
            img = js_env.ensure_browser_runner() or js_env.prepare(target) or img
        else:
            img = js_env.prepare(target) or img
    try:
        v = invmod.investigate(model, briefs._brief_for(c, target, "reverify the patch", scaffold=scaffold,
                                                        mode=mode),
                               image=img, mount=target, network="none",
                               max_steps=max_steps,
                               step_timeout=(300 if mode in briefs.COMPILED_MODES else
                                             (120 if mode in ("render", "asan") else
                                              (90 if briefs._is_js(c.file) else 45))))
    finally:
        repro.remove(target)
    # confirmed = re-fired (still); refuted = the model RAN it and saw it is now safe (cleared);
    # believed/blocked/anomalous = could not re-witness -> UNPROVEN (never a fix).
    status = {"confirmed": "still", "refuted": "cleared"}.get(v.verdict, "unproven")
    return status, f"investigate -> {v.verdict}: {(v.why or '')[:100]}"


def run(model, target, findings_path=None, budget=10, out_dir=None, write=False, max_steps=8):
    """Patch each confirmed finding, reverify with the SAME oracle, restore (unless --write on a pass).
    Returns (results, paths). max_steps matches prove's budget (8): the reverify is at least as hard as the
    original proof -- the model must read the patch AND rebuild the repro -- so it must not be starved of steps."""
    import shutil

    target = str(target)
    out_dir = Path(out_dir or target)
    findings_path = findings_path or (out_dir / "wave_findings.jsonl")
    if not Path(findings_path).exists():
        raise SystemExit(f"no findings at {findings_path} -- run `prove` first")
    confirmed = []
    for line in Path(findings_path).read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            d = json.loads(line)
        except Exception:
            continue
        if d.get("verdict") == "confirmed":
            confirmed.append(d)
    # last record per candidate (append-only findings log)
    uniq = {}
    for d in confirmed:
        uniq[(d["file"], d["line"], d["class"])] = d
    confirmed = list(uniq.values())

    cmap = codemap.build(target)
    rel_index = {prove._rel(target, p): fi for p, fi in cmap.files.items()}
    have_docker = shutil.which("docker") is not None

    results, worked = [], 0
    patches_log = out_dir / "wave_patches.jsonl"
    with patches_log.open("a", encoding="utf-8") as fh:
        for surv in confirmed:
            if worked >= budget:
                break
            worked += 1
            c = prove._to_candidate(surv, rel_index, target)
            fi = rel_index.get(surv.get("file", ""))
            func = prove._enclosing(fi, c.line) if fi else None
            if func:
                try:
                    lines = Path(c.file).read_text(encoding="utf-8", errors="replace").splitlines()
                    c.slice = "\n".join(lines[func.line - 1:func.end or func.line])
                except OSError:
                    pass
            print(f"[patch] {c.cwe}@{surv['file']}:{surv['line']} ({c.unit or 'no-func'}) ...", flush=True)
            if not c.slice:
                rec = {"status": "no-slice", "note": "could not locate the enclosing function to patch"}
            else:
                rec = _patch_one(model, target, c, surv, have_docker, max_steps, write)
            out = {"file": surv["file"], "line": surv["line"], "class": surv["class"], "cwe": c.cwe,
                   "unit": c.unit, **rec}
            fh.write(json.dumps(out) + "\n")
            fh.flush()
            results.append(out)
            print(f"[patch]   -> {rec['status'].upper()}  (gate_a={rec.get('gate_a', '-')}, "
                  f"gate_b={rec.get('gate_b', '-')})", flush=True)

    if model is not None:
        try:
            model.unload()
        except Exception:
            pass
    return results, {"patches": str(patches_log)}


def _patch_one(model, target, c, surv, have_docker, max_steps, write):
    patch = gen_patch(model, c)
    if not patch:
        return {"status": "no-patch", "note": "model produced no code block"}
    original = _apply(c.file, c.slice, patch)
    if original is None:
        return {"status": "apply-failed", "patch": patch, "note": "function slice not found in file"}
    kept = False
    try:
        a_status, a_note = _gate_a(model, target, c, surv, have_docker, max_steps)   # still|cleared|unproven
        ok_b, b_note = _gate_b(c.file)
        gate_a = {"still": "STILL-VULNERABLE", "cleared": "cleared", "unproven": "UNPROVEN"}[a_status]
        gate_b = "pass" if ok_b else "regressed"
        # A fix is CERTIFIED only when the exploit demonstrably no longer fires (cleared) AND the file still
        # parses. `still` -> rejected. `unproven` (couldn't re-witness / flaky reverify) -> NOT fixed, report
        # patch-unverified -- never certify a fix we could not actually re-prove holds.
        if not ok_b:
            status = "patch-rejected"                       # broke the file
        elif a_status == "cleared":
            status = "fixed"
        elif a_status == "still":
            status = "patch-rejected"                       # exploit re-fired
        else:
            status = "patch-unverified"                     # could not re-witness -> human/re-run needed
        if status == "fixed" and write:
            kept = True                                     # keep only a CERTIFIED patch on disk
        return {"status": status, "patch": patch, "gate_a": gate_a, "gate_b": gate_b,
                "gate_a_note": a_note, "gate_b_note": b_note, "written": kept}
    finally:
        if not kept:
            Path(c.file).write_text(original, encoding="utf-8")   # restore (gates are transient)
