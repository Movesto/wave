"""Class -> evidence ORACLE: the HARNESS (not the model) reads the sandbox output and decides whether a
class-appropriate, harness-planted witness actually fired.

The model DRIVES the exploit; the verdict is graded on tokens the model cannot fabricate by narration --
they come from the instrumented sinks (registry.py: `WAVE-SINK-*`), the `wave_HIT` side-effect file an
injection creates, or the headless-browser canary (`WAVE_RENDER_CANARY: 1`). This is the "read the tape,
don't trust the testimony" layer, and the same muscle DAST needs.

Not every class is graded the same (three tiers):
  - TIER 1 (log marker): cmd/eval/deser/sqli/nosqli/ssrf/path/ssti -> a distinctive marker in the run output.
  - TIER 2 (different channel): xss -> the canary EXECUTED in the browser (value 1), not merely present.
  - TIER 3 (judgment, NO marker): authz/idor/bola/access/business logic -> there is no tripwire that proves a
    *vulnerability*; the harness can see the observed state (a differential) but the verdict is a judgment ->
    stays human-review and is where the decorrelated second-model audit earns its keep.

`graded()` returns (witnessed, marker, tier): witnessed True only for a TIER 1/2 class whose marker is present.
"""
import re

# harness-planted, unforgeable side-effect: an injection that runs code creates this file, then `ls` shows it.
_HIT = "wave_HIT"

# per-class deterministic witnesses. TIER 1 = these tokens in the run output; TIER 2 (xss) handled specially.
# An EMPTY tuple = TIER 3 (judgment, no marker). Keys are the detector/prove lowercased class names.
CLASS_WITNESS = {
    "cmd":    ("WAVE-SINK-SHELL", "WAVE-SINK-EXEC", _HIT, "WAVE-PWNED"),
    "eval":   ("WAVE-SINK-EVAL", "WAVE-SINK-EXEC", _HIT, "WAVE-PWNED"),
    "deser":  ("WAVE-SINK-DESER", _HIT, "WAVE-PWNED"),
    "sqli":   ("WAVE-SINK-SQL",),
    "nosqli": ("WAVE-SINK-MONGO",),
    "ssrf":   ("WAVE-SINK-SSRF",),
    "path":   ("WAVE-SINK-PATH",),
    "ssti":   ("WAVE-SINK-TEMPLATE",),
    "xss":    ("WAVE_RENDER_CANARY:1",),        # TIER 2: only the FIRED canary (value 1); scan() adds it via regex
    # TIER 3 (no deterministic marker -> judgment + second-model audit):
    "authz": (), "idor": (), "access": (), "bola": (), "bfla": (), "redirect": (), "other": (),
}
# tokens scanned generically from run output. `wave_HIT` is EXCLUDED here on purpose: it is model-planted
# (the exploit does `touch <marker>`), so a memorized/prompt-injected bare "wave_HIT" must NOT auto-witness.
# The harness matches a PER-RUN random `wave_HIT_<rand>` explicitly (investigate.py) -- proof integrity.
_ALL_TOKENS = sorted({t for toks in CLASS_WITNESS.values() for t in toks if t != _HIT})

# --- THE PROOF SEAL (improvements remaining-work 1a) ---------------------------------------------------
# The WAVE-SINK-* markers are HARNESS-planted (emitted by the instrumented sink hooks, registry.py), NOT by
# the model. Without a seal they are forgeable: a `cat` of a hook file, a marker literal in scanned source,
# or memorization prints `WAVE-SINK-SQL`, and scan() would witness it -> a FAKE tape-grade confirm that
# skips the audit (and would be learned as truth). The seal: each hook reads a PER-RUN secret from the
# `WAVE_WITNESS` env var (the model is never told it) and prints `WAVE-SINK-<KIND>#<secret>`; scan(secret)
# counts a sink marker ONLY when it carries that run's secret. The hook SOURCE contains os.environ[...], not
# the value, so it cannot be reproduced by reading/memorizing/injection.
#
# Out of this seal's scope (unchanged, each sealed by its own mechanism): the model-planted exec markers
# `wave_HIT_<rand>` (already per-run random) and `WAVE-PWNED` (the model's cooperative exec echo), and the
# xss canary `WAVE_RENDER_CANARY:1` (sealed by requiring the browser to have EXECUTED it to value 1).
WITNESS_ENV = "WAVE_WITNESS"                     # env var the hooks read the per-run secret from
_SINK_TOKENS = sorted(t for t in _ALL_TOKENS if t.startswith("WAVE-SINK-"))   # harness-planted -> sealed
_UNSEALED_TOKENS = sorted(t for t in _ALL_TOKENS if not t.startswith("WAVE-SINK-"))  # model/canary -> as-is


def seal(token, secret):
    """The on-the-wire form of a harness marker for a run: `WAVE-SINK-SQL#<secret>`. The hooks build the
    same string from $WAVE_WITNESS; scan() looks for it. No secret -> the bare token (back-compat)."""
    return f"{token}#{secret}" if secret else token

# CWE -> class, for callers that carry only a cwe (mirror of prove._CLASS_CWE, injection classes only).
_CWE_CLASS = {"CWE-78": "cmd", "CWE-89": "sqli", "CWE-943": "nosqli", "CWE-918": "ssrf", "CWE-22": "path",
              "CWE-79": "xss", "CWE-502": "deser", "CWE-601": "redirect", "CWE-639": "authz",
              "CWE-95": "eval", "CWE-94": "eval", "CWE-1336": "ssti"}

_XSS_FIRED = re.compile(r"WAVE_RENDER_CANARY:\s*1\b")


def _class_of(cls, cwe=""):
    c = (cls or "").lower()
    if c in CLASS_WITNESS:
        return c
    return _CWE_CLASS.get((cwe or "").upper(), c)


def scan(text, secret=""):
    """The set of harness witness tokens present in a run's output (accumulated across runs by investigate).

    `secret` (the per-run witness seal, improvements 1a): when given, a HARNESS-planted sink marker counts
    ONLY if it carries this run's secret (`WAVE-SINK-SQL#<secret>`) -- a bare `WAVE-SINK-SQL` from a cat'd
    hook / scanned-source literal / memorization is IGNORED. Model-planted markers (WAVE-PWNED) and the
    fired xss canary are matched the same way with or without a secret (each is sealed by its own means).
    No secret -> legacy behaviour (bare match), for the boot-path oracle and isolated unit tests."""
    t = text or ""
    if secret:
        found = {tok for tok in _SINK_TOKENS if seal(tok, secret) in t}
        found |= {tok for tok in _UNSEALED_TOKENS if tok != "WAVE_RENDER_CANARY:1" and tok in t}
    else:
        found = {tok for tok in _ALL_TOKENS if tok in t}
    if _XSS_FIRED.search(t):
        found.add("WAVE_RENDER_CANARY:1")           # the canary EXECUTED (not merely printed 'none')
    return found


def graded(cls, markers, cwe=""):
    """Did a class-appropriate harness marker fire? `markers` = the token set investigate accumulated
    (oracle.scan over every run). Returns (witnessed, marker, tier):
      tier 'marker'  -> TIER 1/2: witnessed is authoritative (the tape).
      tier 'judgment'-> TIER 3: no marker exists for this class -> model judgment + second-model audit."""
    c = _class_of(cls, cwe)
    toks = CLASS_WITNESS.get(c)
    if not toks:                                     # unknown class OR TIER 3 -> judgment
        return False, "", "judgment"
    # a per-run `wave_HIT_<rand>` witness normalizes to the canonical `wave_HIT` for matching.
    marks = {(_HIT if str(m).startswith(_HIT) else m) for m in (markers or ())}
    if c == "xss":                                   # TIER 2: require the canary to have FIRED
        return ("WAVE_RENDER_CANARY:1" in marks, "WAVE_RENDER_CANARY:1", "marker")
    for tok in toks:
        if tok in marks:
            return True, tok, "marker"
    return False, "", "marker"
