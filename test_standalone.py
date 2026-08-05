"""Unit-test `_standalone` against the exact R6 ghosts it exists to prevent."""
import build_js_contrastive as J
import build_ts_contrastive as T

CASES = [
    # (code, ident, expected, why)
    ("if (key === '__proto__' || key === 'prototype') {", "__proto__", False,
     "only inside a string literal"),
    ("if (key === '__proto__' || key === 'prototype') {", "key", True,
     "a real variable"),
    ("const isReplay = markReplay(plivoReplayCache, replayKey);", "plivo", False,
     "only inside a longer identifier"),
    ("const isReplay = markReplay(plivoReplayCache, replayKey);", "replayKey", True,
     "a real variable"),
    ("throw new SandboxAccessError(`Access to prototype is not permitted`);",
     "Access", False, "only inside a template literal"),
    ("case 'link': return onlink()", "link", False, "only as a string case label"),
    ("case 'link': return onlink()", "onlink", True, "a real function"),
    ("function createMatrixExposedActions(params) {", "Matrix", False,
     "only inside a longer identifier"),
    ('const dest = new URL(destination).hostname;', "destination", True,
     "a real variable"),
]

fails = 0
for mod, name in ((T, "TS"), (J, "JS")):
    for code, ident, expect, why in CASES:
        got = mod._standalone(ident, code)
        if got != expect:
            fails += 1
            print(f"  FAIL [{name}] {ident!r} -> {got}, expected {expect} ({why})")
print(f"{'PASS' if not fails else 'FAIL'}: {len(CASES) * 2 - fails}/{len(CASES) * 2} checks")
raise SystemExit(1 if fails else 0)
