"""Safe twins (remaining-work 4): one SECURE control per vuln fixture. A safe twin = the same stack/shape
as its vuln fixture but with the bug FIXED, so ANY finding on it is a false positive. They are the only
false-positive alarm the scoreboard has, so every twin must be well-formed and mirror a real vuln target."""
import json
from pathlib import Path

BENCH = Path(__file__).resolve().parents[1] / "agent" / "bench" / "targets"


def _manifests():
    return {p.name: json.loads((p / "MANIFEST.json").read_text(encoding="utf-8"))
            for p in BENCH.iterdir() if (p / "MANIFEST.json").is_file()}


def test_safe_twins_are_well_formed_and_mirror_a_vuln_fixture():
    man = _manifests()
    safe = {n: m for n, m in man.items() if m.get("safe")}
    assert len(safe) >= 5, f"expected the expanded safe-twin set, got {sorted(safe)}"
    for name, m in safe.items():
        assert m["vulns"] == [], f"{name}: a safe control must declare zero vulns"
        twin = m.get("twin_of")
        if twin is None:
            continue                                        # the original two controls (safeapp/htmlsafe) have none
        assert twin in man, f"{name}: twin_of {twin!r} is not a target"
        assert not man[twin].get("safe"), f"{name}: twin_of must point at a VULN fixture"
        assert man[twin]["vulns"], f"{name}: the twinned fixture has no vulns"
        assert m["stack"] == man[twin]["stack"], f"{name}: stack must match its twin {twin}"


def test_new_twins_present_and_distinct_stacks_covered():
    man = _manifests()
    for t in ("nodesafe", "pgsafe", "crossfsafe"):
        assert t in man and man[t].get("safe"), t
    # the point of the expansion: a NON-python control now exists (every prior twin was python/flask)
    safe_stacks = {m["stack"] for m in man.values() if m.get("safe")}
    assert "node/express" in safe_stacks


def test_python_twins_compile_and_bind_params():
    for name in ("pgsafe", "crossfsafe"):
        src = (BENCH / name / "app.py").read_text(encoding="utf-8")
        compile(src, f"{name}/app.py", "exec")
        assert ":q" in src or ":term" in src                 # a bound parameter is present
        assert "'+" not in src and "+ q" not in src          # no string-concatenated SQL


def test_nodesafe_sinks_present_but_defended():
    src = (BENCH / "nodesafe" / "server.js").read_text(encoding="utf-8")
    # sinks still present (so the detector flags them)...
    for sink in ("eval(", "/ping", "readFileSync", "http.get", "/load", "/echo"):
        assert sink in src, sink
    # ...but defended (so the oracle must defer)
    assert "execFile(" in src and "path.basename(" in src
    assert "ALLOWED_HOSTS" in src and "JSON.parse(" in src
    assert ".unserialize(" not in src and 'require("node-serialize")' not in src   # deser sink is JSON, not RCE
