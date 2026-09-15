"""Deterministic DETECTION-recall benchmark for the SAST front-end (no model / docker / network).

Scores whether wave's DETERMINISTIC pins (sinks / routes / authz) FLAG a known vulnerable location, and stay
quiet on safe code -- a fast, reproducible measuring stick for the detection stage's recall + precision, per
CWE and per language. Real-world end-to-end CVE numbers come from agent/bench/ghsa_bench.py (model + docker);
this isolates the cheap deterministic layer so a recall regression is caught in <1s, every change.

A `vuln` case passes if a pin lands within +/-2 lines of the marked line; a `clean` case passes if NO pin
lands there (false-positive check). Run:  python -m agent.bench.detect_recall
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from agent.orchestrator import repomap                                  # noqa: E402

# (name, filename, source, marked-line, cwe, kind, guard) where kind is:
#   "vuln"  -> a pin of ANY class must land near the line (recall).
#   "clean" -> the DETERMINISTIC precision layer must keep quiet: no pin whose label is in `guard` near the
#              line. (Pins are recall-first, so parameterized-SQL / constant sinks still pin BY DESIGN -- the
#              model detector + taint gate clear those downstream; they aren't deterministic-precision cases.)
CASES = [
    ("py-sqli", "a.py", "def h(req):\n    q = req.args['id']\n    db.execute(f\"SELECT * FROM u WHERE id={q}\")\n", 3, "CWE-89", "vuln", None),
    ("py-cmd", "c.py", "import os\ndef h(req):\n    os.system('ping ' + req.args['host'])\n", 3, "CWE-78", "vuln", None),
    ("py-path", "d.py", "def h(req):\n    open('/data/' + req.args['f'])\n", 2, "CWE-22", "vuln", None),
    ("py-ssrf", "e.py", "import requests\ndef h(req):\n    requests.get(req.args['url'])\n", 3, "CWE-918", "vuln", None),
    ("py-deser", "f.py", "import pickle\ndef h(req):\n    pickle.loads(req.data)\n", 3, "CWE-502", "vuln", None),
    ("py-redirect", "g.py", "def h(req):\n    return redirect(req.args['next'])\n", 2, "CWE-601", "vuln", None),
    ("py-idor", "h.py", "from x import *\n@router.get('/o/{oid}')\ndef get_o(oid: int):\n    return db.query(O).get(oid)\n", 3, "CWE-639", "vuln", None),
    ("js-xss", "j.js", "function h(req, res){\n  res.send('<b>' + req.query.name + '</b>');\n}\n", 2, "CWE-79", "vuln", None),
    ("js-nosqli", "k.js", "function h(req){\n  db.find({$where: req.query.q});\n}\n", 2, "CWE-943", "vuln", None),
    ("js-cmd", "l.js", "const cp=require('child_process');\nfunction h(req){\n  cp.exec('ls ' + req.query.d);\n}\n", 3, "CWE-78", "vuln", None),
    ("go-cmd", "m.go", "func h(w http.ResponseWriter, r *http.Request){\n  exec.Command(\"sh\", \"-c\", r.URL.Query().Get(\"c\"))\n}\n", 2, "CWE-78", "vuln", None),
    ("php-cmd", "n.php", "<?php\nfunction h(){\n  system($_GET['c']);\n}\n", 3, "CWE-78", "vuln", None),
    ("rust-cmd", "o.rs", "fn h(c: &str) {\n    Command::new(\"sh\").arg(\"-c\").arg(c);\n}\n", 2, "CWE-78", "vuln", None),
    ("ruby-cmd", "p.rb", "def h(id)\n  system(\"echo #{id}\")\nend\n", 2, "CWE-78", "vuln", None),
    # deterministic-precision cases: the layer that CAN decide statically must stay quiet
    ("idor-owned", "i.py", "from x import *\n@router.get('/o/{oid}')\ndef get_o(oid: int, user=Depends(current_user)):\n    o = db.query(O).get(oid)\n    if o.owner_id != user.id: raise E\n    return o\n", 3, "CWE-639", "clean", ("authz",)),
    ("frontend-fetch", "app/ui.jsx", "export function C(){\n  return fetch('/api/' + userInput);\n}\n", 2, "CWE-918", "clean", ("ssrf", "SQLi", "cmd", "path", "deser")),
]


def _pins_near(target_dir, filename, line, window=2):
    """All pin lines (sinks+routes+authz) within +/-window of `line` in `filename`."""
    res = repomap.build_map(str(target_dir))
    hits = []
    for p, (routes, sinks, dyn) in res["per_file"].items():
        if Path(p).name != Path(filename).name:
            continue
        for ln, label, _code in list(routes) + list(sinks) + list(dyn):
            if abs(ln - line) <= window:
                hits.append((ln, label))
    return hits


def run():
    from collections import defaultdict
    tp = fp = fn = tn = 0
    per_cwe = defaultdict(lambda: [0, 0])                                # cwe -> [detected, total] for vuln cases
    rows = []
    for name, fn_name, src, line, cwe, kind, guard in CASES:
        with tempfile.TemporaryDirectory() as d:
            fp_ = Path(d) / fn_name
            fp_.parent.mkdir(parents=True, exist_ok=True)
            fp_.write_text(src, encoding="utf-8")
            hits = _pins_near(d, fn_name, line)
        labels = {lbl for _ln, lbl in hits}
        if kind == "vuln":
            per_cwe[cwe][1] += 1
            if hits:
                tp += 1; per_cwe[cwe][0] += 1; ok = "HIT "
            else:
                fn += 1; ok = "MISS"
        else:                                                           # clean: the guarded label(s) must be absent
            leaked = labels & set(guard or ())
            if leaked:
                fp += 1; ok = "FP  "
            else:
                tn += 1; ok = "ok  "
        rows.append(f"  [{ok}] {name:16} {cwe:9} pins={sorted(labels)[:4]}")
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fp_rate = fp / (fp + tn) if (fp + tn) else 0.0
    print("\n".join(rows))
    print(f"\nDETECTION RECALL (pins flag the vuln): {tp}/{tp + fn} = {recall:.0%}")
    print(f"DETERMINISTIC PRECISION (guarded-clean stays quiet): {tn}/{tn + fp} = {(1 - fp_rate):.0%}")
    print("per-CWE recall:", {c: f"{d}/{t}" for c, (d, t) in sorted(per_cwe.items())})
    return {"recall": recall, "fp_rate": fp_rate, "tp": tp, "fn": fn, "fp": fp, "tn": tn,
            "per_cwe": {c: (d, t) for c, (d, t) in per_cwe.items()}}


if __name__ == "__main__":
    run()
