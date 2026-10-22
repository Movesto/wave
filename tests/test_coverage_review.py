"""Stage 1a coverage review: the audit model negotiates MISSED attack surface into the notebook read set.

These lock in the two load-bearing properties:
  1. `explain_inclusion` is an HONEST, deterministic lookup -- every exclusion gate maps to the right reason
     (included / below-top-n / demoted / no-pattern / not-source), and only REAL unpinned files are promotable.
  2. the negotiation promotes a model-confirmed promotable file into the read set, while a hallucinated path
     (not in the code map) can NEVER be promoted -- the safety bound that makes feeding a cloud model safe.
"""
import json

from agent.orchestrator import coverage, repomap, select as _select


def _build(tmp_path):
    # app.py: a real route + sink (the surface that gets pinned + ranked first)
    (tmp_path / "app.py").write_text(
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "@app.route('/run')\n"
        "def run():\n"
        "    return eval(request.args['x'])\n", encoding="utf-8")
    # util.py: a bare sink, no route -> pinned but ranks below app.py
    (tmp_path / "util.py").write_text(
        "import os\n"
        "def run(c):\n"
        "    return os.system(c)\n", encoding="utf-8")
    # orders.py: a message-queue consumer. Imports `pika` (NOT in the capability dictionary) and has no
    # sink line -> UNPINNED. This is the regex blind spot the review exists to catch.
    (tmp_path / "orders.py").write_text(
        "import pika\n"
        "def process(msg):\n"
        "    handle(msg.body)\n"
        "def handle(x):\n"
        "    return x\n", encoding="utf-8")
    # a build/deploy script with a sink -> IN the code map but dropped on a partial scan (low-priority dir,
    # unlike test/ dirs which the code map excludes outright)
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "deploy.py").write_text(
        "import os\n"
        "def deploy(c):\n"
        "    os.system(c)\n", encoding="utf-8")

    res = repomap.build_map(str(tmp_path), out=str(tmp_path / "wave_map.md"))
    ranked, dropped = _select.partition_surface(res["cmap"], res["per_file"], res["pinned"], partial=True)
    return res, ranked, dropped


def _path(cmap, name):
    for p in cmap.files:
        if p.replace("\\", "/").endswith(name):
            return p
    raise AssertionError(f"{name} not in code map")


# -------------------------------------------------- explain_inclusion (the honest harness) ----------------

def test_included_file_is_not_promotable(tmp_path):
    res, ranked, dropped = _build(tmp_path)
    cmap, per_file = res["cmap"], res["per_file"]
    app = _path(cmap, "app.py")
    info = coverage.explain_inclusion(app, cmap, per_file, ranked, dropped, budget=60)
    assert info["reason"] == coverage.INCLUDED
    assert info["promotable"] is False


def test_pinned_but_below_budget_is_promotable(tmp_path):
    res, ranked, dropped = _build(tmp_path)
    cmap, per_file = res["cmap"], res["per_file"]
    assert len(ranked) >= 2, f"expected >=2 pinned, got {[repomap._rel(str(tmp_path), p) for p in ranked]}"
    # budget 1 -> everything after rank 0 is below the cutoff
    below = coverage.explain_inclusion(ranked[1], cmap, per_file, ranked, dropped, budget=1)
    assert below["reason"] == coverage.BELOW_TOPN
    assert below["promotable"] is True


def test_dropped_low_priority_file_is_demoted_and_promotable(tmp_path):
    res, ranked, dropped = _build(tmp_path)
    cmap, per_file = res["cmap"], res["per_file"]
    testf = _path(cmap, "scripts/deploy.py")
    assert testf in dropped, "the build script should be dropped on a partial scan"
    info = coverage.explain_inclusion(testf, cmap, per_file, ranked, dropped, budget=60)
    assert info["reason"] == coverage.DEMOTED
    assert info["promotable"] is True


def test_unpinned_capability_outside_dictionary_is_no_pattern(tmp_path):
    res, ranked, dropped = _build(tmp_path)
    cmap, per_file = res["cmap"], res["per_file"]
    orders = _path(cmap, "orders.py")
    assert orders not in ranked and orders not in dropped, "orders.py must be unpinned (no sink/route/cap)"
    info = coverage.explain_inclusion(orders, cmap, per_file, ranked, dropped, budget=60)
    assert info["reason"] == coverage.NO_PATTERN
    assert info["promotable"] is True


def test_hallucinated_path_is_not_source_and_not_promotable(tmp_path):
    res, ranked, dropped = _build(tmp_path)
    info = coverage.explain_inclusion(str(tmp_path / "ghost.py"), res["cmap"], res["per_file"],
                                      ranked, dropped, budget=60)
    assert info["reason"] == coverage.NOT_SOURCE
    assert info["promotable"] is False


# -------------------------------------------------- resolve (path OR feature keyword) ---------------------

def test_resolve_finds_file_by_import_keyword(tmp_path):
    res, _ranked, _dropped = _build(tmp_path)
    hits = coverage._resolve(res["cmap"], str(tmp_path), "pika")
    assert any(p.endswith("orders.py") for p in hits), "a feature keyword must resolve via file imports"


# -------------------------------------------------- the negotiation (end to end) --------------------------

class _FakeAudit:
    """Scripts the model side of the negotiation; records what it was asked."""
    def __init__(self, replies):
        self.replies, self.i, self.model_id = replies, 0, "fake-audit"

    def generate(self, system, user, **kw):
        r = self.replies[min(self.i, len(self.replies) - 1)]
        self.i += 1
        return json.dumps(r)


def test_review_promotes_confirmed_miss_and_rejects_hallucination(tmp_path, monkeypatch):
    res, ranked, dropped = _build(tmp_path)
    replies = [
        {"ask": ["pika"], "done": False},                               # turn 0: ask about the feature
        {"confirm_promote": ["orders.py", "ghost.py"], "done": True},   # turn 1: confirm real + hallucinated
    ]
    fake = _FakeAudit(replies)
    monkeypatch.setattr(coverage, "make_audit_model", lambda primary: fake)

    promoted, log = coverage.review(object(), str(tmp_path), res["cmap"], res["per_file"],
                                    ranked, dropped, budget=60, out_dir=str(tmp_path))

    names = [p.replace("\\", "/").rsplit("/", 1)[-1] for p in promoted]
    assert "orders.py" in names, "a model-confirmed, harness-promotable miss must be promoted"
    assert "ghost.py" not in names, "a hallucinated path (not in the code map) must never be promoted"
    assert (tmp_path / "wave_coverage.md").is_file(), "the review must write an auditable log"


def test_review_is_safe_noop_without_audit_model(tmp_path, monkeypatch):
    res, ranked, dropped = _build(tmp_path)
    monkeypatch.setattr(coverage, "make_audit_model", lambda primary: None)
    promoted, log = coverage.review(object(), str(tmp_path), res["cmap"], res["per_file"],
                                    ranked, dropped, budget=60, out_dir=str(tmp_path))
    assert promoted == [] and log == []
