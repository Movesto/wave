"""Missing ownership-check / IDOR-comparison regression (controls.py, sast-improvement plan 3). Pure
guard detection + the odd-one-out comparison + source reading. No model, no network.

Run: pytest tests/test_controls_authz.py -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.orchestrator import controls


def test_has_ownership_guard():
    assert controls._has_ownership_guard("q = Note.query.filter_by(user_id=current_user.id)")
    assert controls._has_ownership_guard("if note.owner != req.user:\n        abort(403)")
    assert controls._has_ownership_guard("@login_required\ndef h(): ...")
    assert controls._has_ownership_guard("rows = scope_listing(select(Note), Note, user_id)")
    assert not controls._has_ownership_guard("return db.query(Note).get(note_id)")
    assert not controls._has_ownership_guard("note = Note.query.get(id)\n    return note")


def _H(name, guard):
    return {"method": "GET", "path": "/x/{id}", "file": "f", "function": name, "has_guard": guard}


def test_ownership_gaps_flags_the_odd_one_out():
    gaps = controls._ownership_gaps([_H("a", True), _H("b", True), _H("c", True), _H("gap", False)])
    assert [h["function"] for h in gaps] == ["gap"]


def test_ownership_gaps_quiet_when_no_norm():
    assert controls._ownership_gaps([_H("a", True), _H("b", True), _H("c", True)]) == []     # all guarded
    assert controls._ownership_gaps([_H("a", True), _H("gap", False)]) == []                 # too few handlers
    # a codebase that mostly does NOT check is not an "odd one out" -> stay quiet (no per-route spam)
    assert controls._ownership_gaps([_H("a", True), _H("b", False), _H("c", False), _H("d", False)]) == []


def test_id_handlers_reads_guard_from_source(tmp_path):
    from agent.orchestrator import routes as R
    (tmp_path / "a.py").write_text(
        "def get_mine(id):\n    return Note.query.filter_by(id=id, user_id=current_user.id).first()\n",
        encoding="utf-8")
    (tmp_path / "b.py").write_text(
        "def get_any(id):\n    return Note.query.get(id)\n", encoding="utf-8")
    routes = [R.Route("GET", "/notes/{id}", str(tmp_path / "a.py"), "get_mine"),
              R.Route("GET", "/items/{id}", str(tmp_path / "b.py"), "get_any")]
    byfn = {h["function"]: h["has_guard"] for h in controls._id_handlers(str(tmp_path), routes)}
    assert byfn["get_mine"] is True and byfn["get_any"] is False


def test_non_id_routes_are_not_handlers(tmp_path):
    from agent.orchestrator import routes as R
    # a route with no id-like path param is not part of the IDOR surface
    routes = [R.Route("GET", "/health", "x.py", "health"), R.Route("POST", "/login", "x.py", "login")]
    assert controls._id_handlers(str(tmp_path), routes) == []
