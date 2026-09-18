"""The trust-boundary model (Shift 1, docs/trust_boundary_plan.md).

The ONE place that answers "what carries untrusted input, and what is each module's deployment context",
built once from the codemap and persisted to wave_trust.json -- so every gate consults ONE model instead of
re-deriving trust per sink with scattered heuristics (is_frontend / is_desktop_app / entry-name lists ...).

Deterministic today; Shift 2 will let the model ENRICH the same artifact (safe-direction only: it may only
mark something MORE trusted -> review, never fabricate an untrusted entry). Because the artifact is persisted
and human-readable, the trust boundary wave assumed is inspectable (`wave trust <target>`).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from . import reachability

# a file that is TEST-HARNESS code: not a production runtime surface (cucumber/behave steps, unit tests, e2e).
_TEST_SIGNALS = ("/test/", "/tests/", "/spec/", "/specs/", "/cucumber/", "/features/", "/e2e/", "/it/",
                 "conftest", ".spec.", ".test.", "_test.", "/test_")
# build / CI / dev-tooling scripts: run by a developer or CI, not a remote surface (the CLI/build class).
_CLI_PATH_SIGNALS = ("/scripts/", "/tools/", "/bin/", "/packaging/", "/.github/", "/ci/", "/build-tools/",
                     "/devtools/", "/hack/")


def _is_test(path):
    p = str(path).replace("\\", "/").lower()
    return any(s in p for s in _TEST_SIGNALS)


def _is_cli_path(path):
    p = str(path).replace("\\", "/").lower()
    return any(s in p for s in _CLI_PATH_SIGNALS)


def _rel(path, target):
    try:
        return str(Path(path).resolve().relative_to(Path(target).resolve())).replace("\\", "/")
    except Exception:
        return str(path).replace("\\", "/")


def _kind(func, trust):
    decs = " ".join(getattr(func, "decorators", None) or []).lower()
    if any(h in decs for h in reachability._ROUTE_HINTS):
        return "route"
    return "cli" if trust == "local" else "handler"


def _module_roots(target, cap=200):
    """Directories that look like a module root (have a build manifest). Bounded for big monorepos."""
    root = Path(target)
    roots, seen = [], set()
    for m in reachability._MODULE_MANIFESTS:
        for mf in list(root.rglob(m))[:cap]:
            if any(s in mf.parts for s in reachability._DESKTOP_SKIP):
                continue
            d = mf.parent
            if d not in seen:
                seen.add(d)
                roots.append(d)
    if root not in seen:
        roots.append(root)                                  # the repo itself is always a module
    return roots


@dataclass
class TrustModel:
    target: str
    entries: dict = field(default_factory=dict)             # func_name -> {trust, kind, files}
    modules: dict = field(default_factory=dict)             # module_rel -> "web"|"desktop"|"cli"|"library"

    def module_context(self, file):
        """web | desktop | cli | library | test -- the deployment context of the finding's file/module. Path
        signals (test harness, build/CLI tooling) win over the module classification, since such files live
        outside their own manifest and would otherwise inherit the repo-root module's aggregate."""
        rel = "/" + _rel(file, self.target)                 # relative to target, so an absolute prefix (e.g. a
        if _is_test(rel):                                    # pytest tmp dir containing "test_") can't false-match
            return "test"
        if _is_cli_path(rel):
            return "cli"
        root = reachability._module_root(file, self.target)
        return self.modules.get(_rel(root, self.target), "library")

    def to_dict(self):
        return {"target": self.target, "entries": self.entries, "modules": self.modules}


def _detect_desktop_shallow(root):
    """Desktop markers in the module's OWN root (not descending into sibling/nested modules -- that is what
    wrongly made a repo root 'desktop' just because a sub-module ships a desktop build)."""
    root = Path(root)
    try:
        if (root / "src-tauri").is_dir():
            return True
        ct = root / "Cargo.toml"
        if ct.exists() and reachability.re.search(r'(?im)^\s*tauri\s*=', ct.read_text(encoding="utf-8", errors="replace")):
            return True
        pj = root / "package.json"
        if pj.exists():
            t = pj.read_text(encoding="utf-8", errors="replace").lower()
            if '"electron"' in t or "@tauri-apps" in t:
                return True
    except Exception:
        pass
    return False


def _classify_module(root, has):
    """desktop (own Tauri/Electron manifest) > web (owns a remote/route entry) > cli (owns only a local main) >
    library (no entry). `has` = {'remote': bool, 'local': bool} for entries this module OWNS (nearest-module)."""
    if _detect_desktop_shallow(root):
        return "desktop"
    if has.get("remote"):
        return "web"
    if has.get("local"):
        return "cli"
    return "library"


def build(cmap, target):
    """Build the trust model from the codemap (deterministic). Each entry is attributed to the module that OWNS
    it (nearest module root), so a module is classified from ITS OWN entries -- the repo root no longer absorbs
    a sub-module's routes or a sibling's desktop build."""
    tm = TrustModel(target=str(target))
    owner = {}                                              # file -> owning module root (memoized)

    def own(fp):
        if fp not in owner:
            owner[fp] = str(reachability._module_root(fp, target))
        return owner[fp]

    mod_has = {}                                            # module_root(str) -> {"remote","local": bool}
    for name, funcs in cmap.funcs.items():
        for f in funcs:
            t = reachability.entry_trust(f)
            if not t:
                continue
            fp = str(getattr(f, "file", "") or "").replace("\\", "/")
            e = tm.entries.setdefault(name, {"trust": t, "kind": _kind(f, t), "files": []})
            if t == "remote":                               # remote wins if a name is both
                e["trust"] = "remote"
                e["kind"] = _kind(f, t)
            if fp and fp not in e["files"]:
                e["files"].append(fp)
            if fp:
                mod_has.setdefault(own(fp), {"remote": False, "local": False})[t] = True
    for root in _module_roots(target):
        tm.modules[_rel(root, target)] = _classify_module(root, mod_has.get(str(root), {}))
    return tm


def save(tm, out_dir):
    p = Path(out_dir) / "wave_trust.json"
    p.write_text(json.dumps(tm.to_dict(), indent=1), encoding="utf-8")
    return p


def load(out_dir):
    p = Path(out_dir) / "wave_trust.json"
    if not p.exists():
        return None
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
        return TrustModel(target=d.get("target", str(out_dir)), entries=d.get("entries", {}),
                          modules=d.get("modules", {}))
    except Exception:
        return None


def summary(tm):
    n_remote = sum(1 for e in tm.entries.values() if e["trust"] == "remote")
    n_local = sum(1 for e in tm.entries.values() if e["trust"] == "local")
    ctx = {}
    for c in tm.modules.values():
        ctx[c] = ctx.get(c, 0) + 1
    modstr = ", ".join(f"{k}={v}" for k, v in sorted(ctx.items()))
    return f"trust boundary: {n_remote} remote + {n_local} local entry point(s); modules: {modstr or '(none)'}"
