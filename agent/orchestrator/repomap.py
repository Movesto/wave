"""Stage 1a -- the detailed whole-repo MAP (deterministic, local, NO model).

This is the thing a human views first (to confirm nothing was missed) and, more importantly, the thing the
comprehension model reads so it knows the repo bottom-to-top before it investigates. It is a COMPLETE
inventory -- every source file, what each is *composed of* (imports, functions/classes with signatures,
exports) and what it *does* (module docstring) -- plus inline PINS on the high-value targets: HTTP routes
and the 9 injection-class sinks the detector tries first. Depth (a file's full source) is fetched later by
the model's tool-calling; the map is orientation, not the whole source.

Built on codemap.py's tree-sitter structure + per-file view. No aider/grep-ast dependency. The sink pins
are HINTS for triage, never verdicts -- the detector re-judges and a tool proves.
"""
from __future__ import annotations

import re
from pathlib import Path

from . import codemap, eyes

# --- Routes (entry points untrusted input arrives through) --------------------------------------------
_ROUTE = re.compile(
    r"@\w+\.(route|get|post|put|delete|patch|options|head)\b"                       # flask / fastapi
    r"|@(Get|Post|Put|Delete|Patch|All)\s*\("                                        # nestjs controllers
    r"|\b(app|router|r|api|route)\.(get|post|put|delete|patch|use|all|head)\s*\(\s*['\"]"  # express
    r"|\.add_(url_rule|route)\s*\(|\brouter\.(register|add)"                          # flask/connexion/etc
)

# --- The 9 injection classes the detector tries FIRST (class label -> sink regex) ---------------------
# Language-specific tables avoid the exec()/eval() ambiguity between Python (code-eval) and JS (child_process).
_SINKS_COMMON = [
    ("NoSQLi",   re.compile(r"\$where|\.find(One)?\s*\(|\$regex\b|\.aggregate\s*\(")),
    ("ssrf",     re.compile(r"\bfetch\s*\(|\baxios\b|\.urlopen\s*\(|requests\.(get|post|put|request|head)\b|urllib\.request|http\.(get|request)\s*\(|\bgot\s*\(")),
    ("xss",      re.compile(r"innerHTML|dangerouslySetInnerHTML|document\.write|render_template_string|\bMarkup\s*\(|\.send\s*\(\s*[`\"']?\s*<")),
    ("redirect", re.compile(r"\bredirect\s*\(|res\.redirect\s*\(|sendRedirect")),
    ("deser",    re.compile(r"pickle\.loads?|yaml\.load\s*\(|marshal\.loads?|node-serialize|\bunserialize\s*\(|cPickle")),
]
_SINKS_PY = [
    ("SQLi",  re.compile(r"\.execute\w*\s*\(|cursor\.execute|\.raw\s*\(|\btext\s*\(\s*[f\"'(]|\.filter\s*\(\s*[f\"']")),
    ("cmd",   re.compile(r"\bos\.system\s*\(|\bos\.popen\s*\(|\bsubprocess\.|\bpty\.spawn|\bcommands\.getoutput")),
    ("eval",  re.compile(r"\beval\s*\(|\bexec\s*\(|\bcompile\s*\(\s*[f\"']|\b__import__\s*\(")),
    ("path",  re.compile(r"\bopen\s*\(|\bsend_file\s*\(|os\.path\.join\s*\(|shutil\.(copy|move|rmtree)")),
]
_SINKS_JS = [
    ("SQLi",  re.compile(r"\.query\s*\(|sequelize\.query|\.execute\s*\(|knex\.raw|\$queryRawUnsafe|\.\$queryRaw")),
    ("cmd",   re.compile(r"child_process|\bexec(Sync|File(Sync)?)?\s*\(|\bspawn(Sync)?\s*\(|\.exec\s*\(")),
    ("eval",  re.compile(r"\beval\s*\(|new\s+Function\s*\(|vm\.(runIn|createContext)|setTimeout\s*\(\s*['\"]")),
    ("path",  re.compile(r"fs\.(readFile|writeFile|createReadStream|createWriteStream|sendFile|readdir|unlink)|res\.sendFile|\.sendFile\s*\(")),
]


def _lang_sinks(lang):
    return (_SINKS_PY if lang == "python" else _SINKS_JS) + _SINKS_COMMON


def _read_lines(path):
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def _strip_comment(line):
    return line.split("//")[0].split("#")[0]


_IMPORT_LINE = re.compile(r"^\s*(from\s+\S+\s+import\b|import\s+|export\s+.*\bfrom\b|import\s*\{)")


def _is_import(line):
    """Import statements name modules (`from sqlalchemy import text`) and must not be mistaken for the
    sink calls that use them -- otherwise every import of a db/exec library lights up as a sink."""
    return bool(_IMPORT_LINE.match(line))


def scan_pins(finfo):
    """Scan one file's lines for routes, 9-class sinks, and dynamic blind spots. Returns three lists of
    (line, label, code). Sink pins are hints, not verdicts."""
    routes, sinks, dyn = [], [], []
    sink_tbl = _lang_sinks(finfo.lang)
    for i, raw in enumerate(_read_lines(finfo.path), 1):
        s = _strip_comment(raw)
        code = raw.strip()[:160]
        if _ROUTE.search(s):
            routes.append((i, "ROUTE", code))
        if _is_import(raw):                                # imports name libraries, they aren't sink calls
            continue
        matched = False
        for label, rx in sink_tbl:
            if rx.search(s):
                sinks.append((i, label, code))
                matched = True
                break
        if not matched:                                    # dynamic dispatch / reflection the call graph misses
            for rx, kind in eyes._DYNAMIC:
                if kind == "route registration":
                    continue                               # handled by _ROUTE
                if rx.search(s):
                    dyn.append((i, kind, code))
                    break
    return routes, sinks, dyn


def _enclosing(finfo, line):
    """The innermost function/method whose body contains `line` -- so a sink can be traced to its fn."""
    best = None
    cands = list(finfo.functions)
    for c in finfo.classes:
        cands.extend(c.methods)
    for f in cands:
        if f.line <= line <= (f.end or f.line):
            if best is None or f.line > best.line:
                best = f
    return best


# --- rendering ----------------------------------------------------------------------------------------

def _flow(cmap, finfo, line):
    fn = _enclosing(finfo, line)
    if fn is None:
        return ""
    chain = cmap.chain_to_entry(fn.name)
    if chain and len(chain) > 1:
        return "flow: " + " -> ".join(chain)
    return f"in {fn.name}()"


def _render_structure(finfo, indent="   "):
    out = []
    for f in finfo.functions:
        tag = " [exported]" if f.exported else ""
        deco = ("  " + " ".join(f.decorators)) if f.decorators else ""
        out.append(f"{indent}{f.name}{f.sig or '()'}   L{f.line}-{f.end}{tag}{deco}")
    for c in finfo.classes:
        tag = " [exported]" if c.exported else ""
        out.append(f"{indent}class {c.name}   L{c.line}-{c.end}{tag}")
        for m in c.methods:
            out.append(f"{indent}   . {m.name}{m.sig or '()'}   L{m.line}")
    return out


def _render_file(cmap, root, path, pins, full=True):
    fi = cmap.files[path]
    routes, sinks, dyn = pins
    rel = _rel(root, path)
    head = f"### {rel}   ({fi.lang}, {fi.loc} loc)"
    if routes or sinks or dyn:
        head += f"   PINS: routes={len(routes)} sinks={len(sinks)} dyn={len(dyn)}"
    lines = [head]
    lines.append(f"purpose: {fi.doc or '(no docstring)'}")
    if fi.imports:
        imp = ", ".join(fi.imports)
        lines.append(f"imports: {imp[:300]}{'  ...' if len(imp) > 300 else ''}")
    if fi.exports:
        lines.append(f"exports: {', '.join(fi.exports[:20])}")
    if routes or sinks or dyn:
        lines.append("targets:")
        for ln, _, code in routes:
            lines.append(f"   [ROUTE] {code}   L{ln}")
        for ln, label, code in sinks:
            flow = _flow(cmap, fi, ln)
            lines.append(f"   [SINK:{label}] {code}   L{ln}" + (f"   {flow}" if flow else ""))
        for ln, kind, code in dyn:
            lines.append(f"   [DYN:{kind}] {code}   L{ln}")
    if full and (fi.functions or fi.classes):
        lines.append("structure:")
        lines.extend(_render_structure(fi))
    return "\n".join(lines)


def _rel(root, path):
    try:
        return str(Path(path).relative_to(root)).replace("\\", "/")
    except ValueError:
        return path.replace("\\", "/")


def render(cmap, root, per_file, pinned, rest):
    n_routes = sum(len(per_file[p][0]) for p in per_file)
    n_sinks = sum(len(per_file[p][1]) for p in per_file)
    out = [
        f"# wave repo map — {Path(root).name}",
        "",
        f"files: {len(cmap.files)}   functions: {sum(len(v) for v in cmap.funcs.values())}   "
        f"classes: {sum(len(v) for v in cmap.classes.values())}   routes: {n_routes}   sink-pins: {n_sinks}",
        "",
        "Pins are triage HINTS (routes = where input enters; [SINK:<class>] = one of the 9 injection "
        "classes to check first), never verdicts. Full source of any file is available on request.",
        "",
        "=" * 90,
        "## PINNED — files with routes or sinks (check these first)",
        "=" * 90,
    ]
    if not pinned:
        out.append("(none — no routes or 9-class sinks matched; see the full inventory below)")
    for p in pinned:
        out.append("")
        out.append(_render_file(cmap, root, p, per_file[p], full=True))
    out += ["", "=" * 90, "## FULL INVENTORY — every remaining file", "=" * 90]
    for p in rest:
        out.append("")
        out.append(_render_file(cmap, root, p, per_file[p], full=True))
    out.append("")
    return "\n".join(out)


def build_map(target, out=None):
    """Build the detailed whole-repo map and write it to `out` (default <target>/wave_map.md).

    Returns {map_path, text, stats, cmap} -- cmap is reused by the ledger pass so we parse once."""
    cmap = codemap.build(target)
    root = Path(target)
    per_file = {p: scan_pins(fi) for p, fi in cmap.files.items()}

    def pincount(p):
        r, s, d = per_file[p]
        return len(r) * 2 + len(s) * 2 + len(d)

    pinned = sorted([p for p in cmap.files if pincount(p) > 0], key=lambda p: (-pincount(p), p))
    rest = sorted(p for p in cmap.files if pincount(p) == 0)
    text = render(cmap, root, per_file, pinned, rest)

    outp = Path(out) if out else root / "wave_map.md"
    outp.write_text(text, encoding="utf-8")
    stats = {"files": len(cmap.files), "pinned_files": len(pinned),
             "functions": sum(len(v) for v in cmap.funcs.values()),
             "classes": sum(len(v) for v in cmap.classes.values()),
             "routes": sum(len(per_file[p][0]) for p in per_file),
             "sink_pins": sum(len(per_file[p][1]) for p in per_file),
             "map_chars": len(text)}
    return {"map_path": str(outp), "text": text, "stats": stats, "cmap": cmap}
