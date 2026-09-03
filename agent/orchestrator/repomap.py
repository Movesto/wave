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
    # .find(<callback>) is Array.prototype.find, NOT a Mongo query -- require an object filter `{` (or
    # $-operators / findOne / aggregate) so JS array methods don't false-pin as NoSQLi.
    ("NoSQLi",   re.compile(r"\$where\b|\.findOne\s*\(|\.find\s*\(\s*\{|\$regex\b|\.aggregate\s*\(")),
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


# --- Infrastructure / non-code files -----------------------------------------------------------------
# SAST is not just backend/frontend code. Containers, CI, reverse proxies, shell scripts, and env files
# carry their own critical bugs (root containers, docker-socket mounts, pull_request_target RCE, curl|sh,
# hardcoded secrets, open proxies). We inventory the WHOLE repo so the model understands it, and pin the
# infra-security patterns the same way we pin code sinks. Non-security config/docs are listed as context.
_INFRA_PINS = {
    "dockerfile": [
        ("container-root",   re.compile(r"^\s*USER\s+root\b", re.I)),
        ("remote-add",       re.compile(r"^\s*ADD\s+https?://", re.I)),
        ("curl-pipe-sh",     re.compile(r"(curl|wget)\b.*\|\s*(sh|bash)")),
        ("secret-in-image",  re.compile(r"^\s*(ENV|ARG)\s+\w*(SECRET|PASSWORD|TOKEN|API_?KEY|PRIVATE_KEY)", re.I)),
        ("world-writable",   re.compile(r"chmod\s+-?R?\s*777")),
    ],
    "compose": [
        ("privileged",       re.compile(r"privileged:\s*true", re.I)),
        ("host-network",     re.compile(r"network_mode:\s*[\"']?host", re.I)),
        ("docker-socket",    re.compile(r"/var/run/docker\.sock")),
        ("secret-literal",   re.compile(r"(PASSWORD|SECRET|TOKEN|API_?KEY)\s*[:=]\s*\S", re.I)),
    ],
    "nginx": [
        ("proxy-pass-dynamic", re.compile(r"proxy_pass\s+[^;]*\$(http_|arg_|request_|cookie_)")),
        ("proxy-pass",       re.compile(r"proxy_pass\s+https?://")),
        ("autoindex",        re.compile(r"autoindex\s+on", re.I)),
        ("nginx-if",         re.compile(r"^\s*if\s*\(")),
    ],
    "workflow": [
        ("pr-target",        re.compile(r"pull_request_target")),
        ("event-injection",  re.compile(r"\$\{\{\s*github\.event\.")),
        ("checkout-pr-ref",  re.compile(r"ref:\s*\$\{\{\s*github\.event")),
        ("curl-pipe-sh",     re.compile(r"(curl|wget)\b.*\|\s*(sh|bash)")),
    ],
    "shell": [
        ("curl-pipe-sh",     re.compile(r"(curl|wget)\b.*\|\s*(sh|bash)")),
        ("eval",             re.compile(r"\beval\b")),
        ("rm-rf-root",       re.compile(r"rm\s+-rf\s+/(\s|$|\*)")),
    ],
    "env": [
        ("secret-literal",   re.compile(r"^\s*\w*(SECRET|PASSWORD|TOKEN|API_?KEY|PRIVATE_KEY)\w*\s*=\s*.+", re.I)),
    ],
    "terraform": [
        ("public-ingress",   re.compile(r"cidr_blocks\s*=\s*\[?\s*[\"']0\.0\.0\.0/0")),
        ("secret-literal",   re.compile(r"(password|secret|token|access_key)\s*=\s*[\"']\S", re.I)),
    ],
}
# Dockerfile structural directives worth showing so the model grasps the image even absent a pin.
_DOCKER_KEYS = re.compile(r"^\s*(FROM|USER|EXPOSE|ENTRYPOINT|CMD|WORKDIR)\b", re.I)
# Files we inventory as context (no security pins): manifests, generic config, docs.
_INVENTORY_ONLY = {"manifest", "config-yaml", "config", "doc"}


def _classify_infra(path):
    """Category for a non-code file, or None if it's not worth mapping."""
    p = path.replace("\\", "/").lower()
    base = p.rsplit("/", 1)[-1]
    if base == "dockerfile" or base.startswith("dockerfile.") or base.endswith(".dockerfile"):
        return "dockerfile"
    if re.match(r"(docker[-.])?compose.*\.ya?ml$", base) or base in ("compose.yml", "compose.yaml"):
        return "compose"
    if "/.github/workflows/" in p and base.endswith((".yml", ".yaml")):
        return "workflow"
    if base == "nginx.conf" or base.endswith(".nginx") or (base.endswith(".conf") and "nginx" in p):
        return "nginx"
    if base.endswith((".sh", ".bash")):
        return "shell"
    if base == ".env" or base.startswith(".env.") or base.endswith(".env"):
        return "env"
    if base.endswith((".tf", ".tfvars")):
        return "terraform"
    if (base in ("package.json", "requirements.txt", "pyproject.toml", "pipfile", "go.mod", "gemfile",
                 "cargo.toml", "composer.json") or base.startswith("requirements")):
        return "manifest"
    if base.endswith((".yml", ".yaml")):
        return "config-yaml"
    if base.endswith((".toml", ".ini", ".cfg", ".conf", ".properties")):
        return "config"
    if base.endswith((".md", ".rst", ".txt")) or base in ("license", "makefile", "procfile"):
        return "doc"
    return None


def _secret_value(rhs):
    """True only for a REAL literal secret value -- not an env reference (${VAR}), a number (durations/
    ports), or an empty/placeholder. Kills the `JWT_SECRET: ${JWT_SECRET:?}` and `TOKEN_MINUTES=30` FPs."""
    v = rhs.strip().strip("\"'").strip()
    if not v or v.startswith(("${", "$(", "$")):
        return False
    if re.fullmatch(r"\d+", v):
        return False
    if v.lower() in ("changeme", "change_me", "yourpassword", "your-secret", "your_secret", "xxx", "...",
                     "true", "false", "none", "null"):
        return False
    return True


def _infra_purpose(cat, lines):
    for ln in lines:
        s = ln.strip().lstrip("#/*-! ").strip()
        if s:
            return s[:140]
    return f"({cat} file)"


def scan_infra(root):
    """Walk the WHOLE repo (pruning the usual junk dirs) for non-code files and pin infra-security
    patterns. Returns a list of {path, category, loc, purpose, pins, keys}."""
    import os
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in codemap._SKIP and d != ".git"]
        for fn in filenames:
            f = Path(dirpath) / fn
            if f.suffix.lower() in codemap._EXT_LANG:          # code -> handled by codemap
                continue
            cat = _classify_infra(str(f))
            if cat is None:
                continue
            try:
                if f.stat().st_size > 300_000:
                    continue
                lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            pins, keys = [], []
            for i, raw in enumerate(lines, 1):
                # strip comments (# is the comment char for all these formats) so a `curl|bash` inside a
                # comment isn't pinned; whole-line comments scan nothing.
                scan_line = "" if raw.lstrip().startswith("#") else re.split(r"\s#", raw, 1)[0]
                for label, rx in _INFRA_PINS.get(cat, ()):
                    if rx.search(scan_line):
                        if label == "secret-literal":
                            rhs = re.split(r"[:=]", raw, 1)
                            if len(rhs) < 2 or not _secret_value(rhs[1]):
                                continue
                        pins.append((i, label, raw.strip()[:160]))
                        break
                if cat == "dockerfile" and _DOCKER_KEYS.match(raw):
                    keys.append((i, raw.strip()[:120]))
            out.append({"path": str(f), "category": cat, "loc": len(lines),
                        "purpose": _infra_purpose(cat, lines), "pins": pins, "keys": keys})
    return out


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
    # Client-side code's fetch() is a browser call, not server-side SSRF. Recognize it by: JSX component
    # (.tsx/.jsx), a React/Next import, or living under a frontend/client/public tree.
    _p = finfo.path.replace("\\", "/").lower()
    is_client = (Path(finfo.path).suffix.lower() in (".tsx", ".jsx")
                 or bool(set(_p.split("/")) & {"frontend", "client", "public"})
                 or any(("react" in i.lower() or "next" in i.lower()) for i in finfo.imports))
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
                if not (label == "ssrf" and is_client):    # client-side fetch is not server SSRF
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


def _render_infra(root, inf):
    rel = _rel(root, inf["path"])
    head = f"### {rel}   ({inf['category']}, {inf['loc']} loc)"
    if inf["pins"]:
        head += f"   PINS: {len(inf['pins'])}"
    lines = [head, f"purpose: {inf['purpose']}"]
    for ln, code in inf.get("keys", []):
        lines.append(f"   {code}   L{ln}")
    for ln, label, code in inf["pins"]:
        lines.append(f"   [INFRA:{label}] {code}   L{ln}")
    return "\n".join(lines)


def render(cmap, root, per_file, pinned, rest, infra=None):
    infra = infra or []
    n_routes = sum(len(per_file[p][0]) for p in per_file)
    n_sinks = sum(len(per_file[p][1]) for p in per_file)
    n_infra_pins = sum(len(i["pins"]) for i in infra)
    out = [
        f"# wave repo map — {Path(root).name}",
        "",
        f"code files: {len(cmap.files)}   functions: {sum(len(v) for v in cmap.funcs.values())}   "
        f"classes: {sum(len(v) for v in cmap.classes.values())}   routes: {n_routes}   sink-pins: {n_sinks}   "
        f"infra/config files: {len(infra)}   infra-pins: {n_infra_pins}",
        "",
        "Pins are triage HINTS (routes = where input enters; [SINK:<class>] = one of the 9 injection "
        "classes; [INFRA:<kind>] = an infrastructure/CI misconfig), never verdicts. Full source of any "
        "file is available on request.",
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
    out += ["", "=" * 90, "## FULL INVENTORY — every remaining code file", "=" * 90]
    for p in rest:
        out.append("")
        out.append(_render_file(cmap, root, p, per_file[p], full=True))

    # Infrastructure / CI / config -- the non-code attack surface, security cats first (pinned first).
    sec = [i for i in infra if i["category"] not in _INVENTORY_ONLY]
    ctx = [i for i in infra if i["category"] in _INVENTORY_ONLY]
    sec.sort(key=lambda i: (-len(i["pins"]), i["path"]))
    if sec:
        out += ["", "=" * 90, "## INFRASTRUCTURE & CI/CONFIG (non-code attack surface)", "=" * 90]
        for i in sec:
            out.append("")
            out.append(_render_infra(root, i))
    if ctx:
        out += ["", "=" * 90, "## DOCS, MANIFESTS & OTHER FILES (context)", "=" * 90]
        for i in sorted(ctx, key=lambda i: i["path"]):
            out.append(f"- {_rel(root, i['path'])}  ({i['category']}, {i['loc']} loc)  — {i['purpose']}")
    out.append("")
    return "\n".join(out)


def _render_digest(cmap, root, per_file, pinned, infra):
    """A DENSE attack-surface digest for the ledger's model input: per pinned file, only its path +
    purpose + [ROUTE]/[SINK]/[DYN] pins (no signature/structure dumps), plus infra misconfig pins. ~10x
    smaller than the full map, so the ledger sees the whole pinned surface even on a monorepo. The full
    detailed map (with structure) stays as wave_map.md for viewing and tool-calling depth."""
    out = ["# wave attack-surface digest — " + Path(root).name, "",
           "Pinned files (routes + 9-class sink candidates) and infra/CI misconfigs only -- the surface to "
           "triage. Pins are HINTS, not verdicts. Full source + structure of any file are available on "
           "request via tools.", "", "## PINNED CODE (routes + sinks)"]
    for p in pinned:
        routes, sinks, dyn = per_file[p]
        fi = cmap.files[p]
        out.append("")
        out.append(f"### {_rel(root, p)}  ({fi.lang})  {fi.doc or ''}".rstrip())
        for ln, _, code in routes:
            out.append(f"   [ROUTE] {code}   L{ln}")
        for ln, label, code in sinks:
            flow = _flow(cmap, fi, ln)
            out.append(f"   [SINK:{label}] {code}   L{ln}" + (f"   {flow}" if flow else ""))
        for ln, kind, code in dyn:
            out.append(f"   [DYN:{kind}] {code}   L{ln}")
    sec = [i for i in infra if i["category"] not in _INVENTORY_ONLY and i["pins"]]
    if sec:
        out += ["", "## INFRASTRUCTURE & CI (misconfig pins)"]
        for i in sorted(sec, key=lambda i: (-len(i["pins"]), i["path"])):
            out.append("")
            out.append(f"### {_rel(root, i['path'])}  ({i['category']})  {i['purpose']}".rstrip())
            for ln, label, code in i["pins"]:
                out.append(f"   [INFRA:{label}] {code}   L{ln}")
    out.append("")
    return "\n".join(out)


def build_map(target, out=None):
    """Build the detailed whole-repo map and write it to `out` (default <target>/wave_map.md).

    Returns {map_path, text, digest, stats, cmap} -- `text` is the full detailed map (for viewing +
    tool-calling); `digest` is the dense pins-only view fed to the ledger. cmap is reused so we parse once."""
    cmap = codemap.build(target)
    root = Path(target)
    per_file = {p: scan_pins(fi) for p, fi in cmap.files.items()}

    def pincount(p):
        r, s, d = per_file[p]
        return len(r) * 2 + len(s) * 2 + len(d)

    pinned = sorted([p for p in cmap.files if pincount(p) > 0], key=lambda p: (-pincount(p), p))
    rest = sorted(p for p in cmap.files if pincount(p) == 0)
    infra = scan_infra(target)
    text = render(cmap, root, per_file, pinned, rest, infra=infra)
    digest = _render_digest(cmap, root, per_file, pinned, infra)

    outp = Path(out) if out else root / "wave_map.md"
    outp.write_text(text, encoding="utf-8")
    stats = {"files": len(cmap.files), "pinned_files": len(pinned),
             "functions": sum(len(v) for v in cmap.funcs.values()),
             "classes": sum(len(v) for v in cmap.classes.values()),
             "routes": sum(len(per_file[p][0]) for p in per_file),
             "sink_pins": sum(len(per_file[p][1]) for p in per_file),
             "infra_files": len(infra), "infra_pins": sum(len(i["pins"]) for i in infra),
             "map_chars": len(text), "digest_chars": len(digest)}
    return {"map_path": str(outp), "text": text, "digest": digest, "stats": stats, "cmap": cmap}
