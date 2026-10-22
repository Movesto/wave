"""Data-driven runtime registry -- what the investigate/prove sandbox can PROVISION, as a table not a branch.

Provisioning used to hard-code `node:20-slim` + tsx + `npm install`. So a project on a runtime the harness
had never been taught (Bun, Deno, ...) could not be WITNESSED even when wave read its code correctly -- the
opencode/Bun miss: the sink chain was BELIEVED but the repro died because `node:20-slim` can't run `Bun.*`
and `npm install` can't resolve a Bun workspace. Technologies keep appearing, so the fix is a DATA table,
not another `if bun: ...` branch: add a Runtime row here and the sandbox can provision + run that stack.

Policy is "flexible in WHAT, strict in HOW": the registry IS the trust boundary -- only an image named here
can be provisioned, so a model's provisioning request can never pull an arbitrary image, and egress stays
confined to the one install step (execute.install_packages / js_env). Detection prefers a strong manifest
signal (a lockfile) and falls back to a source signal (`Bun.`, `Deno.`). Everything degrades gracefully:
no match -> None -> the caller keeps its existing default image.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

_SKIP = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", "vendor", "target", ".next"}


@dataclass(frozen=True)
class Runtime:
    name: str                         # "bun", "deno", "node", "python", ...
    image: str                        # the ONE trusted base image this runtime provisions into
    manifests: tuple = ()             # lockfiles/manifests that SIGNAL this runtime (strong evidence)
    source_res: tuple = ()            # compiled regexes over source that signal it (weaker -- Bun./Deno.)
    install: str = ""                 # shell to install the project's declared deps (run at the pkg root)
    run: str = ""                     # how to run ONE file, with a {file} placeholder (for the model's hint)
    dep_kind: str = "js"              # execute.install_packages kind for extra per-test deps ("js"|"py")
    family: str = "js"                # which provisioning path owns it (js_env handles the "js" family)


# Order matters: the FIRST runtime whose manifest/signal is present wins, so put the more specific
# lockfiles (bun/deno) ahead of the generic package.json (node). Adding a stack = one row here.
REGISTRY = (
    Runtime("bun", "oven/bun:1",
            manifests=("bun.lockb", "bun.lock"),
            source_res=(re.compile(r"\bBun\.\w"), re.compile(r'from\s+["\']bun["\']')),
            install="bun install", run="bun {file}", dep_kind="js", family="js"),
    Runtime("deno", "denoland/deno:latest",
            manifests=("deno.json", "deno.jsonc", "deno.lock"),
            source_res=(re.compile(r"\bDeno\.\w"),),
            install="deno cache {file}", run="deno run -A {file}", dep_kind="js", family="js"),
    Runtime("node", "wave-js-runner:latest",
            manifests=("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "package.json"),
            source_res=(),
            install="npm install --no-audit --no-fund --ignore-scripts", run="tsx {file}",
            dep_kind="js", family="js"),
    Runtime("python", "python:3.12-slim",
            manifests=("pyproject.toml", "requirements.txt", "setup.py", "Pipfile"),
            source_res=(),
            install="pip install -r requirements.txt", run="python {file}", dep_kind="py", family="py"),
    Runtime("ruby", "ruby:3.3-slim",
            manifests=("Gemfile", "Gemfile.lock"), source_res=(),
            install="bundle install", run="ruby {file}", dep_kind="rb", family="rb"),
    Runtime("go", "golang:1.22",
            manifests=("go.mod", "go.sum"), source_res=(),
            install="go mod download", run="go run {file}", dep_kind="go", family="go"),
)

_BY_NAME = {r.name: r for r in REGISTRY}
# The trusted image set: every registry image + the images wave builds/uses itself. A model-named image
# outside this set is never pulled (strict HOW).
_TRUSTED_IMAGES = ({r.image for r in REGISTRY}
                   | {"wave-js-runner:latest", "wave-js-browser:latest", "node:20-slim", "python:3.12-slim",
                      "node:20", "python:3.11-slim", "gcc:13"})


def by_name(name):
    """The registry Runtime for a model-nominated name, or None if it is not a known/trusted runtime."""
    return _BY_NAME.get(str(name or "").strip().lower())


def names():
    return [r.name for r in REGISTRY]


def _image_repo(image):
    return str(image or "").split(":", 1)[0].strip().lower()


def is_trusted_image(image):
    """True if `image` is one the harness is allowed to provision/pull. Tag-insensitive: a trusted repo at
    any tag is accepted (so `oven/bun:1.1` clears on `oven/bun:1`)."""
    img = str(image or "").strip().lower()
    if not img:
        return False
    if img in {i.lower() for i in _TRUSTED_IMAGES}:
        return True
    repo = _image_repo(img)
    return repo in {_image_repo(i) for i in _TRUSTED_IMAGES}


def runtime_for_image(image):
    """The Runtime whose image matches (tag-insensitive), or None."""
    repo = _image_repo(image)
    for r in REGISTRY:
        if _image_repo(r.image) == repo:
            return r
    return None


def _iter_source(root, cap=400):
    n = 0
    for p in Path(root).rglob("*"):
        if n >= cap:
            return
        if p.is_dir() or p.suffix.lower() not in (".ts", ".tsx", ".js", ".mjs", ".cjs", ".py"):
            continue
        if set(p.parts) & _SKIP:
            continue
        n += 1
        yield p


def _manifest_present(root, manifests):
    """A manifest from `manifests` at `root` or any parent up to a repo boundary (.git / fs root)."""
    cur = Path(root).resolve()
    for d in (cur, *cur.parents):
        for m in manifests:
            if (d / m).exists():
                return True
        if (d / ".git").exists():
            break
    return False


def detect(target):
    """Best-effort: the Runtime this project needs, by the strongest available signal. A manifest (lockfile)
    is strong and checked first across ALL runtimes; only if none matches do we fall back to a source signal
    (`Bun.`/`Deno.`), which catches the scoped-subdir case where the lockfile sits at an un-scanned repo
    root. Returns None when nothing matches (caller keeps its default image)."""
    target = str(target)
    for r in REGISTRY:                                   # strong: a declared manifest
        if r.manifests and _manifest_present(target, r.manifests):
            return r
    sig_runtimes = [r for r in REGISTRY if r.source_res]  # weak: a source signal (Bun./Deno.)
    if sig_runtimes:
        for p in _iter_source(target):
            try:
                src = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for r in sig_runtimes:
                if any(rx.search(src) for rx in r.source_res):
                    return r
    return None
