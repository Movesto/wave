"""Run-recipe detection (sast-improvements-v2 #5).

To provision a target (boot it to witness a sink) and to run a STRONGER patch gate (plan §5: "run the
repo's own tests when present"), wave first needs to know HOW a repo installs, builds, runs and tests.
This detects that statically -- the ecosystem, package manager, and the install/build/run/test commands --
modeled on grok-cli's verify subsystem (manifest + static recipe detection). No model.

`detect()` is pure. `run_tests()` executes the detected test command through an INJECTABLE runner (default:
subprocess) so the patch gate can require the repo's own tests still pass, and so the gate logic is
testable without actually running a suite.
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass
class Recipe:
    ecosystem: str = ""            # node | python | go | rust | java | ruby | php | unknown
    package_manager: str = ""      # npm | yarn | pnpm | bun | pip | poetry | pdm | uv | go | cargo | ...
    manifest: str = ""             # the file that identified the ecosystem
    install: str = ""
    build: str = ""
    run: str = ""
    test: str = ""

    def as_dict(self):
        return asdict(self)


def _read_json(p):
    try:
        return json.loads(Path(p).read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return {}


def _node_pm(root):
    for lock, pm in (("pnpm-lock.yaml", "pnpm"), ("yarn.lock", "yarn"), ("bun.lockb", "bun"),
                     ("package-lock.json", "npm")):
        if (root / lock).exists():
            return pm
    return "npm"


def _node(root):
    pkg = _read_json(root / "package.json")
    scripts = pkg.get("scripts", {}) if isinstance(pkg, dict) else {}
    pm = _node_pm(root)
    run_script = next((s for s in ("start", "dev", "serve") if s in scripts), None)
    r = Recipe(ecosystem="node", package_manager=pm, manifest="package.json",
               install=f"{pm} install")
    if "build" in scripts:
        r.build = f"{pm} run build"
    if run_script:
        r.run = f"{pm} run {run_script}"
    if "test" in scripts:
        # npm/yarn/pnpm/bun all support `<pm> test`
        r.test = f"{pm} test" if pm != "pnpm" else "pnpm test"
    return r


def _python(root):
    pm, install, manifest = "pip", "", ""
    if (root / "poetry.lock").exists() or ("tool.poetry" in (root / "pyproject.toml").read_text(
            encoding="utf-8", errors="replace") if (root / "pyproject.toml").exists() else False):
        pm, install, manifest = "poetry", "poetry install", "pyproject.toml"
    elif (root / "uv.lock").exists():
        pm, install, manifest = "uv", "uv sync", "pyproject.toml"
    elif (root / "pdm.lock").exists():
        pm, install, manifest = "pdm", "pdm install", "pyproject.toml"
    elif (root / "requirements.txt").exists():
        install, manifest = "pip install -r requirements.txt", "requirements.txt"
    elif (root / "pyproject.toml").exists():
        install, manifest = "pip install -e .", "pyproject.toml"
    elif (root / "setup.py").exists():
        install, manifest = "pip install -e .", "setup.py"
    else:
        return None
    # tests: pytest if there's any pytest signal, else unittest discovery
    has_pytest = ((root / "pytest.ini").exists() or (root / "conftest.py").exists()
                  or (root / "tox.ini").exists()
                  or any((root / d).is_dir() for d in ("tests", "test")))
    prefix = {"poetry": "poetry run ", "uv": "uv run ", "pdm": "pdm run "}.get(pm, "")
    test = f"{prefix}pytest" if has_pytest else f"{prefix}python -m pytest"
    return Recipe(ecosystem="python", package_manager=pm, manifest=manifest, install=install,
                  run="", test=test)


def _simple(root):
    """Single-manifest ecosystems with conventional commands."""
    if (root / "go.mod").exists():
        return Recipe("go", "go", "go.mod", install="go mod download",
                      build="go build ./...", run="go run .", test="go test ./...")
    if (root / "Cargo.toml").exists():
        return Recipe("rust", "cargo", "Cargo.toml", install="cargo fetch",
                      build="cargo build", run="cargo run", test="cargo test")
    if (root / "pom.xml").exists():
        return Recipe("java", "maven", "pom.xml", install="mvn -q install -DskipTests",
                      build="mvn -q package -DskipTests", test="mvn -q test")
    if (root / "build.gradle").exists() or (root / "build.gradle.kts").exists():
        return Recipe("java", "gradle", "build.gradle", install="./gradlew dependencies",
                      build="./gradlew build -x test", test="./gradlew test")
    if (root / "Gemfile").exists():
        return Recipe("ruby", "bundler", "Gemfile", install="bundle install",
                      test="bundle exec rspec" if (root / "spec").is_dir() else "bundle exec rake test")
    if (root / "composer.json").exists():
        return Recipe("php", "composer", "composer.json", install="composer install",
                      test="composer test" if "test" in _read_json(root / "composer.json").get(
                          "scripts", {}) else "./vendor/bin/phpunit")
    return None


def _makefile_fallback(root, r):
    """If the ecosystem gave no test/build, borrow a Makefile `test`/`build` target."""
    mk = root / "Makefile"
    if not mk.exists():
        return r
    text = mk.read_text(encoding="utf-8", errors="replace")
    import re
    for target in ("test", "build"):
        if re.search(rf"(?m)^{target}\s*:", text) and not getattr(r, target):
            setattr(r, target, f"make {target}")
    return r


def detect(target) -> Recipe:
    """Statically detect the run recipe for a repo. Node first (package.json scripts are authoritative),
    then Python, then the single-manifest ecosystems; a Makefile fills gaps. Unknown -> an empty Recipe."""
    root = Path(target)
    r = None
    if (root / "package.json").exists():
        r = _node(root)
    if r is None:
        r = _python(root)
    if r is None:
        r = _simple(root)
    if r is None:
        r = Recipe(ecosystem="unknown")
    return _makefile_fallback(root, r)


def manifest_path(target):
    return Path(target) / ".wave" / "environment.json"


def save_manifest(target, recipe: Recipe):
    p = manifest_path(target)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(recipe.as_dict(), indent=2), encoding="utf-8")
    return p


def load_manifest(target):
    d = _read_json(manifest_path(target))
    return Recipe(**{k: d.get(k, "") for k in Recipe().as_dict()}) if d else None


def load_or_detect(target, persist=False) -> Recipe:
    """The persisted manifest wins when present (user-editable source of truth); else detect fresh."""
    r = load_manifest(target)
    if r is not None and r.ecosystem:
        return r
    r = detect(target)
    if persist:
        save_manifest(target, r)
    return r


def _subprocess_runner(cmd, cwd, timeout):
    try:
        p = subprocess.run(cmd, cwd=cwd, shell=True, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, f"test command timed out after {timeout}s"
    except Exception as e:
        return 1, f"could not run tests: {type(e).__name__}: {e}"


def run_tests(recipe: Recipe, cwd, runner=None, timeout=600):
    """Run the repo's own test command. Returns (passed, note): passed is True/False, or None when there is
    no test command / it could not be run. `runner(cmd, cwd, timeout) -> (returncode, output)` is injectable
    (default: subprocess) so the patch gate's use of this is testable without executing a real suite."""
    if not recipe or not recipe.test:
        return None, "no test command detected"
    run = runner or _subprocess_runner
    code, out = run(recipe.test, str(cwd), timeout)
    if code == 0:
        return True, f"`{recipe.test}` passed"
    return False, f"`{recipe.test}` failed (exit {code}): {(out or '')[-200:]}"
