"""Stage a bench target's APP CODE into a neutral temp dir -- without the answer key (remaining-work 3).

The leak: a bench target folder holds MANIFEST.json (the CWE-level ground truth) next to the app code,
plus wave's own outputs from prior runs (casefile.json, wave_*.jsonl, traces, the provisioning artifacts).
The prover mounts the target into the sandbox, so the model can `cat MANIFEST.json` (or an earlier
wave_findings.jsonl) and read the answers -- which would inflate scoreboard recall and make every later
tuning decision unreliable.

The fix: copy ONLY the app code into a throwaway dir, scan THAT, and keep MANIFEST.json + outputs in the
ORIGINAL folder (read the truth / write the report there, never inside the scanned tree). Deterministic,
no model. Used by the bench runner; any scan harness that wants a clean tree can reuse `staged()`.
"""
import shutil
import tempfile
from contextlib import contextmanager
from pathlib import Path

# The ANSWER KEY and wave's own artifacts -- never copied into the scanned tree (exact basenames).
_EXCLUDE_NAMES = {
    "MANIFEST.json",                                  # THE ground truth (CWE-level, safe-twin flags)
    "casefile.json",                                  # a prior run's Case File report
    "WAVE_REPORT.md",                                 # a prior run's rendered report
    ".git", ".hg", ".svn", "__pycache__", ".pytest_cache", ".mypy_cache",
}
# wave-generated artifacts by PREFIX/suffix (prior-run outputs + provisioning scaffolding).
_EXCLUDE_PREFIX = ("wave_", ".wave", "_wave_", "Dockerfile.wave")
_EXCLUDE_SUFFIX = (".pyc",)
_EXCLUDE_GLOBS = ("wave.compose*.yml", "wave.compose*.yaml")


def _is_excluded(name: str) -> bool:
    if name in _EXCLUDE_NAMES:
        return True
    if name.startswith(_EXCLUDE_PREFIX):
        return True
    if name.endswith(_EXCLUDE_SUFFIX):
        return True
    from fnmatch import fnmatch
    return any(fnmatch(name, g) for g in _EXCLUDE_GLOBS)


def _ignore(_dir, names):
    """shutil.copytree ignore callback: drop the answer key + wave artifacts at every level."""
    return [n for n in names if _is_excluded(n)]


def stage_appdir(src) -> str:
    """Copy `src`'s app code into a fresh temp dir (MANIFEST.json + wave outputs EXCLUDED) and return it.
    The caller owns cleanup (or use the `staged` context manager)."""
    src = Path(src)
    dest = Path(tempfile.mkdtemp(prefix="wave-stage-"))
    # copytree needs the dest not to pre-exist; mkdtemp made it, so copy INTO a child and return that.
    app = dest / src.name
    shutil.copytree(src, app, ignore=_ignore, symlinks=True)
    return str(app)


@contextmanager
def staged(src):
    """`with staged(target) as appdir:` -- a MANIFEST-free copy of the app code, auto-cleaned on exit."""
    app = stage_appdir(src)
    root = str(Path(app).parent)
    try:
        yield app
    finally:
        shutil.rmtree(root, ignore_errors=True)
