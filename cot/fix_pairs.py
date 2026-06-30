# ============================================================
# cot/fix_pairs.py
#
# Loads (vulnerable_code, fixed_code, cwe, language) records for the
# verified-regeneration pipeline. The fixed_code is what gives us the
# patch-localization oracle (cot/oracle.py).
#
# Sources:
#   - morefixes_pairs.jsonl  (primary; all 4 target languages, but the
#     "Fixed code:" block is the changed region, not the full method)
#   - cve_fix_pairs.csv      (small, full-method pairs; mostly non-target
#     languages, included for completeness)
# ============================================================
import csv
import re
from typing import Iterator, Optional

from .shapes.common import iter_jsonl, get_messages, extract_scan_code, detect_language

csv.field_size_limit(10 ** 7)

# Rough vulnerability-type -> CWE map (cve_fix_pairs has free-text types).
_TYPE_CWE = {
    "sql injection": "CWE-89", "xss": "CWE-79", "cross-site scripting": "CWE-79",
    "command injection": "CWE-78", "path traversal": "CWE-22",
    "ssrf": "CWE-918", "open redirect": "CWE-601",
    "deserialization": "CWE-502", "xxe": "CWE-611", "csrf": "CWE-352",
    "code injection": "CWE-94", "prototype pollution": "CWE-1321",
}


def _type_to_cwe(t: Optional[str]) -> Optional[str]:
    if not t:
        return None
    s = t.strip().lower()
    for k, v in _TYPE_CWE.items():
        if k in s:
            return v
    m = re.search(r"CWE-?(\d+)", t, re.I)
    return f"CWE-{m.group(1)}" if m else None


def _extract_fixed_block(asst_text: str) -> Optional[str]:
    """morefixes assistant text: 'Fixed code:\n<block>'."""
    low = asst_text.lower()
    idx = low.find("fixed code:")
    if idx < 0:
        return None
    block = asst_text[idx + len("fixed code:"):].strip()
    return block or None


def _from_morefixes(languages: set[str]) -> Iterator[dict]:
    for rec in iter_jsonl("morefixes_pairs.jsonl"):
        m = get_messages(rec)
        if not m:
            continue
        user, asst = m
        low = asst.lower()
        # vuln records only (this pipeline regenerates vuln traces)
        if not ("vulnerability detected" in low or "security flaw" in low
                or "security issue" in low):
            continue
        vuln = extract_scan_code(user)
        fixed = _extract_fixed_block(asst)
        if not vuln or not fixed or len(vuln) < 60:
            continue
        lang = detect_language(vuln)
        if languages and lang not in languages:
            continue
        yield {
            "vuln_code": vuln, "fixed_code": fixed, "cwe": None,
            "language": lang, "vuln_type": None, "source": "morefixes",
        }


def _from_cve_fix_pairs(languages: set[str]) -> Iterator[dict]:
    from .config import REPO_ROOT
    path = REPO_ROOT / "data" / "downloads" / "cve-fix-pairs" / "cve_fix_pairs.csv"
    if not path.exists():
        return
    with open(path, encoding="utf-8", errors="replace") as f:
        for row in csv.DictReader(f):
            vuln = (row.get("vulnerable_code") or "").strip()
            fixed = (row.get("fixed_code") or "").strip()
            if not vuln or not fixed or vuln == fixed or len(vuln) < 60:
                continue
            lang = (row.get("language") or "").strip().lower()
            lang = {"javascript": "javascript", "typescript": "typescript",
                    "python": "python"}.get(lang, lang)
            if languages and lang not in languages:
                continue
            yield {
                "vuln_code": vuln, "fixed_code": fixed,
                "cwe": _type_to_cwe(row.get("vulnerability_type")),
                "language": lang, "vuln_type": row.get("vulnerability_type"),
                "source": "cve_fix_pairs",
            }


# --- raw git patches (cvedataset-patches): the high-quality source ---

_EXT_LANG = {
    ".py": "python", ".js": "javascript", ".ts": "typescript",
    ".tsx": "react", ".jsx": "react",
    ".php": "php", ".java": "java", ".go": "go",
    ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".hpp": "cpp",
    ".rb": "ruby", ".cs": "csharp",
}
_TEST_PATH = re.compile(r"(^|/)(tests?|spec|__tests__|fixtures?|examples?)/|\.(test|spec)\.", re.I)
# Non-code / collateral files a security patch also touches (translations, config,
# docs, type stubs, version/lockfiles) — skip; the real fix is in the code.
_SKIP_PATH = re.compile(
    r"(^|/)(i18n|locales?|lang|translations?|messages)/"
    r"|\.(po|json|md|txt|lock|ya?ml|cfg|ini|toml|d\.ts|svg|html?|css|snap)$"
    r"|(^|/)(package\.json|package-lock\.json|yarn\.lock|setup\.py|setup\.cfg|version\.\w+|changelog)\b",
    re.I,
)
# A hunk is security-relevant if it touches a sink or a security-sensitive op.
_RELEVANT = re.compile(
    r"\b(system|popen|exec(?:ve|file|sync)?|eval|compile|subprocess|spawn|child_process"
    r"|cursor|execute(?:many)?|query|raw_query|innerHTML|dangerouslySetInnerHTML|insertAdjacentHTML"
    r"|document\.write|fetch|axios|urlopen|urlretrieve|requests?|send_?file|render_template_string"
    r"|pickle|marshal|yaml|deserialize|unserialize|redirect|location|sql|format|template"
    r"|path|escape|sanitiz|session|token|password|secret|crypto|md5|sha1|random|jwt|verify|auth"
    r"|cors|csrf|__proto__|prototype|chmod|chown|os\.|open|readFile|writeFile"
    # cross-language sinks: C, Java, PHP, Go
    r"|strcpy|strcat|sprintf|memcpy|gets|malloc|free|Runtime|ProcessBuilder|Statement"
    r"|createQuery|getRuntime|mysql_?|mysqli|pg_query|shell_exec|passthru|include|require"
    r"|exec\.Command|db\.Query|html/template|filepath|ioutil|unserialize)\b",
    re.I,
)


def _reconstruct_hunks(file_body: str):
    """From one file's diff body, yield (old_hunk, new_hunk) per @@ hunk.
    old = context + removed lines; new = context + added lines."""
    hunk: list[str] = []
    in_hunk = False
    for line in file_body.split("\n"):
        if line.startswith("@@"):
            if hunk:
                yield _split_hunk(hunk)
            hunk = []
            in_hunk = True
            continue
        if not in_hunk:
            continue
        if line.startswith("\\"):       # "\ No newline at end of file"
            continue
        if line[:1] in (" ", "+", "-"):
            hunk.append(line)
        else:
            # left the hunk body
            if hunk:
                yield _split_hunk(hunk)
            hunk = []
            in_hunk = False
    if hunk:
        yield _split_hunk(hunk)


def _split_hunk(hunk: list[str]) -> tuple[str, str]:
    old, new = [], []
    for l in hunk:
        tag, content = l[0], l[1:]
        if tag == " ":
            old.append(content); new.append(content)
        elif tag == "-":
            old.append(content)
        elif tag == "+":
            new.append(content)
    return "\n".join(old), "\n".join(new)


def _from_patches(languages: set[str], patches_dir=None) -> Iterator[dict]:
    import os
    from .config import REPO_ROOT
    base = patches_dir or (REPO_ROOT / "data" / "downloads" / "morefixes-patches" / "cvedataset-patches")
    if not os.path.isdir(base):
        return
    file_hdr = re.compile(r"^diff --git a/(.+?) b/(.+?)\s*$", re.M)
    for fname in sorted(os.listdir(base)):
        if not fname.endswith(".patch"):
            continue
        try:
            text = open(os.path.join(base, fname), encoding="utf-8", errors="replace").read()
        except Exception:
            continue
        # split into per-file sections
        parts = re.split(r"^diff --git ", text, flags=re.M)
        for part in parts[1:]:
            m = re.match(r"a/(.+?) b/(.+?)\s*$", part.split("\n", 1)[0])
            if not m:
                continue
            path_b = m.group(2)
            ext = "." + path_b.rsplit(".", 1)[-1] if "." in path_b else ""
            lang = _EXT_LANG.get(ext)
            if not lang or (languages and lang not in languages):
                continue
            if _TEST_PATH.search(path_b) or _SKIP_PATH.search(path_b):
                continue
            for old_hunk, new_hunk in _reconstruct_hunks(part):
                if old_hunk == new_hunk:
                    continue
                if not (80 <= len(old_hunk) <= 1500):
                    continue
                if len([l for l in old_hunk.split("\n") if l.strip()]) < 3:
                    continue
                # Density filter: keep only hunks that actually touch a sink /
                # security-sensitive op (drops collateral i18n/config/type hunks).
                if not (_RELEVANT.search(old_hunk) or _RELEVANT.search(new_hunk)):
                    continue
                yield {
                    "vuln_code": old_hunk, "fixed_code": new_hunk, "cwe": None,
                    "language": lang, "vuln_type": None,
                    "source": f"patch:{fname[:40]}",
                }


def iter_fix_pairs(languages: Optional[set[str]] = None,
                   sources: tuple = ("patches", "morefixes", "cve_fix_pairs")) -> Iterator[dict]:
    """Yield vuln fix-pair records for the given languages (None = all), each
    tagged with `vuln_type` (XSS, SQLi, ...) so the pipeline can balance by type.
    Default source order prefers the clean raw patches."""
    from .vuln_types import classify
    langs = languages or set()

    def _tag(it):
        for fp in it:
            vt, vcwe = classify(fp["vuln_code"])
            fp["vuln_type"] = vt
            if not fp.get("cwe"):
                fp["cwe"] = vcwe   # derived CWE when the source had none
            yield fp

    if "patches" in sources:
        yield from _tag(_from_patches(langs))
    if "morefixes" in sources:
        yield from _tag(_from_morefixes(langs))
    if "cve_fix_pairs" in sources:
        yield from _tag(_from_cve_fix_pairs(langs))
