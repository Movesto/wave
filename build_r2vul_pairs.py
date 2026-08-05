"""Build contrastive pairs from r2vul's `map_id`, which links the two revisions.

r2vul stores each function twice -- vulnerable=1 and vulnerable=0 -- joined by
`map_id`. That is a real before/after of the SAME function, so it can carry the
pair rules (R1/R2/R3/R5/R9) that single-sided records can never satisfy.

Do NOT pair on (cve, repo, file): a minified bundle puts thousands of unrelated
functions in one file, and that key groups strangers. Verified by reading diffs --
it produced 2,349 "pairs" that were nonsense. `map_id` gives 242 real ones.

Every lesson from the TS/JS builders is applied here rather than re-learned:
  * source and sink must occur STANDALONE in BOTH sides (a substring test let
    `stat.isDirectory` pass against `rootLstat.isDirectory`)
  * the sink must sit near the source, or the trace pairs two points that never
    meet
  * identifiers are matched outside string literals, so a word in a message is
    not mistaken for a value
  * if no guard can be identified confidently, the pair is dropped, not guessed

    python build_r2vul_pairs.py --write
"""
import argparse
import collections
import difflib
import hashlib
import json
import re
import sys

OUT = "data/cot/staging/shape1_contrastive_r2vul.jsonl"

# The builder must apply the SCANNER's predicate, never a looser one of its own.
# A local `standalone()` accepted `nextToken` in `p.nextToken()` -- a method name,
# not a value -- because it only excluded \w before the match. `occurs` excludes a
# preceding dot and takes the head of a chain, which is the correct question.
MAX_CODE_CHARS = 4500        # the standard's limit, not the filter's 6000


_STR_LIT = re.compile(r"'(?:\\.|[^'\\])*'" r'|"(?:\\.|[^"\\])*"' r"|`(?:\\.|[^`\\])*`")
_IDENT = re.compile(r"[A-Za-z_][\w]*")
_CALL = re.compile(r"([A-Za-z_][\w.]*)\s*\(")

# Constructs that ENFORCE something, as opposed to merely mentioning it.
_CONTROL = re.compile(
    r"\b(if|assert|require|check|validate|verify|ensure|guard|"
    r"return\s+(?:null|false|NULL|-1)|abort|panic|bail)\b", re.I)

# `throw` is what happens AFTER a check fails, not the check. Quoting it as the
# guard names the consequence and leaves the actual condition unstated -- the
# same defect the TS guard picker had, where `throw new SandboxAccessError(...)`
# won over the `['caller','callee','arguments'].includes(b)` that decided it.
_CONSEQUENCE = re.compile(r"^\s*(throw|raise)\b", re.I)

# `if err != nil` is Go's calling convention, not a security control, and it sits
# on almost every Go function. `catch`/`rescue` likewise handle failure rather
# than constrain input. Scoring these as guards produced `err -> r.lookupCNAME`.
_ERRCHECK = re.compile(
    r"^\s*(\}\s*)?(if|when)?\s*\(?\s*(err|error|e|ex|exc|errno)\b\s*"
    r"(!=\s*(nil|NULL|null)|==\s*(nil|NULL|null)|\)|\s*\{)"
    # Go's `if err := doThing(...); err != nil {` -- the check is on the RESULT of
    # the call, so the line reads as a control while enforcing nothing about input.
    r"|^\s*if\s+\w+\s*:=.*;\s*\w*err\w*\s*!=\s*nil", re.I)

# An import binds a name; it enforces nothing. `const { isValidHost } =
# require('@/utils/valid-host')` was quoted as the guard for a command-injection
# fix -- the helper is imported there, but the CHECK is wherever it is called.
_IMPORT = re.compile(
    r"^\s*(import\b|from\b.*\bimport\b|#include\b|using\b|require\s*\(|"
    r"(const|let|var)\s+\{?[\w\s,{}]*\}?\s*=\s*require\s*\()", re.I)
# NO leading \b: security words live INSIDE camelCase identifiers, and requiring
# a boundary made `String.IsNullOrEmpty(value)` score zero on vocabulary -- the
# same boundary assumption that has now bitten this project three times.
_SECVOCAB = re.compile(
    r"(valid|invalid|sanitiz|escap|encode|bound|limit|max|min|size|"
    r"null|nil|none|empty|auth|perm|allow|deny|owner|admin|token|secret|"
    r"overflow|range|index|safe|unsafe|trust|clean|filter|strip|quote|"
    r"canonical|normal|absolut|relativ|traversal|inject|depth|binder)", re.I)

# A fix does not have to be a conditional. These TRANSFORM the value so the
# dangerous input can no longer exist -- canonicalising a path, escaping a URL
# component, parsing an address back to its normal form. Requiring an `if` threw
# away 157 of 242 candidates, most of which are this shape.
_TRANSFORM = re.compile(
    r"\b\w*(Parse|Escape|Encode|Sanitiz|Normaliz|Canonical|GetFullPath|realpath|"
    r"abspath|quote|strip|replace|filter|clamp|truncat|decode|"
    # `new URL(x)` rejects anything that is not a well-formed URL and
    # normalises what remains -- the standard fix for open-redirect and
    # command-injection-via-url. Missing it lost real react fixes.
    r"URL|URI|Url|resolve|join|basename|dirname)\w*\s*\(", re.I)

# Setting a safe option is also a control: a deserialisation binder, a recursion
# depth, a size ceiling.
_CONFIG = re.compile(
    r"\b\w*(MaxDepth|MaxLength|MaxSize|Binder|Limit|Timeout|Quota|Threshold)\w*"
    r"\s*[=:]", re.I)

_KEYWORDS = {"if", "for", "while", "switch", "return", "new", "catch", "throw",
             "else", "try", "do", "case", "sizeof", "typeof", "await", "async",
             "function", "def", "class", "public", "private", "protected",
             "static", "void", "int", "char", "const", "struct", "final",
             "import", "from", "self", "this", "true", "false", "null", "None",
             "True", "False", "and", "or", "not", "in", "is", "len", "str",
             # C#/Java/C type names read as identifiers and were picked as the
             # SOURCE -- `string` is a type, never an attacker-controlled value.
             "string", "String", "var", "object", "Object", "bool", "boolean",
             "Boolean", "byte", "short", "long", "float", "double", "decimal",
             "Integer", "Long", "Double", "Float", "List", "Map", "Set", "Dictionary",
             "unsigned", "signed", "size_t", "uint", "ulong", "ushort", "sbyte",
             "override", "virtual", "abstract", "internal", "readonly", "out",
             "ref", "params", "using", "namespace", "package", "extends",
             "implements", "throws", "synchronized", "volatile", "transient",
             # C constants and macros are not attacker-controlled values
             "NULL", "TRUE", "FALSE", "EOF", "INT_MAX", "INT_MIN", "SIZE_MAX",
             "stdin", "stdout", "stderr", "errno", "goto", "enum", "union",
             "typedef", "extern", "register", "inline", "restrict",
             # Callback and error-plumbing names are not attacker-controlled
             # values -- they are the shape of the language, not of the data.
             "undefined", "NaN", "Infinity", "arguments", "globalThis",
             "err", "error", "errors", "resolve", "reject", "next", "done",
             "callback", "cb", "require", "module", "exports", "console",
             "logger", "log", "printf", "fmt", "res", "req", "ctx", "ok"}

# C typedef convention: `mf_t`, `size_t`, `uint32_t` are TYPES, not values.
_C_TYPEDEF = re.compile(r"_t$|^u?int\d+_t$")


def bare(code):
    return _STR_LIT.sub("''", code)


def standalone(ident, code):
    """Delegates to the scanner so builder and scanner can never disagree."""
    from scan_ts_standard import occurs
    return occurs(ident, code)


def added_lines(vuln, safe):
    out = []
    for l in difflib.unified_diff(vuln.splitlines(), safe.splitlines(), lineterm="", n=0):
        if l.startswith("+") and not l.startswith("+++"):
            out.append(l[1:])
    return out


def pick_guard(vuln, safe):
    """The control the fix ADDED. None if nothing added actually enforces."""
    best, best_score = None, 0
    for l in added_lines(vuln, safe):
        s = l.strip()
        if len(s) < 12 or s.startswith(("//", "#", "*", "/*")):
            continue
        if s in vuln:
            continue
        # A bare `if` is GENERIC -- `if (savePaths.Count > 0)` is a loop guard, not
        # a control -- so it needs corroboration from the vocabulary. A sanitiser
        # or a limit is SELF-EVIDENCING: `IPAddress.Parse(ip)` and
        # `.replace(/%/gu, "^%")` are the entire fix for their CVEs and contain no
        # security word at all. Scoring both at 2 under a threshold of 3 assumed
        # every control mentions security vocabulary, which is false for exactly
        # the transformation fixes that make up most of what we were losing.
        if _ERRCHECK.match(s) or _IMPORT.match(s):
            continue
        score = 0
        if _CONSEQUENCE.match(s):
            score -= 2          # last resort: prefer the check over its result
        if _CONTROL.search(s):
            score += 2          # generic: needs a vocabulary hit to clear the bar
        if _TRANSFORM.search(s):
            score += 3          # self-evidencing
        if _CONFIG.search(s):
            score += 3          # self-evidencing
        score += min(2, len(set(x.lower() for x in _SECVOCAB.findall(s))))
        if score >= 3 and score > best_score:
            best, best_score = s, score
    return best


_TYPEISH = re.compile(r"(Exception|Error|Throwable|Fault)s?$")
# ALL_CAPS is the constant convention in every language here. A constant is fixed
# at build time, so it is never the attacker-controlled value -- `GX_PATH` and
# `Permissions` were both named as sources.
_CONSTANT = re.compile(r"^[A-Z][A-Z0-9_]{2,}$")
# Library functions are not values either. `intval` was named as the source of a
# PHP authentication flaw.
_BUILTIN_FN = {"intval", "strval", "floatval", "boolval", "strlen", "count",
               "sizeof", "isset", "empty", "printf", "sprintf", "strcmp",
               "substr", "explode", "implode", "trim", "json", "array", "list",
               "range", "map", "filter", "reduce", "sorted", "enumerate",
               "getenv", "define", "defined", "typeof", "instanceof"}
_STDLIB_TYPES = {"Path", "File", "Files", "System", "Math", "Console", "Array",
                 "Arrays", "Collections", "Objects", "Class", "Type", "Uri",
                 "URL", "URI", "Encoding", "Convert", "Buffer", "JSON", "Date",
                 "Regex", "Pattern", "Matcher", "Thread", "Task", "Stream"}


def pick_source(guard, vuln, safe):
    inner = guard
    m = re.search(r"\(([^)]*)\)", guard)
    if m and m.group(1).strip():
        inner = m.group(1)
    for pool in (inner, guard):
        for ident in _IDENT.findall(pool):
            if ident in _KEYWORDS or len(ident) < 3:
                continue
            if ident in _STDLIB_TYPES or _TYPEISH.search(ident):
                continue
            if _C_TYPEDEF.search(ident):
                continue
            if _CONSTANT.match(ident) or ident.lower() in _BUILTIN_FN:
                continue
            if standalone(ident, vuln) and standalone(ident, safe):
                return ident
    return None


def pick_sink(code, near, window=25):
    """A call the source reaches, taken from the source's own neighbourhood."""
    b = bare(code)
    lines = b.splitlines()
    anchors = [i for i, l in enumerate(lines)
               if re.search(r"(?<![\w])" + re.escape(near) + r"(?![\w])", l)]
    if not anchors:
        return None
    keep = set()
    for a in anchors:
        keep.update(range(max(0, a - window), min(len(lines), a + window + 1)))
    scope = "\n".join(l if i in keep else "" for i, l in enumerate(lines))
    best = None
    for m in _CALL.finditer(scope):
        name = m.group(1)
        base = name.split(".")[-1]
        if base in _KEYWORDS or len(base) < 3 or name == near:
            continue
        # A member call ON the source is not a sink the value FLOWS to --
        # `value -> value.Replace` describes one expression, not a path.
        if name.split(".")[0] == near:
            continue
        if not standalone(name, code):
            continue
        if best is None or len(name) > len(best):
            best = name
    return best


def record(code, label, cwe, src, snk, guard, meta, pid):
    if label == "vuln":
        think = (f"Hypothesis: `{src}` is attacker-influenced and reaches `{snk}` - "
                 f"the shape of {cwe}.\n"
                 f"Trigger path: `{src}` flows into `{snk}` as written.\n"
                 f"Defensive check: I look along that path for a control that "
                 f"constrains `{src}`, and this revision has none.\n"
                 f"The mechanism is intact and the value is caller-chosen, so it is "
                 f"exploitable. Confirmed {cwe}.")
        tail = (f"status: confirmed\ncwe: {cwe}\nseverity: HIGH\n"
                f"trace: {src} -> {snk}\nfix: constrain `{src}` before it reaches `{snk}`")
    else:
        think = (f"Hypothesis: `{src}` reaches `{snk}`, which is the shape of {cwe} - "
                 f"check whether the mechanism is still present.\n"
                 f"Trigger path: the call structure is the dangerous one, so shape alone "
                 f"does not settle it.\n"
                 f"Defensive check: this revision applies `{guard}`, which constrains "
                 f"`{src}` before it reaches `{snk}`.\n"
                 f"Because that control sits on the path, the value arriving at `{snk}` "
                 f"can no longer be chosen freely, so the hypothesis is refuted.")
        tail = ("status: safe\ncwe: none\nseverity: none\n"
                f"trace: {src} -> {snk} is constrained by `{guard}`\nfix: none")
    m = dict(meta)
    m.update(shape="shape1", source="contrastive_r2vul", origin="real",
             label=label, cwes=[cwe], ground_truth_cwe=cwe, pair_id=pid,
             contrastive=True, synthetic=False, cleaned=True)
    return {"messages": [{"role": "user", "content": f"<SCAN>\n{code}\n</SCAN>"},
                         {"role": "assistant",
                          "content": f"<think>\n{think}\n</think>\n{tail}"}],
            "_meta": m}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()

    from datasets import load_from_disk
    ds = load_from_disk("data/r2vul_dataset")
    groups = collections.defaultdict(lambda: collections.defaultdict(list))
    for split in ds:
        for r in ds[split]:
            groups[r.get("map_id")][r.get("vulnerable")].append(r)

    from filter_corpus import load_eval_codes
    evalcodes = load_eval_codes()
    out, f = [], collections.Counter()
    for mid, sides in groups.items():
        if 1 not in sides or 0 not in sides:
            continue
        v, s = sides[1][0], sides[0][0]
        vuln, safe = v.get("function") or "", s.get("function") or ""
        f["candidate"] += 1

        if not (120 <= len(vuln) <= MAX_CODE_CHARS
                and 120 <= len(safe) <= MAX_CODE_CHARS):
            f["size"] += 1
            continue
        nch = len(added_lines(vuln, safe))
        if not (1 <= nch <= 24):
            f["diff_too_large_or_empty"] += 1
            continue
        guard = pick_guard(vuln, safe)
        if not guard:
            f["no_guard_identified"] += 1
            continue
        if guard in vuln:
            f["guard_already_in_vuln"] += 1
            continue
        src = pick_source(guard, vuln, safe)
        if not src:
            f["no_source"] += 1
            continue
        snk = pick_sink(vuln, src)
        if not snk or snk == src:
            f["no_distinct_sink"] += 1
            continue
        if not (standalone(snk, vuln) and standalone(snk, safe)):
            f["sink_not_in_both"] += 1
            continue
        if any(re.sub(r"\s+", " ", x).strip().lower() in evalcodes for x in (vuln, safe)):
            f["eval_leakage"] += 1
            continue
        cwes = v.get("cwe_id") or []
        cwe = next((c for c in cwes if str(c).startswith("CWE-")), "")
        if not cwe:
            f["no_cwe"] += 1
            continue

        pid = hashlib.sha1(f"r2vul|{mid}".encode()).hexdigest()[:12]
        meta = dict(language=v.get("lang", ""), cve=v.get("cve_id", ""),
                    repo=v.get("repo", ""), sha=v.get("parent_commit_sha", ""),
                    src_file=v.get("file", ""), cwe_source="r2vul_upstream",
                    map_id=str(mid), fix_status="r2vul_map_id")
        out.append(record(vuln, "vuln", cwe, src, snk, guard, meta, pid))
        out.append(record(safe, "safe", cwe, src, snk, guard, meta, pid))
        f["PAIR_BUILT"] += 1

    print("=== funnel ===")
    for k, val in f.most_common():
        print(f"  {k:26s} {val:5d}")
    if args.write and out:
        with open(OUT, "w", encoding="utf-8") as fh:
            for r in out:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        print(f"\npairs: {len(out)//2}  records: {len(out)} -> {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
