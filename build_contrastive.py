"""Contrastive-pair builder (2026-07-24).

The v2p autopsy proved the model learned TOPIC discrimination, not GUARD
discrimination: vuln and safe traces came from unrelated code, so "vuln" merely
correlated with surface features. Patched code keeps those features + adds a
guard -> still flagged. Fix: train on BOTH sides of the same fix pair, where the
only difference is the guard the patch added, and the SAFE trace QUOTES that
guard as its reason. Same code, opposite label -> the model is forced to learn
"is this flow actually guarded?" instead of "does this look vuln-shaped?".

Emits shape1-format records (vuln_code->vuln, fixed_code->safe) sharing a
pair_id, to data/cot/staging/shape1_contrastive.jsonl. Deterministic, no model.
Reasoning is grounded in the real source/sink/guard tokens and phrase-varied so
it does NOT reproduce the 21% "the fix adds a control..." boilerplate.

Run:  python build_contrastive.py [--limit N] [--langs a,b,c]
"""
import argparse, glob, hashlib, json, os, re, difflib, collections

from cot.fix_pairs import iter_fix_pairs
from cot.oracle import locate_from_diff, identifiers
from cot.cwe_contracts import family_of, CONTRACTS
from cot.template_reason import _find_sink, _find_source

OUT = "data/cot/staging/shape1_contrastive.jsonl"
PILOT = "data/cot/pilot_clean"
EVAL = os.environ.get("WAVE_EVAL_DIR", "data/cot/eval_v2")  # retired bench was provenance-free

# A line added by the patch is a GUARD if it introduces a security control. This
# is also the security-fix filter: comment shifts / refactors add no guard line
# and are dropped (fixes the ANTLR-comment contamination the audit found).
_GUARD = re.compile(
    r"\b(validat|sanitiz|escap|encode|quote|htmlspecialchars|htmlentities|bleach|purify"
    r"|parameteriz|prepare|bindparam|bind_param|execute\s*\([^)]*[,%]"          # param query
    r"|is_valid|isvalid|check|verify|assert|allow(ed|list)?|whitelist|deny|reject"
    r"|permission|authori[sz]|authenticate|can[A-Z_]|has_?role|is_?admin|access|acl"
    r"|csrf|token|nonce|verify_?signature|hmac|compare_digest"
    r"|shlex\.quote|shell_quote|realpath|abspath|normpath|basename|secure_filename"
    r"|is_safe_url|url_?parse|urlparse|hostname|allowed_hosts"
    r"|strncpy|strncat|snprintf|bounds?|limit|min\(|max\(|len\s*\(|clamp"
    r"|filter_var|intval|ctype_|preg_match|type\s*==|instanceof|isinstance)\b",
    re.I,
)
_COMMENTONLY = re.compile(r"^\s*(//|#|\*|/\*|\*/|<!--)")
_NEWCOND = re.compile(r"^\s*(if|elif|unless|when|guard|switch|case|assert)\b|\?\s*.+:")  # a new conditional

# The GUARD reveals the vuln CLASS. When a pair has no CWE (48.6K real patches
# dropped for this), derive the CWE from the kind of guard the patch added — no
# external CVE->CWE lookup needed. Ordered: first match wins (most specific first).
_GUARD_CWE = [
    (re.compile(r"parameteriz|bindparam|bind_param|prepare(d)?statement|execute\s*\([^)]*[,%]\?|cursor\.execute\([^)]*,|\?\s*\)|%s", re.I), "CWE-89"),
    (re.compile(r"htmlspecialchars|htmlentities|\bescapeHtml\b|bleach|DOMPurify|sanitize_html|encodeURI|escape\(|markupsafe|\|e\b", re.I), "CWE-79"),
    (re.compile(r"shlex\.quote|escapeshellarg|escapeshellcmd|shell_quote|shell=False|subprocess\.(run|call)\(\[", re.I), "CWE-78"),
    (re.compile(r"realpath|abspath|normpath|basename|secure_filename|startswith\(|\.\.\s|werkzeug\.security|os\.path\.commonprefix", re.I), "CWE-22"),
    (re.compile(r"is_safe_url|allowed_hosts|url(lib)?\.?parse|hostname|netloc|urlsplit", re.I), "CWE-601"),
    (re.compile(r"yaml\.safe_load|SafeLoader|pickle|json\.loads|ast\.literal_eval|disallow.*type|allow.?list.*class", re.I), "CWE-502"),
    (re.compile(r"permission|authori[sz]|authenticate|can[A-Z_]|has_?role|is_?admin|access_control|\bacl\b|current_user|require_?login|@login_required", re.I), "CWE-284"),
    (re.compile(r"csrf|nonce|verify_?token|same_?site|origin.?check", re.I), "CWE-352"),
    (re.compile(r"compare_digest|hmac|constant_time|bcrypt|scrypt|pbkdf2|argon2|secrets\.|os\.urandom|secure.?random", re.I), "CWE-327"),
    (re.compile(r"defusedxml|resolve_entities\s*=\s*False|no_?network|XMLParser\([^)]*resolve", re.I), "CWE-611"),
    (re.compile(r"filter_var|intval|ctype_|preg_match|isinstance|instanceof|type\s*==|is_valid|validate|assert", re.I), "CWE-20"),
]


def _cwe_from_guard(guard_line, added):
    """Derive a CWE from the guard the patch added (for no-CWE real patches)."""
    blob = guard_line + "\n" + "\n".join(added)
    for rx, cwe in _GUARD_CWE:
        if rx.search(blob):
            return cwe
    return None


def _added_lines(vuln_code, fixed_code):
    """Lines the patch ADDED (present in fixed, new vs vuln)."""
    v, f = vuln_code.splitlines(), fixed_code.splitlines()
    sm = difflib.SequenceMatcher(a=v, b=f, autojunk=False)
    added = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag in ("insert", "replace"):
            added += [f[j] for j in range(j1, j2)]
    return [l for l in added if l.strip()]


def _pick_guard(added):
    """Choose the single most representative added guard line to quote.
    Prefer a validation/authz call, then a new conditional. Ignore comments."""
    cands = [l for l in added if not _COMMENTONLY.match(l) and not _SIG_LINE.match(l)]
    scored = []
    for l in cands:
        s = 0
        if _GUARD.search(l): s += 2
        if _NEWCOND.match(l): s += 1
        if s: scored.append((s, len(l), l))
    if not scored:
        return None
    # highest signal, then shortest (most focused) line
    scored.sort(key=lambda x: (-x[0], x[1]))
    return scored[0][2].strip()


_CALL = re.compile(r"([A-Za-z_][\w.]*)\s*\(")
_SINK_STOP = {"if", "for", "while", "switch", "return", "printf", "println",
              "print", "log", "console.log", "len", "str", "int", "isinstance",
              "type", "assert", "range", "super", "self",
              # language keywords the fallback must never treat as a sink
              "func", "function", "def", "class", "new", "var", "let", "const",
              "public", "private", "protected", "static", "void", "sub", "lambda"}
# A guard must be an actual control, not a function/method DECLARATION line.
_SIG_LINE = re.compile(r"^\s*(func |def |function |public |private |protected "
                       r"|static |void |sub |class |interface |type\s+\w+\s+struct)")


def _fallback_sink(vuln_code, region):
    """When contract markers don't match, ground the sink as the most salient
    function call on a changed (region) line — that's what the guard protects.
    Recovers real no-CWE patches that have a guard+derived-CWE but no marker sink."""
    lines = vuln_code.split("\n")
    region_lines = region.lines or set(range(1, len(lines) + 1))
    best = None
    for ln in sorted(region_lines):
        if not (1 <= ln <= len(lines)):
            continue
        for m in _CALL.finditer(lines[ln - 1]):
            tok = m.group(1)
            base = tok.split(".")[-1]
            if base.lower() in _SINK_STOP or len(base) < 3:
                continue
            # prefer a call that touches the changed identifiers
            score = 2 if (region.identifiers and set(re.findall(r"\w+", tok)) & region.identifiers) else 1
            if best is None or score > best[0]:
                best = (score, tok, ln)
    return (best[1], best[2]) if best else (None, None)


def _variant(seed, options):
    return options[int(hashlib.md5(seed.encode()).hexdigest(), 16) % len(options)]


from cot.deep_trace import deep_vuln_think, deep_safe_think

_ARG = re.compile(r"\(\s*([^)]*)")
_GENERIC_SRC = {"untrusted input", "input", "data", "user", "value", "none", ""}


def _better_source(source, sink, vuln_code):
    """If _find_source gave a generic placeholder, recover the real tainted
    variable from the SINK's argument on its line in the vuln code."""
    if source and source.lower() not in _GENERIC_SRC:
        return source
    base = (sink or "").split(".")[-1]
    for line in vuln_code.split("\n"):
        if base and base in line:
            m = _ARG.search(line[line.find(base):])
            if m:
                # first identifier-looking argument
                for tok in re.findall(r"[A-Za-z_$][\w$.\[\]'\"]*", m.group(1)):
                    t = tok.strip("'\"")
                    if len(t) > 2 and not t.isdigit() and t.split(".")[0].lower() not in _SINK_STOP:
                        return t
    return source or "untrusted input"


def _vuln_trace(source, sink, line, cwe, seed):
    think = deep_vuln_think(source, sink, line, cwe)
    fields = (f"status: confirmed\ncwe: {cwe}\nseverity: {_SEV.get(family_of(cwe),'MEDIUM')}\n"
              f"line: {line if line else 'none'}\ntrace: {source} -> {sink}\n"
              f"fix: add a guard on the path from {source} to {sink}")
    return think + "\n" + fields


def _safe_trace(source, sink, guard_line, cwe, seed):
    think = deep_safe_think(source, sink, guard_line, cwe)
    fields = (f"status: safe\ncwe: none\nseverity: none\nline: none\n"
              f"trace: {source} -> {sink} is neutralized by `{guard_line}`\nfix: none")
    return think + "\n" + fields


from cot.template_reason import _SEV


def _norm(s): return re.sub(r"\s+", " ", s or "").strip().lower()


def _leak_hashes():
    h = set()
    for path in glob.glob(f"{EVAL}/*.jsonl"):
        for line in open(path, encoding="utf-8"):
            line = line.strip()
            if not line: continue
            try: r = json.loads(line)
            except: continue
            m = r.get("messages") or []
            if m:
                mm = re.search(r"<SCAN>\n?(.*?)\n?</SCAN>", m[0].get("content",""), re.S)
                if mm: h.add(_norm(mm.group(1)))
    return h


def _rec(code, trace, lang, cwe, label, pid, src):
    return {
        "messages": [
            {"role": "user", "content": f"<SCAN>\n{code}\n</SCAN>"},
            {"role": "assistant", "content": trace},
        ],
        "_meta": {"shape": "shape1", "source": "contrastive", "origin": src,
                  "language": lang, "label": label, "cwes": [cwe],
                  "ground_truth_cwe": cwe, "pair_id": pid,
                  "contrastive": True, "synthetic": src == "vuln_fix_dataset",
                  "cleaned": True},
    }


_VT_CWE = {
    "cross-site scripting (xss)": "CWE-79", "xss": "CWE-79",
    "sql injection": "CWE-89", "command injection": "CWE-78",
    "path traversal": "CWE-22", "buffer overflow": "CWE-120",
    "insecure deserialization": "CWE-502", "deserialization": "CWE-502",
    "ssrf": "CWE-918", "open redirect": "CWE-601", "code injection": "CWE-94",
}
_SYNTH_LANG = re.compile(r"\b(import java|public class|#include|def |function |<\?php|package main|require\(|console\.)", re.I)


def _from_vuln_fix_dataset(langs):
    """Synthetic-heavy paired CSV (vulnerable_code/fixed_code/vulnerability_type).
    Tagged origin=vuln_fix_dataset so it stays separable + low-weight."""
    import csv as _csv
    _csv.field_size_limit(10 ** 7)
    path = "data/downloads/vulnerability-fix-dataset/vulnerability_fix_dataset.csv"
    if not os.path.exists(path):
        return
    def guess_lang(code):
        c = code.lower()
        if "import java" in c or "public class" in c: return "java"
        if "#include" in c or "int main" in c: return "cpp"
        if "<?php" in c: return "php"
        if "def " in c or "import " in c and "from " in c: return "python"
        if "function " in c or "console." in c or "=>" in c: return "javascript"
        if "package main" in c: return "go"
        return "unknown"
    with open(path, encoding="utf-8", errors="replace") as f:
        for row in _csv.DictReader(f):
            v = (row.get("vulnerable_code") or "").strip()
            fx = (row.get("fixed_code") or "").strip()
            vt = (row.get("vulnerability_type") or "").strip().lower()
            cwe = _VT_CWE.get(vt)
            if not v or not fx or not cwe:
                continue
            lang = guess_lang(v)
            if langs and lang not in langs and lang != "unknown":
                continue
            yield {"vuln_code": v, "fixed_code": fx, "cwe": cwe,
                   "language": lang, "vuln_type": vt, "origin": "vuln_fix_dataset"}


def _from_primevul(langs):
    """PrimeVul paired data (colin/PrimeVul) — the cleanest curated vuln/patch
    pairs (manual curation + strict dedup). Adjacent records: target=1 vuln then
    target=0 patch, same commit. Mostly C/C++. origin=primevul (real, high value)."""
    import glob
    # TRAIN AND VALID ONLY. The old glob was "*_paired.jsonl", which also matched
    # primevul_test_paired.jsonl and put 53 of its 868 test records into training —
    # PrimeVul is the benchmark we score against, so its test split must stay unseen.
    for path in ("data/downloads/PrimeVul/primevul_train_paired.jsonl",
                 "data/downloads/PrimeVul/primevul_valid_paired.jsonl"):
        if not os.path.exists(path):
            continue
        rows = [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]
        for i in range(0, len(rows) - 1, 2):
            a, b = rows[i], rows[i + 1]
            if {a.get("target"), b.get("target")} != {0, 1}:
                continue
            vuln = a if a.get("target") == 1 else b
            patch = b if a.get("target") == 1 else a
            v, fx = (vuln.get("func") or "").strip(), (patch.get("func") or "").strip()
            if not v or not fx or v == fx:
                continue
            cwes = vuln.get("cwe") or []
            cwe = cwes[0] if cwes else None
            ext = (vuln.get("file_name") or "").rsplit(".", 1)[-1].lower()
            lang = {"c": "c", "cpp": "cpp", "cc": "cpp", "h": "c", "hpp": "cpp",
                    "java": "java", "py": "python", "js": "javascript"}.get(ext, "c")
            if langs and lang not in langs:
                continue
            yield {"vuln_code": v, "fixed_code": fx, "cwe": cwe,
                   "language": lang, "vuln_type": None, "origin": "primevul"}


def _all_pairs(langs):
    """Every contrastive-capable source. iter_fix_pairs = REAL git patches +
    cve_fix_pairs (origin=real); primevul = curated clean pairs; vuln_fix_dataset
    = synthetic-heavy (tagged, capped)."""
    for fp in iter_fix_pairs(langs):
        fp.setdefault("origin", "real")
        yield fp
    for fp in _from_primevul(langs):
        yield fp
    for fp in _from_vuln_fix_dataset(langs):
        yield fp


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0, help="max PAIRS (0=all)")
    ap.add_argument("--langs", default="python,javascript,typescript,java,php,go,c,ruby,csharp,cpp,react")
    ap.add_argument("--max-synthetic", type=int, default=1000,
                    help="cap on synthetic (vuln_fix_dataset) pairs — keeps the set "
                         "REAL-dominated; synthetic is Java-only textbook (low transfer)")
    ap.add_argument("--per-cwe-synthetic", type=int, default=150,
                    help="per-CWE cap on synthetic, so it doesn't skew to XSS/path")
    args = ap.parse_args()
    syn_kept = collections.Counter()
    langs = {l.strip() for l in args.langs.split(",") if l.strip()}
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    leak = _leak_hashes()
    print(f"leak-guard: {len(leak)} eval snippets loaded")

    seen_code = set()
    kept = 0
    stats = collections.Counter()
    by_lang = collections.Counter(); by_cwe = collections.Counter()
    with open(OUT, "w", encoding="utf-8") as out:
        for fp in _all_pairs(langs):
            stats["seen_pairs"] += 1
            v, fx, cwe, lang = fp.get("vuln_code",""), fp.get("fixed_code",""), fp.get("cwe"), fp.get("language","?")
            if not v or not fx or v == fx: stats["drop_empty"] += 1; continue
            if not (60 <= len(v) <= 1500 and 60 <= len(fx) <= 1500): stats["drop_len"] += 1; continue
            # Detect the guard FIRST — it doubles as the security-fix filter AND
            # (when the pair has no CWE) reveals the vuln class.
            origin = fp.get("origin", "real")
            if _norm(v) == _norm(fx):                                  # whitespace/brace-only "fix"
                stats["drop_cosmetic"] += 1; continue
            added = _added_lines(v, fx)
            guard = _pick_guard(added)
            if not guard: stats["drop_no_guard"] += 1; continue        # refactor / comment-shift
            if len(guard) > 200: guard = guard[:200]
            # The guard must be GENUINELY NEW — if it already appears in the vuln
            # code, the diff paired a barely-changed line and the "neutralized by X"
            # claim would be false (X is in the vuln too). Drop such non-contrastive pairs.
            gnorm = _norm(guard)
            if len(gnorm) > 8 and gnorm in _norm(v):
                stats["drop_guard_in_vuln"] += 1; continue
            fam = family_of(cwe)
            # Cap synthetic so real data dominates (synthetic = Java-only textbook).
            if origin == "vuln_fix_dataset":
                if sum(syn_kept.values()) >= args.max_synthetic: stats["drop_syn_cap"] += 1; continue
                if syn_kept[cwe] >= args.per_cwe_synthetic: stats["drop_syn_cwe_cap"] += 1; continue
            if fam is None:                                            # recover no-CWE real patches
                cwe = _cwe_from_guard(guard, added)
                fam = family_of(cwe)
                if fam is None: stats["drop_no_family"] += 1; continue
                stats["recovered_from_guard"] += 1
            region = locate_from_diff(v, fx)
            c = CONTRACTS[fam]
            sink, sink_line = _find_sink(v, c["markers"], region.lines)
            if sink is None:                                          # marker miss -> fallback
                sink, sink_line = _fallback_sink(v, region)
                if sink is None: stats["drop_no_sink"] += 1; continue
                stats["sink_via_fallback"] += 1
            source = _find_source(v, fx, region)
            if source == sink: source = "untrusted input"
            source = _better_source(source, sink, v)   # recover real tainted var if generic
            if source == sink: source = "untrusted input"
            nv = _norm(v)
            if nv in seen_code: stats["drop_dup"] += 1; continue
            if nv in leak or _norm(fx) in leak: stats["drop_leak"] += 1; continue
            seen_code.add(nv)
            if origin == "vuln_fix_dataset": syn_kept[cwe] += 1
            pid = hashlib.md5((nv + cwe).encode()).hexdigest()[:12]
            out.write(json.dumps(_rec(v, _vuln_trace(source, sink, sink_line, cwe, pid+"v"),
                                      lang, cwe, "vuln", pid, origin), ensure_ascii=False) + "\n")
            out.write(json.dumps(_rec(fx, _safe_trace(source, sink, guard, cwe, pid+"s"),
                                      lang, cwe, "safe", pid, origin), ensure_ascii=False) + "\n")
            kept += 1
            by_lang[lang] += 1; by_cwe[cwe] += 1
            stats["kept_pairs"] += 1; stats[f"origin_{origin}"] += 1
            if args.limit and kept >= args.limit: break

    print(f"\nKEPT {kept} contrastive pairs -> {kept*2} records -> {OUT}")
    print("drops:", {k: v for k, v in stats.items() if k.startswith("drop")})
    print("recovered from guard (no-CWE real patches):", stats["recovered_from_guard"])
    print("sink via fallback:", stats["sink_via_fallback"])
    print("origin:", {k.replace('origin_',''): v for k, v in stats.items() if k.startswith("origin_")})
    print("by language:", dict(by_lang.most_common()))
    print("top CWEs:", dict(by_cwe.most_common(15)))


if __name__ == "__main__":
    main()
