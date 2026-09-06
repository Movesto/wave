"""Does the authored TypeScript sit inside the distribution of REAL harvested code?

The failure this tests for: `shape_react_syn` scored 100% while real React scored
41%, because the model learned to recognise TEXTBOOK-NESS rather than
vulnerability. Tutorial code is characteristically shorter, flatter, more
uniformly named, less typed and less defensive than production code. If the
authored records are visibly cleaner than the real ones, that signature will show
up as numbers instead of a hunch.

Per-LINE ratios are used throughout, because the authored snippets are single
functions by design while real excerpts span whole enclosing functions across
files -- raw totals would just measure that difference.

    python compare_realism.py
"""
import json
import re
import statistics as st

REAL = "data/cot/staging/shape1_contrastive_ts_osv.jsonl"
import sys as _s
AUG = _s.argv[1] if len(_s.argv) > 1 else "data/cot/staging/shape1_ts_augment_pilot.jsonl"


def code_of(r):
    return r["messages"][0]["content"].replace("<SCAN>", "").replace("</SCAN>", "").strip()


def load(p):
    return [code_of(json.loads(l)) for l in open(p, encoding="utf-8") if l.strip()]


IDENT = re.compile(r"[A-Za-z_$][\w$]*")
KEYWORDS = {"const", "let", "var", "function", "return", "if", "else", "await", "async",
            "import", "export", "from", "new", "throw", "try", "catch", "this", "type",
            "interface", "class", "for", "of", "in", "true", "false", "null", "undefined"}


def metrics(code):
    lines = [l for l in code.splitlines() if l.strip()]
    if not lines:
        return None
    n = len(lines)
    idents = [i for i in IDENT.findall(code) if i not in KEYWORDS]
    long_ids = [i for i in idents if len(i) > 3]
    return {
        "lines": n,
        "avg_line_len": st.mean(len(l.rstrip()) for l in lines),
        "max_indent": max((len(l) - len(l.lstrip())) for l in lines),
        # production code is densely typed; tutorials often are not
        "type_annots_per_line": len(re.findall(r":\s*[A-Z][\w<>\[\]|]*", code)) / n,
        "generics_per_line": len(re.findall(r"<[A-Z][\w, .<>\[\]]*>", code)) / n,
        # real code is defensive and full of optional access
        "optional_chain_per_line": len(re.findall(r"\?\.|\?\?", code)) / n,
        "error_handling_per_line": len(re.findall(r"\bthrow\b|\bcatch\b|\btry\b", code)) / n,
        "await_per_line": len(re.findall(r"\bawait\b", code)) / n,
        # naming: tutorials use short, tidy names
        "mean_ident_len": st.mean(len(i) for i in long_ids) if long_ids else 0,
        "comment_ratio": sum(1 for l in lines if l.strip().startswith(("//", "*", "/*"))) / n,
    }


def summarize(name, codes):
    ms = [m for m in (metrics(c) for c in codes) if m]
    keys = list(ms[0].keys())
    return name, {k: [m[k] for m in ms] for k in keys}, len(ms)


def main():
    _, R, nr = summarize("real", load(REAL))
    _, A, na = summarize("authored", load(AUG))
    print("real records: %d   authored records: %d" % (nr, na))
    print()
    print("%-26s %10s %10s %10s   %s" % ("metric", "REAL med", "AUTH med", "real IQR", "verdict"))
    print("-" * 84)
    inside = 0
    total = 0
    for k in R:
        rv, av = sorted(R[k]), A[k]
        rmed, amed = st.median(rv), st.median(av)
        q1, q3 = rv[len(rv) // 4], rv[3 * len(rv) // 4]
        ok = q1 <= amed <= q3
        total += 1
        inside += ok
        print("%-26s %10.2f %10.2f  [%5.2f,%5.2f]   %s"
              % (k, rmed, amed, q1, q3, "inside" if ok else "OUTSIDE"))
    print()
    print("authored medians inside the real interquartile range: %d/%d" % (inside, total))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
