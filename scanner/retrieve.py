"""Layer B — CVE-corpus retrieval flagger (the data moat vs Semgrep).

Indexes your 26K known-vulnerable code snippets (each with a CWE). For target code,
finds the nearest known vulns; if a target strongly resembles known vulnerable code,
it's flagged WITH the CWE it matches — "this looks like known vulnerabilities."

Semgrep matches hand-written rules; this matches against actual historical vulns.
CPU-only: char n-gram TF-IDF + cosine (no neural model, no GPU, no download).

  python retrieve.py build              # build the index (once)
  python retrieve.py query app.py       # nearest known-vuln matches per function
"""
import io, json, glob, re, pickle, argparse, sys, os
from pathlib import Path
import numpy as np
from scipy import sparse
from sklearn.feature_extraction.text import TfidfVectorizer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)                          # find cot/ at repo root
INDEX_DIR = Path(__file__).parent / "index"       # self-contained in scanner/
CORPUS_GLOB = os.path.join(ROOT, "data", "cot", "pilot_clean", "*.jsonl")
_SCAN = re.compile(r"</?SCAN>")
FAMILY = None
try:
    from cot.cwe_contracts import family_of as FAMILY
except Exception:
    FAMILY = lambda c: None


def _clean(code):
    return _SCAN.sub("", code).strip()


def build(max_docs=26000):
    codes, meta = [], []
    seen = set()
    for p in sorted(glob.glob(CORPUS_GLOB)):
        for line in io.open(p, encoding="utf-8"):
            if not line.strip():
                continue
            r = json.loads(line); m = r["_meta"]
            if m.get("label") not in ("vuln", "confirmed") or not m.get("ground_truth_cwe"):
                continue
            code = _clean(r["messages"][0]["content"])
            key = hash(code[:400])
            if len(code) < 40 or key in seen:
                continue
            seen.add(key)
            codes.append(code)
            meta.append({"cwe": m["ground_truth_cwe"], "family": FAMILY(m["ground_truth_cwe"]),
                         "source": m.get("source")})
            if len(codes) >= max_docs:
                break
        if len(codes) >= max_docs:
            break

    vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2,
                          max_features=60000, sublinear_tf=True)
    X = vec.fit_transform(codes)                       # already L2-normalized rows
    INDEX_DIR.mkdir(parents=True, exist_ok=True)
    sparse.save_npz(INDEX_DIR / "matrix.npz", X)
    pickle.dump(vec, open(INDEX_DIR / "vectorizer.pkl", "wb"))
    json.dump(meta, open(INDEX_DIR / "meta.json", "w"))
    print(f"indexed {len(codes)} vuln snippets, {X.shape[1]} features -> {INDEX_DIR}/")


_CACHE = {}
def _load():
    if not _CACHE:
        _CACHE["X"] = sparse.load_npz(INDEX_DIR / "matrix.npz")
        _CACHE["vec"] = pickle.load(open(INDEX_DIR / "vectorizer.pkl", "rb"))
        _CACHE["meta"] = json.load(open(INDEX_DIR / "meta.json"))
    return _CACHE["X"], _CACHE["vec"], _CACHE["meta"]


def retrieve(code, k=5):
    """Return top-k [(score, cwe, family, source)] for a code snippet."""
    if not (INDEX_DIR / "matrix.npz").exists():
        return []
    X, vec, meta = _load()
    q = vec.transform([_clean(code)])                  # L2-normalized
    sims = (X @ q.T).toarray().ravel()                 # cosine (rows normalized)
    idx = np.argsort(-sims)[:k]
    return [(float(sims[i]), meta[i]["cwe"], meta[i]["family"], meta[i]["source"]) for i in idx]


def flag_by_retrieval(code, threshold=0.45, min_votes=2, k=7):
    """Aggregate top-k into a single CWE flag when the corpus agrees strongly."""
    hits = retrieve(code, k=k)
    if not hits or hits[0][0] < threshold:
        return None
    from collections import Counter
    votes = Counter(h[1] for h in hits if h[0] >= threshold * 0.8)
    cwe, n = votes.most_common(1)[0]
    if n < min_votes:
        return None
    return {"cwe": cwe, "family": FAMILY(cwe), "score": round(hits[0][0], 3),
            "votes": n, "example_source": hits[0][3]}


def main():
    ap = argparse.ArgumentParser(description="Layer B: CVE-corpus retrieval flagger")
    ap.add_argument("cmd", choices=["build", "query"])
    ap.add_argument("target", nargs="?")
    ap.add_argument("--k", type=int, default=5)
    args = ap.parse_args()
    if args.cmd == "build":
        build()
        return
    import ast
    code = Path(args.target).read_text(encoding="utf-8", errors="replace")
    try:
        tree = ast.parse(code)
        fns = [(f.name, ast.get_source_segment(code, f)) for f in ast.walk(tree)
               if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef))]
    except SyntaxError:
        fns = [("<file>", code)]
    for name, src in fns:
        if not src or len(src) < 40:
            continue
        flag = flag_by_retrieval(src)
        top = retrieve(src, k=3)
        tag = f"  => RESEMBLES {flag['cwe']} (score {flag['score']}, {flag['votes']} votes)" if flag else ""
        print(f"\n{name}(){tag}")
        for score, cwe, fam, src_ in top:
            print(f"    {score:.3f}  {cwe} {fam or ''}  [{src_}]")


if __name__ == "__main__":
    main()
