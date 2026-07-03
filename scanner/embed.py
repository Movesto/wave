"""Layer B (neural) — semantic code embedder for CVE-corpus retrieval.

Upgrades retrieve.py's surface-level TF-IDF to SEMANTIC similarity: two snippets
that are vulnerable in the same way score high even with different variable names /
formatting. This is what turns Layer B from an "evidence net" into a real recall
engine (the moat vs Semgrep).

CPU-only (no GPU — the 8B owns the GPU). Uses a small HF encoder via mean-pooling;
no sentence-transformers dependency. The index is built once and cached on disk.

  python embed.py build            # embed the CVE corpus (once, ~few min CPU)
  python embed.py query app.py     # semantic nearest known-vuln matches
"""
import io, json, glob, re, os, sys, argparse
from pathlib import Path
import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
INDEX_DIR = Path(__file__).parent / "index"
CORPUS_GLOB = os.path.join(ROOT, "data", "cot", "pilot_clean", "*.jsonl")
# small, CPU-friendly encoder; override with WAVE_EMBED_MODEL
MODEL = os.environ.get("WAVE_EMBED_MODEL", "sentence-transformers/all-MiniLM-L6-v2")
_SCAN = re.compile(r"</?SCAN>")

try:
    from cot.cwe_contracts import family_of as FAMILY
except Exception:
    FAMILY = lambda c: None

_M = {}


def _clean(code):
    return _SCAN.sub("", code).strip()[:1200]      # cap for the encoder window


def _encoder():
    if not _M:
        import torch
        from transformers import AutoTokenizer, AutoModel
        _M["tok"] = AutoTokenizer.from_pretrained(MODEL)
        _M["model"] = AutoModel.from_pretrained(MODEL).eval()   # CPU
        _M["torch"] = torch
    return _M["tok"], _M["model"], _M["torch"]


def embed(texts, batch=32):
    tok, model, torch = _encoder()
    vecs = []
    for i in range(0, len(texts), batch):
        chunk = texts[i:i + batch]
        enc = tok(chunk, padding=True, truncation=True, max_length=256, return_tensors="pt")
        with torch.no_grad():
            out = model(**enc)
        # mean-pool over tokens with the attention mask
        mask = enc["attention_mask"].unsqueeze(-1).float()
        summed = (out.last_hidden_state * mask).sum(1)
        counts = mask.sum(1).clamp(min=1e-9)
        emb = (summed / counts).cpu().numpy()
        emb /= (np.linalg.norm(emb, axis=1, keepdims=True) + 1e-9)   # L2 normalize
        vecs.append(emb.astype("float32"))
    return np.vstack(vecs) if vecs else np.zeros((0, 384), "float32")


def build(max_docs=23500):
    codes, meta, seen = [], [], set()
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
    print(f"embedding {len(codes)} snippets with {MODEL} (CPU)...")
    emb = embed(codes)
    INDEX_DIR.mkdir(parents=True, exist_ok=True)
    np.save(INDEX_DIR / "neural_emb.npy", emb)
    json.dump({"model": MODEL, "meta": meta}, open(INDEX_DIR / "neural_meta.json", "w"))
    print(f"neural index: {emb.shape} -> {INDEX_DIR}/neural_emb.npy")


_IDX = {}
def _load():
    if not _IDX:
        self_ = INDEX_DIR / "neural_emb.npy"
        _IDX["emb"] = np.load(self_)
        d = json.load(open(INDEX_DIR / "neural_meta.json"))
        _IDX["meta"] = d["meta"]
    return _IDX["emb"], _IDX["meta"]


def retrieve(code, k=5):
    if not (INDEX_DIR / "neural_emb.npy").exists():
        return []
    emb, meta = _load()
    q = embed([_clean(code)])
    if q.shape[0] == 0:
        return []
    sims = emb @ q[0]                              # cosine (both normalized)
    idx = np.argsort(-sims)[:k]
    return [(float(sims[i]), meta[i]["cwe"], meta[i]["family"], meta[i]["source"]) for i in idx]


def flag_by_retrieval(code, threshold=0.62, min_votes=2, k=7):
    hits = retrieve(code, k=k)
    if not hits or hits[0][0] < threshold:
        return None
    from collections import Counter
    votes = Counter(h[1] for h in hits if h[0] >= threshold * 0.9)
    if not votes:
        return None
    cwe, n = votes.most_common(1)[0]
    if n < min_votes:
        return None
    return {"cwe": cwe, "family": FAMILY(cwe), "score": round(hits[0][0], 3),
            "votes": n, "example_source": hits[0][3]}


def main():
    ap = argparse.ArgumentParser(description="Layer B neural: semantic CVE-corpus retrieval")
    ap.add_argument("cmd", choices=["build", "query"])
    ap.add_argument("target", nargs="?")
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
