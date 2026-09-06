"""Local cross-file symbol retrieval -- the inference-time tool the agent loop calls when it
says "I need to see function X". The generation pipeline fetched missing code from GitHub
(resolve.py); at inference the target project is on disk, so we walk it and pull the definition.

This is the piece that lets the model follow a multi-file flow in the user's OWN code: reason ->
realise the sink is in an unseen helper -> retrieve it -> conclude.

  from scanner.local_retrieve import resolve_local
  hit = resolve_local("/path/to/project", "runScheduledRefresh")
  # -> {"symbol":..., "path": "src/gateway.ts", "snippet": "<def>"} or None
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from resolve import extract_def          # reuse the brace/indent definition-block extractor

SRC_EXT = {".py", ".js", ".ts", ".jsx", ".tsx", ".vue", ".go", ".rb", ".php", ".java",
           ".c", ".h", ".cc", ".cpp", ".hpp", ".cs", ".rs", ".kt", ".scala", ".swift"}
SKIP_DIR = {".git", "node_modules", "venv", ".venv", "env", "__pycache__", "dist", "build",
            ".next", "vendor", "target", ".gradle", "out", "bin", "obj", ".idea", "coverage"}


def _iter_files(root, max_files=8000):
    n = 0
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in SKIP_DIR and not d.startswith(".")]
        for fn in fns:
            if os.path.splitext(fn)[1].lower() in SRC_EXT:
                yield os.path.join(dp, fn)
                n += 1
                if n >= max_files:
                    return


def resolve_local(root, symbol, exclude_path=None, max_files=8000):
    """Find `symbol`'s definition in the project on disk. Returns {symbol, path, snippet} or None.
    Cheap prefilter: only parse files whose text contains the symbol. Skips exclude_path (the file
    the model is already looking at) so it retrieves the OTHER file, not the current one."""
    if not symbol or not root or not os.path.isdir(root):
        return None
    exc = os.path.abspath(exclude_path) if exclude_path else None
    best = None
    for path in _iter_files(root, max_files):
        if exc and os.path.abspath(path) == exc:
            continue
        try:
            txt = open(path, encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        if symbol not in txt:
            continue
        snip = extract_def(txt, symbol)
        if snip:
            return {"symbol": symbol, "path": os.path.relpath(path, root), "snippet": snip}
        if best is None:                 # symbol appears but no clean def block -> remember as fallback
            best = path
    return None


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Find a symbol's definition in a project")
    ap.add_argument("root")
    ap.add_argument("symbol")
    args = ap.parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    hit = resolve_local(args.root, args.symbol)
    if hit:
        print(f"{args.symbol}  <-  {hit['path']}\n{'-'*50}\n{hit['snippet']}")
    else:
        print(f"'{args.symbol}' not resolved in {args.root}")
