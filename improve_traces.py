"""Improve trace REASONING with a stronger model, keeping ground truth fixed.

Reads all_v8_traces.jsonl, sends each trace (optionally filtered by --tier) to a
stronger backend with a strict rewrite spec, and writes `improved_reasoning`.
Resumable (skips ids already in the output). Then run rebuild_from_improved.py.

Backend via WAVE_GENERATOR_BACKEND (anthropic / gemini / local) — must be a model
STRONGER than the one that made the traces (local gpt-oss won't improve its own
output). Usage:
  WAVE_GENERATOR_BACKEND=anthropic python improve_traces.py --tier weak,synthetic
"""
import io, json, argparse
from pathlib import Path
from cot.generator import call_generator  # existing pluggable backend dispatch

SYS = """You are a senior application-security engineer improving the REASONING of \
vulnerability-scan training traces. You are given source code, the CURRENT reasoning, \
and the VERIFIED ground truth (label + CWE) established by a patch-diff oracle.

Rewrite the reasoning to be higher quality. STRICT RULES:
1. NEVER change the verdict: the `status` must match the given label \
(vuln/confirmed for vulnerable code, safe for safe code) and `cwe` must match the \
given CWE exactly (or `none` if safe). The oracle is ground truth — do not second-guess it.
2. The <think> block: concise (3-6 steps), trace the actual data flow from source to \
sink in THIS code. No speculation ("if X were user input"), no invented CVE ids, no \
generic boilerplate, no markdown headers.
3. Then emit EXACTLY these fields, one per line, concise values only:
   status: <vuln|confirmed|safe>
   cwe: <CWE-NN or none>
   severity: <LOW|MEDIUM|HIGH|none>
   line: <the sink line number, or none>
   trace: <short source -> ... -> sink chain; arrows; no prose>
   fix: <one concrete remediation, or none if safe>
4. For SAFE code: explain WHY the control (parameterization, escaping, validation) \
neutralizes the risk. status: safe, cwe: none, no fabricated weakness.
Output ONLY the improved reasoning (<think>...</think> then the fields). No preamble."""

TMPL = """CODE:
{code}

VERIFIED GROUND TRUTH: label={label}  cwe={cwe}

CURRENT REASONING (improve this):
{cur}"""


def _iter(path):
    with io.open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default="data/cot/all_v8_traces.jsonl")
    ap.add_argument("--out", default="data/cot/all_v8_traces.improved.jsonl")
    ap.add_argument("--tier", default="weak,synthetic", help="comma tiers to improve; 'all' for everything")
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()
    tiers = None if args.tier == "all" else set(args.tier.split(","))

    done = set()
    outp = Path(args.out)
    if outp.exists():
        for r in _iter(outp):
            done.add(r["id"])
    print(f"resuming: {len(done)} already improved")

    n = 0
    with io.open(outp, "a", encoding="utf-8") as out:
        for rec in _iter(args.src):
            if tiers is not None and rec.get("tier") not in tiers:
                continue
            if rec["id"] in done:
                continue
            prompt = TMPL.format(code=rec["prompt"], label=rec.get("label"),
                                 cwe=rec.get("cwe") or "none", cur=rec["current_reasoning"])
            try:
                improved = call_generator(prompt, system=SYS).get("text", "")
            except Exception as e:
                print(f"  ERR {rec['id']}: {e}")
                continue
            if not improved.strip():
                print(f"  SKIP {rec['id']}: empty response")
                continue
            rec["improved_reasoning"] = improved.strip()
            out.write(json.dumps(rec, ensure_ascii=False) + "\n")
            out.flush()
            n += 1
            if n % 25 == 0:
                print(f"  improved {n}...")
            if args.limit and n >= args.limit:
                break
    print(f"\nDone: improved {n} traces -> {outp}")
    print("Next: merge into all_v8_traces.jsonl (or pass this file) then rebuild_from_improved.py")


if __name__ == "__main__":
    main()
