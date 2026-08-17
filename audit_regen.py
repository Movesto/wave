"""Corpus-wide quality audit of the regen output -- the checks the generation GATES do NOT do.

The gates verify grounding/verdict/leak/sink per record. This inspects the whole corpus for the
failure modes that pass those gates: a reasoning FORM creeping back (the v14 disease), corruption
tokens, thin traces, vuln sides with no concrete payload, safe sides that name no control.

  python audit_regen.py
"""
import json, os, re, sys
from collections import Counter
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

STAGING = "data/cot/staging"
FILES = ["regen_deepseek", "regen_singles", "regen_unsure", "regen_suspect"]

# corruption: unicode replacement char (�), known garbage tokens, or raw control bytes
_CORRUPT = re.compile("[�\x00-\x08\x0b\x0c\x0e-\x1f]" + r"|\bMend\b|\)Skip|quotedrop|email The ")
_PAYLOAD = re.compile(r"`[^`]*[<>'\";(){}=/\\][^`]*`|payload|attacker (supplies|sends|provides|controls|crafts)"
                      r"|such as|for example|e\.g\.|1=1|\.\./|<script|onerror|; *DROP|%2e|\\x")
_CONTROL = re.compile(r"valid|escap|saniti|check|guard|whitelist|allowlist|param|prepared|bind|token|"
                      r"middleware|encode|htmlspecial|bound|null check|permission|authorize|"
                      r"authenticated|realpath|normaliz|filter|reject|constrain", re.I)

_STOP = set("the a an is are was to of in on and or but if it that this with as at by for not no from "
            "here there where when which what does do can could would should into onto over under only "
            "so then than because since while its their they i we you he she".split())


def load(name):
    p = f"{STAGING}/{name}.jsonl"
    return [json.loads(l) for l in open(p, encoding="utf-8")] if os.path.exists(p) else []


def trace_of(r):
    return r["messages"][1]["content"]


def opening(t, n=7):
    return " ".join(re.findall(r"[A-Za-z]+", t.lower())[:n])


def skeleton(t):
    """Normalise a trace's first sentence: identifiers/quotes/numbers -> placeholders. Many traces
    sharing one signature == a reused reasoning skeleton (the v14 failure mode)."""
    first = re.split(r"(?<=[.!?])\s", t.strip(), 1)[0]
    s = re.sub(r"`[^`]*`", "X", first)
    s = re.sub(r"\"[^\"]*\"|'[^']*'", "S", s)
    s = re.sub(r"\b[A-Za-z_]\w*\b",
               lambda m: m.group(0).lower() if m.group(0).lower() in _STOP else "W", s)
    s = re.sub(r"\d+", "N", s)
    return re.sub(r"\s+", " ", s).strip()[:120]


def main():
    recs = {f: load(f) for f in FILES}
    allr = [(f, r) for f in FILES for r in recs[f]]
    train = recs["regen_deepseek"] + [r for r in recs["regen_singles"]
                                      if r["_meta"].get("single_strength") == "strong"]
    print("loaded: " + " | ".join(f"{f}={len(recs[f])}" for f in FILES))
    print(f"training-grade (keep + strong singles) = {len(train)}\n")

    print("=== reasoning-form diversity (training-grade) ===")
    ops = Counter(opening(trace_of(r)) for r in train)
    sks = Counter(skeleton(trace_of(r)) for r in train)
    to, tos = ops.most_common(1)[0], sks.most_common(1)[0]
    print(f"distinct 7-word openings          : {len(ops)}/{len(train)}  "
          f"(top covers {to[1]} = {100*to[1]//len(train)}%)")
    print(f"distinct first-sentence skeletons : {len(sks)}/{len(train)}  "
          f"(top covers {tos[1]} = {100*tos[1]//len(train)}%)")
    print("  most-repeated openings:")
    for o, c in ops.most_common(5):
        print(f"    {c:3d}x  {o}")
    print()

    flags = {"corruption": [], "too_short": [], "verdict_mismatch": [],
             "vuln_no_payload": [], "safe_no_control": []}
    for f, r in allr:
        m = r["_meta"]; t = trace_of(r); lbl = m["label"]; v = m.get("model_verdict")
        if _CORRUPT.search(t):
            flags["corruption"].append((f, m["cve"], lbl))
        if len(t) < 500:
            flags["too_short"].append((f, m["cve"], lbl, len(t)))
        if f == "regen_deepseek" and v != lbl:
            flags["verdict_mismatch"].append((f, m["cve"], lbl, v))
        if lbl == "vuln" and v == "vuln" and not _PAYLOAD.search(t):
            flags["vuln_no_payload"].append((f, m["cve"]))
        if lbl == "safe" and v == "safe" and not _CONTROL.search(t):
            flags["safe_no_control"].append((f, m["cve"]))
    print("=== per-record red flags (whole corpus) ===")
    for k, v in flags.items():
        print(f"  {k:18s}: {len(v)}")
        for item in v[:8]:
            print(f"      {item}")
    return flags


if __name__ == "__main__":
    main()
