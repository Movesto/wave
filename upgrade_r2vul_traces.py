"""Upgrade the 4,191 R2Vul shape1 records in place: replace the placeholder
`trace: see reasoning above` line with a real one-line summary extracted from
the <think> block. Fix line is upgraded similarly.

Idempotent — running twice does nothing the second time.
"""
import json
import re
import sys
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


SRC = Path("data/cot/pilot/shape1.jsonl")


def derive_trace_summary(reasoning: str, cwe: str | None, lang: str | None,
                          is_vulnerable: bool) -> str:
    if not reasoning:
        return f"{cwe or 'CWE-UNK'} in {lang or 'code'}" if is_vulnerable else "safe code pattern"
    t = re.sub(r"^[\s\d\.\)\*\-•]+", "", reasoning).strip()
    parts = re.split(r"[.!?]\s+", t, maxsplit=1)
    head = parts[0].strip() if parts else t
    if len(head) > 120:
        head = head[:117].rstrip() + "..."
    if len(head) < 20:
        return f"{cwe or 'CWE-UNK'} in {lang or 'code'}" if is_vulnerable else "safe code pattern"
    return head


def derive_fix_summary(reasoning: str, is_vulnerable: bool) -> str:
    if not is_vulnerable:
        return "none"
    if not reasoning:
        return "consult security guidance for this CWE class"
    m = re.search(
        r"([A-Z][^.!?]*?\b(fix|patch|sanitize|replace|use(?:s|d)?\s+\w+|should|must)\b[^.!?]*[.!?])",
        reasoning,
    )
    if m:
        s = m.group(1).strip()
        if len(s) <= 200:
            return s
        return s[:197].rstrip() + "..."
    return "remediate at the dangerous sink (see reasoning for details)"


def upgrade_assistant(asst: str, meta: dict) -> tuple[str, bool]:
    """Return (new_assistant, changed). Only modifies records where trace is
    a placeholder. Returns (asst, False) if no change needed."""
    # Find the <think> block content
    think_m = re.search(r"<think>(.*?)</think>", asst, re.DOTALL | re.IGNORECASE)
    if not think_m:
        return asst, False
    reasoning = think_m.group(1).strip()

    # Identify CWE + lang + vuln from meta
    cwes = meta.get("cwes") or []
    cwe = cwes[0] if cwes else meta.get("ground_truth_cwe")
    lang = meta.get("language")
    label = meta.get("label")
    is_vuln = label == "vuln"

    # Find current trace line
    trace_m = re.search(r"^trace\s*:\s*(.*)$", asst, re.MULTILINE | re.IGNORECASE)
    fix_m = re.search(r"^fix\s*:\s*(.*)$", asst, re.MULTILINE | re.IGNORECASE)
    if not trace_m:
        return asst, False

    current_trace = trace_m.group(1).strip().lower()
    if "see reasoning" not in current_trace:
        return asst, False  # already non-placeholder, leave alone

    new_trace = derive_trace_summary(reasoning, cwe, lang, is_vuln)
    # Use lambda to bypass re.sub's backslash interpretation in repl strings
    out = re.sub(
        r"^trace\s*:.*$",
        lambda _m: f"trace: {new_trace}",
        asst, count=1, flags=re.MULTILINE | re.IGNORECASE,
    )

    # Upgrade fix too if it's a placeholder
    if fix_m:
        current_fix = fix_m.group(1).strip().lower()
        if "see reasoning" in current_fix or "do not include patches" in current_fix:
            new_fix = derive_fix_summary(reasoning, is_vuln)
            out = re.sub(
                r"^fix\s*:.*$",
                lambda _m: f"fix: {new_fix}",
                out, count=1, flags=re.MULTILINE | re.IGNORECASE,
            )

    return out, True


def main():
    if not SRC.exists():
        print(f"ERROR: {SRC} not found")
        sys.exit(1)

    print(f"Reading {SRC}...")
    lines = SRC.read_text(encoding="utf-8").splitlines()
    print(f"  {len(lines)} records")

    upgraded = 0
    skipped = 0
    out_lines = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            out_lines.append(line)
            continue
        meta = rec.get("_meta") or {}
        if meta.get("source") != "r2vul":
            out_lines.append(line)
            skipped += 1
            continue
        msgs = rec.get("messages") or []
        if len(msgs) < 2:
            out_lines.append(line)
            continue
        new_asst, changed = upgrade_assistant(msgs[1].get("content", ""), meta)
        if changed:
            msgs[1]["content"] = new_asst
            rec["messages"] = msgs
            upgraded += 1
        out_lines.append(json.dumps(rec, ensure_ascii=False))

    print(f"\nUpgraded {upgraded} R2Vul records")
    print(f"Skipped (non-r2vul or already non-placeholder): {skipped} + {len(lines) - upgraded - skipped}")

    backup = SRC.with_suffix(SRC.suffix + ".pre_upgrade.bak")
    if not backup.exists():
        backup.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"Backup written to {backup}")

    SRC.write_text("\n".join(out_lines) + "\n", encoding="utf-8")
    print(f"Wrote {SRC}")


if __name__ == "__main__":
    main()
