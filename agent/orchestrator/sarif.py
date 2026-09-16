"""Export wave findings as SARIF 2.1.0 -- the standard static-analysis result format.

SARIF is what GitHub code scanning, the VS Code SARIF viewer, and most CI security dashboards consume. Emitting
it lets a wave run drop straight into an existing security workflow instead of living only in a Markdown report.
Deterministic (no model). Each finding -> a `result`; each CWE -> a `rule` (name + remediation + MITRE helpUri);
severity -> SARIF level (critical/high=error, medium=warning, else note); the wave verdict is kept as a property.
"""
from __future__ import annotations

import json
from pathlib import Path

from . import cwe_info

# only actionable findings go in SARIF; refuted/blocked are not results (kept out or a run gets noisy)
_INCLUDE = {"confirmed", "anomalous_state", "believed"}
_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "unknown": "note"}
_KIND = {"confirmed": "confirmed (tool-witnessed)", "anomalous_state": "needs review (observed effect)",
         "believed": "unproven lead (reasoned)"}


def _rel(path, root):
    try:
        return str(Path(path).resolve().relative_to(Path(root).resolve())).replace("\\", "/")
    except Exception:
        return str(path).replace("\\", "/")


def to_sarif(findings, root=".", tool_version="0.1"):
    """Build a SARIF 2.1.0 document (a dict) from wave findings."""
    rules, rule_index = [], {}
    results = []
    for f in findings:
        if f.get("verdict") not in _INCLUDE:
            continue
        cwe = (f.get("cwe") or "").upper().strip()
        name, sev, remediation = cwe_info.describe(cwe, f.get("class", ""))
        rule_id = cwe or ("wave-" + (f.get("class") or "other"))
        if rule_id not in rule_index:
            rule_index[rule_id] = len(rules)
            rule = {
                "id": rule_id, "name": name.replace(" ", ""),
                "shortDescription": {"text": name},
                "fullDescription": {"text": f"{name}. {remediation}"},
                "help": {"text": remediation},
                "defaultConfiguration": {"level": _LEVEL.get(sev, "note")},
                "properties": {"security-severity": {"critical": "9.0", "high": "8.0", "medium": "5.0",
                                                     "low": "3.0", "unknown": "0.0"}.get(sev, "0.0"),
                               "tags": ["security", "external/cwe/" + rule_id.lower()]},
            }
            if cwe.startswith("CWE-") and cwe[4:].isdigit():
                rule["helpUri"] = f"https://cwe.mitre.org/data/definitions/{cwe[4:]}.html"
            rules.append(rule)
        ev = (f.get("evidence") or f.get("why") or "").strip()
        text = f"{name} in {f.get('unit') or 'this location'}."
        if ev:
            text += f" {ev[:400]}"
        text += f" [{_KIND.get(f.get('verdict'), f.get('verdict'))}] Fix: {remediation}"
        results.append({
            "ruleId": rule_id, "ruleIndex": rule_index[rule_id],
            "level": _LEVEL.get(sev, "note"),
            "message": {"text": text},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": _rel(f.get("file", ""), root)},
                "region": {"startLine": max(1, int(f.get("line") or 1))}}}],
            "properties": {"verdict": f.get("verdict"), "class": f.get("class"),
                           "oracle": f.get("oracle", ""), "wave-severity": sev},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "wave", "informationUri": "https://github.com/wave",
                                "version": tool_version, "rules": rules}},
            "results": results,
        }],
    }


def write(findings, out_path, root="."):
    doc = to_sarif(findings, root=root)
    Path(out_path).write_text(json.dumps(doc, indent=2), encoding="utf-8")
    return len(doc["runs"][0]["results"])
