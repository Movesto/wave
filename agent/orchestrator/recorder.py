"""The Recorder -- the investigation's memory (the Case File). Phase 1 of the investigation-loop plan
(agent/docs/investigation_loop_plan.md).

A persistent, structured, provenanced, revisable record of an investigation -- the single source of
truth the brain (model) consults instead of re-deriving. The body writes here; later phases (Reader,
Architect, Editor, the confirmation ladder) read and extend it.

INVARIANT (the one that must never break): a hypothesis is NOT a finding. Every entry carries a
`status`, and only `confirmed` entries back a reported finding:
  - believed   -- the model's / seed's reading; a lead, not proof.
  - confirmed  -- a demonstration at a ladder rung (sink fired, differential flipped, path proven).
  - refuted    -- proven SAFE (first-class value: clearing noise is what makes the tool trustworthy).
  - blocked    -- cannot be confirmed because the body lacks a real artifact (DB seed, config, device).

Entries are append-only and versioned: a later assertion SUPERSEDES an earlier one (the old is kept,
marked superseded) rather than overwriting it -- so an early wrong belief leaves an audit trail.
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from itertools import count

KINDS = ("file_summary", "route", "dataflow_edge", "entity", "control",
         "hypothesis", "evidence", "confirmation", "blocked")
SOURCES = ("seed", "tool", "model", "oracle")
STATUSES = ("believed", "confirmed", "refuted", "blocked")


@dataclass
class Entry:
    id: int
    kind: str                       # one of KINDS
    subject: str                    # stable key: WHAT this is about (a route, a file, a candidate, an entity)
    source: str                     # who asserted it (SOURCES)
    status: str                     # believed | confirmed | refuted | blocked
    provenance: str = ""            # file:line, or the request that demonstrated it
    data: dict = field(default_factory=dict)
    version: int = 1
    supersedes: int | None = None
    superseded: bool = False
    ts: float = field(default_factory=time.time)


class CaseFile:
    """The investigation record. Append via record(); read via the query helpers; render via report()."""

    def __init__(self, target: str = ""):
        self.target = target
        self._entries: list[Entry] = []
        self._id = count(1)

    # ---- write ----
    def record(self, kind, subject, source, status, provenance="", supersedes=None, **data) -> Entry:
        if kind not in KINDS:
            raise ValueError(f"unknown kind {kind!r}")
        if source not in SOURCES:
            raise ValueError(f"unknown source {source!r}")
        if status not in STATUSES:
            raise ValueError(f"unknown status {status!r}")
        version = 1
        if supersedes is not None:
            old = self.get(supersedes)
            if old is not None:
                old.superseded = True
                version = old.version + 1
        e = Entry(id=next(self._id), kind=kind, subject=str(subject), source=source, status=status,
                  provenance=provenance, data=dict(data), version=version, supersedes=supersedes)
        self._entries.append(e)
        return e

    def supersede(self, old_id, status=None, **data) -> Entry:
        """Revise an earlier entry -- same kind/subject/source, new status/data, old kept + marked."""
        old = self.get(old_id)
        if old is None:
            raise ValueError(f"no entry {old_id}")
        return self.record(old.kind, old.subject, old.source, status or old.status,
                           provenance=old.provenance, supersedes=old_id, **({**old.data, **data}))

    # ---- read ----
    def get(self, entry_id) -> Entry | None:
        return next((e for e in self._entries if e.id == entry_id), None)

    def all(self, include_superseded=False):
        return [e for e in self._entries if include_superseded or not e.superseded]

    def about(self, subject, include_superseded=False):
        return [e for e in self.all(include_superseded) if e.subject == subject]

    def by_kind(self, kind, include_superseded=False):
        return [e for e in self.all(include_superseded) if e.kind == kind]

    def by_status(self, status, include_superseded=False):
        return [e for e in self.all(include_superseded) if e.status == status]

    def hypotheses(self):
        return self.by_kind("hypothesis")

    def confirmed(self):
        """All confirmed-status entries -- includes structural FACTS (routes, dataflow), not just findings."""
        return self.by_status("confirmed")

    def findings(self):
        """Confirmed VULNERABILITY demonstrations -- confirmed status AND confirmation kind (not facts)."""
        return [e for e in self.by_status("confirmed") if e.kind == "confirmation"]

    def refuted(self):
        return self.by_status("refuted")

    def blocked(self):
        return self.by_status("blocked")

    def counts(self):
        return {s: len(self.by_status(s)) for s in STATUSES}

    # ---- persistence ----
    def save(self, path):
        payload = {"target": self.target, "entries": [asdict(e) for e in self._entries]}
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

    @classmethod
    def load(cls, path):
        with open(path, encoding="utf-8") as f:
            payload = json.load(f)
        cf = cls(payload.get("target", ""))
        cf._entries = [Entry(**d) for d in payload.get("entries", [])]
        if cf._entries:
            cf._id = count(max(e.id for e in cf._entries) + 1)
        return cf

    # ---- the human-readable report (the §7 artifact) ----
    def report(self) -> str:
        c = self.counts()
        lines = [f"# Investigation report -- {self.target or '<target>'}",
                 "  ".join(f"{s}={c[s]}" for s in STATUSES),
                 f"({len(self.by_kind('route'))} routes mapped, {len(self.hypotheses())} hypotheses)",
                 ""]
        for status, header, kinds in (
            ("confirmed", "CONFIRMED (findings)", ("confirmation",)),
            ("blocked", "BLOCKED (needs an artifact)", ("blocked", "hypothesis")),
            ("believed", "OPEN HYPOTHESES (not yet confirmed)", ("hypothesis",)),
            ("refuted", "REFUTED (cleared as safe)", ("hypothesis", "confirmation")),
        ):
            es = [e for e in self.by_status(status) if e.kind in kinds]
            if not es:
                continue
            lines.append(f"## {header}  [{len(es)}]")
            for e in es:
                cwe = e.data.get("cwe", "")
                note = e.data.get("evidence") or e.data.get("note") or ""
                tag = f"[{cwe}] " if cwe else ""
                lines.append(f"  - {tag}{e.subject}  ({e.provenance})" + (f"  -- {note}" if note else ""))
            lines.append("")
        return "\n".join(lines)
