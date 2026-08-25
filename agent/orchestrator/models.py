"""Shared data models for the orchestrator loop."""
from dataclasses import dataclass, field


@dataclass
class Candidate:
    """A static-discovery hit: a place worth dynamically proving. Produced by discover.py
    (SAST front-end), consumed by the exploit/oracle stages."""
    file: str
    unit: str              # enclosing function/method
    line: int
    cwe: str
    family: str
    detector: str          # "taint" | "pattern" | "xflow"
    sink: str              # the source snippet at the sink
    provable: bool         # class the dynamic sink/differential oracle can PROVE
    rank: int              # higher = triage first (precision-first ordering)
    route_hint: str = ""   # best-effort "METHOD /path" reaching this sink (from routes.py)
    slice: str = ""        # enclosing function source (feeds model translate/patch + exploit)
    resolved_from: str = ""  # if a cross-file xflow was resolved: "recv.method -> file"

    def loc(self) -> str:
        return f"{self.file}:{self.line} ({self.unit})"


@dataclass
class Finding:
    """A candidate the dynamic loop has acted on."""
    candidate: Candidate
    status: str            # "proven" | "cleared" | "deferred"
    evidence: str = ""     # e.g. the payload observed at the instrumented sink
    payload: str = ""
    patch: str = ""
    gate_a: str = ""       # exploit re-fire result at the sink
    gate_b: str = ""       # regression result (native suite | smoke | skipped)
    proven_request: dict = None  # the model-crafted request that proved the sink (for Gate A/B re-fire)
    baseline_status: int = None  # original app's benign response on that request (differential Gate B)
    notes: str = ""
