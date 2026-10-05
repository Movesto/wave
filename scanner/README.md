# `scanner/` — LEGACY (pre-pivot SFT scanner)

**This directory is the pre-pivot architecture and is NOT the shipped tool.**

The current, authoritative system is **`agent/orchestrator`** — the `wave` CLI
(`wave = agent.orchestrator.run:main` in `pyproject.toml`). The neuro-symbolic agent
(eyes → detect → prove → patch) lives entirely under `agent/` and does **not** import
anything in `scanner/` or the pre-pivot root modules.

`scanner/` is the earlier fine-tuned-0.8B pattern-matching scanner, kept for reference.
It (and only it) still imports these four **pre-pivot root modules**:

- `guard_witness.py`
- `resolve.py`
- `safe_veto.py`
- `scan_ts_standard.py`

These are retained solely because `scanner/` imports them by bare module name; they are
not part of the agent pipeline. If `scanner/` is eventually retired, move it and those
four files to `_legacy/` (the archived-legacy convention in `.gitignore`) or delete them —
the agent will be unaffected.
