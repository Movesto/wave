# wave · agent

The neuro-symbolic vulnerability-discovery agent. **Self-contained**: everything it imports lives
inside this folder — no dependency reaches out to the repo root.

> **Source of truth:** [`docs/master_plan.md`](docs/master_plan.md) — the full architecture
> (two-tier verification, two operating modes, the oracle catalog, build discipline).

## Layout
```
agent/
  orchestrator/   the agent: the ReAct loop + its stages
                  run.py (CLI) · state.py (loop) · discover.py (SAST perception)
                  provision.py · exploit.py · oracle.py · registry.py (sink hooks)
                  remediate.py · auth.py · model.py · models.py · routes.py
  detector/       vendored static detector (canonical copies for the agent)
                  flag.py · local_retrieve.py · resolve.py
  docs/           the plan + design notes (master_plan.md is the live one)
```
Legacy code (scanner/, resolve.py, build_*/bench_* scripts) stays at the repo root as an archive
and is **not** used by this agent — it keeps its own copies of the detector.

## Run (from the repo root)
```
# static discovery only (fast, no model)
python -m agent.orchestrator.run discover data/downloads/VAmPI

# full loop: discover -> provision(Docker) -> craft+prove -> patch + dual-gate
python -m agent.orchestrator.run loop data/downloads/VAmPI --fix
```
- Targets are passed as a path arg (they live in `data/downloads/`, not in this folder — they are
  test data, not code).
- Discovery defaults to the deterministic detector; add `--model-discover` to use the fast review
  model instead (a hint either way — the oracle is what proves a candidate).
- Requires Docker (WSL2) up, and the model weights cached locally. Brain: DeepSeek-R1-Distill-14B.

## Status
Walking skeleton verified end-to-end on VAmPI (SQLi proven at the instrumented sink, parameterized
patch, both gates cleared). See `docs/master_plan.md` §15 (roadmap) / §17 (build discipline).
