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
# interactive shell (Claude-CLI style): banner, /setup, /sast, /dast, /both, /help
wave                       # or: python -m agent.orchestrator.run        (bare -> shell)

# one-shot (scriptable) -- everything the shell does, directly:
python -m agent.orchestrator.run discover data/downloads/VAmPI          # fast SAST, no model
python -m agent.orchestrator.run all data/downloads/VAmPI --patch       # full SAST + repair
python -m agent.orchestrator.run loop data/downloads/VAmPI --fix        # provision + prove + fix
python -m agent.orchestrator.run dast http://localhost:8080 --authorized  # black-box DAST (live URL)
```
The **interactive shell** is the default surface: run `wave` with no command to get a prompt with
slash-commands — `/setup` (model + API endpoint), `/sast [path]`, `/dast [url]`, `/both`, and
`/help [topic]`. DAST is active testing, so both the shell and the one-shot `dast` command require an
explicit authorization affirmation (`--authorized`) before any traffic is sent.
- Targets are passed as a path arg (they live in `data/downloads/`, not in this folder — they are
  test data, not code).
- Discovery defaults to the deterministic detector; add `--model-discover` to use the fast review
  model instead (a hint either way — the oracle is what proves a candidate).
- Requires Docker (WSL2) up, and the model weights cached locally. Brain: DeepSeek-R1-Distill-14B.

## Status
Walking skeleton verified end-to-end on VAmPI (SQLi proven at the instrumented sink, parameterized
patch, both gates cleared). See `docs/master_plan.md` §15 (roadmap) / §17 (build discipline).
