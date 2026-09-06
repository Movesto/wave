# wave tests

Run everything (fast, deterministic — no GPU, docker, model, or network):

```
pytest tests/ -q
```

## Files

- **`test_orchestrator_regression.py`** — the Stage 1–4 + gates regression net. ~55 assertions across the
  orchestrator: value taint, the rung1 canary observer (cmd/path/ssrf/sqli/nosqli), reachability + frontend
  context gates, detector verdict parse, proof-mode routing, prove wiring (`_to_candidate`/`_apply_gate`),
  repomap class pins + frontend suppression, investigate grounding/context-discipline helpers, provisioning
  classify + the 404-is-up probe fix, and web search/read degrade. Each assertion captures a behaviour that
  was verified once by hand and would otherwise silently rot on a future edit.
- **`test_pipeline.py`** — the older data-quality (`cot/`) pipeline: sink classifier, CWE contracts,
  template reason, postprocess.
- **`test_oracle_gates.py`** — the `cot/` oracle gates (localization / cwe / correspondence / substantiveness).
  Script-style (asserts at import); the `sys.exit` is guarded so pytest can collect the directory.

## What this suite does NOT cover

Anything needing a GPU, docker, or the network: the model actually driving a brief to a witnessed effect
(SSTI/deser/proto-pollution/XSS), a real container boot, real patch generation, and the GHSA benchmark.
Those stay manual / integration checks — run them explicitly (`run all`, `ghsa_bench`) when relevant.
