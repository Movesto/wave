# Project map

Where things live and which script produced them. 143 scripts had accumulated at the
repo root with no grouping; the code was left in place (22 modules are imported by ~100
others, so moving them would break more than it tidied) and is instead indexed here.

## Layout

```
data/                       # gitignored
  cot/
    pilot/  staging/        # the training corpus, by shape
    eval_v2/                # eval sets (primevul, tsjs, v3 matched holdout)
    dpo/                    # preference triples + cached reference log-probs
    rejected/               # builds that FAILED a hand-read. do not wire. README inside.
  runs/<version>/           # everything about one training run
    final/  best/           # adapters
    logs/                   # training + bench logs
    MANIFEST.md             # what produced it and what it scored
  eval_runs/                # bench predictions (eval_bench reads these live)
  osv/                      # manifests: every held record, with a reason
  downloads/                # upstream corpora (PrimeVul, CVEFixes, morefixes patches)
docs/                       # this file, TECHNICAL_REPORT.md, sources.txt
eval/  cot/  probes/        # importable packages
```

## Versions

| version | what it is | headline |
|---|---|---|
| v10 | prior production model | 78% acc / 19% FPR on the retired bench |
| v12.1b | prior candidate, baseline for the current gate | 8/52 real pairs, MCC 0.087, FPR 40% |
| v13 | SFT on the rebuilt corpus | 31/77 pairs — but 25/25 was one AUTHORED shape it memorized; 6/52 real, FPR 75% |
| v14 | v13 minus that shape | 7/52 real pairs, MCC 0.039 — at chance, p=0.868 vs v12.1b |
| v15_dpo | DPO on 385 contrastive pairs | in progress |

**Do not score this project on raw accuracy.** v13 read 70.1% accuracy / MCC 0.432 and
was no better than the baseline. Use pair accuracy (both sides of a contrastive pair
correct) plus the capability slices — that is the only thing that separated a
discriminator from a memorizer.

## Core modules (imported widely — treat as the API)

| module | role |
|---|---|
| `scan_ts_standard.py` | the 17 rules. `code_of` / `trace_of` / `occurs` |
| `filter_corpus.py` | `judge()` — per-record rule verdict; `is_test_code`, `load_eval_codes` |
| `build_r2vul_pairs.py` | the hardened pickers: `pick_guard`, `pick_source`, `pick_sink`, `standalone`, `record` |
| `crossfile_candidates.py` | `added_guard()` — the guard predicate for cross-file work |
| `*_vetted.py`, `cwe_disambiguation.py` | hand-vetting registries, with the refusals recorded |

## By purpose

- **corpus builders** — `build_*.py`, `harvest_*.py`, `carve_*.py`, `rebuild_*.py`
- **audits / holds** — `audit_*.py`, `hold_*.py`, `promote_*.py`, `repair_*.py`.
  Every one writes `_meta.held` plus a manifest under `data/osv/`.
- **training** — `train_qwen_cot.py` (SFT), `train_dpo_manual.py` (DPO),
  `build_dpo_pairs.py`
- **evaluation** — `eval_bench.py` (plan / run / score / compare), `eval/` package
- **tools** — `gpu_watch.py`, `watch_training.py`, `organize_runs.py`, `smoke_*.py`

## Rules worth knowing before adding data

- **R6** grounding: a trace may only name identifiers present in its excerpt.
  `occurs()` rejects member positions ON PURPOSE — do not feed it `.body` from
  `req.body.bio` and conclude the trace is ungrounded.
- **R7** boilerplate: runs on every shape. Only the <45-word test is aux-exempt.
- **R14** test code, **R15** byte-identical reasoning, **R17** one-template
  (normalised, ≤35%, only at n≥20).
- **held ≠ deleted**: `_meta.held` retires a record and the trainer skips it. Every
  hold has a reason and a manifest row, so it is reversible.
