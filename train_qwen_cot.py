"""QLoRA fine-tune Qwen3-8B on the CoT pilot data (shape1..shape4).

Differences vs train_qwen_sft.py:
  - 4-bit nf4 quantization (Qwen3-8B fp16 = 16 GB, doesn't fit with optimizer state)
  - Excludes eval records by hashing user-content against data/cot/eval/*.jsonl
  - Weighted sampling so shape2/3/4 are not drowned by shape1's 4k records
  - Loss masked to assistant tokens only (don't waste capacity learning the prompt)
  - max_len 2048 (shape4 multi-finding output needs the room)
  - Gradient checkpointing on (slower but lets the 8B model breathe in 16 GB VRAM)

Usage:
  python train_qwen_cot.py
"""
import hashlib
import json
import math
import os
import random
import time
from pathlib import Path

import torch
from torch.utils.data import Dataset, DataLoader, WeightedRandomSampler
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training


# ---- config ----
CONFIG = {
    # Model + output dirs are env-overridable so we can train a different student
    # (e.g. DeepSeek-R1-Distill-Qwen-14B) without disturbing the 8B setup.
    "model_name":      os.environ.get("WAVE_MODEL_NAME", "Qwen/Qwen3-8B"),
    "pilot_dir":       Path(os.environ.get("WAVE_PILOT_DIR", "data/cot/pilot")),
    # The 369-record bench in data/cot/eval is RETIRED -- 42 of ~1,600 records
    # carried any provenance, so it could not tell an improved model from data
    # that did not work. eval_v2 is standard-built and repo-disjoint from training.
    "eval_dir":        Path(os.environ.get("WAVE_EVAL_DIR", "data/cot/eval_v2")),
    "output_dir":      Path(os.environ.get("WAVE_OUTPUT_DIR", "data/qwen_cot")),
    "best_dir":        Path(os.environ.get("WAVE_BEST_DIR", "data/qwen_cot_best")),

    "shapes":          ["shape2", "shape2_decidable",
                        "shape3", "shape4",
                        # HELD ENTIRELY as unattested verdicts (2026-07-31):
                        #   shape1_ts, shape1_ts_safe, shape1_react, shape1_react_safe,
                        #   shape1_unique.
                        # Each claimed vuln/safe with no CVE and no in-excerpt basis,
                        # and their CWEs came from `upstream_dataset`, which agreed with
                        # OSV advisories only 28% of the time. shape1_verified* keep
                        # only their CVE-carrying records (110 of 846).
                        "shape1_verified", "shape1_verified_safe",
                        "shape3_codeql_localize",
                        "shape1_localize", "shape1_fixgen",
                        # HELD, so unwired (records keep a `held` reason + manifest):
                        #  shape_react_syn -- synthetic; 100% on itself, 41.2% on real
                        #    react. It does not transfer and real react data now exists.
                        #  shape3_crossfile_pairs -- carved as line windows and narrated
                        #    with the commit's CWE. 17 of 38 pairs name a sink that is
                        #    not in the excerpt; most of the rest name `elif`, `main` or
                        #    a class as the "sink". It was weighted 8.0.
                        # --- standard-built sets (2026-07-30) --------------------
                        # Every one passes scan_ts_standard.py at 9/9 (or 15/15 for
                        # the augmentation set) and is repo-disjoint from eval_v2.
                        # `shape1_contrastive_ts` was REMOVED: it was listed with
                        # weight 2.0 for a file that does not exist, so the carve it
                        # named silently contributed nothing.
                        "shape1_contrastive_ts_osv", "shape1_contrastive_js_osv",
                        "shape1_ts_augment_edits",
                        # shape_completeness_js unwired 2026-08-01: it held exactly ONE
                        # pair and that pair went to the eval_v3 holdout, so the shape is
                        # now empty. The file is kept; if more JS completeness pairs are
                        # ever built it can be rewired.
                        "shape1_contrastive_r2vul", "shape_restructure_r2vul",
                        "shape1_contrastive_attested",
                        "shape1_wave3_attested", "shape1_contrastive_react_osv",
                        "shape_completeness_osv", "shape_counterexample_augment",
                        "shape_crossfile_import",
                        # shape_codeql_contrastive HELD 2026-08-02: v13 scored 25/25
                        # on it (MCC 1.000) while below chance elsewhere, and FPR on
                        # real safe code went 40%->75%. Its safe side was AUTHORED, so
                        # the model memorized the inserted guard string instead of
                        # reading the flow. Do not rewire without REAL post-fix guards.
                        "shape1_r2vul_clean",
                        # REGEN 2026-08-17: teaching-quality reasoning REGENERATED from real
                        # CVE patches (vulnrichment<->morefixes bridge), distribution-matched to
                        # fill the authz/CSRF/XSS + multi-file gaps v14 lacked. DeepSeek-authored,
                        # honest-verdict prompt (no templated form: 485/485 unique skeletons),
                        # two-pass cross-file retrieval, gated + corpus-audited. These are the
                        # high-value discrimination signal; the r2vul/localize shapes below are
                        # down-weighted so this leads. regen_deepseek = 154 contrastive PAIRS;
                        # regen_singles_strong = 176 single sides where the model discriminated
                        # (partner out-of-view); regen_singles_weak = 234 detection-only (low wt).
                        "regen_deepseek", "regen_singles_strong", "regen_singles_weak"],
    # Effective sampling weight per shape. shape1 has ~4k records, the others
    # ~170-300. With weights [1,4,4,4] each minibatch sees roughly equal
    # representation despite the 14x raw imbalance. shape1_ts is now vuln-only;
    # its safe counterpart comes from shape1_ts_safe (and react likewise), so
    # together they restore the safe:vuln balance the FPR metric needs.
    # shape2 lowered 4.0->2.0: it has only ~88 unique snippets after dedup, so a
    # high weight would just memorize them. shape3/4 keep 4.0 (more diverse / small).
    "shape_weights":   {"shape1_unique": 1.0, "shape2": 2.0, "shape3": 4.0, "shape4": 4.0,
                        # shape2 is 100% `needs_context`, so on its own it teaches
                        # "unseen import => withhold". shape2_decidable is the mined
                        # counter-case: attested records where an import IS unresolved
                        # and the flow is still fully visible, so the verdict stands.
                        # Weighted with shape2 -- the pair only works if both are seen.
                        "shape2_decidable": 4.0,
                        "shape1_ts": 1.0, "shape1_react": 3.0,
                        "shape1_ts_safe": 1.5, "shape1_react_safe": 3.0,
                        "shape1_verified": 2.0, "shape1_verified_safe": 2.0,
                        # shape1_r2vul_ml and shape1_r2vul_valtest are RETIRED as
                        # DUPLICATES. 81% of their records are byte-identical in code AND
                        # trace to shape1_r2vul_clean -- 11,389 records the model would
                        # otherwise see twice, once rebuilt with provenance and a resolved
                        # CWE and once without. Between them they were 28.8% of training
                        # for data already present in cleaner form.
                        #
                        # Their unique 19% is not a loss: only 18% of it passes the filter,
                        # because it is largely what finalize_r2vul dropped on purpose
                        # (oversize excerpts, no resolvable CWE, claims naming absent code,
                        # test files). Re-adding it through the back door would undo that.
                        # shape1_wave3_other + _jsts (6,275 records) are RETIRED. Their
                        # CWEs came from the same classifier as shape1_contrastive's
                        # (19.7% agreement with CISA/OSV) and 51% of their traces carry
                        # the blocklisted template. Rebuilt from the recovered patches
                        # as shape1_wave3_attested below -- only 7 pairs survive, because
                        # a multi-file commit's CVE-level CWE cannot be trusted to
                        # describe the single hunk we pick from it.
                        "shape1_wave3_attested": 6.0,
                        # React from OSV advisories, hand-vetted. Small, but it is the
                        # only REAL react contrastive data with authoritative CWEs --
                        # react regressed in v12.1b and its existing volume is 600
                        # synthetic records measured not to transfer.
                        "shape1_contrastive_react_osv": 8.0,
                        # shape1_cvefixes (3,349 records) is HELD, not shipped. 2,899 of
                        # them -- 86.6% -- share ONE byte-identical <think> body that names
                        # nothing ("Untrusted input is present, but it does not reach a
                        # dangerous sink unguarded"), which R15 now catches. Zero safe
                        # records carry a CWE, and provenance is unrecoverable: only 0.4%
                        # match the patch corpus, because CVEFixes.csv here is
                        # `code,language,safety` with no repo/sha/cve columns. There is
                        # nothing to resolve a label from, so it cannot be repaired the
                        # way wave3 and contrastive were.
                        # shape1_fixjs (1,028) and shape1_cvefixpairs (18) are HELD.
                        # fixjs fails R7 on 100% of its records -- every trace carries a
                        # blocklisted template -- and cvefixpairs on 72%. I reported
                        # fixjs as "eliminated" when the FILTER dropped it and then left
                        # it in the shape list, so it was still training at 2.3%.
                        # shape1_sft (18,543 records) is HELD, not shipped -- the largest
                        # single block in the corpus and the least verifiable.
                        #
                        # It is generated, not harvested: kaggle_vuln_pairs (15,178) is
                        # textbook demo code (`String userInput = "admin'; DROP TABLE
                        # users; --"`), and there is no repo, sha or CVE anywhere in the
                        # shape, so no label can ever be checked. `language` is None on
                        # every record.
                        #
                        # The decisive measurement: all 8,010 safe records carry the SAME
                        # sentence, "The code applies a control: the untrusted input is
                        # validated/neutralized before any sink" -- and 6,208 of them
                        # (77.5%) contain no control-like construct at all. `def
                        # fibonacci(n)` is labelled safe on those grounds. That is not a
                        # weak trace, it is a false one, asserted 8,010 times.
                        #
                        # R15 catches it now (8,010 identical vs a cap of 927). Synthetic
                        # data also does not transfer here: shape_react_syn scored 100%
                        # while real react scored 41.2% in the same eval.
                        # shape3_codeql (verdict, 8,938 records, 100% VULNERABLE) is
                        # RETIRED and replaced by its localization form. As a verdict
                        # task it was unfalsifiable -- an always-say-vuln stub scores
                        # 100% -- and at 16.7% of sampling it was the largest source of
                        # the "cross-file shape => vuln" shortcut. Balancing it needed
                        # safe cross-file records and that pool is exhausted (600 python
                        # commits -> 2 pairs, 881 javascript -> 0). Asked "where does the
                        # tainted value reach a sink" the same records are sound: every
                        # one has an answer and no verdict bias is learnable.
                        # Weight 2.0 -> 1.0. It is a CAPABILITY supplement, not a verdict
                        # teacher: single-sided, so it cannot teach guard discrimination at
                        # all, and its `why` states that a flow exists without saying why
                        # the sink is dangerous. At 2.0 it was the second-largest share of
                        # training (18.1%) for a shape that answers a different question
                        # from the one the project exists to answer.
                        #
                        # It stays because it is essentially our ONLY interprocedural data:
                        # 99.8% of it is multi-file, against ~14% of the TS/JS pairs and
                        # 0% of everything else. A CVE fix diff is one function, so the
                        # paired sets structurally cannot cover cross-file flow.
                        "shape3_codeql_localize": 0.5,   # REGEN: down-weighted (localization drill)
                        # shape1_contrastive (7,334 pairs) is RETIRED. Its CWEs are
                        # ALL classifier-derived and agree with CISA/OSV on only 19.7%
                        # of 3,215 checked records -- CWE-78 on SSRF fixes, CWE-22 on
                        # SQL injection. It carries no provenance, so nothing can be
                        # re-checked. At 23% of sampling it was teaching wrong CWE
                        # assignment to a fifth of every batch. Its rebuilt, attested
                        # replacement is shape1_contrastive_attested below; the 1,304
                        # pairs whose labels could not be resolved are HELD, not shipped.
                        # --- standard-built sets (2026-07-30) --------------------
                        # Weighted by SIGNAL DENSITY, not size. The small shapes are
                        # the only records in the corpus that break "guard present =>
                        # safe": shape_completeness_js is a guard that is present,
                        # correct, tied to a real CVE, and still exploitable; the
                        # restructure shapes are fixes that REMOVE the dangerous
                        # construct rather than guard it. Those two classes are the
                        # whole point, and there are 12 pairs of them, so they need
                        # the highest weights in the file to be seen at all.
                        "shape_completeness_js": 12.0,
                        # Guard PRESENT in the vulnerable side and insufficient, with the
                        # reason readable from the diff: a string prefix is not a path
                        # prefix, EscapeUriString preserves reserved characters, a CSRF
                        # token scoped to the wrong action, a sanitiser called on the
                        # wrong variable. This is the class the project exists to teach
                        # and it was 1 pair.
                        "shape_completeness_osv": 12.0,
                        # Authored counterexamples: the SAFE side is untouched real
                        # post-fix code, the VULN side is that same code with one guard
                        # weakened in a way an actual CVE was weakened. Passes 16/16 --
                        # R3/R8/R9/R13 all apply because the base is real.
                        "shape_counterexample_augment": 10.0,
                        # The ONLY verified cross-file contrastive pairs (7). The call
                        # edge is proven by a RESOLVED IMPORT, not by name matching --
                        # four earlier constructions failed because "A mentions a name
                        # B defines" is not a call edge in OO code (WordPress siblings
                        # calling parent::method). Caller is byte-identical on both
                        # sides, so the verdict cannot be read off it; only the callee
                        # in the other file differs. 7/7 passed a hand-read.
                        # Weighted high because it is the sole counterweight to
                        # shape3_codeql_localize being 100% vuln at 17% of sampling --
                        # but 7 pairs cannot carry that on their own, so the cross-file
                        # eval is the real deliverable, not this weight.
                        "shape_crossfile_import": 10.0,
                        # 137 cross-file pairs carved from shape3_codeql_localize, which
                        # is 19% of sampling and 100% VULNERABLE -- nothing in it can be
                        # wrong, so an always-say-vuln stub scores perfectly on it. These
                        # give that block a safe side: same two files, same flow, with a
                        # guard placed on the value that actually reaches the sink.
                        # The safe side is AUTHORED (these records carry no commit), so
                        # they are B-grade -- they claim "this control closes this path",
                        # which is checkable from the excerpt, not "this is how it was
                        # fixed upstream". Only CWE-22/78/601/918 are built: for CWE-89
                        # the sink variable is the whole statement, for CWE-1333 it is
                        # the pattern rather than the subject, and for CWE-79 it is a
                        # property name -- all three produced fixes that were wrong, and
                        # were dropped on a hand-read rather than shipped.
                        "shape_codeql_contrastive": 6.0,
                        "shape_restructure_r2vul": 2.0,   # REGEN: down 10->2 (templated r2vul)
                        # shape_restructure_contrastive is NOT listed: it FAILS R4
                        # (no CVE resolvable for any of its 4 pairs) and its source is
                        # degenerate -- `verify` picked out of the construct
                        # `verify=False`, so source and sink share a token. It was wired
                        # at weight 10.0 while failing the standard, which is exactly what
                        # "nothing trains until it meets the standard" forbids.
                        # Hand-authored partial-fix pairs (guard present but does not
                        # cover the path) -- same class, slightly larger.
                        "shape1_ts_augment_edits": 8.0,
                        # Harvested contrastive pairs, provenance + authoritative CWE.
                        # TS stays highest: it is the language at MCC 0.000.
                        "shape1_contrastive_ts_osv": 6.0,
                        "shape1_contrastive_js_osv": 5.0,
                        "shape1_contrastive_r2vul": 1.5,   # REGEN: down 4->1.5 (templated r2vul)
                        "shape1_contrastive_attested": 3.0,
                        # 14,228 single-sided records: correct, provenance-carrying,
                        # zero boilerplate -- but single-sided, so it cannot teach
                        # guard discrimination. Ballast, weighted like shape1.
                        "shape1_r2vul_clean": 0.15,  # REGEN: down 1.0->0.15 -- 14k TEMPLATED r2vul
                        #   discrimination records taught "a form"; this is regen's direct competitor,
                        #   so held BELOW regen_deepseek's effective weight. Kept nonzero only for
                        #   CWE/lang coverage; the regen pairs now carry the discrimination reasoning.
                        #   (localize/fixgen/codeql_localize are AUXILIARY locate/repair tasks, a
                        #   different skill, so they stay at moderate weight -- not form competitors.)
                        # NOT LISTED, DELIBERATELY: shape1_contrastive_syn_java (1,000
                        # pairs, all Java, synthetic:True). shape_react_syn scored 100%
                        # while real react scored 41.2% in the same eval -- synthetic
                        # data flatters itself and does not transfer.
                        # VulLLM (2406.03718) auxiliary tasks — localization ("which
                        # line") + fix-generation ("produce the patch"). Force the model
                        # to LOCATE and REPAIR, not just classify -> less pattern-matching.
                        "shape1_localize": 0.5,   # REGEN: down 1.5->0.5 (localization drill)
                        "shape1_fixgen": 0.5,     # REGEN: down 1.0->0.5 (fix-gen drill)
                        # REGEN 2026-08-17: the regenerated teaching corpus leads the discrimination
                        # signal. regen_deepseek = 154 real contrastive PAIRS (both sides gated,
                        # distribution-matched, unique skeletons); regen_singles_strong = 176 sides
                        # where the model discriminated but the partner was out-of-view. High weight
                        # (small sets, ~300+176 rec) so they are well-represented against the 11k
                        # down-weighted r2vul, but not so high as to memorize. Weak singles low.
                        # regen_suspect (label-audit) and regen_unsure (agentic ask-for-X) are NOT
                        # wired here -- separate datasets for a later agentic phase.
                        "regen_deepseek": 8.0,
                        "regen_singles_strong": 6.0,
                        "regen_singles_weak": 1.0,
                        # Cross-file contrastive pairs are GONE (2026-07-31), not merely
                        # unwired. They were the only cross-file SAFE records, and that
                        # is exactly why they were weighted 8.0 -- the sole counterweight
                        # to shape3_codeql_localize being 100% vuln. On audit the set
                        # turned out to be line-window carvings narrated with the
                        # commit's CWE, so the counterweight was fictional and sampling
                        # at ~13x its record share.
                        #
                        # So the imbalance it was covering is now UNADDRESSED and visible
                        # again. The fix is a real cross-file carve (clones exist, see
                        # clone_crossfile_repos.sh) with the sink verified present before
                        # the window is cut -- not another weight.
                        },

    # LoRA — attention AND MLP (see lora_targets below). This comment used to say
    # "attention-only", which stopped being true when the MLP targets were added for
    # v3; it is corrected here because a stale config comment is how a change gets
    # made twice.
    "lora_r":          16,
    "lora_alpha":      32,
    "lora_dropout":    0.05,
    # Added MLP targets (gate/up/down) for more capacity — the attention-only v2
    # under-detected vulns (50% FNR). max_len reduced to 1664 to fit the extra
    # adapter params in 16GB (v2 peaked at 15.85/16GB attention-only).
    "lora_targets":    os.environ.get("WAVE_LORA_TARGETS",
                        "q_proj,k_proj,v_proj,o_proj,gate_proj,up_proj,down_proj").split(","),

    # Training
    "epochs":          int(os.environ.get("WAVE_EPOCHS", "3")),
    "batch_size":      1,
    "grad_accum":      16,        # effective batch = 16
    # LR is env-overridable because a WARM START (WAVE_INIT_ADAPTER) must NOT reuse
    # the from-scratch 2e-4. Measured on v12 run2: warm-starting with a fresh
    # optimizer and a full 2e-4 warmup applied that peak to already-converged
    # weights, knocked the model out of the basin run1 had found, and cost ~2,000
    # steps before cosine decay recovered it. For continued training use ~3e-5
    # (WAVE_LR=3e-5) and a short warmup (WAVE_WARMUP_RATIO=0.01).
    "lr":              float(os.environ.get("WAVE_LR", "2e-4")),
    "max_len":         int(os.environ.get("WAVE_MAX_LEN", "1664")),  # 14B needs less (VRAM)
    # WAVE_MAX_STEPS>0 = smoke mode: exit cleanly after N optimizer steps (pre-flight
    # check of the full load+fwd/bwd+optim path without a multi-day commitment).
    "warmup_ratio":    float(os.environ.get("WAVE_WARMUP_RATIO", "0.03")),
    # 5% of TRAIN split set aside for in-loop val. Env-overridable because the
    # epoch-END val is a full forward pass over the whole slice: at 0.05 that is
    # ~3,375 records (~1.7h), which is fine amortised over a 1-day run but nearly
    # doubles a short continued-training run. Lower it (WAVE_VAL_FRAC=0.01) when
    # the real acceptance test is an external bench rather than val loss;
    # mid_best still checkpoints every eval_every steps for crash insurance.
    "val_frac":        float(os.environ.get("WAVE_VAL_FRAC", "0.05")),
    "patience":        2,
    "seed":            42,

    # Mid-epoch observability: every eval_every optimizer steps, run a fast
    # stratified validation (fastval_per_shape records per shape) and append
    # per-shape losses to <output_dir>/train_metrics.jsonl. On a ~31h epoch the
    # once-per-epoch val is far too late to catch a doomed run; this gives a
    # signal every ~2h at ~3% throughput cost. 0 disables.
    "eval_every":      int(os.environ.get("WAVE_EVAL_EVERY", "200")),
    "fastval_per_shape": int(os.environ.get("WAVE_FASTVAL_PER_SHAPE", "16")),
    # Pairs generated at each epoch end for the selection metric. 40 pairs = 80
    # generations, a few minutes against a multi-hour epoch.
    "pair_eval_pairs":  int(os.environ.get("WAVE_PAIR_EVAL_PAIRS", "40")),
}

# Optional per-run override of shape sampling weights, e.g. v8 rebalance toward
# vuln recall: WAVE_SHAPE_WEIGHTS='{"shape1_ts":2.0,"shape1_verified_safe":1.5}'
# Merged onto the defaults so you only specify the shapes you change.
if os.environ.get("WAVE_SHAPE_WEIGHTS"):
    import json as _json
    _ov = _json.loads(os.environ["WAVE_SHAPE_WEIGHTS"])
    CONFIG["shape_weights"].update({k: float(v) for k, v in _ov.items()})
    log_msg = "  [config] shape_weights overridden: " + str(_ov)
    print(log_msg, flush=True)

# Smoke mode: >0 exits cleanly after N optimizer steps (pre-flight only).
_MAX_STEPS = int(os.environ.get("WAVE_MAX_STEPS", "0"))


def log(msg: str) -> None:
    print(msg, flush=True)


# Structured metrics sink for the watcher/dashboard. One JSON object per line;
# set in main() once output_dir exists. Append-only so a tail-reader is safe.
METRICS_PATH: Path | None = None


def write_metric(row: dict) -> None:
    if METRICS_PATH is None:
        return
    row.setdefault("t", time.strftime("%Y-%m-%dT%H:%M:%S"))
    try:
        with open(METRICS_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(row) + "\n")
    except OSError:
        pass  # metrics must never kill a 3-day run


# ---- data loading ----

def _user_hash(rec: dict) -> str:
    msgs = rec.get("messages") or []
    if not msgs:
        return ""
    return hashlib.sha256(msgs[0].get("content", "").encode("utf-8")).hexdigest()


def _iter_jsonl(path: Path):
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def load_train_records() -> list[dict]:
    """Load pilot/*.jsonl, drop any record whose user content matches an eval
    record (by sha256). Tags each record with its `_shape` so the sampler can
    apply per-shape weights."""
    # Hash EVERY eval file, not just ones whose filename matches a shape name.
    # The old form built `eval_dir/{shape}.jsonl` per shape, so an eval file named
    # `shape1_eval_primevul.jsonl` -- which is not a shape -- excluded nothing at
    # all. The protection only worked while eval and train happened to share names.
    excluded = set()
    for eval_path in sorted(CONFIG["eval_dir"].glob("*.jsonl")):
        for rec in _iter_jsonl(eval_path):
            excluded.add(_user_hash(rec))
    log(f"Eval exclusion set: {len(excluded)} hashes from "
        f"{len(list(CONFIG['eval_dir'].glob('*.jsonl')))} eval files")

    # Shapes live in either directory: the older ones under pilot/, everything
    # built to the standard under staging/. Looking in only one silently dropped
    # every new shape with a WARN that a long run scrolls past.
    search_dirs = [CONFIG["pilot_dir"], Path("data/cot/staging")]

    records = []
    per_shape: dict[str, int] = {}
    for shape in CONFIG["shapes"]:
        pilot_path = next((d / f"{shape}.jsonl" for d in search_dirs
                           if (d / f"{shape}.jsonl").exists()), None)
        if pilot_path is None:
            log(f"  WARN: {shape}.jsonl missing in {[str(d) for d in search_dirs]}"
                f" — skipped")
            continue
        kept = 0
        held = 0
        for rec in _iter_jsonl(pilot_path):
            if _user_hash(rec) in excluded:
                continue
            # `_meta.held` is how a record is retired WITHOUT deleting it: the audits
            # write a reason there and log the record to a manifest, so the judgement
            # stays auditable and reversible. Before this check existed, "held" was a
            # field nothing read and every held record still trained.
            if rec.get("_meta", {}).get("held"):
                held += 1
                continue
            rec["_shape"] = shape
            records.append(rec)
            kept += 1
        per_shape[shape] = kept
        log(f"  {shape}: kept {kept} training records"
            + (f" ({held} held)" if held else ""))
    log(f"Total training pool: {len(records)} records ({per_shape})")
    return records


# ---- dataset ----

class CoTDataset(Dataset):
    """Tokenizes (user, assistant) pairs with the chat template and masks loss
    on the user portion so the model only learns to *produce* the assistant
    response, not to predict the user prompt."""

    def __init__(self, records: list[dict], tokenizer, max_len: int):
        self.records = records
        self.tokenizer = tokenizer
        self.max_len = max_len

    def __len__(self) -> int:
        return len(self.records)

    def __getitem__(self, idx: int) -> dict:
        rec = self.records[idx]
        msgs = rec["messages"]
        user_msg = msgs[0]["content"]
        asst_msg = msgs[1]["content"]

        # Render with chat template; we need user-only and full versions so we
        # know where assistant tokens begin. enable_thinking is Qwen3-only — fall
        # back without it for other students (e.g. R1-Distill on Qwen2.5).
        def _tmpl(msgs, add_gen):
            try:
                return self.tokenizer.apply_chat_template(
                    msgs, tokenize=False, add_generation_prompt=add_gen, enable_thinking=True)
            except TypeError:
                return self.tokenizer.apply_chat_template(
                    msgs, tokenize=False, add_generation_prompt=add_gen)
        user_only_text = _tmpl([{"role": "user", "content": user_msg}], True)
        full_text = _tmpl([{"role": "user", "content": user_msg},
                           {"role": "assistant", "content": asst_msg}], False)

        # Dynamic padding: tokenize WITHOUT padding here; the collate_fn pads each
        # batch to its own longest sequence. With short records (shape2/3/ts/react
        # are ~400-700 tokens) this is ~2-4x faster than padding everything to 2048.
        full = self.tokenizer(full_text, truncation=True, max_length=self.max_len,
                              return_tensors="pt")
        user_ids = self.tokenizer(user_only_text, truncation=True,
                                  max_length=self.max_len, return_tensors="pt")["input_ids"]
        user_len = int(user_ids.shape[1])

        input_ids = full["input_ids"].squeeze(0)
        attention_mask = full["attention_mask"].squeeze(0)
        labels = input_ids.clone()
        # Mask user portion + padding -> loss only on assistant tokens
        labels[:user_len] = -100
        labels[attention_mask == 0] = -100

        return {
            "input_ids": input_ids,
            "attention_mask": attention_mask,
            "labels": labels,
        }


def make_collate_fn(pad_token_id: int):
    """Pad a batch to its own longest sequence (dynamic padding). Padded
    positions get attention_mask=0 and labels=-100 (ignored in loss)."""
    def collate(batch: list[dict]) -> dict:
        maxlen = max(x["input_ids"].size(0) for x in batch)
        input_ids, attn, labels = [], [], []
        for x in batch:
            n = x["input_ids"].size(0)
            pad = maxlen - n
            input_ids.append(torch.cat([x["input_ids"], torch.full((pad,), pad_token_id, dtype=x["input_ids"].dtype)]))
            attn.append(torch.cat([x["attention_mask"], torch.zeros(pad, dtype=x["attention_mask"].dtype)]))
            labels.append(torch.cat([x["labels"], torch.full((pad,), -100, dtype=x["labels"].dtype)]))
        return {
            "input_ids": torch.stack(input_ids),
            "attention_mask": torch.stack(attn),
            "labels": torch.stack(labels),
        }
    return collate


# ---- model setup ----

def build_model_and_tokenizer():
    log(f"Loading tokenizer: {CONFIG['model_name']}")
    tokenizer = AutoTokenizer.from_pretrained(CONFIG["model_name"], trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    log(f"Loading {CONFIG['model_name']} in 4-bit nf4...")
    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_compute_dtype=torch.bfloat16,
        bnb_4bit_use_double_quant=True,
        bnb_4bit_quant_type="nf4",
    )
    # Qwen3.5-9B is MULTIMODAL (Qwen3_5ForConditionalGeneration), so the plain causal-LM class
    # fails to load it; fall back to AutoModelForImageTextToText (same pattern as run_local_model.py
    # / scanner/full_model.py). We still fine-tune it as a TEXT model: the dataset feeds only
    # input_ids/attention_mask/labels, the top-level forward routes through the language tower when
    # no pixel_values are present, and the LoRA target suffixes (q_proj/k_proj/... ) match the LM
    # tower -- the vision blocks use fused 'qkv'/'proj' names, so they are not adapted.
    try:
        model = AutoModelForCausalLM.from_pretrained(
            CONFIG["model_name"], quantization_config=bnb_config,
            device_map="auto", trust_remote_code=True)
        log("  loaded as causal LM")
    except Exception as e:
        log(f"  causal-LM load failed ({str(e)[:90]}); loading as multimodal image-text-to-text")
        from transformers import AutoModelForImageTextToText
        model = AutoModelForImageTextToText.from_pretrained(
            CONFIG["model_name"], quantization_config=bnb_config,
            device_map="auto", trust_remote_code=True)
        log("  loaded as multimodal (fine-tuning the language tower only)")
    model.config.use_cache = False
    # multimodal models keep the LM knobs on a nested text_config -- disable cache there too.
    if hasattr(model.config, "text_config"):
        try:
            model.config.text_config.use_cache = False
        except Exception:
            pass

    log("Preparing model for k-bit training (gradient checkpointing on, non-reentrant)")
    model = prepare_model_for_kbit_training(
        model,
        use_gradient_checkpointing=True,
        gradient_checkpointing_kwargs={"use_reentrant": False},
    )

    log(f"Adding LoRA adapters (r={CONFIG['lora_r']}, targets={CONFIG['lora_targets']})")
    lora = LoraConfig(
        r=CONFIG["lora_r"],
        lora_alpha=CONFIG["lora_alpha"],
        lora_dropout=CONFIG["lora_dropout"],
        bias="none",
        task_type="CAUSAL_LM",
        target_modules=CONFIG["lora_targets"],
    )
    model = get_peft_model(model, lora)

    # Warm-start (crash recovery): WAVE_INIT_ADAPTER=<dir with adapter_model.safetensors>
    # loads a previous run's LoRA weights into the fresh adapter before training.
    # Optimizer state and LR schedule still start fresh — this recovers learned
    # weights after a power loss, it is not a true mid-step resume.
    init_adapter = os.environ.get("WAVE_INIT_ADAPTER", "")
    if init_adapter:
        from safetensors.torch import load_file as _load_st
        from peft import set_peft_model_state_dict
        sd = _load_st(str(Path(init_adapter) / "adapter_model.safetensors"))
        result = set_peft_model_state_dict(model, sd)
        unexpected = len(getattr(result, "unexpected_keys", []) or [])
        if not sd or unexpected == len(sd):
            raise SystemExit(f"WAVE_INIT_ADAPTER: no weights matched from {init_adapter}")
        log(f"Warm-start: loaded {len(sd)} adapter tensors from {init_adapter} "
            f"(unexpected: {unexpected})")

    trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
    total = sum(p.numel() for p in model.parameters())
    log(f"Trainable: {trainable:,} / {total:,} ({trainable/total*100:.2f}%)")
    return model, tokenizer


# ---- training ----

@torch.no_grad()
class PairAdjacentSampler(torch.utils.data.Sampler):
    """Weighted sampling that keeps both sides of a contrastive pair in one step.

    Why. Gradients accumulate over `grad_accum` micro-batches before a single update.
    When the two sides of a pair land in the SAME window, that update has to satisfy
    "this code is vulnerable" and "this near-identical code with a guard is safe" at
    once, and the only direction that satisfies both is the difference between them --
    the guard. When they are hundreds of steps apart the model can satisfy each on its
    own, which is how it learns a repo name or a topic word instead. That shortcut is
    the failure this whole corpus was rebuilt to prevent, so it is worth removing from
    the optimiser as well as from the data.

    Weighting is unchanged at the RECORD level. A pair unit carries the same weight as
    a single unit and emits two records, so a shape contributes
    `w * (2*pairs + singles) = w * n` either way -- the sampling shares stay exactly
    what `shape_weights` describes. Giving pairs double weight would silently double
    every contrastive set.

    Pairs are never split across an accumulation boundary: if only one slot is left in
    the window, a single is emitted first and the pair is held for the next one.
    """

    def __init__(self, records, weights, num_samples, grad_accum, seed=0):
        self.num_samples = num_samples
        self.grad_accum = max(1, grad_accum)
        self.rng = random.Random(seed)

        by_pair: dict[str, list[int]] = {}
        singles: list[int] = []
        for i, r in enumerate(records):
            pid = (r.get("_meta") or {}).get("pair_id")
            if pid:
                by_pair.setdefault(pid, []).append(i)
            else:
                singles.append(i)
        # a pair_id with only one live side is not a pair -- treat it as a single
        self.units: list[tuple[int, ...]] = []
        for idxs in by_pair.values():
            if len(idxs) == 2:
                self.units.append((idxs[0], idxs[1]))
            else:
                self.units.extend((i,) for i in idxs)
        self.units.extend((i,) for i in singles)
        self.unit_w = [weights[u[0]] for u in self.units]
        self.n_pairs = sum(1 for u in self.units if len(u) == 2)
        # Fillers for the odd slot at the end of an accumulation window. Drawn from
        # SINGLE units only -- an earlier version fell back to emitting one side of the
        # deferred pair, which is the exact thing this sampler exists to avoid and left
        # 130 lone sides per epoch.
        self.single_uids = [i for i, u in enumerate(self.units) if len(u) == 1]
        self.single_w = [self.unit_w[i] for i in self.single_uids]

    def __len__(self):
        return self.num_samples

    def __iter__(self):
        emitted, deferred = 0, None
        # sample unit ids in blocks; random.choices is weighted-with-replacement
        while emitted < self.num_samples:
            block = self.rng.choices(range(len(self.units)), weights=self.unit_w, k=512)
            for uid in block:
                if emitted >= self.num_samples:
                    return
                unit = deferred if deferred else self.units[uid]
                deferred = None
                room = self.grad_accum - (emitted % self.grad_accum)
                if len(unit) == 2 and room < 2:
                    # hold the pair, fill the last slot with a genuine single
                    deferred = unit
                    if self.single_uids:
                        fid = self.rng.choices(self.single_uids,
                                               weights=self.single_w, k=1)[0]
                        yield self.units[fid][0]
                        emitted += 1
                    continue
                for i in unit:
                    if emitted >= self.num_samples:
                        return
                    yield i
                    emitted += 1


def load_pair_eval(limit_pairs: int = 40) -> list[dict]:
    """Complete contrastive pairs from the eval holdout, for the selection metric.

    Only pairs -- a single-sided record cannot show the failure this is here to catch.
    """
    from collections import defaultdict
    by_pair = defaultdict(list)
    for path in sorted(CONFIG["eval_dir"].glob("*.jsonl")):
        for rec in _iter_jsonl(path):
            m = rec.get("_meta") or {}
            if m.get("pair_id") and m.get("label") in ("vuln", "safe"):
                by_pair[m["pair_id"]].append(rec)
    full = [v for v in by_pair.values() if len(v) == 2]
    full.sort(key=lambda v: v[0]["_meta"]["pair_id"])      # deterministic across epochs

    # Stratify by capability. Taking the first N by pair_id gave 66 contrastive / 10
    # cross-file / 4 counterexample, so the metric that PICKS THE CHECKPOINT would have
    # been nearly blind to the two capabilities this corpus was rebuilt for.
    def cap(sides):
        m = sides[0]["_meta"]
        if m.get("cross_file"):
            return "cross_file"
        return "counterexample" if m.get("weakness_class") else "contrastive"

    buckets = defaultdict(list)
    for sides in full:
        buckets[cap(sides)].append(sides)
    order = ["contrastive", "cross_file", "counterexample"]
    quota = {k: limit_pairs // len(order) for k in order}
    out, taken = [], 0
    for k in order:                       # first pass: each capability's share
        for sides in buckets[k][:quota[k]]:
            out.extend(sides)
            taken += 1
    for k in order:                       # second pass: fill from whatever is left
        for sides in buckets[k][quota[k]:]:
            if taken >= limit_pairs:
                break
            out.extend(sides)
            taken += 1
    return out


@torch.no_grad()
def evaluate_pair_accuracy(model, tokenizer, records, device) -> tuple[float, int, int]:
    """Fraction of pairs where BOTH sides get the right verdict.

    Why this replaces val loss as the SELECTION signal: on a mixed corpus, loss tracks
    fluency. A model that answers "vuln" to everything can ride a good loss curve while
    scoring 0 here, because every pair has a safe side it gets wrong. That is exactly
    the shortcut the corpus was rebuilt to prevent, so it is what checkpoint selection
    should optimise.

    Generation is capped: we only need to reach the `status:` line. A record that never
    emits one counts as wrong, deliberately -- an unparseable answer is not a correct
    one, and treating it as "safe" was a silent failure observed on v10.
    """
    from eval.parsers import parse_shape1
    model.eval()
    # generate() allocates a KV cache on top of whatever training left resident, so
    # hand the allocator its free blocks back first.
    torch.cuda.empty_cache()
    verdicts: dict[str, list[bool]] = {}
    for rec in records:
        msgs = [{"role": "user", "content": rec["messages"][0]["content"]}]
        try:
            text = tokenizer.apply_chat_template(msgs, tokenize=False,
                                                 add_generation_prompt=True,
                                                 enable_thinking=True)
        except TypeError:
            text = tokenizer.apply_chat_template(msgs, tokenize=False,
                                                 add_generation_prompt=True)
        ids = tokenizer(text, return_tensors="pt", truncation=True,
                        max_length=CONFIG["max_len"]).to(device)
        gen = model.generate(**ids, max_new_tokens=320, do_sample=False,
                             pad_token_id=tokenizer.pad_token_id or tokenizer.eos_token_id)
        out = tokenizer.decode(gen[0][ids["input_ids"].shape[1]:], skip_special_tokens=True)
        status = parse_shape1(out).get("status")
        pred = "vuln" if status in ("vuln", "confirmed") else (
            "safe" if status == "safe" else None)
        m = rec["_meta"]
        verdicts.setdefault(m["pair_id"], []).append(pred == m["label"])
    pairs = [v for v in verdicts.values() if len(v) == 2]
    ok = sum(1 for v in pairs if all(v))
    model.train()
    torch.cuda.empty_cache()
    return (ok / len(pairs) if pairs else 0.0), ok, len(pairs)


@torch.no_grad()
def evaluate(model, val_loader, device) -> float:
    """Validation loss.

    `@torch.no_grad()` is not optional here: `model.eval()` only changes dropout and
    norm behaviour, it does NOT stop autograd from building a graph. Without it this
    stores activations for a backward pass that never comes, and the epoch-end
    validation OOMs on a 16 GB card. The other eval helpers in this file already had
    the decorator; this one did not.
    """
    model.eval()
    losses = []
    for batch in val_loader:
        input_ids = batch["input_ids"].to(device)
        attention_mask = batch["attention_mask"].to(device)
        labels = batch["labels"].to(device)
        out = model(input_ids=input_ids, attention_mask=attention_mask, labels=labels)
        loss_val = out.loss.item()
        if not math.isnan(loss_val) and not math.isinf(loss_val):
            losses.append(loss_val)
    model.train()
    return sum(losses) / max(len(losses), 1) if losses else float("nan")


def build_fastval_indices(val_records: list[dict], per_shape: int) -> list[int]:
    """Fixed stratified subset of the val split: up to per_shape records from
    every shape. Fixed across the whole run so the fastval curve is
    apples-to-apples between checks (the full val stays the best-checkpoint
    criterion; this is the trend/observability signal)."""
    by_shape: dict[str, list[int]] = {}
    for i, rec in enumerate(val_records):
        by_shape.setdefault(rec["_shape"], []).append(i)
    indices = []
    for shape in sorted(by_shape):
        indices.extend(by_shape[shape][:per_shape])
    return indices


@torch.no_grad()
def evaluate_per_shape(model, val_ds, indices, collate_fn, device):
    """Loss on the fastval subset, overall + per shape. Record-at-a-time
    (batch_size 1 matches training) so each loss attributes to its shape."""
    model.eval()
    per: dict[str, list[float]] = {}
    for i in indices:
        batch = collate_fn([val_ds[i]])
        out = model(input_ids=batch["input_ids"].to(device),
                    attention_mask=batch["attention_mask"].to(device),
                    labels=batch["labels"].to(device))
        loss_val = out.loss.item()
        if math.isnan(loss_val) or math.isinf(loss_val):
            continue
        per.setdefault(val_ds.records[i]["_shape"], []).append(loss_val)
    model.train()
    shape_means = {s: sum(v) / len(v) for s, v in per.items() if v}
    all_losses = [x for v in per.values() for x in v]
    overall = sum(all_losses) / len(all_losses) if all_losses else float("nan")
    return overall, shape_means


def _existing_checkpoint(d: Path) -> bool:
    """Treat a dir as 'occupied' if it has adapter files. An empty dir is fine."""
    if not d.exists():
        return False
    for marker in ("adapter_config.json", "adapter_model.safetensors", "adapter_model.bin"):
        if (d / marker).exists():
            return True
    return False


def main():
    random.seed(CONFIG["seed"])
    torch.manual_seed(CONFIG["seed"])
    device = "cuda" if torch.cuda.is_available() else "cpu"
    log(f"Device: {device}")

    # Safety net: refuse to clobber an existing checkpoint. Force the operator to
    # rename it (e.g., qwen_cot_best -> qwen_cot_v1_best) before training v2/v3.
    # Override with WAVE_OVERWRITE=1 when you genuinely want to overwrite.
    if os.environ.get("WAVE_OVERWRITE", "").lower() not in ("1", "true", "yes"):
        existing = [d for d in (CONFIG["best_dir"], CONFIG["output_dir"]) if _existing_checkpoint(d)]
        if existing:
            log("\nABORT: existing checkpoint(s) found — refusing to overwrite.")
            for d in existing:
                log(f"  {d}")
            log("\nRename the directory before re-training, e.g.:")
            log(f"  Move-Item {CONFIG['best_dir']} {CONFIG['best_dir'].parent / (CONFIG['best_dir'].name + '_vN')}")
            log(f"  Move-Item {CONFIG['output_dir']} {CONFIG['output_dir'].parent / (CONFIG['output_dir'].name + '_vN')}")
            log("\nOr force overwrite with: $env:WAVE_OVERWRITE = '1'")
            raise SystemExit(2)

    CONFIG["output_dir"].mkdir(parents=True, exist_ok=True)
    CONFIG["best_dir"].mkdir(parents=True, exist_ok=True)
    global METRICS_PATH
    METRICS_PATH = CONFIG["output_dir"] / "train_metrics.jsonl"

    records = load_train_records()
    if not records:
        raise SystemExit("No training records loaded — check pilot/eval dirs.")

    random.shuffle(records)
    val_size = max(1, int(len(records) * CONFIG["val_frac"]))
    val_records = records[:val_size]
    train_records = records[val_size:]
    log(f"In-loop split: train={len(train_records)}  val={len(val_records)}")

    model, tokenizer = build_model_and_tokenizer()

    train_ds = CoTDataset(train_records, tokenizer, CONFIG["max_len"])
    val_ds = CoTDataset(val_records, tokenizer, CONFIG["max_len"])

    # Weighted sampler — each training record's draw probability ~= shape weight.
    # num_samples caps the epoch LENGTH independently of corpus size, to fit the
    # ~2-day hardware wall (5070 Ti's sustained limit; v11 crashed near it twice).
    # MEASURED v12 throughput = 331 optim-steps/hr, so full 2 epochs (8,010 steps)
    # = ~1.0 day (~1.5 with v11-style degradation) — under the wall. So default OFF
    # (full corpus). Set WAVE_MAX_SAMPLES_PER_EPOCH>0 to time-box (e.g. for 3 epochs
    # or if throughput degrades): safe budget ~= 10,500 total steps for 2 days.
    weights = [CONFIG["shape_weights"][r["_shape"]] for r in train_records]
    _cap = int(os.environ.get("WAVE_MAX_SAMPLES_PER_EPOCH", "0"))
    num_samples = min(_cap, len(train_records)) if _cap > 0 else len(train_records)
    log(f"Sampler: {num_samples} weighted draws/epoch (corpus {len(train_records)}, cap {_cap or 'off'})")
    if os.environ.get("WAVE_PAIR_ADJACENT", "1") == "1":
        sampler = PairAdjacentSampler(train_records, weights, num_samples,
                                      CONFIG["grad_accum"], seed=CONFIG["seed"])
        log(f"Sampler: pair-adjacent ({sampler.n_pairs} complete pairs kept inside a "
            f"{CONFIG['grad_accum']}-microbatch window; record weights unchanged)")
    else:
        sampler = WeightedRandomSampler(weights, num_samples=num_samples, replacement=True)
        log("Sampler: independent weighted draws (WAVE_PAIR_ADJACENT=0)")
    collate_fn = make_collate_fn(tokenizer.pad_token_id)
    train_loader = DataLoader(train_ds, batch_size=CONFIG["batch_size"], sampler=sampler, collate_fn=collate_fn)
    val_loader = DataLoader(val_ds, batch_size=CONFIG["batch_size"], shuffle=False, collate_fn=collate_fn)
    log(f"Train batches: {len(train_loader)}  Val batches: {len(val_loader)}")

    optimizer = torch.optim.AdamW(
        [p for p in model.parameters() if p.requires_grad],
        lr=CONFIG["lr"], weight_decay=0.01,
    )

    total_optim_steps = (len(train_loader) * CONFIG["epochs"]) // CONFIG["grad_accum"]
    warmup_steps = int(total_optim_steps * CONFIG["warmup_ratio"])
    log(f"Total optimizer steps: {total_optim_steps}  Warmup: {warmup_steps}")

    pair_eval_records = load_pair_eval(CONFIG["pair_eval_pairs"])
    log(f"Pair-eval holdout: {len(pair_eval_records)//2} complete pairs "
        f"(selection metric; val loss is logged but does not pick the checkpoint)")

    fastval_indices = build_fastval_indices(val_records, CONFIG["fastval_per_shape"])
    log(f"Fastval subset: {len(fastval_indices)} records "
        f"(<= {CONFIG['fastval_per_shape']}/shape), every {CONFIG['eval_every']} steps")
    write_metric({
        "type": "run_start",
        "pilot_dir": str(CONFIG["pilot_dir"]),
        "epochs": CONFIG["epochs"],
        "train_records": len(train_records),
        "val_records": len(val_records),
        "fastval_records": len(fastval_indices),
        "total_optim_steps": total_optim_steps,
    })

    def get_lr(step: int) -> float:
        if step < warmup_steps:
            return CONFIG["lr"] * (step + 1) / max(1, warmup_steps)
        progress = (step - warmup_steps) / max(1, total_optim_steps - warmup_steps)
        return CONFIG["lr"] * 0.5 * (1 + math.cos(math.pi * progress))

    best_val_loss = float("inf")
    best_fastval = float("inf")
    best_pair_acc = -1.0
    patience = 0
    global_step = 0
    nan_streak = 0          # consecutive batches with NaN/inf loss
    NAN_ABORT_THRESHOLD = 5  # abort if 5 in a row -> something is fundamentally broken
    mid_best_dir = CONFIG["output_dir"] / "mid_best"
    model.train()

    for epoch in range(CONFIG["epochs"]):
        epoch_start = time.time()
        running_loss = 0.0
        running_count = 0
        optimizer.zero_grad(set_to_none=True)

        for i, batch in enumerate(train_loader):
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["labels"].to(device)

            # No autocast wrapper: bnb_4bit_compute_dtype=bf16 already handles
            # dtype inside the model. Stacking autocast on top of QLoRA +
            # gradient checkpointing produces NaN gradients on bf16.
            out = model(input_ids=input_ids, attention_mask=attention_mask, labels=labels)
            loss = out.loss / CONFIG["grad_accum"]
            loss_val = loss.item() * CONFIG["grad_accum"]

            if math.isnan(loss_val) or math.isinf(loss_val):
                nan_streak += 1
                log(f"  WARN: NaN/inf loss at batch {i} (streak={nan_streak})")
                write_metric({"type": "nan_warn", "epoch": epoch + 1,
                              "batch": i, "streak": nan_streak})
                if nan_streak >= NAN_ABORT_THRESHOLD:
                    log(f"\nABORT: loss has been NaN/inf for {nan_streak} batches. "
                        f"Something is fundamentally wrong — stopping to save your time.")
                    raise SystemExit(1)
                # Skip backward/optimizer step on bad loss
                optimizer.zero_grad(set_to_none=True)
                continue
            nan_streak = 0

            loss.backward()
            running_loss += loss_val
            running_count += 1

            if (i + 1) % CONFIG["grad_accum"] == 0:
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                optimizer.step()
                optimizer.zero_grad(set_to_none=True)
                global_step += 1
                if _MAX_STEPS and global_step >= _MAX_STEPS:
                    log(f"WAVE_MAX_STEPS={_MAX_STEPS} reached — smoke run OK "
                        f"(model+LoRA+data+fwd/bwd+optim verified), exiting cleanly.")
                    raise SystemExit(0)
                lr = get_lr(global_step)
                for g in optimizer.param_groups:
                    g["lr"] = lr
                if global_step % 25 == 0:
                    avg = running_loss / max(running_count, 1)
                    log(f"  step {global_step:>5}/{total_optim_steps}  train_loss={avg:.4f}  lr={lr:.2e}")
                    write_metric({"type": "train", "epoch": epoch + 1,
                                  "step": global_step, "loss": round(avg, 4),
                                  "lr": lr})

                if CONFIG["eval_every"] and global_step % CONFIG["eval_every"] == 0:
                    fv, shape_fv = evaluate_per_shape(
                        model, val_ds, fastval_indices, collate_fn, device)
                    xfile = shape_fv.get("shape3_codeql")
                    log(f"  [fastval] step {global_step}  overall={fv:.4f}  "
                        f"shape3_codeql={xfile if xfile is None else round(xfile, 4)}")
                    write_metric({"type": "fastval", "epoch": epoch + 1,
                                  "step": global_step, "overall": round(fv, 4),
                                  "per_shape": {k: round(v, 4) for k, v in shape_fv.items()}})
                    # Rolling insurance checkpoint: a crash at hour 50 keeps the
                    # best mid-run adapter. Does NOT touch best_dir semantics
                    # (those stay on the full epoch-end val, comparable to v1-v10).
                    if not math.isnan(fv) and fv < best_fastval:
                        best_fastval = fv
                        model.save_pretrained(mid_best_dir)
                        write_metric({"type": "mid_checkpoint", "step": global_step,
                                      "fastval": round(fv, 4)})

        avg_train = running_loss / max(running_count, 1)
        val_loss = evaluate(model, val_loader, device)
        elapsed = time.time() - epoch_start
        log(f"Epoch {epoch+1}/{CONFIG['epochs']}  train={avg_train:.4f}  val={val_loss:.4f}  "
            f"time={elapsed:.0f}s")
        write_metric({"type": "epoch", "epoch": epoch + 1,
                      "train": round(avg_train, 4), "val": round(val_loss, 4),
                      "seconds": round(elapsed)})

        # SELECTION IS ON PAIR ACCURACY, not val loss. Val loss is still logged and
        # still useful for spotting divergence, but it is not what picks the
        # checkpoint: it measures fluency on a mixed corpus, and a model that answers
        # "vuln" to everything can improve it while getting every pair wrong.
        pair_acc, p_ok, p_n = evaluate_pair_accuracy(
            model, tokenizer, pair_eval_records, device)
        log(f"  [pair] {p_ok}/{p_n} pairs both-sides-correct = {pair_acc*100:.1f}%")
        write_metric({"type": "pair_eval", "epoch": epoch + 1,
                      "pair_acc": round(pair_acc, 4), "ok": p_ok, "n": p_n})

        if pair_acc > best_pair_acc:
            best_pair_acc = pair_acc
            best_val_loss = min(best_val_loss, val_loss)
            patience = 0
            model.save_pretrained(CONFIG["best_dir"])
            tokenizer.save_pretrained(CONFIG["best_dir"])
            log(f"  -> new best (pair={pair_acc*100:.1f}%, val={val_loss:.4f}), "
                f"saved to {CONFIG['best_dir']}")
            write_metric({"type": "best_checkpoint", "epoch": epoch + 1,
                          "pair_acc": round(pair_acc, 4), "val": round(val_loss, 4)})
        else:
            patience += 1
            log(f"  -> no improvement in pair accuracy ({patience}/{CONFIG['patience']})")
            if patience >= CONFIG["patience"]:
                log("Early stopping.")
                break

    model.save_pretrained(CONFIG["output_dir"])
    tokenizer.save_pretrained(CONFIG["output_dir"])
    write_metric({"type": "run_end", "best_val": round(best_val_loss, 4)})
    log(f"\nTraining complete.")
    log(f"Best (val={best_val_loss:.4f}): {CONFIG['best_dir']}")
    log(f"Final epoch:                  {CONFIG['output_dir']}")


if __name__ == "__main__":
    main()
