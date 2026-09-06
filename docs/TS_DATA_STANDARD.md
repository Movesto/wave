# Contrastive data — the standard (TypeScript and JavaScript)

**Read this before changing any data builder. `scan_ts_standard.py` enforces it.
Nothing ships unless that scanner exits 0.**

## THE GOAL — read this before touching a rule

**A model that, shown code it has never seen, can work out whether a specific flow
is exploitable, and knows when it cannot tell.**

Not classify. Not recognise a family. Work it out — find what crosses the trust
boundary, follow it, ask whether the control on that path actually covers it, and
say "not enough context here" when the evidence is absent.

Everything in this file is study material. **The exam is real code in the wild:
messy, refactored, unfamiliar.** Passing that is the only thing that counts;
benchmark numbers are practice scores. A rule that makes the study material
cleaner than the exam is a rule that hurts.

Every rule below is judged against that sentence. If a rule cannot be traced back
to it, the rule is wrong — not the data.

## Why this data exists (the thing that keeps getting lost)

Teach the model to decide whether **this specific code is exploitable**, by
reasoning about the flow from source to sink and whether a control actually stops
it.

**Not** to classify a vulnerability family. The corpus already taught family
recognition — organised by CWE, `cwe:` as a trained output field, per-CWE recall
as the metric — and the result is a topic classifier: 89% on Python where the
topics are familiar, MCC 0.000 on TypeScript where the same topics wear different
clothes.

The measured proof that family recognition is what got learned: v12 fits
`shape1_contrastive_ts` to **0.0076 loss** and still scores **0.000** on TS. It
learned the boundary perfectly, and the boundary is "is a guard-shaped token
present?" — which is a surface feature, not a mechanism.

Every requirement below exists to stop that shortcut from being learnable.

## Requirements

They are three different kinds of thing, and conflating them caused a full day of
misdirected work on R2:

- **TEACH THE GOAL** (R1, R3, R6, R7, R8, R12) — these shape what the model learns.
- **GUARANTEE INTEGRITY** (R4, R5, R9, R10, R13) — these teach the model nothing;
  they make the data checkable, which is how 64 wrong CWEs and 12 ghost
  identifiers were caught at all.
- **TECHNICAL LIMIT** (R11) — labels are masked above ~6000 chars.

| # | Requirement | Why — the failure it prevents |
|---|---|---|
| R1 | **Paired.** Every `pair_id` has exactly one `vuln` and one `safe` record. | Without a pair there is no contrast, and contrast is the only thing that forces attention to the mechanism. A standalone record teaches a label. |
| R2 | **Minimal difference — AUGMENTATION PAIRS ONLY** (≤ 12 semantic lines). Not applied to harvested pairs. | For an edit I author, a large diff means I was sloppy. For a real commit the diff is reality, and forcing it minimal makes the study material cleaner than the exam. See the amendment log. |
| R3 | **Real code.** Realism metrics within tolerance of the base real record. | Hand-authored code failed 6/10 realism metrics (7 lines vs real median 57, 6× type-annotation density). `shape_react_syn` scored 100% while real React scored 41% — the model learns to spot tidy code. |
| R4 | **Auditable provenance.** `repo`, `sha`, `src_file`, **and at least one of `cve`/`ghsa`**. | The old 324 TS records carry none, so they can never be audited against NVD or CISA. That is why the fix/CWE comparison was impossible on them. |
| R5 | **CWE from the base record**, never hardcoded; CISA-preferred. | CISA names the mechanism (CWE-59 symlink following) over the family (CWE-22 path traversal). Hardcoding re-introduces the guessing that labelled a credential-masking fix as CSRF. |
| R6 | **Every identifier the trace names occurs in the code**, outside string literals. | Naming something absent from the excerpt is confabulation — the exact failure being trained out (32/32 missed vulns invented a guard). |
| R7 | **Trace states a mechanism**, has `source -> sink`, and is not boilerplate. | 77% of existing TS records share a top-20 template sentence. Those teach the sentence. |
| R8 | **Safe side states a reason.** Source-justified always allowed; guard-justified **only** when the record is untouched real post-fix code. | "Is this value attacker-reachable?" is checkable by reading. "Is this guard adequate?" is a judgement — permitted only when the CVE fix itself establishes it. |
| R9 | **Safe side is real post-fix code, or a source-substitution of it.** | The post-fix code is verified safe by the CVE fix itself. Anything else is an unverified label. |
| R10 | **No eval leakage.** | Contaminated eval was already found once: `primevul_test_paired.jsonl` was being fed into training. |
| R11 | **Size within limits** (120–4500 chars). | Above ~6000 chars assembled, labels are masked and the record yields NaN instead of gradient. |
| R12 | **Balanced.** Equal vuln and safe counts. | An imbalanced set lets the prior do the work. |
| R13 | **Coverage.** Every candidate base is either BUILT or listed in `EXCLUSIONS` with a reason. | A scanner over emitted records cannot see a record that was never emitted. CWE-59 (`openclaw src/browser/paths.ts`, CVE-2026-32054) was skipped on the assumption its comparison site was missing — it wasn't, and nothing noticed until it was asked about directly. |
| R13b | **Exclusion reasons are substantive** (≥12 words). | A one-word reason is a silent skip wearing a label. A reason must state what was CHECKED, not what was assumed. |

## Two augmentation kinds, and the only defensible way to build each

**`variant_vuln`** — start from the **real post-fix (safe) code** and remove a
sanitiser that code itself applies. In renovate, `quote(username)` exists because
that value is dangerous, and the CVE in that same function *is* unquoted
interpolation — so removing it recreates a mechanism the CVE proves exploitable.
This is not generic guard-removal; the exploit is demonstrated in the same
function.

**`nearmiss_safe`** — start from the real post-fix code and replace the **source**
with a value no caller controls, keeping the dangerous shape. Unquoted
interpolation into a shell string is still present; it is safe only because the
interpolated value is a constant.

**Always edit the SAFE side.** Editing the vulnerable side cannot produce a pair —
there is no verified-safe counterpart for it. This was the mistake in the first
attempt.

## Amendment log — every change to a requirement gets recorded here

**R4, 2026-07-29.** Originally required `cve` unconditionally. Amended to require
`repo` + `sha` + `src_file` plus **either** `cve` or `ghsa`.

Reason: 17 of 223 guards resolve to a GHSA advisory that carries no CVE alias.
R4 exists so a record can be traced back and re-verified, and `ghsa + repo + sha +
src_file` identifies the exact fix commit completely — the CVE adds nothing for
auditing. The original wording over-specified the identifier rather than the
capability.

This was written while data was failing the check, which is the shape of
post-hoc goalpost-shifting. The test applied: does the amended requirement still
guarantee the PURPOSE (can this record be re-verified against an authoritative
source)? Yes. If the answer had been no, the data should have been dropped
instead.

**R2, 2026-07-30. Scoped to augmentation pairs only.** Previously applied to every
pair at <= 12 changed lines.

Reason — and this one is a change of MIND, not of threshold. R2 was a PROXY for
"the guard should be the only thing that differs". The property actually wanted is
"can the model identify which change is the security-relevant one?", and those come
apart on real code. Measured on 85 harvested pairs: real security fixes change
20-30 SEMANTIC lines (median 30; 33% of every raw diff was imports, comments and
braces, now excluded). Narrowing excerpts to one file, then to the guard's region,
moved the median only 36 -> 30 -> 20. The fixes are simply that size.

Forcing them to 12 would train "find the one changed line", and then the exam —
real code, which arrives with refactoring — does not look like that. That is the
`shape_react_syn` failure in a new form: synthetic scored 100% while real React
scored 41% BECAUSE it was too clean.

What R2 was protecting is already protected: R6 requires the trace to NAME the
guard and verifies it exists in the code, and R8 requires the safe side to explain
why. With the guard named, grounded and explained, a wider diff does not hand the
model a cheaper feature — the contrast is anchored to a specific token.

Kept at <= 12 for AUGMENTATION pairs, where the edit is authored here and a large
diff means the author was careless.

REJECTED ALTERNATIVE, recorded so it is not retried: deriving the bound from the
distribution. A Tukey fence (q3 + 1.5*IQR) on the observed data came out at **110**,
which would have passed 99% of pairs and left the rule meaning nothing. "Typical"
is not "safe" when the whole distribution is large. A number that accepts
everything is not a standard.

**R8, 2026-07-30.** Originally required the safe side to be justified by the
SOURCE only. Amended to allow guard-justification when — and only when — the
record is the untouched real post-fix code.

Reason: the guard-completeness shape (from the paper) needs a safe side whose
safety comes from the guard covering every path. That is a judgement in general,
which is why the original rule banned it. It is NOT a judgement when the code is
the maintainer's actual fix, because the CVE confirms that fix resolved the issue.
The amendment therefore ADDS a constraint (the code must be byte-identical to the
base's safe side) rather than removing one.

## The guard-completeness shape (from the paper)

`thegriffyn.me/blog/oss/twelve-cves-in-datamodel-code-generator` — 5 of 12 CVEs
were obtained by attacking patches that looked correct. Recurring patterns:
inconsistent escaping across similar positions; a gate blocking `http://` while
exempting `file://`; validation that misses an input state.

**Why this is the shape the corpus lacks.** Every existing pair is consistent with
"guard present => safe", so that is the rule the model learned. In a
completeness pair a sanitiser is VISIBLY PRESENT and the code is still
exploitable, because it does not cover every position or value. Token presence
cannot solve these.

**The trace must NAME the present guard.** Existing traces say "I look for a
control between source and sink and find none" even when `quote()` sits three
lines away — renovate's own CVE is the inconsistent-escaping pattern, with
`quote(username)` two lines above the unquoted `value.name`. Those traces teach
the model to ignore guards that are right there.

## Process note to self

Every past failure here came from a gate that tested what I thought to test:

- the trace verifier reported "0 defects" on traces naming Node **modules** as tainted sources
- the realism check was meaningless until controlled against each record's own base
- the edits passed verification while not being pairs at all

So: **when adding a fix, add its check to `scan_ts_standard.py` in the same
change.** A fix without a check is how the next regression gets shipped.

**And a gate that has never fired is not known to work.** R13 was verified by
removing one entry from `EXCLUSIONS` and confirming the scanner reported
`1 unaccounted for` and exited non-zero. Do the same for any new rule — assert
that it FAILS on the defect it exists to catch, not just that it passes on good
data.

**The deeper pattern to watch for:** every miss in this project came from
assuming instead of looking. Predicting `isPathInside` when the function was
`isPathInsideHost`. Assuming CWE-59's comparison site was absent without opening
the file. Assuming the hand-authored code read like production code. In each case
the check was cheap and the assumption was wrong.
