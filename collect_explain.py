# ============================================================
# PART 3: collect_explain.py
# Downloads (function, docstring) pairs from CodeSearchNet
# Requires: pip install datasets
# Output: data/sft/explain_pairs.jsonl
# ============================================================
import os
import json

os.makedirs(os.path.join("data", "sft"), exist_ok=True)

from datasets import load_dataset

output_path = os.path.join("data", "sft", "explain_pairs.jsonl")
target = 600

print(f"Loading CodeSearchNet Python split (target: {target} pairs)...")

ds = load_dataset(
    "code-search-net/code_search_net",
    "python",
    split="train",
    streaming=True
)

pairs = []
count = 0

for sample in ds:
    doc = sample["func_documentation_string"].strip()
    code = sample["whole_func_string"].strip()

    # Skip bad pairs
    if len(doc) < 30 or len(doc) > 500:
        continue
    if len(code) < 50 or len(code) > 2000:
        continue
    # Skip if docstring is just a one-word description
    if len(doc.split()) < 5:
        continue
    # Skip if docstring looks auto-generated
    if doc.startswith("TODO") or doc.startswith("FIXME"):
        continue

    pair = {
        "messages": [
            {"role": "user", "content": f"<EXPLAIN>\n{code}\n</EXPLAIN>"},
            {"role": "assistant", "content": doc}
        ]
    }
    pairs.append(pair)
    count += 1

    if count % 100 == 0:
        print(f"  Collected {count}/{target} explain pairs...")

    if count >= target:
        break

with open(output_path, "w", encoding="utf-8") as f:
    for pair in pairs:
        f.write(json.dumps(pair) + "\n")

print(f"\nSaved {len(pairs)} explain pairs to {output_path}")
