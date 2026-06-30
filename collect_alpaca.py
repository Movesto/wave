# ============================================================
# collect_alpaca.py
# 18k Python code instruction → code pairs
# Output: data/sft/alpaca_generate_pairs.jsonl
# ============================================================
import os
import json
from datasets import load_dataset

os.makedirs(os.path.join("data", "sft"), exist_ok=True)
output_path = os.path.join("data", "sft", "alpaca_generate_pairs.jsonl")

print("Loading python_code_instructions_18k_alpaca...")
ds = load_dataset(
    "iamtarun/python_code_instructions_18k_alpaca",
    split="train",
    streaming=True
)

pairs = []
count = 0

for sample in ds:
    instruction = sample.get("instruction", "").strip()
    output = sample.get("output", "").strip()

    if not instruction or not output:
        continue
    if len(instruction) < 10 or len(output) < 20:
        continue
    if len(output) > 3000:
        continue

    pair = {
        "messages": [
            {"role": "user", "content": f"<GENERATE>\n{instruction}\n</GENERATE>"},
            {"role": "assistant", "content": output}
        ]
    }
    pairs.append(pair)
    count += 1

    if count % 5000 == 0:
        print(f"  Collected {count} pairs...")

with open(output_path, "w", encoding="utf-8") as f:
    for pair in pairs:
        f.write(json.dumps(pair) + "\n")

print(f"Saved {len(pairs)} pairs to {output_path}")
