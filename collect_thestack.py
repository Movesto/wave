# ============================================================
# PART 1B: collect_thestack.py
# Streams Python files from The Stack on HuggingFace
# Requires: pip install datasets huggingface_hub
# Requires: huggingface-cli login (free account)
# Output: data/pretrain/thestack_python.txt
# ============================================================
import os

os.makedirs(os.path.join("data", "pretrain"), exist_ok=True)

from datasets import load_dataset

output_path = os.path.join("data", "pretrain", "thestack_python.txt")
target_gb = 5
target_bytes = target_gb * 1024 * 1024 * 1024

print(f"Streaming Python files from The Stack (target: {target_gb}GB)...")
print("This will take a while. You can stop it early and use what you have.\n")

ds = load_dataset(
    "Nan-Do/code-search-net-python",
    split="train",
    streaming=True
)

total_bytes = 0
count = 0

with open(output_path, "w", encoding="utf-8") as f:
    for sample in ds:
        code = sample["code"]

        # Skip tiny files, huge files, and non-utf8
        if len(code) < 100 or len(code) > 100000:
            continue

        # Skip files that are mostly not code (data files, etc)
        lines = code.split('\n')
        if len(lines) < 5:
            continue

        f.write(f"\n# FILE: {sample.get('path', 'unknown')}\n")
        f.write(code)
        f.write("\n")

        total_bytes += len(code.encode('utf-8'))
        count += 1

        if count % 10000 == 0:
            gb = total_bytes / (1024 ** 3)
            print(f"  {count} files, {gb:.2f} GB collected...")

        if total_bytes >= target_bytes:
            break

gb = total_bytes / (1024 ** 3)
print(f"\nDone! Collected {count} files, {gb:.2f} GB into {output_path}")
