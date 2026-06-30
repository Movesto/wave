# ============================================================
# PART 4: collect_generate.py
# Downloads (description, code) pairs for code generation
# Requires: pip install datasets
# Output: data/sft/generate_pairs.jsonl
# ============================================================
import os
import json

os.makedirs(os.path.join("data", "sft"), exist_ok=True)

from datasets import load_dataset

output_path = os.path.join("data", "sft", "generate_pairs.jsonl")
target = 600
pairs = []
count = 0

# ============================================================
# Source 1: xlcost-text-to-code (description → code snippets)
# ============================================================
print("Loading xlcost Python snippet-level data...")
try:
    ds1 = load_dataset(
        "codeparrot/xlcost-text-to-code",
        "Python-snippet-level",
        split="train",
        streaming=True
    )

    for sample in ds1:
        text = sample["text"].strip()
        code = sample["code"].strip()

        if len(text) < 20 or len(code) < 30:
            continue
        if len(text) > 500 or len(code) > 2000:
            continue

        pair = {
            "messages": [
                {"role": "user", "content": f"<GENERATE>\n{text}\n</GENERATE>"},
                {"role": "assistant", "content": code}
            ]
        }
        pairs.append(pair)
        count += 1

        if count % 100 == 0:
            print(f"  xlcost: {count} pairs...")

        if count >= target // 2:
            break

except Exception as e:
    print(f"  xlcost error: {e}")

print(f"  Got {count} pairs from xlcost")

# ============================================================
# Source 2: Code-Feedback (multi-turn code conversations)
# ============================================================
print("\nLoading Code-Feedback data...")
try:
    ds2 = load_dataset(
        "m-a-p/Code-Feedback",
        split="train",
        streaming=True
    )

    for sample in ds2:
        messages = sample.get("messages", [])

        # Need at least user + assistant turn
        if len(messages) < 2:
            continue

        user_msg = ""
        assistant_msg = ""

        for msg in messages:
            role = msg.get("role", "")
            content = msg.get("content", "").strip()
            if role == "user" and not user_msg:
                user_msg = content
            elif role == "assistant" and not assistant_msg:
                assistant_msg = content

        if not user_msg or not assistant_msg:
            continue

        # Only keep if it looks like a code generation request
        code_keywords = ["write", "create", "implement", "build", "make",
                         "function", "class", "script", "program", "code"]
        if not any(kw in user_msg.lower() for kw in code_keywords):
            continue

        # Skip if too long
        if len(user_msg) > 500 or len(assistant_msg) > 3000:
            continue

        pair = {
            "messages": [
                {"role": "user", "content": f"<GENERATE>\n{user_msg}\n</GENERATE>"},
                {"role": "assistant", "content": assistant_msg}
            ]
        }
        pairs.append(pair)
        count += 1

        if count % 100 == 0:
            print(f"  Code-Feedback: {count} total pairs...")

        if count >= target:
            break

except Exception as e:
    print(f"  Code-Feedback error: {e}")

# ============================================================
# Save
# ============================================================
with open(output_path, "w", encoding="utf-8") as f:
    for pair in pairs:
        f.write(json.dumps(pair) + "\n")

print(f"\nSaved {len(pairs)} generate pairs to {output_path}")
