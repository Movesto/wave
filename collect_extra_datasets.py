# ============================================================
# collect_extra_datasets.py
# securecode-web, glaive QA, Ling-Coder, rStar-Coder, CodeFeedback
# Output: data/sft/securecode_pairs.jsonl
#         data/sft/glaive_explain_pairs.jsonl
#         data/sft/lingcoder_pairs.jsonl
#         data/sft/rstarcoder_pairs.jsonl
#         data/sft/codefeedback_pairs.jsonl
# ============================================================
import os
import json
from datasets import load_dataset

os.makedirs(os.path.join("data", "sft"), exist_ok=True)

# ============================================================
# 1. scthornton/securecode-web — web security code pairs
# ============================================================
print("=" * 50)
print("1. Loading scthornton/securecode-web...")
output1 = os.path.join("data", "sft", "securecode_pairs.jsonl")

try:
    ds = load_dataset("scthornton/securecode-web", split="train", streaming=True)
    
    first = True
    pairs = []
    for sample in ds:
        if first:
            print(f"  Fields: {list(sample.keys())}")
            first = False

        # Try to find the right fields
        instruction = ""
        response = ""
        
        for key in sample:
            val = str(sample[key]).strip()
            key_lower = key.lower()
            if key_lower in ["instruction", "input", "prompt", "question", "text"]:
                instruction = val
            elif key_lower in ["output", "response", "answer", "completion"]:
                response = val

        # Fallback: use first two substantial text fields
        if not instruction or not response:
            texts = [(k, str(v).strip()) for k, v in sample.items()
                    if isinstance(v, str) and len(str(v)) > 30]
            if len(texts) >= 2:
                instruction = texts[0][1]
                response = texts[1][1]

        if not instruction or not response:
            continue
        if len(instruction) > 3000 or len(response) > 3000:
            continue

        pair = {
            "messages": [
                {"role": "user", "content": f"<SCAN>\n{instruction}\n</SCAN>"},
                {"role": "assistant", "content": response}
            ]
        }
        pairs.append(pair)

        if len(pairs) % 500 == 0:
            print(f"  securecode: {len(pairs)} pairs...")

    with open(output1, "w", encoding="utf-8") as f:
        for p in pairs:
            f.write(json.dumps(p) + "\n")
    print(f"  Saved {len(pairs)} pairs to {output1}")

except Exception as e:
    print(f"  securecode-web error: {e}")

# ============================================================
# 2. thedevastator/glaive-python-code-qa-dataset — explain
# ============================================================
print("\n" + "=" * 50)
print("2. Loading thedevastator/glaive-python-code-qa-dataset...")
output2 = os.path.join("data", "sft", "glaive_explain_pairs.jsonl")

try:
    ds = load_dataset(
        "thedevastator/glaive-python-code-qa-dataset",
        split="train",
        streaming=True
    )

    first = True
    pairs = []
    for sample in ds:
        if first:
            print(f"  Fields: {list(sample.keys())}")
            first = False

        question = ""
        answer = ""

        for key in sample:
            val = str(sample[key]).strip()
            key_lower = key.lower()
            if any(w in key_lower for w in ["question", "instruction", "input", "prompt"]):
                question = val
            elif any(w in key_lower for w in ["answer", "output", "response", "completion"]):
                answer = val

        if not question or not answer:
            texts = [(k, str(v).strip()) for k, v in sample.items()
                    if isinstance(v, str) and len(str(v)) > 30]
            if len(texts) >= 2:
                question = texts[0][1]
                answer = texts[1][1]

        if not question or not answer:
            continue
        if len(question) > 2000 or len(answer) > 3000:
            continue

        pair = {
            "messages": [
                {"role": "user", "content": f"<EXPLAIN>\n{question}\n</EXPLAIN>"},
                {"role": "assistant", "content": answer}
            ]
        }
        pairs.append(pair)

        if len(pairs) % 1000 == 0:
            print(f"  glaive: {len(pairs)} pairs...")

        if len(pairs) >= 2000:
            break

    with open(output2, "w", encoding="utf-8") as f:
        for p in pairs:
            f.write(json.dumps(p) + "\n")
    print(f"  Saved {len(pairs)} pairs to {output2}")

except Exception as e:
    print(f"  glaive error: {e}")

# ============================================================
# 3. inclusionAI/Ling-Coder-SFT — Python code SFT
# ============================================================
print("\n" + "=" * 50)
print("3. Loading inclusionAI/Ling-Coder-SFT (Python only)...")
output3 = os.path.join("data", "sft", "lingcoder_pairs.jsonl")

try:
    ds = load_dataset("inclusionAI/Ling-Coder-SFT", split="train", streaming=True)

    first = True
    pairs = []
    for sample in ds:
        if first:
            print(f"  Fields: {list(sample.keys())}")
            first = False

        # Try to get messages or instruction/output format
        messages = sample.get("messages", None)
        
        if messages and isinstance(messages, list) and len(messages) >= 2:
            user_msg = ""
            assistant_msg = ""
            for msg in messages:
                role = msg.get("role", "")
                content = str(msg.get("content", "")).strip()
                if role == "user" and not user_msg:
                    user_msg = content
                elif role == "assistant" and not assistant_msg:
                    assistant_msg = content

            if not user_msg or not assistant_msg:
                continue

            # Filter for Python
            python_signals = ["python", "def ", "import ", "class ", "print(",
                              ".py", "flask", "django"]
            is_python = any(s in user_msg.lower() or s in assistant_msg.lower()
                           for s in python_signals)
            if not is_python:
                continue

            if len(user_msg) > 2000 or len(assistant_msg) > 3000:
                continue

            pair = {
                "messages": [
                    {"role": "user", "content": f"<GENERATE>\n{user_msg}\n</GENERATE>"},
                    {"role": "assistant", "content": assistant_msg}
                ]
            }
            pairs.append(pair)
        else:
            # Try instruction/output format
            instruction = str(sample.get("instruction", sample.get("input", ""))).strip()
            output_text = str(sample.get("output", sample.get("response", ""))).strip()

            if not instruction or not output_text:
                continue

            python_signals = ["python", "def ", "import ", "class ", "print("]
            is_python = any(s in instruction.lower() or s in output_text.lower()
                           for s in python_signals)
            if not is_python:
                continue

            if len(instruction) > 2000 or len(output_text) > 3000:
                continue

            pair = {
                "messages": [
                    {"role": "user", "content": f"<GENERATE>\n{instruction}\n</GENERATE>"},
                    {"role": "assistant", "content": output_text}
                ]
            }
            pairs.append(pair)

        if len(pairs) % 500 == 0:
            print(f"  Ling-Coder: {len(pairs)} Python pairs...")

        if len(pairs) >= 2000:
            break

    with open(output3, "w", encoding="utf-8") as f:
        for p in pairs:
            f.write(json.dumps(p) + "\n")
    print(f"  Saved {len(pairs)} pairs to {output3}")

except Exception as e:
    print(f"  Ling-Coder error: {e}")

# ============================================================
# 4. microsoft/rStar-Coder — code reasoning
# ============================================================
print("\n" + "=" * 50)
print("4. Loading microsoft/rStar-Coder...")
output4 = os.path.join("data", "sft", "rstarcoder_pairs.jsonl")

try:
    ds = load_dataset("microsoft/rStar-Coder", split="train", streaming=True)

    first = True
    pairs = []
    for sample in ds:
        if first:
            print(f"  Fields: {list(sample.keys())}")
            first = False

        messages = sample.get("messages", None)
        question = ""
        answer = ""

        if messages and isinstance(messages, list) and len(messages) >= 2:
            for msg in messages:
                role = msg.get("role", "")
                content = str(msg.get("content", "")).strip()
                if role == "user" and not question:
                    question = content
                elif role == "assistant" and not answer:
                    answer = content
        else:
            question = str(sample.get("question", sample.get("instruction", sample.get("input", "")))).strip()
            answer = str(sample.get("answer", sample.get("output", sample.get("response", "")))).strip()

        if not question or not answer:
            continue

        python_signals = ["python", "def ", "import ", "class ", "print("]
        is_python = any(s in question.lower() or s in answer.lower()
                       for s in python_signals)
        if not is_python:
            continue

        if len(question) > 2000 or len(answer) > 4000:
            continue

        pair = {
            "messages": [
                {"role": "user", "content": f"<EXPLAIN>\n{question}\n</EXPLAIN>"},
                {"role": "assistant", "content": answer}
            ]
        }
        pairs.append(pair)

        if len(pairs) % 500 == 0:
            print(f"  rStar-Coder: {len(pairs)} Python pairs...")

        if len(pairs) >= 2000:
            break

    with open(output4, "w", encoding="utf-8") as f:
        for p in pairs:
            f.write(json.dumps(p) + "\n")
    print(f"  Saved {len(pairs)} pairs to {output4}")

except Exception as e:
    print(f"  rStar-Coder error: {e}")

# ============================================================
# 5. m-a-p/CodeFeedback-Filtered-Instruction
# ============================================================
print("\n" + "=" * 50)
print("5. Loading m-a-p/CodeFeedback-Filtered-Instruction...")
output5 = os.path.join("data", "sft", "codefeedback_pairs.jsonl")

try:
    ds = load_dataset(
        "m-a-p/CodeFeedback-Filtered-Instruction",
        split="train",
        streaming=True
    )

    first = True
    pairs = []
    for sample in ds:
        if first:
            print(f"  Fields: {list(sample.keys())}")
            first = False

        messages = sample.get("messages", None)
        question = ""
        answer = ""

        if messages and isinstance(messages, list) and len(messages) >= 2:
            for msg in messages:
                role = msg.get("role", "")
                content = str(msg.get("content", "")).strip()
                if role == "user" and not question:
                    question = content
                elif role == "assistant" and not answer:
                    answer = content
        else:
            question = str(sample.get("query", sample.get("instruction", ""))).strip()
            answer = str(sample.get("answer", sample.get("response", sample.get("output", "")))).strip()

        if not question or not answer:
            continue

        # Filter for Python code generation requests
        python_signals = ["python", "def ", "import ", "class ", "print(",
                          "write a function", "write a program", "implement"]
        is_python = any(s in question.lower() or s in answer.lower()
                       for s in python_signals)
        if not is_python:
            continue

        if len(question) > 2000 or len(answer) > 3000:
            continue

        pair = {
            "messages": [
                {"role": "user", "content": f"<GENERATE>\n{question}\n</GENERATE>"},
                {"role": "assistant", "content": answer}
            ]
        }
        pairs.append(pair)

        if len(pairs) % 500 == 0:
            print(f"  CodeFeedback: {len(pairs)} Python pairs...")

        if len(pairs) >= 2000:
            break

    with open(output5, "w", encoding="utf-8") as f:
        for p in pairs:
            f.write(json.dumps(p) + "\n")
    print(f"  Saved {len(pairs)} pairs to {output5}")

except Exception as e:
    print(f"  CodeFeedback error: {e}")

# ============================================================
# Summary
# ============================================================
print("\n" + "=" * 50)
print("COLLECTION SUMMARY")
print("=" * 50)
files = [
    ("securecode-web (scan)", output1),
    ("glaive QA (explain)", output2),
    ("Ling-Coder (generate)", output3),
    ("rStar-Coder (explain)", output4),
    ("CodeFeedback (generate)", output5),
]
total = 0
for name, path in files:
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            c = sum(1 for line in f if line.strip())
        print(f"  {name}: {c} pairs")
        total += c
    else:
        print(f"  {name}: FAILED")
print(f"\n  Total new pairs: {total}")
