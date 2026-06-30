# ============================================================
# collect_vuln_datasets.py
# CyberNative DPO + Python Vulnerability Remediation
# Output: data/sft/cybernative_vuln_pairs.jsonl
#         data/sft/python_remediation_pairs.jsonl
# ============================================================
import os
import json
from datasets import load_dataset

os.makedirs(os.path.join("data", "sft"), exist_ok=True)

# ============================================================
# Dataset 1: CyberNative/Code_Vulnerability_Security_DPO
# ============================================================
print("Loading CyberNative Code_Vulnerability_Security_DPO...")
output1 = os.path.join("data", "sft", "cybernative_vuln_pairs.jsonl")

try:
    ds1 = load_dataset("CyberNative/Code_Vulnerability_Security_DPO", split="train")

    pairs1 = []
    for sample in ds1:
        question = str(sample.get("question", "")).strip()
        chosen = str(sample.get("chosen", "")).strip()
        rejected = str(sample.get("rejected", "")).strip()

        if not question or not chosen or not rejected:
            continue

        python_signals = ["python", "def ", "import ", "class ", "print(",
                          "flask", "django", "sql", "subprocess", "os."]
        is_python = any(s in question.lower() or s in rejected.lower()
                       for s in python_signals)
        if not is_python:
            continue
        if len(rejected) > 3000 or len(chosen) > 3000:
            continue

        report = f"VULNERABLE CODE DETECTED\n\nInsecure version:\n{rejected}\n\nSecure version:\n{chosen}\n\nTask: {question}"
        pair = {
            "messages": [
                {"role": "user", "content": f"<SCAN>\n{rejected}\n</SCAN>"},
                {"role": "assistant", "content": report}
            ]
        }
        pairs1.append(pair)

        if len(pairs1) % 500 == 0:
            print(f"  CyberNative: {len(pairs1)} Python pairs...")

    with open(output1, "w", encoding="utf-8") as f:
        for pair in pairs1:
            f.write(json.dumps(pair) + "\n")
    print(f"Saved {len(pairs1)} pairs to {output1}")

except Exception as e:
    print(f"CyberNative error: {e}")

# ============================================================
# Dataset 2: cmonplz/Python_Vulnerability_Remediation
# ============================================================
print("\nLoading cmonplz/Python_Vulnerability_Remediation...")
output2 = os.path.join("data", "sft", "python_remediation_pairs.jsonl")

try:
    ds2 = load_dataset("cmonplz/Python_Vulnerability_Remediation", split="train")
    print(f"  Fields: {ds2.column_names}")

    pairs2 = []
    for sample in ds2:
        vuln_code = ""
        fixed_code = ""
        description = ""

        for key in sample:
            val = str(sample[key]).strip()
            key_lower = key.lower()
            if any(w in key_lower for w in ["vuln", "insecure", "bad", "unsafe", "original", "input"]):
                vuln_code = val
            elif any(w in key_lower for w in ["fix", "secure", "safe", "remediat", "patch", "correct", "output"]):
                fixed_code = val
            elif any(w in key_lower for w in ["desc", "explain", "cwe", "type", "instruction"]):
                description = val

        if not vuln_code and not fixed_code:
            text_fields = [str(v).strip() for v in sample.values()
                          if isinstance(v, str) and len(str(v)) > 50]
            if len(text_fields) >= 2:
                vuln_code = text_fields[0]
                fixed_code = text_fields[1]

        if not vuln_code or len(vuln_code) < 20 or len(vuln_code) > 3000:
            continue

        if fixed_code and description:
            response = f"{description}\n\nFix:\n{fixed_code}"
        elif fixed_code:
            response = f"Vulnerability detected.\n\nFixed version:\n{fixed_code}"
        elif description:
            response = description
        else:
            continue

        pair = {
            "messages": [
                {"role": "user", "content": f"<SCAN>\n{vuln_code}\n</SCAN>"},
                {"role": "assistant", "content": response}
            ]
        }
        pairs2.append(pair)

        if len(pairs2) % 500 == 0:
            print(f"  Remediation: {len(pairs2)} pairs...")

    with open(output2, "w", encoding="utf-8") as f:
        for pair in pairs2:
            f.write(json.dumps(pair) + "\n")
    print(f"Saved {len(pairs2)} pairs to {output2}")

except Exception as e:
    print(f"Python_Vulnerability_Remediation error: {e}")
