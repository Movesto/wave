# ============================================================
# collect_cvefixes_and_morefixes.py
#
# CVEfixes CSV format: code, language, safety
#   - safety = "vulnerable" or "safe"
#   - We create SCAN pairs from both!
#
# morefixes: .patch files with git diffs
#   - "-" lines (removed) -> vulnerable input
#   - "+" lines (added)   -> fixed input (clean code pair)
#   - Each diff produces TWO SCAN pairs: vuln + safe
#
# Usage:
#   python collect_cvefixes_and_morefixes.py                  # run all
#   python collect_cvefixes_and_morefixes.py morefixes        # run only morefixes
# ============================================================
import os
import json
import csv
import sys
import random

random.seed(42)
csv.field_size_limit(sys.maxsize)
os.makedirs(os.path.join("data", "sft"), exist_ok=True)

VALID_SECTIONS = {"cvefixes", "morefixes", "secbench"}
sections = set(a.lower() for a in sys.argv[1:]) if len(sys.argv) > 1 else VALID_SECTIONS
unknown = sections - VALID_SECTIONS
if unknown:
    print(f"Unknown sections: {unknown}. Valid: {VALID_SECTIONS}")
    sys.exit(1)
print(f"Running sections: {sorted(sections)}\n")

output1 = os.path.join("data", "sft", "cvefixes_pairs.jsonl")
output2 = os.path.join("data", "sft", "morefixes_pairs.jsonl")
output3 = os.path.join("data", "sft", "secbench_pairs.jsonl")


# ============================================================
# 1. CVEfixes CSV
# ============================================================
def process_cvefixes():
    print("=" * 60)
    print("1. Processing CVEfixes CSV")
    print("=" * 60)

    cvefixes_dir = os.path.join("data", "downloads", "CVEfixes")

    csv_file = None
    for f in os.listdir(cvefixes_dir):
        full = os.path.join(cvefixes_dir, f)
        if os.path.isfile(full) and os.path.getsize(full) > 100000000:
            csv_file = full
            print(f"  Found: {f} ({os.path.getsize(full)/(1024*1024):.0f} MB)")
            break

    if not csv_file:
        print("  ERROR: CSV file not found")
        return

    vuln_pairs = []
    safe_pairs = []
    count = 0
    skipped_lang = 0
    skipped_size = 0

    allowed_langs = {"python", "javascript", "typescript", "py", "js", "ts"}

    print("  Processing (this may take a few minutes)...")

    with open(csv_file, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)

        for row in reader:
            count += 1

            code = row.get("code", "").strip()
            language = row.get("language", "").strip().lower()
            safety = row.get("safety", "").strip().lower()

            if language not in allowed_langs:
                skipped_lang += 1
                continue

            if len(code) < 30 or len(code) > 3000:
                skipped_size += 1
                continue

            if safety == "vulnerable":
                vuln_pairs.append({
                    "messages": [
                        {"role": "user", "content": f"<SCAN>\n{code}\n</SCAN>"},
                        {"role": "assistant", "content": f"Vulnerability detected in {language} code.\n\nThis code contains a security flaw that could be exploited. Review for common vulnerability patterns such as injection, improper input validation, or unsafe data handling."}
                    ]
                })
            elif safety in ["safe", "fixed", "clean", "patched"]:
                safe_pairs.append({
                    "messages": [
                        {"role": "user", "content": f"<SCAN>\n{code}\n</SCAN>"},
                        {"role": "assistant", "content": f"No vulnerabilities detected. This {language} code follows secure coding practices."}
                    ]
                })

            if count % 100000 == 0:
                print(f"  {count:,} rows | vuln: {len(vuln_pairs):,} | safe: {len(safe_pairs):,} | skipped: {skipped_lang + skipped_size:,}")

    all_pairs = vuln_pairs + safe_pairs

    with open(output1, "w", encoding="utf-8") as f:
        for p in all_pairs:
            f.write(json.dumps(p) + "\n")

    print(f"\n  Total rows processed: {count:,}")
    print(f"  Skipped (wrong language): {skipped_lang:,}")
    print(f"  Skipped (too small/large): {skipped_size:,}")
    print(f"  Vulnerable pairs: {len(vuln_pairs):,}")
    print(f"  Safe pairs: {len(safe_pairs):,}")
    print(f"  TOTAL saved: {len(all_pairs):,} to {output1}")


# ============================================================
# 2. morefixes .patch files
# ============================================================
def process_morefixes():
    print("\n" + "=" * 60)
    print("2. Processing morefixes patch files")
    print("=" * 60)

    patches_dir = None
    candidates = [
        os.path.join("data", "downloads", "morefixes-patches", "cvedataset-patches"),
        os.path.join("data", "downloads", "morefixes-patches"),
        os.path.join("data", "downloads", "cvedataset-patches"),
    ]
    for c in candidates:
        if os.path.exists(c):
            files = [f for f in os.listdir(c) if f.endswith(".patch")]
            if files:
                patches_dir = c
                break
            for sub in os.listdir(c):
                sub_path = os.path.join(c, sub)
                if os.path.isdir(sub_path):
                    sub_files = [f for f in os.listdir(sub_path) if f.endswith(".patch")]
                    if sub_files:
                        patches_dir = sub_path
                        break

    if not patches_dir:
        print(f"  ERROR: Could not find patch files directory")
        print(f"  Checked: {candidates}")
        return

    patch_files = [f for f in os.listdir(patches_dir) if f.endswith(".patch")]
    print(f"  Found {len(patch_files):,} patch files in {patches_dir}")

    vuln_pairs = []
    safe_pairs = []
    processed = 0
    errors = 0
    no_code = 0

    for patch_file in patch_files:
        filepath = os.path.join(patches_dir, patch_file)

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            diffs = content.split("diff --git")

            for diff_section in diffs[1:]:
                lines = diff_section.split("\n")
                file_line = lines[0] if lines else ""

                is_python = file_line.endswith(".py")
                is_js = any(file_line.endswith(ext) for ext in [".js", ".jsx", ".ts", ".tsx"])

                if not is_python and not is_js:
                    continue

                lang = "Python" if is_python else "JavaScript"

                removed_lines = []
                added_lines = []
                context_before = []
                context_after = []

                in_hunk = False
                for line in lines:
                    if line.startswith("@@"):
                        in_hunk = True
                        continue
                    if not in_hunk:
                        continue

                    if line.startswith("---") or line.startswith("+++"):
                        continue
                    elif line.startswith("-"):
                        removed_lines.append(line[1:])
                    elif line.startswith("+"):
                        added_lines.append(line[1:])
                    elif line.startswith(" "):
                        if not removed_lines and not added_lines:
                            context_before.append(line[1:])
                        else:
                            context_after.append(line[1:])

                if not removed_lines or not added_lines:
                    no_code += 1
                    continue

                # Same surrounding context for both versions so the model sees
                # structurally similar snippets — one with the bug, one without.
                ctx_before = context_before[-5:]
                ctx_after = context_after[:3]

                vuln_code = "\n".join(ctx_before + removed_lines + ctx_after)
                safe_code = "\n".join(ctx_before + added_lines + ctx_after)
                fixed_blob = "\n".join(added_lines)

                if len(vuln_code) < 30 or len(vuln_code) > 3000:
                    continue
                if len(safe_code) < 30 or len(safe_code) > 3000:
                    continue
                if len(fixed_blob) < 10:
                    continue

                vuln_intro = random.choice([
                    f"Vulnerability detected in this {lang} code.",
                    f"Security issue found.",
                    f"This {lang} code contains a vulnerability.",
                    f"Vulnerability detected.",
                    f"Security flaw identified in this code.",
                ])

                safe_response = random.choice([
                    f"No vulnerabilities detected. The code uses safe practices.",
                    f"No security issues found in this code.",
                    f"This code looks secure — no obvious vulnerabilities.",
                    f"No vulnerabilities detected. Input handling and data flow look safe.",
                    f"No security issues detected in this {lang} code.",
                ])

                vuln_pairs.append({
                    "messages": [
                        {"role": "user", "content": f"<SCAN>\n{vuln_code}\n</SCAN>"},
                        {"role": "assistant", "content": f"{vuln_intro}\n\nFixed code:\n{fixed_blob}"}
                    ]
                })

                safe_pairs.append({
                    "messages": [
                        {"role": "user", "content": f"<SCAN>\n{safe_code}\n</SCAN>"},
                        {"role": "assistant", "content": safe_response}
                    ]
                })

            processed += 1

            if processed % 5000 == 0:
                total = len(vuln_pairs) + len(safe_pairs)
                print(f"  Processed {processed:,}/{len(patch_files):,} patches, {total:,} pairs ({len(vuln_pairs):,} vuln + {len(safe_pairs):,} safe)...")

        except Exception:
            errors += 1

    all_pairs = vuln_pairs + safe_pairs

    with open(output2, "w", encoding="utf-8") as f:
        for p in all_pairs:
            f.write(json.dumps(p) + "\n")

    print(f"\n  Patches processed: {processed:,}")
    print(f"  Patches with errors: {errors:,}")
    print(f"  Diffs without Python/JS code: {no_code:,}")
    print(f"  Vulnerable pairs: {len(vuln_pairs):,}")
    print(f"  Safe pairs: {len(safe_pairs):,}")
    print(f"  TOTAL saved: {len(all_pairs):,} to {output2}")


# ============================================================
# 3. SEC-bench
# ============================================================
def process_secbench():
    print("\n" + "=" * 60)
    print("3. SEC-bench from HuggingFace")
    print("=" * 60)

    try:
        from datasets import load_dataset

        pairs = []

        try:
            from datasets import get_dataset_config_names
            configs = get_dataset_config_names("SEC-bench/SEC-bench")
            print(f"  Available configs: {configs}")
        except Exception as e:
            print(f"  Could not list configs: {str(e)[:100]}")
            configs = [None]

        for config in configs:
            try:
                print(f"  Trying config: {config}")
                if config:
                    ds = load_dataset("SEC-bench/SEC-bench", config, split="train", streaming=True)
                else:
                    ds = load_dataset("SEC-bench/SEC-bench", split="train", streaming=True)

                first = True
                for sample in ds:
                    if first:
                        print(f"  Fields: {list(sample.keys())}")
                        for key in list(sample.keys())[:8]:
                            val = str(sample[key])[:150]
                            print(f"    {key}: {val}")
                        first = False

                    vuln = ""
                    fixed = ""
                    cwe = ""

                    for key in sample:
                        val = str(sample[key]).strip()
                        kl = key.lower()

                        if len(val) < 20:
                            continue

                        if any(w in kl for w in ["vuln", "before", "buggy", "source",
                                                  "func_before", "code_before", "input",
                                                  "original", "old"]):
                            if len(val) > len(vuln):
                                vuln = val
                        elif any(w in kl for w in ["fix", "after", "patch", "target",
                                                    "func_after", "code_after", "output",
                                                    "correct", "new"]):
                            if len(val) > len(fixed):
                                fixed = val
                        elif "cwe" in kl:
                            cwe = val

                    if not vuln:
                        for key in sample:
                            val = str(sample[key]).strip()
                            if len(val) > 50 and any(c in val for c in ["def ", "function ", "import ", "class "]):
                                vuln = val
                                break

                    if vuln and len(vuln) > 20 and len(vuln) < 3000:
                        resp = ""
                        if cwe:
                            resp += f"{cwe}\n"
                        if fixed:
                            resp += f"\nFixed code:\n{fixed}"
                        if not resp:
                            resp = "Vulnerability detected."

                        pairs.append({
                            "messages": [
                                {"role": "user", "content": f"<SCAN>\n{vuln}\n</SCAN>"},
                                {"role": "assistant", "content": resp}
                            ]
                        })

                    if len(pairs) >= 3000:
                        break

                if pairs:
                    print(f"  Got {len(pairs)} pairs from config '{config}'")
                    break

            except Exception as e:
                print(f"  Config '{config}' error: {str(e)[:100]}")

        if pairs:
            with open(output3, "w", encoding="utf-8") as f:
                for p in pairs:
                    f.write(json.dumps(p) + "\n")
            print(f"  Saved {len(pairs)} pairs to {output3}")
        else:
            print("  SEC-bench: No pairs extracted")

    except ImportError:
        print("  Install datasets: pip install datasets")
    except Exception as e:
        print(f"  Error: {e}")


# ============================================================
# Run selected sections
# ============================================================
if "cvefixes" in sections:
    process_cvefixes()
if "morefixes" in sections:
    process_morefixes()
if "secbench" in sections:
    process_secbench()


# ============================================================
# FINAL SUMMARY
# ============================================================
print("\n" + "=" * 60)
print("FINAL SUMMARY")
print("=" * 60)

total = 0
for name, path in [
    ("CVEfixes (vuln + safe)", output1),
    ("morefixes (vuln + safe)", output2),
    ("SEC-bench", output3),
    ("Kaggle vuln pairs (previous)", os.path.join("data", "sft", "kaggle_vuln_pairs.jsonl")),
]:
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            c = sum(1 for line in f if line.strip())
        print(f"  {name:35s} {c:>8,} pairs")
        total += c
    else:
        print(f"  {name:35s}  not found")

print(f"\n  TOTAL NEW PAIRS: {total:,}")
