# ============================================================
# collect_high_priority.py
# Collects vulnerability + fix pairs from:
#   1. SEC-bench (HuggingFace)
#   2. CVEfixes (GitHub)
#   3. FixJS (GitHub)
#   4. SecJS-Benchmark (GitHub)
#   5. Kaggle datasets (after manual download)
#
# Run: python collect_high_priority.py
# ============================================================
import os
import json
import csv
import urllib.request
import zipfile

os.makedirs(os.path.join("data", "sft"), exist_ok=True)
os.makedirs(os.path.join("data", "downloads"), exist_ok=True)

# ============================================================
# 1. SEC-bench (HuggingFace — easiest)
# ============================================================
print("=" * 60)
print("1. SEC-bench from HuggingFace")
print("=" * 60)
output1 = os.path.join("data", "sft", "secbench_pairs.jsonl")

try:
    from datasets import load_dataset

    ds = load_dataset("SEC-bench/SEC-bench", split="train", streaming=True)

    first = True
    pairs = []

    for sample in ds:
        if first:
            print(f"  Fields: {list(sample.keys())}")
            for key in list(sample.keys())[:8]:
                val = str(sample[key])[:200]
                print(f"    {key}: {val}")
            first = False

        # Try to find vuln code and fix
        vuln_code = ""
        fixed_code = ""
        description = ""
        cwe = ""

        for key in sample:
            val = str(sample[key]).strip()
            key_lower = key.lower()

            if any(w in key_lower for w in ["vuln", "insecure", "buggy", "before", "bad", "original", "source"]):
                if len(val) > 20:
                    vuln_code = val
            elif any(w in key_lower for w in ["fix", "secure", "patch", "after", "correct", "target"]):
                if len(val) > 20:
                    fixed_code = val
            elif any(w in key_lower for w in ["desc", "message", "summary", "explanation"]):
                description = val
            elif "cwe" in key_lower:
                cwe = val
            elif key_lower in ["func_before", "code_before", "vulnerable_code"]:
                vuln_code = val
            elif key_lower in ["func_after", "code_after", "fixed_code"]:
                fixed_code = val

        # Fallback: use first two large text fields
        if not vuln_code or not fixed_code:
            texts = [(k, str(v).strip()) for k, v in sample.items()
                    if isinstance(v, str) and len(str(v)) > 50]
            if len(texts) >= 2:
                vuln_code = texts[0][1]
                fixed_code = texts[1][1]

        if not vuln_code or len(vuln_code) < 20:
            continue
        if len(vuln_code) > 3000:
            continue

        # Build response
        response_parts = []
        if cwe:
            response_parts.append(f"{cwe}")
        if description:
            response_parts.append(f"{description}")
        if fixed_code:
            response_parts.append(f"\nFixed code:\n{fixed_code}")

        response = "\n".join(response_parts) if response_parts else f"Vulnerability detected.\n\nFixed code:\n{fixed_code}"

        pairs.append({
            "messages": [
                {"role": "user", "content": f"<SCAN>\n{vuln_code}\n</SCAN>"},
                {"role": "assistant", "content": response}
            ]
        })

        if len(pairs) % 500 == 0 and len(pairs) > 0:
            print(f"  {len(pairs)} pairs...")

        if len(pairs) >= 3000:
            break

    with open(output1, "w", encoding="utf-8") as f:
        for p in pairs:
            f.write(json.dumps(p) + "\n")
    print(f"  Saved {len(pairs)} pairs to {output1}")

except Exception as e:
    print(f"  SEC-bench error: {e}")
    print("  Try: pip install datasets")

# ============================================================
# 2. CVEfixes (GitHub — clone and extract)
# ============================================================
print("\n" + "=" * 60)
print("2. CVEfixes from GitHub")
print("=" * 60)
output2 = os.path.join("data", "sft", "cvefixes_pairs.jsonl")

cvefixes_dir = os.path.join("data", "downloads", "CVEfixes")

try:
    # Download the repo
    if not os.path.exists(cvefixes_dir):
        print("  Downloading CVEfixes repo...")
        zip_url = "https://github.com/secureIT-project/CVEfixes/archive/refs/heads/main.zip"
        zip_path = os.path.join("data", "downloads", "cvefixes.zip")
        urllib.request.urlretrieve(zip_url, zip_path)
        with zipfile.ZipFile(zip_path, 'r') as z:
            z.extractall(os.path.join("data", "downloads"))
        os.remove(zip_path)
        # Rename extracted folder
        for d in os.listdir(os.path.join("data", "downloads")):
            if d.startswith("CVEfixes"):
                os.rename(
                    os.path.join("data", "downloads", d),
                    cvefixes_dir
                )
                break
        print("  Downloaded!")

    # Look for CSV/JSON data files
    pairs = []
    data_files = []

    for root, dirs, files in os.walk(cvefixes_dir):
        for f in files:
            if f.endswith(('.csv', '.json', '.jsonl')):
                data_files.append(os.path.join(root, f))

    print(f"  Found {len(data_files)} data files")
    for df in data_files[:5]:
        print(f"    {df}")

    for data_file in data_files:
        try:
            if data_file.endswith('.csv'):
                with open(data_file, 'r', encoding='utf-8', errors='ignore') as f:
                    reader = csv.DictReader(f)
                    first_row = True
                    for row in reader:
                        if first_row:
                            print(f"  CSV fields in {os.path.basename(data_file)}: {list(row.keys())[:10]}")
                            first_row = False

                        vuln_code = ""
                        fixed_code = ""
                        cwe = ""
                        desc = ""

                        for key, val in row.items():
                            if not val:
                                continue
                            key_lower = key.lower()
                            if any(w in key_lower for w in ["before", "vuln", "buggy", "old"]):
                                vuln_code = val
                            elif any(w in key_lower for w in ["after", "fix", "patch", "new"]):
                                fixed_code = val
                            elif "cwe" in key_lower:
                                cwe = val
                            elif any(w in key_lower for w in ["desc", "message", "commit_message"]):
                                desc = val

                        if vuln_code and fixed_code and len(vuln_code) > 20 and len(vuln_code) < 3000:
                            response = ""
                            if cwe:
                                response += f"{cwe}\n"
                            if desc:
                                response += f"{desc}\n"
                            response += f"\nFixed code:\n{fixed_code}"

                            pairs.append({
                                "messages": [
                                    {"role": "user", "content": f"<SCAN>\n{vuln_code}\n</SCAN>"},
                                    {"role": "assistant", "content": response}
                                ]
                            })

            elif data_file.endswith('.json'):
                with open(data_file, 'r', encoding='utf-8', errors='ignore') as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        print(f"  JSON array with {len(data)} items in {os.path.basename(data_file)}")
                        if data:
                            print(f"  Keys: {list(data[0].keys())[:10]}")

            elif data_file.endswith('.jsonl'):
                with open(data_file, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                row = json.loads(line)
                                # Same extraction logic as CSV
                                vuln_code = ""
                                fixed_code = ""
                                for key, val in row.items():
                                    if not val:
                                        continue
                                    key_lower = key.lower()
                                    if any(w in key_lower for w in ["before", "vuln", "buggy"]):
                                        vuln_code = str(val)
                                    elif any(w in key_lower for w in ["after", "fix", "patch"]):
                                        fixed_code = str(val)
                                if vuln_code and fixed_code and len(vuln_code) > 20:
                                    pairs.append({
                                        "messages": [
                                            {"role": "user", "content": f"<SCAN>\n{vuln_code}\n</SCAN>"},
                                            {"role": "assistant", "content": f"Vulnerability detected.\n\nFixed code:\n{fixed_code}"}
                                        ]
                                    })
                            except:
                                pass

        except Exception as e:
            print(f"  Error processing {data_file}: {e}")

    with open(output2, "w", encoding="utf-8") as f:
        for p in pairs:
            f.write(json.dumps(p) + "\n")
    print(f"  Saved {len(pairs)} pairs to {output2}")

except Exception as e:
    print(f"  CVEfixes error: {e}")

# ============================================================
# 3. morefixes (GitHub)
# ============================================================
print("\n" + "=" * 60)
print("3. morefixes from GitHub")
print("=" * 60)
output3 = os.path.join("data", "sft", "morefixes_pairs.jsonl")

morefixes_dir = os.path.join("data", "downloads", "morefixes")

try:
    if not os.path.exists(morefixes_dir):
        print("  Downloading morefixes repo...")
        zip_url = "https://github.com/JafarAkhondali/morefixes/archive/refs/heads/main.zip"
        zip_path = os.path.join("data", "downloads", "morefixes.zip")
        urllib.request.urlretrieve(zip_url, zip_path)
        with zipfile.ZipFile(zip_path, 'r') as z:
            z.extractall(os.path.join("data", "downloads"))
        os.remove(zip_path)
        for d in os.listdir(os.path.join("data", "downloads")):
            if d.startswith("morefixes"):
                os.rename(
                    os.path.join("data", "downloads", d),
                    morefixes_dir
                )
                break
        print("  Downloaded!")

    # Look for data files
    pairs = []
    data_files = []

    for root, dirs, files in os.walk(morefixes_dir):
        for f in files:
            if f.endswith(('.csv', '.json', '.jsonl', '.parquet')):
                data_files.append(os.path.join(root, f))

    print(f"  Found {len(data_files)} data files")
    for df in data_files[:10]:
        print(f"    {os.path.relpath(df, morefixes_dir)}")

    # Process each data file
    for data_file in data_files:
        try:
            if data_file.endswith('.csv'):
                with open(data_file, 'r', encoding='utf-8', errors='ignore') as f:
                    reader = csv.DictReader(f)
                    first_row = True
                    for row in reader:
                        if first_row:
                            print(f"  Fields: {list(row.keys())[:10]}")
                            first_row = False

                        vuln = ""
                        fixed = ""
                        lang = ""
                        cwe = ""

                        for key, val in row.items():
                            if not val:
                                continue
                            kl = key.lower()
                            if any(w in kl for w in ["before", "vuln", "buggy", "old_code", "removed"]):
                                vuln = val
                            elif any(w in kl for w in ["after", "fix", "patch", "new_code", "added"]):
                                fixed = val
                            elif "lang" in kl:
                                lang = val.lower()
                            elif "cwe" in kl:
                                cwe = val

                        # Filter for Python/JS/TS
                        if lang and lang not in ["python", "javascript", "typescript", "py", "js", "ts", ""]:
                            continue

                        if vuln and fixed and len(vuln) > 20 and len(vuln) < 3000:
                            resp = f"Vulnerability detected.\n"
                            if cwe:
                                resp += f"{cwe}\n"
                            resp += f"\nFixed code:\n{fixed}"
                            pairs.append({
                                "messages": [
                                    {"role": "user", "content": f"<SCAN>\n{vuln}\n</SCAN>"},
                                    {"role": "assistant", "content": resp}
                                ]
                            })

            elif data_file.endswith('.json'):
                with open(data_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()[:100]
                    print(f"  JSON preview: {content}")

        except Exception as e:
            print(f"  Error: {e}")

    with open(output3, "w", encoding="utf-8") as f:
        for p in pairs:
            f.write(json.dumps(p) + "\n")
    print(f"  Saved {len(pairs)} pairs to {output3}")

except Exception as e:
    print(f"  morefixes error: {e}")

# ============================================================
# 4. FixJS (GitHub — JavaScript fixes)
# ============================================================
print("\n" + "=" * 60)
print("4. FixJS from GitHub")
print("=" * 60)
output4 = os.path.join("data", "sft", "fixjs_pairs.jsonl")

fixjs_dir = os.path.join("data", "downloads", "FixJS")

try:
    if not os.path.exists(fixjs_dir):
        print("  Downloading FixJS repo...")
        zip_url = "https://github.com/AAI-USZ/FixJS/archive/refs/heads/main.zip"
        zip_path = os.path.join("data", "downloads", "fixjs.zip")
        urllib.request.urlretrieve(zip_url, zip_path)
        with zipfile.ZipFile(zip_path, 'r') as z:
            z.extractall(os.path.join("data", "downloads"))
        os.remove(zip_path)
        for d in os.listdir(os.path.join("data", "downloads")):
            if d.startswith("FixJS"):
                os.rename(
                    os.path.join("data", "downloads", d),
                    fixjs_dir
                )
                break
        print("  Downloaded!")

    pairs = []
    data_files = []

    for root, dirs, files in os.walk(fixjs_dir):
        for f in files:
            if f.endswith(('.csv', '.json', '.jsonl')):
                data_files.append(os.path.join(root, f))

    print(f"  Found {len(data_files)} data files")
    for df in data_files[:10]:
        print(f"    {os.path.relpath(df, fixjs_dir)}")

    for data_file in data_files:
        try:
            if data_file.endswith('.csv'):
                with open(data_file, 'r', encoding='utf-8', errors='ignore') as f:
                    reader = csv.DictReader(f)
                    first_row = True
                    for row in reader:
                        if first_row:
                            print(f"  Fields: {list(row.keys())[:10]}")
                            first_row = False

                        vuln = ""
                        fixed = ""
                        for key, val in row.items():
                            if not val:
                                continue
                            kl = key.lower()
                            if any(w in kl for w in ["before", "vuln", "buggy", "old", "source"]):
                                vuln = val
                            elif any(w in kl for w in ["after", "fix", "patch", "new", "target"]):
                                fixed = val

                        if vuln and fixed and len(vuln) > 20 and len(vuln) < 3000:
                            pairs.append({
                                "messages": [
                                    {"role": "user", "content": f"<SCAN>\n{vuln}\n</SCAN>"},
                                    {"role": "assistant", "content": f"JavaScript vulnerability detected.\n\nFixed code:\n{fixed}"}
                                ]
                            })

            elif data_file.endswith('.json'):
                with open(data_file, 'r', encoding='utf-8', errors='ignore') as f:
                    data = json.load(f)
                    if isinstance(data, list) and data:
                        print(f"  JSON: {len(data)} items, keys: {list(data[0].keys())[:8]}")

        except Exception as e:
            print(f"  Error: {e}")

    with open(output4, "w", encoding="utf-8") as f:
        for p in pairs:
            f.write(json.dumps(p) + "\n")
    print(f"  Saved {len(pairs)} pairs to {output4}")

except Exception as e:
    print(f"  FixJS error: {e}")

# ============================================================
# 5. SecJS-Benchmark (GitHub — JS vulnerability benchmark)
# ============================================================
print("\n" + "=" * 60)
print("5. SecJS-Benchmark from GitHub")
print("=" * 60)
output5 = os.path.join("data", "sft", "secjs_pairs.jsonl")

secjs_dir = os.path.join("data", "downloads", "SecJS")

try:
    if not os.path.exists(secjs_dir):
        print("  Downloading SecJS-Benchmark repo...")
        zip_url = "https://github.com/SecJS-Vuln-Benchmark/SecJS-Benchmark/archive/refs/heads/main.zip"
        zip_path = os.path.join("data", "downloads", "secjs.zip")
        urllib.request.urlretrieve(zip_url, zip_path)
        with zipfile.ZipFile(zip_path, 'r') as z:
            z.extractall(os.path.join("data", "downloads"))
        os.remove(zip_path)
        for d in os.listdir(os.path.join("data", "downloads")):
            if d.startswith("SecJS"):
                os.rename(
                    os.path.join("data", "downloads", d),
                    secjs_dir
                )
                break
        print("  Downloaded!")

    pairs = []

    # Look for JS/JSON files with vulnerable code
    for root, dirs, files in os.walk(secjs_dir):
        for f in files:
            if f.endswith(('.json', '.csv', '.jsonl')):
                filepath = os.path.join(root, f)
                try:
                    if f.endswith('.json'):
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as fh:
                            data = json.load(fh)
                            if isinstance(data, list) and data:
                                print(f"  {f}: {len(data)} items, keys: {list(data[0].keys())[:8]}")
                                for item in data:
                                    vuln = ""
                                    fixed = ""
                                    cwe = ""
                                    for key, val in item.items():
                                        if not val:
                                            continue
                                        kl = key.lower()
                                        if any(w in kl for w in ["vuln", "before", "buggy", "source", "code"]):
                                            vuln = str(val)
                                        elif any(w in kl for w in ["fix", "after", "patch", "target"]):
                                            fixed = str(val)
                                        elif "cwe" in kl:
                                            cwe = str(val)

                                    if vuln and len(vuln) > 20 and len(vuln) < 3000:
                                        resp = f"JavaScript vulnerability detected.\n"
                                        if cwe:
                                            resp += f"{cwe}\n"
                                        if fixed:
                                            resp += f"\nFixed code:\n{fixed}"
                                        pairs.append({
                                            "messages": [
                                                {"role": "user", "content": f"<SCAN>\n{vuln}\n</SCAN>"},
                                                {"role": "assistant", "content": resp}
                                            ]
                                        })

                    elif f.endswith('.csv'):
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as fh:
                            reader = csv.DictReader(fh)
                            first_row = True
                            for row in reader:
                                if first_row:
                                    print(f"  {f} fields: {list(row.keys())[:10]}")
                                    first_row = False
                                vuln = ""
                                fixed = ""
                                for key, val in row.items():
                                    if not val:
                                        continue
                                    kl = key.lower()
                                    if any(w in kl for w in ["before", "vuln", "buggy"]):
                                        vuln = val
                                    elif any(w in kl for w in ["after", "fix", "patch"]):
                                        fixed = val
                                if vuln and fixed and len(vuln) > 20 and len(vuln) < 3000:
                                    pairs.append({
                                        "messages": [
                                            {"role": "user", "content": f"<SCAN>\n{vuln}\n</SCAN>"},
                                            {"role": "assistant", "content": f"JavaScript vulnerability detected.\n\nFixed code:\n{fixed}"}
                                        ]
                                    })
                except Exception as e:
                    pass

    with open(output5, "w", encoding="utf-8") as f:
        for p in pairs:
            f.write(json.dumps(p) + "\n")
    print(f"  Saved {len(pairs)} pairs to {output5}")

except Exception as e:
    print(f"  SecJS error: {e}")

# ============================================================
# 6. Kaggle datasets (MANUAL DOWNLOAD REQUIRED)
# ============================================================
print("\n" + "=" * 60)
print("6. Kaggle datasets")
print("=" * 60)

kaggle_vuln_fix = os.path.join("data", "downloads", "vulnerability-fix-dataset")
kaggle_cve_fix = os.path.join("data", "downloads", "cve-fix-pairs")
output6 = os.path.join("data", "sft", "kaggle_vuln_pairs.jsonl")

print("  Kaggle datasets require manual download:")
print("  1. Go to kaggle.com/datasets/jiscecseaiml/vulnerability-fix-dataset")
print("     Download and extract to data/downloads/vulnerability-fix-dataset/")
print("  2. Go to kaggle.com/datasets/hasaber8/cve-fix-pairs")
print("     Download and extract to data/downloads/cve-fix-pairs/")
print("")

pairs = []

for kaggle_dir, name in [(kaggle_vuln_fix, "vulnerability-fix"), (kaggle_cve_fix, "cve-fix-pairs")]:
    if not os.path.exists(kaggle_dir):
        print(f"  {name}: NOT FOUND (download from Kaggle first)")
        continue

    print(f"  Processing {name}...")
    for root, dirs, files in os.walk(kaggle_dir):
        for f in files:
            if f.endswith('.csv'):
                filepath = os.path.join(root, f)
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as fh:
                        reader = csv.DictReader(fh)
                        first_row = True
                        for row in reader:
                            if first_row:
                                print(f"    {f} fields: {list(row.keys())[:10]}")
                                first_row = False

                            vuln = ""
                            fixed = ""
                            cwe = ""
                            lang = ""
                            desc = ""

                            for key, val in row.items():
                                if not val:
                                    continue
                                kl = key.lower()
                                if any(w in kl for w in ["before", "vuln", "buggy", "old", "source", "insecure"]):
                                    vuln = val
                                elif any(w in kl for w in ["after", "fix", "patch", "new", "target", "secure"]):
                                    fixed = val
                                elif "cwe" in kl:
                                    cwe = val
                                elif "lang" in kl:
                                    lang = val.lower()
                                elif any(w in kl for w in ["desc", "message", "summary"]):
                                    desc = val

                            # Filter for Python/JS/TS if language field exists
                            if lang and lang not in ["python", "javascript", "typescript", "py", "js", "ts", ""]:
                                continue

                            if vuln and len(vuln) > 20 and len(vuln) < 3000:
                                resp = ""
                                if cwe:
                                    resp += f"{cwe}\n"
                                if desc:
                                    resp += f"{desc}\n"
                                if fixed:
                                    resp += f"\nFixed code:\n{fixed}"
                                else:
                                    resp += "Vulnerability detected."

                                pairs.append({
                                    "messages": [
                                        {"role": "user", "content": f"<SCAN>\n{vuln}\n</SCAN>"},
                                        {"role": "assistant", "content": resp}
                                    ]
                                })

                except Exception as e:
                    print(f"    Error: {e}")

            elif f.endswith('.json'):
                filepath = os.path.join(root, f)
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as fh:
                        data = json.load(fh)
                        if isinstance(data, list) and data:
                            print(f"    {f}: {len(data)} items, keys: {list(data[0].keys())[:8]}")
                except:
                    pass

with open(output6, "w", encoding="utf-8") as f:
    for p in pairs:
        f.write(json.dumps(p) + "\n")
print(f"  Saved {len(pairs)} Kaggle pairs to {output6}")

# ============================================================
# SUMMARY
# ============================================================
print("\n" + "=" * 60)
print("COLLECTION SUMMARY")
print("=" * 60)

total = 0
outputs = [
    ("SEC-bench", output1),
    ("CVEfixes", output2),
    ("morefixes", output3),
    ("FixJS", output4),
    ("SecJS-Benchmark", output5),
    ("Kaggle datasets", output6),
]

for name, path in outputs:
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            count = sum(1 for line in f if line.strip())
        status = f"{count} pairs" if count > 0 else "0 pairs (check format)"
        total += count
    else:
        status = "FAILED"
    print(f"  {name:25s} {status}")

print(f"\n  Total new pairs: {total}")
print(f"\nNext steps:")
print(f"  1. Download Kaggle datasets manually if you haven't")
print(f"  2. Add new files to balance_sft.py")
print(f"  3. Run balance_sft.py")
print(f"  4. Retrain with train_qwen_sft.py")