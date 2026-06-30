# ============================================================
# PART 2: collect_vuln_pairs.py
# Runs Bandit on downloaded repos and converts findings to SFT pairs
# Requires: pip install bandit
# Run AFTER collect_github.py (needs the repos)
# Output: data/sft/bandit_vuln_pairs.jsonl
# ============================================================
import os
import json
import subprocess

os.makedirs(os.path.join("data", "sft"), exist_ok=True)

repos_dir = os.path.join("data", "pretrain", "repos")
output_path = os.path.join("data", "sft", "bandit_vuln_pairs.jsonl")

# CWE mapping for common Bandit test IDs
bandit_to_cwe = {
    "B101": "CWE-703: Improper Check — use of assert in production code",
    "B102": "CWE-78: OS Command Injection — exec() used",
    "B103": "CWE-276: Insecure file permissions",
    "B104": "CWE-200: Binding to all interfaces (0.0.0.0)",
    "B105": "CWE-798: Hardcoded Password",
    "B106": "CWE-798: Hardcoded Password in function argument",
    "B107": "CWE-798: Hardcoded Password in default argument",
    "B108": "CWE-377: Insecure temp file usage",
    "B110": "CWE-390: Try/except/pass — silently catching exceptions",
    "B112": "CWE-390: Try/except/continue — silently catching exceptions",
    "B201": "CWE-78: Flask debug mode enabled",
    "B301": "CWE-502: Unsafe pickle usage",
    "B302": "CWE-78: Unsafe marshal usage",
    "B303": "CWE-328: Insecure hash function (MD5/SHA1)",
    "B304": "CWE-327: Insecure cipher usage",
    "B305": "CWE-327: Insecure cipher mode",
    "B306": "CWE-377: Insecure temp file creation",
    "B307": "CWE-78: eval() used",
    "B308": "CWE-79: mark_safe() used in Django",
    "B310": "CWE-918: URL open with user input",
    "B311": "CWE-330: Random not suitable for security",
    "B312": "CWE-295: Telnet usage — no encryption",
    "B313": "CWE-611: XML parsing vulnerable to entity expansion",
    "B320": "CWE-79: lxml HTML parsing without sanitization",
    "B321": "CWE-295: FTP usage — no encryption",
    "B323": "CWE-295: SSL — unverified context",
    "B324": "CWE-328: Insecure hash function",
    "B501": "CWE-295: SSL verify=False",
    "B502": "CWE-295: SSL with no version check",
    "B503": "CWE-295: SSL with insecure version",
    "B504": "CWE-295: SSL with no cert verification",
    "B506": "CWE-250: Unsafe YAML load",
    "B507": "CWE-295: SSH no host key verification",
    "B601": "CWE-78: Paramiko shell command",
    "B602": "CWE-78: subprocess with shell=True",
    "B603": "CWE-78: subprocess without shell",
    "B604": "CWE-78: Function call with shell=True",
    "B605": "CWE-78: os.system() call",
    "B606": "CWE-78: os.popen() call",
    "B607": "CWE-78: Partial executable path",
    "B608": "CWE-89: SQL injection — string formatting in query",
    "B609": "CWE-78: Wildcard injection",
    "B610": "CWE-78: Django extra() SQL injection",
    "B611": "CWE-78: Django RawSQL usage",
    "B701": "CWE-79: Jinja2 autoescape disabled",
    "B702": "CWE-79: Mako template injection",
    "B703": "CWE-79: Django mark_safe on user input",
}

pairs = []

# Walk through each repo directory
for repo_dir in os.listdir(repos_dir):
    full_path = os.path.join(repos_dir, repo_dir)
    if not os.path.isdir(full_path):
        continue

    print(f"Scanning {repo_dir} with Bandit...")

    try:
        result = subprocess.run(
            ["bandit", "-r", full_path, "-f", "json", "-q"],
            capture_output=True,
            text=True,
            timeout=120,
            encoding="utf-8",
            errors="ignore"
        )
        
        if not result.stdout:
            continue

        findings = json.loads(result.stdout)

        for finding in findings.get("results", []):
            test_id = finding.get("test_id", "")
            filename = finding.get("filename", "")
            line_number = finding.get("line_number", 0)
            code = finding.get("code", "").strip()
            severity = finding.get("issue_severity", "LOW")
            confidence = finding.get("issue_confidence", "LOW")
            issue_text = finding.get("issue_text", "")

            # Skip low confidence findings
            if confidence == "LOW":
                continue

            # Skip if no code snippet
            if not code or len(code) < 20:
                continue

            # Read surrounding context (10 lines before and after)
            try:
                with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                    all_lines = f.readlines()
                    start = max(0, line_number - 10)
                    end = min(len(all_lines), line_number + 10)
                    context = ''.join(all_lines[start:end])
            except:
                context = code

            # Skip if context is too long
            if len(context) > 3000:
                context = code

            # Build the CWE description
            cwe_desc = bandit_to_cwe.get(test_id, f"Security Issue ({test_id})")

            # Create the SFT pair
            pair = {
                "messages": [
                    {
                        "role": "user",
                        "content": f"<SCAN>\n{context}\n</SCAN>"
                    },
                    {
                        "role": "assistant",
                        "content": f"{cwe_desc}\nLine {line_number}: {issue_text}\nSeverity: {severity}\nConfidence: {confidence}"
                    }
                ]
            }
            pairs.append(pair)

    except subprocess.TimeoutExpired:
        print(f"  Timeout scanning {repo_dir}")
    except json.JSONDecodeError:
        print(f"  No findings in {repo_dir}")
    except Exception as e:
        print(f"  Error: {e}")

# Save
with open(output_path, "w", encoding="utf-8") as f:
    for pair in pairs:
        f.write(json.dumps(pair) + "\n")

print(f"\nSaved {len(pairs)} vulnerability pairs to {output_path}")
