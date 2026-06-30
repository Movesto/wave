# ============================================================
# PART 1C: collect_security_repos.py
# Downloads repos specifically about security/exploitation
# These teach the model security-relevant code patterns
# Output: data/pretrain/security_python.txt
# ============================================================
import os
import urllib.request
import zipfile

os.makedirs(os.path.join("data", "pretrain", "security_repos"), exist_ok=True)

security_repos = [
    # Vulnerability scanners and security tools
    "sqlmapproject/sqlmap",
    "commixproject/commix",
    "s0md3v/XSStrike",
    "maurosoria/dirsearch",
    "wapiti-scanner/wapiti",
    "Yelp/detect-secrets",
    "trufflesecurity/trufflehog",
    # Deliberately vulnerable apps (great for learning patterns)
    "digininja/DVWA",
    "juice-shop/juice-shop-ctf",
    # Security libraries
    "pyca/cryptography",
    "jpadilla/pyjwt",
    # Exploit frameworks
    "Gallopsled/pwntools",
    "stamparm/maltrail",
    # Code analysis
    "PyCQA/bandit",
    "returntocorp/semgrep",
    "PyCQA/flake8",
    # Web security
    "mitmproxy/mitmproxy",
    "nabla-c0d3/sslyze",
    # Auth and crypto
    "oauthlib/oauthlib",
    "lepture/authlib",
]

downloaded = 0
save_dir = os.path.join("data", "pretrain", "security_repos")

for repo in security_repos:
    name = repo.split("/")[1]
    zip_path = os.path.join(save_dir, f"{name}.zip")

    for branch in ["main", "master"]:
        url = f"https://github.com/{repo}/archive/refs/heads/{branch}.zip"
        try:
            print(f"Downloading {repo} ({branch})...")
            urllib.request.urlretrieve(url, zip_path)
            with zipfile.ZipFile(zip_path, 'r') as z:
                z.extractall(save_dir)
            os.remove(zip_path)
            downloaded += 1
            break
        except:
            continue
    else:
        print(f"  SKIPPED {repo}")

print(f"\nDownloaded {downloaded}/{len(security_repos)} repos")

# Collect all .py files
print("\nCollecting .py files...")
all_code = ""
count = 0

for root, dirs, files in os.walk(save_dir):
    dirs[:] = [d for d in dirs if d not in ['__pycache__', '.git', 'node_modules']]
    for f in files:
        if f.endswith(".py"):
            path = os.path.join(root, f)
            try:
                with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
                    code = fh.read()
                    if 100 < len(code) < 100000:
                        all_code += f"\n# FILE: {f}\n" + code + "\n"
                        count += 1
            except:
                pass

output_path = os.path.join("data", "pretrain", "security_python.txt")
with open(output_path, 'w', encoding='utf-8') as fh:
    fh.write(all_code)

mb = len(all_code) / (1024 * 1024)
print(f"Collected {count} security files, {mb:.1f} MB into {output_path}")
