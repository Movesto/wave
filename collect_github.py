# ============================================================
# PART 1A: collect_github.py
# Downloads top Python repos and combines all .py files
# Run this FIRST — quick, no auth needed
# Output: data/pretrain/github_python.txt
# ============================================================
import os
import urllib.request
import zipfile

os.makedirs(os.path.join("data", "pretrain", "repos"), exist_ok=True)

# Top Python repos — heavy on web frameworks and security-relevant code
repos = [
    # Web frameworks (where most vulns live)
    "pallets/flask",
    "django/django",
    "tiangolo/fastapi",
    "encode/starlette",
    "aio-libs/aiohttp",
    "pallets/werkzeug",
    "bottlepy/bottle",
    # HTTP/networking
    "psf/requests",
    "encode/httpx",
    "urllib3/urllib3",
    # Database
    "sqlalchemy/sqlalchemy",
    "coleifer/peewee",
    # Security tools
    "PyCQA/bandit",
    "mitmproxy/mitmproxy",
    "paramiko/paramiko",
    "pyca/cryptography",
    # Auth
    "pennersr/django-allauth",
    "jazzband/django-oauth-toolkit",
    # General popular
    "celery/celery",
    "python-pillow/Pillow",
    "psf/black",
    "PyCQA/pylint",
    "pytest-dev/pytest",
    "pallets/jinja",
    "pallets/click",
    # Data/API
    "marshmallow-code/marshmallow",
    "pydantic/pydantic",
    "encode/django-rest-framework",
    # More security relevant
    "stamparm/maltrail",
    "Gallopsled/pwntools",
]

downloaded = 0
for repo in repos:
    name = repo.split("/")[1]
    save_dir = os.path.join("data", "pretrain", "repos")
    zip_path = os.path.join(save_dir, f"{name}.zip")

    # Try main branch first, then master
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
        except Exception as e:
            continue
    else:
        print(f"  SKIPPED {repo}")

print(f"\nDownloaded {downloaded}/{len(repos)} repos")

# Collect all .py files into one text file
print("\nCollecting .py files...")
all_code = ""
count = 0
repos_dir = os.path.join("data", "pretrain", "repos")

for root, dirs, files in os.walk(repos_dir):
    # Skip test directories to focus on source code
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

output_path = os.path.join("data", "pretrain", "github_python.txt")
with open(output_path, 'w', encoding='utf-8') as fh:
    fh.write(all_code)

mb = len(all_code) / (1024 * 1024)
print(f"Collected {count} files, {mb:.1f} MB into {output_path}")
