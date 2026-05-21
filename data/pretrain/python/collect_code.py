# save this as collect_code.py
import os
import urllib.request
import zipfile

# Download a repo as a zip
def download_repo(url, save_dir):
    zip_path = os.path.join(save_dir, "repo.zip")
    urllib.request.urlretrieve(url, zip_path)
    with zipfile.ZipFile(zip_path, 'r') as z:
        z.extractall(save_dir)
    os.remove(zip_path)
    print(f"Downloaded to {save_dir}")

# Example: grab TheAlgorithms/Python
download_repo(
    "https://github.com/TheAlgorithms/Python/archive/refs/heads/master.zip",
    "data/pretrain/python"
)

# Now walk through and collect all .py files into one big text file
def collect_files(folder, extension, output_file):
    all_code = ""
    count = 0
    for root, dirs, files in os.walk(folder):
        for f in files:
            if f.endswith(extension):
                path = os.path.join(root, f)
                try:
                    with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
                        code = fh.read()
                        all_code += f"\n# FILE: {f}\n" + code + "\n"
                        count += 1
                except:
                    pass
    with open(output_file, 'w') as fh:
        fh.write(all_code)
    print(f"Collected {count} files into {output_file}")

collect_files("data/pretrain/python", ".py", "data/pretrain/all_python.txt")