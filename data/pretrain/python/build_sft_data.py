# save this as build_sft_data.py
import json

# Each example is a conversation: user asks to scan, assistant reports findings
pairs = [
    {
        "messages": [
            {"role": "user", "content": "Scan this code:\n```python\nimport sqlite3\ndef login(user, pwd):\n    query = f\"SELECT * FROM users WHERE name='{user}'\"\n    return conn.execute(query).fetchone()\n```"},
            {"role": "assistant", "content": "CWE-89: SQL Injection\nLine 3: User input directly in f-string SQL query.\nFix: Use parameterized query:\nquery = \"SELECT * FROM users WHERE name=?\"\nconn.execute(query, (user,))"}
        ]
    },
    {
        "messages": [
            {"role": "user", "content": "Scan this code:\n```python\nimport subprocess\ndef run(cmd):\n    return subprocess.run(cmd, shell=True)\n```"},
            {"role": "assistant", "content": "CWE-78: OS Command Injection\nLine 3: User input passed directly to shell=True.\nFix: Use subprocess.run(shlex.split(cmd)) without shell=True."}
        ]
    },
    {
        "messages": [
            {"role": "user", "content": "Scan this code:\n```python\ndef add(a, b):\n    return a + b\n```"},
            {"role": "assistant", "content": "No vulnerabilities detected. This function performs safe arithmetic."}
        ]
    },
    # You'll add hundreds more...
]

# Save as JSONL (one JSON per line)
with open("data/sft/vuln_pairs.jsonl", "w") as f:
    for pair in pairs:
        f.write(json.dumps(pair) + "\n")

print(f"Saved {len(pairs)} training pairs")