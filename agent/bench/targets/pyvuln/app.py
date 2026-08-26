"""pyvuln -- a controlled multi-vuln Flask target for the wave benchmark. One clean, discoverable
sink per class so the full loop can be scored end-to-end. Ground truth in MANIFEST.json.
DELIBERATELY VULNERABLE -- test target only."""
import os
import subprocess

import requests
from flask import Flask, request, session
from jinja2 import Template
from sqlalchemy import create_engine, text

app = Flask(__name__)
app.secret_key = "wavebench-secret"
engine = create_engine("sqlite:////tmp/bench.db")


def _init():
    with engine.begin() as c:
        c.execute(text("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)"))
        c.execute(text("CREATE TABLE IF NOT EXISTS docs (id INTEGER PRIMARY KEY, owner TEXT, secret TEXT)"))
        for i, u in enumerate(["alice", "bob", "carol"], start=1):
            c.execute(text("INSERT OR IGNORE INTO users (id, username, password) VALUES (:i, :u, 'pw')"),
                      {"i": i, "u": u})
            body = f"Private document #{i} owned by {u}. Confidential holdings and notes for {u}. " * 4
            c.execute(text("INSERT OR IGNORE INTO docs (id, owner, secret) VALUES (:i, :u, :s)"),
                      {"i": i, "u": u, "s": body})
    os.makedirs("/app/files", exist_ok=True)
    with open("/app/files/readme.txt", "w") as f:
        f.write("public readme")


@app.route("/register", methods=["POST"])
def register():
    d = request.get_json(silent=True) or request.form
    with engine.begin() as c:
        c.execute(text("INSERT INTO users (username, password) VALUES (:u, :p)"),
                  {"u": d.get("username"), "p": d.get("password")})
    return {"ok": True}


@app.route("/login", methods=["POST"])
def login():
    d = request.get_json(silent=True) or request.form
    session["user"] = d.get("username")
    return {"ok": True}


@app.route("/search")                                   # CWE-89 SQL injection
def search():
    q = request.args.get("q", "")
    with engine.begin() as c:
        rows = c.execute(text("SELECT username FROM users WHERE username = '" + q + "'")).fetchall()
    return {"rows": [r[0] for r in rows]}


@app.route("/ping")                                     # CWE-78 command injection
def ping():
    host = request.args.get("host", "127.0.0.1")
    out = subprocess.run("echo pinging " + host, shell=True, capture_output=True).stdout.decode("utf-8", "replace")
    return {"out": out}


@app.route("/read")                                     # CWE-22 path traversal
def read():
    name = request.args.get("file", "readme.txt")
    return open("/app/files/" + name).read()


@app.route("/fetch")                                    # CWE-918 SSRF
def fetch():
    url = request.args.get("url", "http://localhost/")
    return {"body": requests.get(url, timeout=3).text[:200]}


@app.route("/greet")                                    # CWE-1336 SSTI
def greet():
    name = request.args.get("name", "world")
    return Template("Hello " + name).render()


@app.route("/calc")                                     # CWE-95 code injection (eval)
def calc():
    expr = request.args.get("expr", "1+1")
    return {"result": str(eval(expr))}


@app.route("/echo")                                     # CWE-79 reflected XSS
def echo():
    msg = request.args.get("msg", "")
    return "<html><body>You said: " + msg + "</body></html>"


@app.route("/doc/<int:doc_id>")                         # CWE-639 IDOR (no ownership check)
def doc(doc_id):
    with engine.begin() as c:
        row = c.execute(text("SELECT owner, secret FROM docs WHERE id = :i"), {"i": doc_id}).fetchone()
    if not row:
        return {"error": "not found"}, 404
    return {"owner": row[0], "secret": row[1]}


@app.route("/")
def index():
    return {"app": "pyvuln", "routes": ["/search", "/ping", "/read", "/fetch", "/greet", "/calc", "/echo", "/doc/<id>"]}


_init()
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
