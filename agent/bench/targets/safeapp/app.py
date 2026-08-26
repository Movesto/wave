"""safeapp -- a SECURE control target for the wave benchmark. Its routes LOOK vulnerable (so the
detector flags candidates) but are correctly defended, so every oracle must DEFER -> zero findings.
This measures the false-positive rate: the whole soundness claim is 'flagged-but-safe -> not proven'."""
import os

import requests
from flask import Flask, request, session
from jinja2 import Template
from markupsafe import escape
from sqlalchemy import create_engine, text
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "safeapp-secret"
engine = create_engine("sqlite:////tmp/safe.db")
_ALLOWED_HOSTS = {"example.com", "api.internal"}


def _init():
    with engine.begin() as c:
        c.execute(text("CREATE TABLE IF NOT EXISTS docs (id INTEGER PRIMARY KEY, owner TEXT, secret TEXT)"))
        for i, u in enumerate(["alice", "bob", "carol"], start=1):
            c.execute(text("INSERT OR IGNORE INTO docs (id, owner, secret) VALUES (:i, :u, :s)"),
                      {"i": i, "u": u, "s": f"private doc {i} for {u}. " * 8})
    os.makedirs("/app/files", exist_ok=True)
    open("/app/files/readme.txt", "w").write("public readme")


@app.route("/login", methods=["POST"])
def login():
    d = request.get_json(silent=True) or request.form
    session["user"] = d.get("username")
    return {"ok": True}


@app.route("/greet")                                    # SSTI-safe: input is CONTEXT, not the template
def greet():
    name = request.args.get("name", "world")
    return Template("Hello {{ n }}").render(n=name)


@app.route("/read")                                     # traversal-safe: basename only
def read():
    name = secure_filename(request.args.get("file", "readme.txt"))
    return open("/app/files/" + name).read()


@app.route("/fetch")                                    # SSRF-safe: host allowlist
def fetch():
    url = request.args.get("url", "http://example.com/")
    from urllib.parse import urlparse
    if urlparse(url).hostname not in _ALLOWED_HOSTS:
        return {"error": "host not allowed"}, 400
    return {"body": requests.get(url, timeout=3).text[:200]}


@app.route("/echo")                                     # XSS-safe: output escaped
def echo():
    msg = request.args.get("msg", "")
    return "<html><body>You said: " + str(escape(msg)) + "</body></html>"


@app.route("/doc/<int:doc_id>")                         # IDOR-safe: ownership enforced
def doc(doc_id):
    user = session.get("user")
    with engine.begin() as c:
        row = c.execute(text("SELECT owner, secret FROM docs WHERE id = :i"), {"i": doc_id}).fetchone()
    if not row:
        return {"error": "not found"}, 404
    if row[0] != user:
        return {"error": "forbidden"}, 403
    return {"owner": row[0], "secret": row[1]}


@app.route("/")
def index():
    return {"app": "safeapp"}


_init()
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
