"""Sample file with known vulnerabilities (and one safe function) to test scan.py."""
import os
import sqlite3
from flask import Flask, request

app = Flask(__name__)


@app.route("/user")
def get_user():
    # VULNERABLE: SQL injection — user input concatenated into the query
    uid = request.args.get("id")
    conn = sqlite3.connect("app.db")
    query = "SELECT * FROM users WHERE id = '" + uid + "'"
    return str(conn.execute(query).fetchall())


@app.route("/ping")
def ping():
    # VULNERABLE: OS command injection — user input passed to the shell
    host = request.args.get("host")
    return os.popen("ping -c 1 " + host).read()


@app.route("/read")
def read_file():
    # VULNERABLE: path traversal — user input used to build a file path
    name = request.args.get("name")
    with open("/var/data/" + name) as f:
        return f.read()


@app.route("/user_safe")
def get_user_safe():
    # SAFE: parameterized query — should NOT be flagged
    uid = request.args.get("id")
    conn = sqlite3.connect("app.db")
    return str(conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchall())
