"""redosvuln -- a controlled ReDoS (CWE-1333) target. A catastrophic-backtracking regex runs on user
input, so a crafted string causes exponential CPU. DELIBERATELY VULNERABLE -- test only."""
import re

from flask import Flask, request

app = Flask(__name__)


@app.route("/validate")                                 # CWE-1333 catastrophic regex backtracking
def validate():
    s = request.args.get("s", "")
    ok = re.match(r"^(a+)+$", s) is not None
    return {"valid": ok}


@app.route("/")
def index():
    return {"app": "redosvuln"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
