"""asyncvuln -- a controlled SECOND-ORDER / async blind SSRF target for the OAST canary.
The request returns 202 immediately and does NO synchronous egress; a background worker fetches the
user-supplied URL 6 seconds LATER. The synchronous sink poll (~3s) structurally misses it -- only the
OAST canary's post-loop sweep catches the delayed callback. DELIBERATELY VULNERABLE -- test only."""
import threading
import time

import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/webhook")                                  # CWE-918 second-order / async blind SSRF
def webhook():
    url = request.args.get("url", "http://localhost/")

    def worker():
        time.sleep(6)                                   # a background job processes it later
        try:
            requests.get(url, timeout=3)
        except Exception:
            pass

    threading.Thread(target=worker, daemon=True).start()
    return {"status": "queued"}, 202                    # immediate response, no synchronous egress


@app.route("/")
def index():
    return {"app": "asyncvuln"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
