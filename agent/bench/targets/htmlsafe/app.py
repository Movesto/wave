"""htmlsafe -- secure HTML-rendering control (mirrors htmlvuln). Every flagged route is defended, so
every oracle must DEFER -> zero findings. This proves the HTML-aware readback does NOT over-flag when
the markup renders numbers/fields but the server logic is correct."""
from flask import Flask, request
from markupsafe import escape

app = Flask(__name__)
_CATALOG = {1: 999.99, 2: 25.00, 3: 249.50}
_sbank = {}


def _page(title, body):
    return f"<!doctype html><html><head><title>{title}</title></head><body>{body}</body></html>"


@app.route("/checkout", methods=["POST"])               # tamper-safe + qty-clamped, HTML-rendered
def checkout():
    d = request.get_json(silent=True) or request.form
    pid = int(d.get("product_id", 1))
    qty = max(0, int(d.get("quantity", 1)))             # non-negativity enforced
    total = _CATALOG.get(pid, 0.0) * qty                # server-authoritative price
    return _page("Receipt", f'<table><tr><td>Total</td><td>${total:.2f}</td></tr></table>')


@app.route("/order", methods=["POST"])                  # same secure logic
def order():
    return checkout()


@app.route("/withdraw", methods=["POST"])               # flow-safe: positive amount + funds check
def withdraw():
    d = request.get_json(silent=True) or request.form
    amt = float(d.get("amount", 0))
    if amt <= 0:
        return _page("Error", "<p>amount must be positive</p>"), 400
    u = d.get("username", "guest")
    bal = _sbank.get(u, 1000.0)
    if amt > bal:
        return _page("Error", "<p>insufficient funds</p>"), 400
    _sbank[u] = bal - amt
    return _page("Wallet", f'<div>Balance: <span id="balance">{_sbank[u]:.2f}</span></div>')


@app.route("/account", methods=["POST"])                # mass-assignment-safe: role server-fixed
def account():
    d = request.get_json(silent=True) or request.form
    u = escape(d.get("username", "guest"))
    return _page("Account", f'<p>Username: {u}</p><input name="role" value="user"><p>Role: user</p>')


@app.route("/")
def index():
    return _page("htmlsafe", "<p>htmlsafe</p>")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
