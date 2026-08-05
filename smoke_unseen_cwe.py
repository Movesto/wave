"""Unseen-CWE smoke: does the model generalize to vuln CLASSES it never trained on?

Three groups of hand-authored vuln snippets (identical style, so style can't
confound the comparison; all leak-free by construction — authored 2026-07-24,
never in any corpus):
  - unseen : CWEs with 0 records in data/cot/pilot_clean (verified via
             data/train_cwe_counts.json)
  - rare   : CWEs with <=6 training records
  - seen   : heavily-trained CWEs (SQLi/XSS/path-trav/cmd-inj) = the CONTROL.
             If seen-recall here ~= the model's normal smoke recall, the
             authoring style isn't skewing the result and the unseen-vs-seen
             delta measures class generalization.

All records are vuln-side; the headline number is recall per group. Secondary:
does the predicted CWE land in the right neighborhood?

Usage:
  WAVE_ADAPTER_PATH=data/qwen_cot_v11_best python smoke_unseen_cwe.py
  python smoke_unseen_cwe.py --stub
"""
import argparse
import json
import os

from eval.parsers import parse_shape1

# (group, cwe, lang, code)
CASES = [
    # ---------------- UNSEEN (0 training records) ----------------
    ("unseen", "CWE-841", "python", """@app.route('/checkout/complete', methods=['POST'])
def complete_order():
    order = Order.query.get(request.form['order_id'])
    # ships the order regardless of whether the payment step ever ran
    order.status = 'shipped'
    db.session.commit()
    schedule_shipment(order)
    return jsonify({'status': 'shipped'})"""),
    ("unseen", "CWE-841", "javascript", """router.post('/wizard/step3', async (req, res) => {
  // step3 finalizes the account without checking step1 (identity
  // verification) or step2 (document upload) were completed
  const acct = await Account.findByPk(req.body.accountId);
  acct.verified = true;
  await acct.save();
  res.json({ ok: true });
});"""),
    ("unseen", "CWE-841", "java", """public void transfer(HttpServletRequest req) {
    String from = req.getParameter("from");
    String to = req.getParameter("to");
    double amt = Double.parseDouble(req.getParameter("amount"));
    // executes the transfer without requiring the approval step
    // recorded by ApprovalService for transfers over the limit
    ledger.debit(from, amt);
    ledger.credit(to, amt);
}"""),

    ("unseen", "CWE-799", "python", """@app.route('/api/redeem', methods=['POST'])
def redeem_coupon():
    code = request.json['code']
    coupon = Coupon.query.filter_by(code=code).first()
    if coupon:
        apply_discount(current_user, coupon)
        return jsonify({'ok': True})
    return jsonify({'ok': False})"""),
    ("unseen", "CWE-799", "javascript", """app.post('/api/verify-otp', async (req, res) => {
  const { userId, otp } = req.body;
  const record = await OtpStore.get(userId);
  if (record && record.code === otp) {
    await grantSession(res, userId);
    return res.json({ ok: true });
  }
  res.status(401).json({ ok: false });
});"""),
    ("unseen", "CWE-799", "java", """@PostMapping("/api/guess-pin")
public ResponseEntity<String> guessPin(@RequestBody PinAttempt a) {
    String stored = pinService.getPin(a.getCardId());
    if (stored.equals(a.getPin())) {
        sessionService.unlock(a.getCardId());
        return ResponseEntity.ok("unlocked");
    }
    return ResponseEntity.status(401).body("wrong pin");
}"""),

    ("unseen", "CWE-425", "python", """@app.route('/admin/export-users')
def export_users():
    # only linked from the admin dashboard, so no check here
    rows = User.query.all()
    csv = '\\n'.join(f'{u.email},{u.phone},{u.ssn}' for u in rows)
    return Response(csv, mimetype='text/csv')"""),
    ("unseen", "CWE-425", "javascript", """// internal page, reached via the hidden admin menu only
router.get('/internal/billing-report', async (req, res) => {
  const report = await Billing.generateFullReport();
  res.json(report);
});"""),
    ("unseen", "CWE-425", "php", """<?php
// wp-content/backup.php — obscure filename keeps it private
$dump = shell_exec('mysqldump --all-databases');
header('Content-Type: application/octet-stream');
header('Content-Disposition: attachment; filename="backup.sql"');
echo $dump;"""),

    ("unseen", "CWE-489", "python", """if __name__ == '__main__':
    app.config['SECRET_KEY'] = load_secret()
    # Werkzeug debugger left on for the production container
    app.run(host='0.0.0.0', port=80, debug=True)"""),
    ("unseen", "CWE-489", "javascript", """app.use((err, req, res, next) => {
  // TEMP: full diagnostics while we chase the prod crash
  res.status(500).json({
    message: err.message,
    stack: err.stack,
    env: process.env,
    query: req.query,
  });
});"""),
    ("unseen", "CWE-489", "java", """public class PaymentServlet extends HttpServlet {
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws IOException {
        if ("1".equals(req.getParameter("debug"))) {
            resp.getWriter().println("cfg=" + this.config.dumpAll());
        }
        processPayment(req, resp);
    }
}"""),

    ("unseen", "CWE-598", "python", """def login_redirect(user, password):
    # credentials end up in access logs, proxies and browser history
    return redirect(
        f'https://sso.example.com/auth?user={user}&password={password}')"""),
    ("unseen", "CWE-598", "javascript", """async function refreshProfile(token) {
  const resp = await fetch(
    'https://api.example.com/v1/me?api_key=' + token +
    '&include=payment_methods');
  return resp.json();
}"""),
    ("unseen", "CWE-598", "php", """<form method="GET" action="/do-login.php">
  <input name="username" type="text">
  <input name="password" type="password">
  <button type="submit">Sign in</button>
</form>"""),

    ("unseen", "CWE-334", "python", """def make_reset_code(user):
    code = str(random.randint(1000, 9999))
    ResetCode.create(user=user, code=code, ttl_hours=24)
    send_email(user.email, f'Your reset code is {code}')"""),
    ("unseen", "CWE-334", "javascript", """function newSessionToken() {
  // 6 hex chars = ~16.7M values
  return Math.floor(Math.random() * 0xffffff).toString(16);
}
app.post('/login', (req, res) => {
  if (checkPassword(req.body)) {
    sessions[newSessionToken()] = req.body.user;
  }
});"""),
    ("unseen", "CWE-334", "java", """public String generateApiKey(long userId) {
    Random r = new Random(userId);   // seeded with the public user id
    return Long.toHexString(r.nextLong());
}"""),

    ("unseen", "CWE-836", "python", """@app.route('/api/login', methods=['POST'])
def api_login():
    user = User.query.filter_by(name=request.json['user']).first()
    # client sends the sha256 of the password; we compare hashes directly,
    # so a stolen hash works as the credential (pass-the-hash)
    if user and user.password_sha256 == request.json['password_hash']:
        return issue_token(user)
    abort(401)"""),
    ("unseen", "CWE-836", "javascript", """app.post('/auth', async (req, res) => {
  const u = await User.findOne({ name: req.body.user });
  // mobile app pre-hashes the password and posts the digest
  if (u && u.pwHash === req.body.digest) {
    return res.json({ token: sign(u.id) });
  }
  res.sendStatus(401);
});"""),

    ("unseen", "CWE-408", "python", """@app.route('/upload', methods=['POST'])
def upload():
    f = request.files['doc']
    dest = os.path.join(UPLOAD_DIR, f.filename)
    f.save(dest)                       # saved and shared first
    share_link = publish(dest)
    if not allowed_type(dest):         # ...validated afterwards
        os.remove(dest)
    return share_link"""),
    ("unseen", "CWE-408", "java", """public void handleWithdrawal(Withdrawal w) {
    bank.execute(w);                  // money moves first
    auditLog.record(w);
    if (!fraudChecker.approve(w)) {   // fraud check runs after execution
        bank.tryReverse(w);
    }
}"""),

    # ---------------- RARE (<=6 training records) ----------------
    ("rare", "CWE-384", "python", """@app.route('/login', methods=['POST'])
def login():
    user = authenticate(request.form['user'], request.form['password'])
    if user:
        # keeps whatever session id the client arrived with
        session['user_id'] = user.id
        return redirect('/home')
    return render_template('login.html', error=True)"""),
    ("rare", "CWE-384", "javascript", """app.post('/login', async (req, res) => {
  const user = await auth(req.body.user, req.body.password);
  if (user) {
    // same req.session object (and cookie) as before authentication
    req.session.userId = user.id;
    return res.redirect('/dashboard');
  }
  res.redirect('/login?err=1');
});"""),
    ("rare", "CWE-384", "php", """<?php
session_start();
$u = auth($_POST['user'], $_POST['password']);
if ($u) {
    $_SESSION['uid'] = $u->id;   // session id from the pre-login cookie
    header('Location: /home');
}"""),

    ("rare", "CWE-307", "python", """@app.route('/login', methods=['POST'])
def login():
    user = User.query.filter_by(name=request.form['user']).first()
    if user and bcrypt.verify(request.form['password'], user.pw_hash):
        session.regenerate(); session['uid'] = user.id
        return redirect('/home')
    return render_template('login.html', error='bad credentials')"""),
    ("rare", "CWE-307", "javascript", """app.post('/api/login', async (req, res) => {
  const u = await User.findOne({ name: req.body.user });
  if (u && await bcrypt.compare(req.body.password, u.hash)) {
    return res.json({ token: issueJwt(u) });
  }
  res.status(401).json({ error: 'invalid credentials' });
});"""),

    ("rare", "CWE-470", "python", """@app.route('/api/run')
def run_action():
    action = request.args.get('action')
    handler = getattr(handlers_module, action)
    return jsonify(handler(request.args))"""),
    ("rare", "CWE-470", "java", """public Object dispatch(HttpServletRequest req) throws Exception {
    String cls = req.getParameter("handler");
    Class<?> c = Class.forName("com.app.handlers." + cls);
    Handler h = (Handler) c.getDeclaredConstructor().newInstance();
    return h.handle(req);
}"""),

    ("rare", "CWE-915", "python", """@app.route('/api/profile', methods=['PATCH'])
def update_profile():
    user = User.query.get(session['uid'])
    for key, value in request.json.items():
        setattr(user, key, value)     # is_admin, balance, ... all settable
    db.session.commit()
    return jsonify(user.to_dict())"""),
    ("rare", "CWE-915", "javascript", """router.put('/users/me', async (req, res) => {
  const user = await User.findByPk(req.session.userId);
  await user.update(req.body);   // role/isAdmin accepted from the client
  res.json(user);
});"""),
    ("rare", "CWE-640", "python", """@app.route('/forgot', methods=['POST'])
def forgot():
    user = User.query.filter_by(email=request.form['email']).first()
    if user and request.form['answer'] == user.security_answer:
        # security answer alone resets the password, no email loop
        user.set_password(request.form['new_password'])
        db.session.commit()
    return 'ok'"""),

    # ---------------- SEEN CONTROL (heavily trained classes) ----------------
    ("seen", "CWE-89", "python", """@app.route('/search')
def search():
    q = request.args.get('q', '')
    rows = db.execute(
        f"SELECT id, title FROM posts WHERE title LIKE '%{q}%'")
    return jsonify([dict(r) for r in rows])"""),
    ("seen", "CWE-89", "java", """public List<String> findOrders(HttpServletRequest req) throws SQLException {
    String cust = req.getParameter("customer");
    Statement st = conn.createStatement();
    ResultSet rs = st.executeQuery(
        "SELECT * FROM orders WHERE customer = '" + cust + "'");
    return collect(rs);
}"""),
    ("seen", "CWE-89", "php", """<?php
$id = $_GET['id'];
$res = mysqli_query($db, "SELECT * FROM users WHERE id = $id");
echo json_encode(mysqli_fetch_assoc($res));"""),

    ("seen", "CWE-79", "python", """@app.route('/hello')
def hello():
    name = request.args.get('name', 'world')
    return f'<h1>Hello {name}</h1>'"""),
    ("seen", "CWE-79", "javascript", """app.get('/comment', (req, res) => {
  res.send('<div class="comment">' + req.query.text + '</div>');
});"""),
    ("seen", "CWE-79", "php", """<?php
echo "<p>Search results for: " . $_GET['q'] . "</p>";"""),

    ("seen", "CWE-22", "python", """@app.route('/download')
def download():
    fname = request.args['file']
    return send_file(os.path.join('/srv/docs', fname))"""),
    ("seen", "CWE-22", "javascript", """app.get('/static', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', req.query.f));
});"""),
    ("seen", "CWE-22", "java", """protected void doGet(HttpServletRequest req, HttpServletResponse resp)
        throws IOException {
    File f = new File("/var/www/files", req.getParameter("name"));
    Files.copy(f.toPath(), resp.getOutputStream());
}"""),

    ("seen", "CWE-78", "python", """@app.route('/ping')
def ping():
    host = request.args.get('host')
    out = os.popen('ping -c 1 ' + host