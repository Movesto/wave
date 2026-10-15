// nodesafe -- a SECURE control twin of nodevuln (same Express routes + sinks, each correctly defended).
// The detector FLAGS these sinks (they look vulnerable), so every oracle must DEFER -> zero findings.
// Any finding here is a FALSE POSITIVE. Mirrors nodevuln route-for-route.
"use strict";
const express = require("express");
const { execFile } = require("child_process");
const fs = require("fs");
const path = require("path");
const http = require("http");

const app = express();
app.use(express.json());
const ALLOWED_HOSTS = new Set(["example.com", "api.internal"]);

app.get("/calc", (req, res) => {                                  // eval-safe: input restricted to arithmetic
  const expr = String(req.query.expr || "1+1");
  if (!/^[0-9+\-*/(). ]+$/.test(expr)) return res.status(400).json({ error: "invalid expression" });
  res.json({ result: eval(expr) });                               // no identifiers/calls possible -> no code injection
});

app.get("/ping", (req, res) => {                                  // command-safe: argv array, NO shell
  execFile("echo", ["pinging", String(req.query.host || "x")], (e, out) => res.send(String(out)));
});

app.get("/read", (req, res) => {                                  // traversal-safe: basename only, fixed root
  const name = path.basename(String(req.query.file || "readme.txt"));
  try { res.send(fs.readFileSync(path.join("/app/files", name))); }
  catch (e) { res.status(404).send("not found"); }
});

app.get("/fetch", (req, res) => {                                 // SSRF-safe: host allowlist
  let u;
  try { u = new URL(String(req.query.url || "http://example.com/")); }
  catch (e) { return res.status(400).send("bad url"); }
  if (!ALLOWED_HOSTS.has(u.hostname)) return res.status(400).json({ error: "host not allowed" });
  http.get(u.href, (r) => { let d = ""; r.on("data", (c) => d += c); r.on("end", () => res.send(d.slice(0, 200))); })
    .on("error", () => res.send("err"));
});

app.post("/load", (req, res) => {                                 // deser-safe: plain JSON, never node-serialize
  try { res.json(JSON.parse(String(req.body.data || "{}"))); }
  catch (e) { res.status(400).json({ error: "bad json" }); }
});

app.get("/echo", (req, res) => {                                  // XSS-safe: HTML-escape the reflection
  const esc = String(req.query.msg || "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  res.send("<html><body>You said: " + esc + "</body></html>");
});

app.get("/", (req, res) => res.json({ app: "nodesafe", routes: ["/calc", "/ping", "/read", "/fetch", "/load", "/echo"] }));

try { fs.mkdirSync("/app/files", { recursive: true }); fs.writeFileSync("/app/files/readme.txt", "public readme"); } catch (e) {}
app.listen(3000, () => console.log("nodesafe on 3000"));
