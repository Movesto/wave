// nodevuln -- a controlled multi-vuln Express target for the wave benchmark (JS-side hooks).
// One clean, discoverable sink per class. Ground truth in MANIFEST.json. DELIBERATELY VULNERABLE.
"use strict";
const express = require("express");
const cp = require("child_process");
const fs = require("fs");
const http = require("http");
let serialize;
try { serialize = require("node-serialize"); } catch (e) { serialize = null; }

const app = express();
app.use(express.json());

app.get("/calc", (req, res) => {                                  // CWE-95 code injection (eval)
  res.json({ result: eval(req.query.expr || "1+1") });
});

app.get("/ping", (req, res) => {                                  // CWE-78 command injection
  cp.exec("echo pinging " + (req.query.host || "x"), (e, out) => res.send(String(out)));
});

app.get("/read", (req, res) => {                                  // CWE-22 path traversal
  try { res.send(fs.readFileSync("/app/files/" + (req.query.file || "readme.txt"))); }
  catch (e) { res.status(404).send("not found"); }
});

app.get("/fetch", (req, res) => {                                 // CWE-918 SSRF
  http.get(req.query.url || "http://localhost/", (r) => {
    let d = ""; r.on("data", (c) => d += c); r.on("end", () => res.send(d.slice(0, 200)));
  }).on("error", () => res.send("err"));
});

app.post("/load", (req, res) => {                                 // CWE-502 deserialization
  res.json(serialize ? serialize.unserialize(req.body.data || "{}") : {});
});

app.get("/echo", (req, res) => {                                  // CWE-79 reflected XSS
  res.send("<html><body>You said: " + (req.query.msg || "") + "</body></html>");
});

app.get("/", (req, res) => res.json({ app: "nodevuln", routes: ["/calc", "/ping", "/read", "/fetch", "/load", "/echo"] }));

try { fs.mkdirSync("/app/files", { recursive: true }); fs.writeFileSync("/app/files/readme.txt", "public readme"); } catch (e) {}
app.listen(3000, () => console.log("nodevuln on 3000"));
