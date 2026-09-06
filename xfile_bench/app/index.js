// Express wiring: registers the route handlers so `req` is a recognised request object
// (framework-aware taint engines need this to treat req.query/body/params as sources).
const express = require('express');
const h = require('./routes/handlers');
const app = express();

app.get('/ping', h.ping);            // F1 command VULN
app.post('/ping-safe', h.pingSafe);  // F2 command SAFE
app.get('/search', h.searchUser);    // F3 sql VULN
app.get('/user/:id', h.getUser);     // F4 sql SAFE
app.get('/doc', h.readDoc);          // F5 path VULN
app.get('/avatar', h.readAvatar);    // F6 path SAFE
app.get('/proxy', h.proxy);          // F7 ssrf VULN

app.listen(3000);
module.exports = app;
