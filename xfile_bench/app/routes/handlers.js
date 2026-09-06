// ROUTE layer: every handler pulls untrusted input (req.*) = the SOURCE, then delegates
// to a SERVICE in another file. The dangerous sink lives in the service, so the taint
// flow crosses the file boundary -- invisible to intra-file analysis.
const net = require('../services/netService');
const users = require('../services/userService');
const files = require('../services/fileService');
const http = require('../services/httpService');

// F1 command injection (VULN): host -> netService.runPing -> exec
function ping(req, res) {
  const host = req.query.host;                 // SOURCE
  res.send(net.runPing(host));                 // -> sink in netService.js
}

// F2 command injection (SAFE): host -> netService.runPingSafe -> execFile arg-array
function pingSafe(req, res) {
  const host = req.body.host;                   // SOURCE
  res.send(net.runPingSafe(host));              // sanitised in the service
}

// F3 sql injection (VULN): name -> userService.findByName -> string-concat query
function searchUser(req, res) {
  const name = req.query.name;                  // SOURCE
  res.json(users.findByName(name));             // -> sink in userService.js
}

// F4 sql injection (SAFE): id -> userService.findById -> parameterised query
function getUser(req, res) {
  const id = req.params.id;                     // SOURCE
  res.json(users.findById(id));                 // parameterised in the service
}

// F5 path traversal (VULN): name -> fileService.readDoc -> readFileSync(BASE + name)
function readDoc(req, res) {
  const name = req.query.doc;                    // SOURCE
  res.send(files.readDoc(name));                 // -> sink in fileService.js
}

// F6 path traversal (SAFE): avatar -> fileService.readAvatar -> basename in service
function readAvatar(req, res) {
  const name = req.query.avatar;                 // SOURCE
  res.send(files.readAvatar(name));              // basename applied in the service
}

// F7 ssrf (VULN): url -> httpService.fetchUrl -> axios.get(url)
function proxy(req, res) {
  const url = req.query.url;                      // SOURCE
  httpService_fetch(url, res);
}
function httpService_fetch(url, res) { http.fetchUrl(url).then((d) => res.send(d)); }

module.exports = { ping, pingSafe, searchUser, getUser, readDoc, readAvatar, proxy };
