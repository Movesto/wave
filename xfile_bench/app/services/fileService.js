// SERVICE layer: the filesystem sinks. Tainted value arrives as a parameter.
const fs = require('fs');
const path = require('path');
const BASE = '/var/app/docs';

// F5 sink (VULN): user value joined into a path with no confinement.
function readDoc(name) {
  return fs.readFileSync(BASE + '/' + name);            // SINK -- cross-file path traversal
}

// F6 sink (SAFE): basename strips any directory components before use.
function readAvatar(name) {
  return fs.readFileSync(path.join(BASE, path.basename(name)));   // safe sink
}

module.exports = { readDoc, readAvatar };
