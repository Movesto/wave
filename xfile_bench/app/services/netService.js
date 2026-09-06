// SERVICE layer: the command-execution sinks. The tainted value arrives as a PARAMETER
// from a handler in routes/handlers.js (a different file).
const { exec, execFile } = require('child_process');

// F1 sink (VULN): host was concatenated straight into a shell command.
function runPing(host) {
  return exec('ping -c 2 ' + host);              // SINK -- cross-file command injection
}

// F2 sink (SAFE): argument array, no shell -> metacharacters are inert.
function runPingSafe(host) {
  return execFile('ping', ['-c', '2', host]);    // safe sink
}

module.exports = { runPing, runPingSafe };
