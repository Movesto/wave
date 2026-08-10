// SERVICE layer: the SQL sinks. Tainted value arrives as a parameter from routes/handlers.js.
const db = require('../utils/db');

// F3 sink (VULN): value concatenated into the SQL string.
function findByName(name) {
  return db.query("SELECT * FROM users WHERE name = '" + name + "'");   // SINK -- cross-file SQLi
}

// F4 sink (SAFE): bound parameter.
function findById(id) {
  return db.query('SELECT * FROM users WHERE id = ?', [id]);            // safe sink
}

module.exports = { findByName, findById };
