// SERVICE layer: SQL sinks. Tainted value arrives as a parameter from routes/handlers.js.
const connection = require('../utils/db');

// F3 sink (VULN): value concatenated into the SQL string (mysql connection.query).
function findByName(name) {
  return connection.query("SELECT * FROM users WHERE name = '" + name + "'");  // SINK cross-file SQLi
}

// F4 sink (SAFE): bound parameter (placeholder + values array).
function findById(id) {
  return connection.query('SELECT * FROM users WHERE id = ?', [id]);           // safe sink
}

module.exports = { findByName, findById };
