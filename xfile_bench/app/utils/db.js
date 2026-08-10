// A recognised SQL library so a real SQL sink exists for the benchmark.
const mysql = require('mysql');
const connection = mysql.createConnection({ host: 'localhost', user: 'app', database: 'app' });
module.exports = connection;   // connection.query(...) is a modelled SQL sink
