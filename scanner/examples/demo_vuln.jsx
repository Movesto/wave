import { exec } from 'child_process';

function Profile(req) {
  const name = req.query.name;
  return <div dangerouslySetInnerHTML={{ __html: name }} />;  // XSS
}

function ping(req) {
  const host = req.query.host;
  exec("ping -c 1 " + host);                                  // command injection
}

function getUser(req) {
  const id = req.params.id;
  return db.query("SELECT * FROM users WHERE id = ?", [id]);  // SAFE parameterized
}
