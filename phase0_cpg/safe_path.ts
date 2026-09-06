import * as fs from 'fs';
import * as path from 'path';
const BASE = '/var/data';

export function handler(req: any, res: any) {
  const name = req.query.file;                       // SOURCE (untrusted)
  const safe = path.basename(name);                  // NEUTRALISER on the path
  return fs.readFileSync(path.join(BASE, safe));     // SINK
}
