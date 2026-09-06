import * as fs from 'fs';
import * as path from 'path';
const BASE = '/var/data';

export function handler(req: any, res: any) {
  const name = req.query.file;                       // SOURCE (untrusted)
  if (name.includes('..')) throw new Error('bad');   // guard: insufficient (runs pre-decode)
  const p = decodeURIComponent(name);                // transform: decode AFTER the check
  return fs.readFileSync(path.join(BASE, p));        // SINK
}
