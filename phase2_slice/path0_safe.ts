import * as fs from 'fs'; import * as path from 'path'; const BASE='/var/data';
export function h(req:any){ const n=req.query.file; const s=path.basename(n); return fs.readFileSync(path.join(BASE,s)); }
