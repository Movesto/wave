import * as fs from 'fs'; import * as path from 'path'; const BASE='/var/data';
export function h(req:any){ const n=req.query.file; const p=path.resolve(BASE,n); if(!p.startsWith(BASE+path.sep))throw 0; return fs.readFileSync(p); }
