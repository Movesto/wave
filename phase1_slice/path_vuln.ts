import * as fs from 'fs'; import * as path from 'path';
const BASE='/var/data';
export function h(req:any){ const n=req.query.file; if(n.includes('..'))throw 0;
  const p=decodeURIComponent(n); return fs.readFileSync(path.join(BASE,p)); }
