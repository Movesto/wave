import * as fs from 'fs'; const BASE='/var/data';
export function h(req:any){ const n=req.query.file; if(n.indexOf('..')!==-1)throw 0; return fs.readFileSync(BASE+n); }
