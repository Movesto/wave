import {execSync} from 'child_process';
export function h(req:any){ const f=req.body.file; const c=f.replace(/[;|&]/g,''); return execSync('convert '+c); }
