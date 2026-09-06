import {execFileSync} from 'child_process';
export function h(req:any){ const f=req.body.file; return execFileSync('convert',[f,'-resize','100x100']); }
