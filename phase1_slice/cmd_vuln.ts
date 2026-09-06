import {execSync} from 'child_process';
export function h(req:any){ const host=req.body.host; return execSync('ping '+host); }
