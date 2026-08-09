export function h(req:any, el:any){ const q=req.query.q; el.innerHTML = q.replace(/<script>/gi,''); }
