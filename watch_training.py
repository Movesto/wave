"""Watch a train_qwen_cot.py run via its train_metrics.jsonl.

Prints a status summary (progress, throughput, ETA, loss trends, on-track
verdict) and regenerates a self-contained HTML dashboard next to the metrics
file. Read-only w.r.t. the training run — safe to run any time, any number of
times, while training is in progress.

Usage:
  python watch_training.py [--metrics data/qwen_cot_v11/train_metrics.jsonl]
                           [--out data/qwen_cot_v11/dashboard.html]
"""
import argparse
import json
import math
import time
from datetime import datetime, timedelta
from pathlib import Path

# Reference baselines for context (best full-val of prior runs; different val
# splits so directional context only, not a pass/fail line).
BASELINES = {"v10": 0.231, "v9": 0.438}
FOCUS_SHAPE = "shape3_codeql"   # the reason v11 exists


def load_metrics(path: Path) -> list[dict]:
    rows = []
    if not path.exists():
        return rows
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def _ts(row: dict) -> float:
    try:
        return datetime.strptime(row["t"], "%Y-%m-%dT%H:%M:%S").timestamp()
    except (KeyError, ValueError):
        return 0.0


def analyze(rows: list[dict]) -> dict:
    run = next((r for r in rows if r.get("type") == "run_start"), {})
    train = [r for r in rows if r.get("type") == "train"]
    fastval = [r for r in rows if r.get("type") == "fastval"]
    epochs = [r for r in rows if r.get("type") == "epoch"]
    nans = [r for r in rows if r.get("type") == "nan_warn"]
    mids = [r for r in rows if r.get("type") == "mid_checkpoint"]
    ended = any(r.get("type") == "run_end" for r in rows)

    total_steps = run.get("total_optim_steps", 0)
    step = train[-1]["step"] if train else 0

    # Throughput from the widest recent window of train points (<= ~3h) so one
    # fastval pause doesn't skew it; ETA from that empirical rate.
    rate_h, eta = None, None
    if len(train) >= 2:
        window = [r for r in train if _ts(train[-1]) - _ts(r) <= 3 * 3600]
        if len(window) < 2:
            window = train[-2:]
        dt = _ts(window[-1]) - _ts(window[0])
        dstep = window[-1]["step"] - window[0]["step"]
        if dt > 0 and dstep > 0:
            rate_h = dstep / dt * 3600
            if total_steps and not ended:
                eta = datetime.now() + timedelta(
                    hours=(total_steps - step) / rate_h)

    fv_overall = [(r["step"], r["overall"]) for r in fastval
                  if not math.isnan(r.get("overall", float("nan")))]
    fv_focus = [(r["step"], r["per_shape"][FOCUS_SHAPE]) for r in fastval
                if FOCUS_SHAPE in r.get("per_shape", {})]

    # ---- verdict ----
    problems, watches = [], []
    # Isolated NaNs are a KNOWN benign cause (163 records whose prompt alone
    # >= max_len tokens -> all labels masked; diagnosed 2026-07-20, none in
    # shape3_codeql). Expected rate ~0.3-1.5% of batches. Flag only streaks or
    # a rate well above expectation.
    recent_nans = [r for r in nans if _ts(train[-1]) - _ts(r) <= 3600] if train else nans
    batches_seen = step * 16 if (step := (train[-1]["step"] if train else 0)) else 0
    nan_rate = len(nans) / batches_seen if batches_seen else 0.0
    if any(r.get("streak", 0) >= 3 for r in recent_nans):
        problems.append(f"NaN loss streak in the last hour ({len(recent_nans)} warns)")
    elif len(nans) > 10 and nan_rate > 0.03:
        watches.append(f"NaN-batch rate {nan_rate:.1%} exceeds the known-benign ~1.5% "
                       f"({len(nans)} total) — new cause?")

    if len(train) >= 12:
        first = min(r["loss"] for r in train[:3])
        last = sum(r["loss"] for r in train[-3:]) / 3
        if last >= first:
            problems.append(
                f"train loss has not dropped ({first:.3f} -> {last:.3f} after {step} steps)")

    # Throughput decline watch: compare a recent clean-step rate against the
    # run's early peak. A sustained drop (allocator thrash near the 16GB VRAM
    # ceiling) doesn't hurt the result but pushes the ETA out — surface it so
    # the banner isn't a flat green while the clock slips.
    if len(train) >= 20:
        def _rate(seg):
            dt = _ts(seg[-1]) - _ts(seg[0]); ds = seg[-1]["step"] - seg[0]["step"]
            return ds / dt * 3600 if dt > 0 else None
        peak = _rate(train[2:10]); recent = _rate(train[-6:])
        if peak and recent and recent < 0.75 * peak:
            watches.append(f"throughput down {(1-recent/peak)*100:.0f}% from peak "
                           f"({peak:.0f}->{recent:.0f} st/h) — VRAM-ceiling allocator thrash; "
                           f"result unaffected, ETA slipping")

    # Genuine overfit = fastval drifting UP meaningfully off its best while train
    # loss keeps falling. A flat plateau within noise on the 253-record subset is
    # expected in epochs 2-3 (the recall recovery shows in the smoke, not here),
    # so only warn on a real >5% rise sustained over the last 3 checks.
    if len(fv_overall) >= 5:
        best = min(v for _, v in fv_overall)
        recent = sum(v for _, v in fv_overall[-3:]) / 3
        if recent > best * 1.05:
            watches.append(f"fastval overall drifting up ({best:.3f} -> {recent:.3f}) "
                           f"while train loss falls — possible overfit")
    # shape3_codeql starts LOW (templated SARIF-derived traces are easy to
    # fit), so absolute level and "not improving" are meaningless — the red
    # flag is a sustained RISE off its floor (forgetting the cross-file slice).
    if len(fv_focus) >= 5:
        floor = min(v for _, v in fv_focus)
        if all(v > floor * 1.25 for _, v in fv_focus[-3:]):
            watches.append(f"{FOCUS_SHAPE} val loss rising off its floor "
                           f"({floor:.3f} -> {fv_focus[-1][1]:.3f}) — cross-file slice regressing")

    if problems:
        verdict, vclass = "OFF TRACK: " + "; ".join(problems), "critical"
    elif watches:
        verdict, vclass = "WATCH: " + "; ".join(watches), "warning"
    elif not train:
        verdict, vclass = "STARTING (no train steps logged yet)", "warning"
    else:
        verdict, vclass = "ON TRACK", "good"
    if ended:
        verdict, vclass = "RUN COMPLETE — " + verdict, vclass

    return {
        "run": run, "train": train, "fastval": fastval, "epochs": epochs,
        "nans": nans, "mids": mids, "ended": ended,
        "step": step, "total_steps": total_steps,
        "rate_h": rate_h, "eta": eta,
        "fv_overall": fv_overall, "fv_focus": fv_focus,
        "verdict": verdict, "vclass": vclass,
    }


def print_summary(a: dict) -> None:
    step, total = a["step"], a["total_steps"]
    pct = 100 * step / total if total else 0
    print(f"=== v11 training watch @ {time.strftime('%Y-%m-%d %H:%M:%S')} ===")
    print(f"verdict : {a['verdict']}")
    print(f"progress: step {step}/{total} ({pct:.1f}%)  epochs done: {len(a['epochs'])}")
    if a["rate_h"]:
        print(f"rate    : {a['rate_h']:.0f} optim steps/h", end="")
        print(f"   ETA {a['eta']:%a %m-%d %H:%M}" if a["eta"] else "")
    if a["train"]:
        print(f"train   : loss {a['train'][-1]['loss']:.4f} (latest)")
    if a["fv_overall"]:
        s, v = a["fv_overall"][-1]
        best = min(v for _, v in a["fv_overall"])
        print(f"fastval : {v:.4f} @ step {s} (best {best:.4f}; "
              f"v10 full-val baseline {BASELINES['v10']})")
    if a["fv_focus"]:
        s, v = a["fv_focus"][-1]
        first = a["fv_focus"][0][1]
        print(f"{FOCUS_SHAPE}: {v:.4f} @ step {s} (first {first:.4f}, "
              f"{'improving' if v < first else 'NOT improving'})")
    for e in a["epochs"]:
        print(f"epoch {e['epoch']}: train {e['train']:.4f}  val {e['val']:.4f}  "
              f"({e['seconds']/3600:.1f}h)")
    if a["mids"]:
        m = a["mids"][-1]
        print(f"mid ckpt: step {m['step']} fastval {m['fastval']:.4f} (crash insurance)")


# ---- dashboard ----

def render_dashboard(a: dict, out: Path) -> None:
    shapes = sorted({s for r in a["fastval"] for s in r.get("per_shape", {})})
    payload = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "verdict": a["verdict"], "vclass": a["vclass"],
        "step": a["step"], "total": a["total_steps"],
        "epochs_total": a["run"].get("epochs"),
        "rate_h": round(a["rate_h"], 1) if a["rate_h"] else None,
        "eta": a["eta"].strftime("%a %b %d %H:%M") if a["eta"] else None,
        "train": [[r["step"], r["loss"]] for r in a["train"]],
        "fv_overall": a["fv_overall"],
        "shapes": shapes,
        "per_shape": {s: [[r["step"], r["per_shape"][s]]
                          for r in a["fastval"] if s in r.get("per_shape", {})]
                      for s in shapes},
        "focus": FOCUS_SHAPE,
        "epochs": a["epochs"],
        "baseline_v10": BASELINES["v10"],
        "nan_count": len(a["nans"]),
    }
    html = TEMPLATE.replace("__DATA__", json.dumps(payload))
    out.write_text(html, encoding="utf-8")
    print(f"dashboard -> {out}")


TEMPLATE = r"""<title>Wave v11 training</title>
<style>
.viz-root {
  color-scheme: light;
  --surface-1:#fcfcfb; --page:#f9f9f7;
  --ink-1:#0b0b0b; --ink-2:#52514e; --muted:#898781;
  --grid:#e1e0d9; --axis:#c3c2b7; --border:rgba(11,11,11,0.10);
  --s1:#2a78d6; --s2:#eb6834;
  --good:#0ca30c; --warning:#fab219; --critical:#d03b3b;
  --good-text:#006300; --warn-text:#7a5200; --crit-text:#a02020;
}
@media (prefers-color-scheme: dark) {
  :root:where(:not([data-theme="light"])) .viz-root {
    color-scheme: dark;
    --surface-1:#1a1a19; --page:#0d0d0d;
    --ink-1:#ffffff; --ink-2:#c3c2b7; --muted:#898781;
    --grid:#2c2c2a; --axis:#383835; --border:rgba(255,255,255,0.10);
    --s1:#3987e5; --s2:#d95926;
    --good-text:#0ca30c; --warn-text:#fab219; --crit-text:#e66767;
  }
}
:root[data-theme="dark"] .viz-root {
  color-scheme: dark;
  --surface-1:#1a1a19; --page:#0d0d0d;
  --ink-1:#ffffff; --ink-2:#c3c2b7; --muted:#898781;
  --grid:#2c2c2a; --axis:#383835; --border:rgba(255,255,255,0.10);
  --s1:#3987e5; --s2:#d95926;
  --good-text:#0ca30c; --warn-text:#fab219; --crit-text:#e66767;
}
.viz-root { font-family: system-ui,-apple-system,"Segoe UI",sans-serif;
  background:var(--page); color:var(--ink-1); margin:0; padding:20px;
  min-height:100vh; box-sizing:border-box; }
.viz-root * { box-sizing:border-box; }
h1 { font-size:1.15rem; margin:0 0 2px; }
.sub { color:var(--ink-2); font-size:0.82rem; margin-bottom:14px; }
.banner { display:flex; align-items:center; gap:8px; padding:10px 14px;
  border:1px solid var(--border); border-radius:8px; background:var(--surface-1);
  font-weight:600; font-size:0.92rem; margin-bottom:14px; }
.dot { width:10px; height:10px; border-radius:50%; flex:none; }
.tiles { display:grid; grid-template-columns:repeat(auto-fit,minmax(130px,1fr));
  gap:10px; margin-bottom:16px; }
.tile { background:var(--surface-1); border:1px solid var(--border);
  border-radius:8px; padding:10px 12px; }
.tile .k { color:var(--muted); font-size:0.7rem; text-transform:uppercase;
  letter-spacing:0.04em; }
.tile .v { font-size:1.35rem; font-weight:650; margin-top:2px; }
.tile .d { font-size:0.72rem; color:var(--ink-2); margin-top:2px; }
.card { background:var(--surface-1); border:1px solid var(--border);
  border-radius:8px; padding:14px; margin-bottom:16px; }
.card h2 { font-size:0.9rem; margin:0 0 4px; }
.card .note { color:var(--ink-2); font-size:0.76rem; margin:0 0 8px; }
.legend { display:flex; gap:14px; font-size:0.76rem; color:var(--ink-2);
  margin-bottom:6px; flex-wrap:wrap; }
.legend span { display:inline-flex; align-items:center; gap:5px; }
.sw { width:14px; height:3px; border-radius:2px; display:inline-block; }
.chartwrap { position:relative; overflow-x:auto; }
svg { display:block; width:100%; height:auto; }
.tip { position:absolute; pointer-events:none; background:var(--surface-1);
  border:1px solid var(--border); border-radius:6px; padding:6px 9px;
  font-size:0.74rem; color:var(--ink-1); box-shadow:0 2px 8px rgba(0,0,0,0.18);
  display:none; white-space:nowrap; z-index:2; }
details { margin-top:8px; }
summary { cursor:pointer; color:var(--ink-2); font-size:0.78rem; }
table { border-collapse:collapse; font-size:0.76rem; margin-top:8px; width:100%; }
th,td { text-align:right; padding:3px 8px; border-bottom:1px solid var(--grid);
  font-variant-numeric:tabular-nums; }
th:first-child,td:first-child { text-align:left; }
th { color:var(--muted); font-weight:600; }
</style>
<div class="viz-root">
<h1>Wave v11 — cross-file training run</h1>
<div class="sub" id="sub"></div>
<div class="banner"><span class="dot" id="vdot"></span><span id="vtext"></span></div>
<div class="tiles" id="tiles"></div>
<div class="card">
  <h2>Loss curves</h2>
  <p class="note">Training loss (running epoch average, every 25 steps) and fast-validation loss on a fixed stratified holdout subset. Dashed gray line = v10's best full-val (0.231), directional context only.</p>
  <div class="legend">
    <span><i class="sw" style="background:var(--s1)"></i>train loss</span>
    <span><i class="sw" style="background:var(--s2)"></i>fastval (overall)</span>
  </div>
  <div class="chartwrap"><svg id="c1" viewBox="0 0 860 300"></svg><div class="tip" id="t1"></div></div>
</div>
<div class="card">
  <h2>Is the cross-file slice learning? (fastval loss per shape)</h2>
  <p class="note">The blue line is <b>shape3_codeql</b> — the verified cross-file traces this run exists for. Gray lines are the other data shapes for context. This slice starts at low loss (its traces have regular, template-derived structure), so the health signal is that it <b>stays low or falls</b>; a sustained rise would mean the cross-file slice is being forgotten. The true capability test is the held-out cross-file smoke after training.</p>
  <div class="legend">
    <span><i class="sw" style="background:var(--s1)"></i>shape3_codeql (cross-file)</span>
    <span><i class="sw" style="background:var(--muted);opacity:.45"></i>other shapes</span>
  </div>
  <div class="chartwrap"><svg id="c2" viewBox="0 0 860 300"></svg><div class="tip" id="t2"></div></div>
  <details><summary>Table: latest fastval loss per shape</summary>
    <table id="shapetable"></table></details>
</div>
</div>
<script>
const D = __DATA__;
const css = v => getComputedStyle(document.querySelector('.viz-root')).getPropertyValue(v).trim();
document.getElementById('sub').textContent =
  'Generated ' + D.generated + ' - refreshed by watch_training.py while the run is live';
const vdot = document.getElementById('vdot');
vdot.style.background = css(D.vclass === 'good' ? '--good' : D.vclass === 'warning' ? '--warning' : '--critical');
const vt = document.getElementById('vtext');
vt.textContent = (D.vclass === 'good' ? '✓ ' : D.vclass === 'warning' ? '⚠ ' : '✗ ') + D.verdict;
vt.style.color = css(D.vclass === 'good' ? '--good-text' : D.vclass === 'warning' ? '--warn-text' : '--crit-text');

function tile(k, v, d) {
  return '<div class="tile"><div class="k">'+k+'</div><div class="v">'+v+'</div>'
       + (d ? '<div class="d">'+d+'</div>' : '') + '</div>';
}
const pct = D.total ? (100*D.step/D.total).toFixed(1)+'%' : '-';
const lastTrain = D.train.length ? D.train[D.train.length-1][1].toFixed(3) : '-';
const fvLast = D.fv_overall.length ? D.fv_overall[D.fv_overall.length-1][1] : null;
const fvBest = D.fv_overall.length ? Math.min(...D.fv_overall.map(p=>p[1])) : null;
const fxLast = D.per_shape[D.focus] && D.per_shape[D.focus].length
  ? D.per_shape[D.focus][D.per_shape[D.focus].length-1][1] : null;
const fxFirst = D.per_shape[D.focus] && D.per_shape[D.focus].length
  ? D.per_shape[D.focus][0][1] : null;
document.getElementById('tiles').innerHTML =
  tile('Progress', pct, 'step '+D.step+' / '+D.total) +
  tile('Train loss', lastTrain, 'latest 25-step avg') +
  tile('Fastval', fvLast!==null ? fvLast.toFixed(3) : '-',
       fvBest!==null ? 'best '+fvBest.toFixed(3) : 'first check pending') +
  tile('Cross-file val', fxLast!==null ? fxLast.toFixed(3) : '-',
       fxFirst!==null ? 'started '+fxFirst.toFixed(3) : 'shape3_codeql') +
  tile('Rate', D.rate_h ? D.rate_h+' st/h' : '-', 'optimizer steps/hour') +
  tile('ETA', D.eta || '-', D.epochs_total ? D.epochs_total+' epochs' : '');

// ---- minimal line-chart renderer with crosshair tooltip ----
function chart(svgId, tipId, seriesList, refLine) {
  const svg = document.getElementById(svgId), tip = document.getElementById(tipId);
  const W=860, H=300, m={t:14,r:16,b:34,l:52};
  const all = seriesList.flatMap(s=>s.pts);
  if (!all.length) {
    svg.innerHTML = '<text x="'+(W/2)+'" y="'+(H/2)+'" text-anchor="middle" fill="'
      +css('--muted')+'" font-size="13">no data yet - check back after the first steps log</text>';
    return;
  }
  const xs = all.map(p=>p[0]), ys = all.map(p=>p[1]).concat(refLine!=null?[refLine]:[]);
  const x0=Math.min(...xs), x1=Math.max(...xs)||1;
  let y0=Math.min(...ys), y1=Math.max(...ys);
  if (y0===y1) { y0-=0.1; y1+=0.1; }
  const pad=(y1-y0)*0.08; y0=Math.max(0,y0-pad); y1+=pad;
  const X=v=>m.l+(v-x0)/(x1-x0||1)*(W-m.l-m.r);
  const Y=v=>H-m.b-(v-y0)/(y1-y0)*(H-m.t-m.b);
  let g='';
  const yticks=4;
  for (let i=0;i<=yticks;i++){
    const v=y0+(y1-y0)*i/yticks, y=Y(v);
    g+='<line x1="'+m.l+'" y1="'+y+'" x2="'+(W-m.r)+'" y2="'+y+'" stroke="'+css('--grid')+'" stroke-width="1"/>';
    g+='<text x="'+(m.l-7)+'" y="'+(y+3.5)+'" text-anchor="end" font-size="10.5" fill="'+css('--muted')+'">'+v.toFixed(2)+'</text>';
  }
  const xticks=6;
  for (let i=0;i<=xticks;i++){
    const v=Math.round(x0+(x1-x0)*i/xticks), x=X(v);
    g+='<text x="'+x+'" y="'+(H-m.b+16)+'" text-anchor="middle" font-size="10.5" fill="'+css('--muted')+'">'+v+'</text>';
  }
  g+='<line x1="'+m.l+'" y1="'+(H-m.b)+'" x2="'+(W-m.r)+'" y2="'+(H-m.b)+'" stroke="'+css('--axis')+'" stroke-width="1"/>';
  g+='<text x="'+((m.l+W-m.r)/2)+'" y="'+(H-4)+'" text-anchor="middle" font-size="10.5" fill="'+css('--muted')+'">optimizer step</text>';
  if (refLine!=null && refLine>=y0 && refLine<=y1) {
    g+='<line x1="'+m.l+'" y1="'+Y(refLine)+'" x2="'+(W-m.r)+'" y2="'+Y(refLine)+'" stroke="'+css('--muted')+'" stroke-width="1" stroke-dasharray="5 4" opacity="0.7"/>';
    g+='<text x="'+(W-m.r-2)+'" y="'+(Y(refLine)-4)+'" text-anchor="end" font-size="10" fill="'+css('--muted')+'">v10 best val '+refLine+'</text>';
  }
  for (const s of seriesList) {
    if (!s.pts.length) continue;
    const d=s.pts.map((p,i)=>(i?'L':'M')+X(p[0]).toFixed(1)+' '+Y(p[1]).toFixed(1)).join(' ');
    g+='<path d="'+d+'" fill="none" stroke="'+s.color+'" stroke-width="'+(s.width||2)+'" opacity="'+(s.opacity!=null?s.opacity:1)+'" stroke-linejoin="round" stroke-linecap="round"/>';
    if (s.dots) for (const p of s.pts)
      g+='<circle cx="'+X(p[0]).toFixed(1)+'" cy="'+Y(p[1]).toFixed(1)+'" r="3.5" fill="'+s.color+'" stroke="'+css('--surface-1')+'" stroke-width="2"/>';
    if (s.label) {
      const lp=s.pts[s.pts.length-1];
      g+='<text x="'+(X(lp[0])+6)+'" y="'+(Y(lp[1])+3.5)+'" font-size="10.5" font-weight="600" fill="'+css('--ink-2')+'">'+s.label+'</text>';
    }
  }
  g+='<line id="'+svgId+'x" x1="0" y1="'+m.t+'" x2="0" y2="'+(H-m.b)+'" stroke="'+css('--axis')+'" stroke-width="1" opacity="0"/>';
  svg.innerHTML=g;
  const cross=document.getElementById(svgId+'x');
  const hoverSeries = seriesList.filter(s=>s.hover!==false);
  svg.addEventListener('mousemove', ev=>{
    const r=svg.getBoundingClientRect();
    const sx=(ev.clientX-r.left)*(W/r.width);
    const step=x0+(sx-m.l)/(W-m.l-m.r)*(x1-x0);
    let rows=[];
    for (const s of hoverSeries){
      if (!s.pts.length) continue;
      let best=s.pts[0];
      for (const p of s.pts) if (Math.abs(p[0]-step)<Math.abs(best[0]-step)) best=p;
      rows.push({name:s.name,color:s.color,pt:best});
    }
    if (!rows.length) return;
    const anchor=rows[0].pt[0];
    cross.setAttribute('x1',X(anchor)); cross.setAttribute('x2',X(anchor));
    cross.setAttribute('opacity','0.6');
    tip.innerHTML='<b>step '+anchor+'</b><br>'+rows.map(r=>
      '<span style="color:'+r.color+'">●</span> '+r.name+': '+r.pt[1].toFixed(4)).join('<br>');
    tip.style.display='block';
    const tw=tip.offsetWidth;
    let lx=(X(anchor)/W)*r.width+12;
    if (lx+tw>r.width-8) lx=(X(anchor)/W)*r.width-tw-12;
    tip.style.left=lx+'px';
    tip.style.top=((ev.clientY-r.top)-10)+'px';
  });
  svg.addEventListener('mouseleave', ()=>{ tip.style.display='none'; cross.setAttribute('opacity','0'); });
}

chart('c1','t1',[
  {name:'train loss', pts:D.train, color:css('--s1'), width:2},
  {name:'fastval', pts:D.fv_overall, color:css('--s2'), width:2, dots:true},
], D.baseline_v10);

const others = D.shapes.filter(s=>s!==D.focus).map(s=>(
  {name:s, pts:D.per_shape[s]||[], color:css('--muted'), width:1.5, opacity:0.4, hover:false}));
const focusSeries = {name:D.focus, pts:D.per_shape[D.focus]||[], color:css('--s1'),
                     width:2.5, dots:true, label:'cross-file'};
chart('c2','t2', others.concat([focusSeries]), null);

const tbl=document.getElementById('shapetable');
if (D.shapes.length) {
  let rows='<tr><th>shape</th><th>first</th><th>latest</th><th>&Delta;</th></tr>';
  for (const s of D.shapes) {
    const p=D.per_shape[s]; if (!p||!p.length) continue;
    const first=p[0][1], last=p[p.length-1][1], d=last-first;
    rows+='<tr'+(s===D.focus?' style="font-weight:650"':'')+'><td>'+s+'</td><td>'+first.toFixed(3)
      +'</td><td>'+last.toFixed(3)+'</td><td>'+(d<=0?'':'+')+d.toFixed(3)+'</td></tr>';
  }
  tbl.innerHTML=rows;
}
</script>
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--metrics", default="data/qwen_cot_v11/train_metrics.jsonl")
    ap.add_argument("--out", default="data/qwen_cot_v11/dashboard.html")
    args = ap.parse_args()

    rows = load_metrics(Path(args.metrics))
    if not rows:
        print(f"No metrics yet at {args.metrics} — training warming up "
              f"(model load + data tokenization takes a few minutes).")
        return
    a = analyze(rows)
    print_summary(a)
    render_dashboard(a, Path(args.out))


if __name__ == "__main__":
    main()
