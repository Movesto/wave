"""Sustained GPU load for hardware diagnosis -- NOT training.

Mirrors the stress profile of a QLoRA run (large bf16 matmuls against a big
resident working set) without touching any model or checkpoint, so we can test
stability without committing to a training run.

Holds a configurable share of VRAM resident and runs back-to-back matmuls,
printing a heartbeat with elapsed time so a hang is distinguishable from a
crash. Any CUDA fault is caught, timestamped and re-raised loudly.

Usage:
    python stress_gpu.py --minutes 90 [--vram-frac 0.80] [--size 8192]
"""
import argparse
import datetime as dt
import sys
import time

import torch


def log(msg):
    print(f"[{dt.datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--minutes", type=float, default=90.0)
    ap.add_argument("--size", type=int, default=8192, help="matmul dimension")
    ap.add_argument("--vram-frac", type=float, default=0.80,
                    help="fraction of total VRAM to hold resident")
    ap.add_argument("--heartbeat", type=float, default=60.0, help="seconds between heartbeats")
    args = ap.parse_args()

    if not torch.cuda.is_available():
        log("CUDA not available -- aborting")
        return 1

    dev = torch.device("cuda:0")
    props = torch.cuda.get_device_properties(0)
    total_gb = props.total_memory / 1024**3
    log(f"device: {props.name}  VRAM {total_gb:.1f} GiB  torch {torch.__version__}")

    n = args.size
    # bf16 matches the training dtype and pushes the tensor cores hardest.
    dtype = torch.bfloat16
    bytes_per = n * n * 2

    # Two operands + one output per working set; fill to the requested fraction.
    target_bytes = props.total_memory * args.vram_frac
    n_buffers = max(3, int(target_bytes // bytes_per))
    log(f"matmul {n}x{n} bf16 | allocating {n_buffers} buffers "
        f"(~{n_buffers * bytes_per / 1024**3:.1f} GiB target {args.vram_frac:.0%})")

    bufs = []
    try:
        for i in range(n_buffers):
            bufs.append(torch.randn(n, n, device=dev, dtype=dtype))
    except torch.cuda.OutOfMemoryError:
        log(f"OOM while filling at buffer {i} -- continuing with {len(bufs)}")
    if len(bufs) < 3:
        log("could not allocate a working set -- aborting")
        return 1

    resident = torch.cuda.memory_allocated() / 1024**3
    log(f"resident: {resident:.1f} GiB across {len(bufs)} buffers")
    log(f"running for {args.minutes:.0f} min -- Ctrl-C or kill to stop early")

    deadline = time.time() + args.minutes * 60
    start = time.time()
    last_beat = start
    iters = 0
    k = len(bufs)

    try:
        while time.time() < deadline:
            # Rotate through buffers so the whole resident set stays hot.
            a = bufs[iters % k]
            b = bufs[(iters + 1) % k]
            out = bufs[(iters + 2) % k]
            torch.matmul(a, b, out=out)
            iters += 1

            now = time.time()
            if now - last_beat >= args.heartbeat:
                torch.cuda.synchronize()
                el = now - start
                log(f"alive  elapsed={el/60:.1f}min  iters={iters}  "
                    f"{iters/el:.1f} it/s  peak={torch.cuda.max_memory_allocated()/1024**3:.1f} GiB")
                last_beat = now

        torch.cuda.synchronize()
        el = time.time() - start
        log(f"COMPLETED CLEAN  {el/60:.1f} min  {iters} iters  no fault")
        return 0

    except KeyboardInterrupt:
        log("interrupted by user")
        return 0
    except Exception as e:
        # A bus-detach / Xid lands here. Timestamp it precisely -- this is the
        # moment to line up against the gpu_watch CSV.
        log(f"*** GPU FAULT after {(time.time() - start)/60:.1f} min / {iters} iters")
        log(f"*** {type(e).__name__}: {e}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
