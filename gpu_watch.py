"""GPU health logger for diagnosing the 'GPU is lost' failures.

Samples NVML at 1 Hz and appends one CSV row per sample, flushed + fsync'd
every row so a hard bus-detach cannot lose the tail of the trace -- the last
few seconds before the card vanishes are the whole point of this script.

Logs the throttle/event-reason bits that discriminate our two live theories:
  hw_power_brake -> the card's over-current protection tripped (power delivery)
  hw_thermal     -> thermal emergency slowdown
  sw_thermal     -> driver-side thermal backoff
A clean disappearance with none of these set argues for PCIe/link or a fault
below the level the driver can see.

Usage:
    python gpu_watch.py --out data/gpu_watch/run.csv [--interval 1.0]
"""
import argparse
import csv
import datetime as dt
import os
import sys
import time

import pynvml as N

# Throttle-reason bits. Names moved between NVML versions, so resolve defensively.
_REASONS = [
    ("sw_power_cap", ("nvmlClocksEventReasonSwPowerCap", "nvmlClocksThrottleReasonSwPowerCap")),
    ("hw_slowdown", ("nvmlClocksEventReasonHwSlowdown", "nvmlClocksThrottleReasonHwSlowdown")),
    ("sw_thermal", ("nvmlClocksEventReasonSwThermalSlowdown", "nvmlClocksThrottleReasonSwThermalSlowdown")),
    ("hw_thermal", ("nvmlClocksEventReasonHwThermalSlowdown", "nvmlClocksThrottleReasonHwThermalSlowdown")),
    ("hw_power_brake", ("nvmlClocksEventReasonHwPowerBrakeSlowdown", "nvmlClocksThrottleReasonHwPowerBrakeSlowdown")),
]


def _resolve_reasons():
    out = []
    for label, names in _REASONS:
        for n in names:
            bit = getattr(N, n, None)
            if isinstance(bit, int):
                out.append((label, bit))
                break
    return out


def _get_event_reasons(h):
    for fn in ("nvmlDeviceGetCurrentClocksEventReasons", "nvmlDeviceGetCurrentClocksThrottleReasons"):
        f = getattr(N, fn, None)
        if f is not None:
            return f(h)
    return 0


def _safe(fn, default=""):
    try:
        return fn()
    except Exception:
        return default


FIELDS = [
    "ts", "elapsed_s", "temp_edge_c", "power_w", "power_limit_w",
    "sm_clock_mhz", "mem_clock_mhz", "gpu_util_pct", "mem_util_pct",
    "mem_used_mib", "fan_pct", "pcie_gen", "pcie_width",
    "perf_state", "reasons_hex",
] + [label for label, _ in _REASONS]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--interval", type=float, default=1.0)
    args = ap.parse_args()

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)

    N.nvmlInit()
    h = N.nvmlDeviceGetHandleByIndex(0)
    reasons = _resolve_reasons()
    print(f"watching {N.nvmlDeviceGetName(h)} | driver {N.nvmlSystemGetDriverVersion()}", flush=True)
    print(f"reason bits resolved: {[r[0] for r in reasons]}", flush=True)
    print(f"logging -> {args.out}", flush=True)

    start = time.time()
    new_file = not os.path.exists(args.out) or os.path.getsize(args.out) == 0

    with open(args.out, "a", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        if new_file:
            w.writeheader()

        while True:
            try:
                mem = N.nvmlDeviceGetMemoryInfo(h)
                util = N.nvmlDeviceGetUtilizationRates(h)
                bits = _get_event_reasons(h)
                row = {
                    "ts": dt.datetime.now().isoformat(timespec="seconds"),
                    "elapsed_s": round(time.time() - start, 1),
                    "temp_edge_c": N.nvmlDeviceGetTemperature(h, N.NVML_TEMPERATURE_GPU),
                    "power_w": round(N.nvmlDeviceGetPowerUsage(h) / 1000.0, 1),
                    "power_limit_w": round(N.nvmlDeviceGetEnforcedPowerLimit(h) / 1000.0, 1),
                    "sm_clock_mhz": _safe(lambda: N.nvmlDeviceGetClockInfo(h, N.NVML_CLOCK_SM)),
                    "mem_clock_mhz": _safe(lambda: N.nvmlDeviceGetClockInfo(h, N.NVML_CLOCK_MEM)),
                    "gpu_util_pct": util.gpu,
                    "mem_util_pct": util.memory,
                    "mem_used_mib": mem.used // (1024 * 1024),
                    "fan_pct": _safe(lambda: N.nvmlDeviceGetFanSpeed(h)),
                    "pcie_gen": _safe(lambda: N.nvmlDeviceGetCurrPcieLinkGeneration(h)),
                    "pcie_width": _safe(lambda: N.nvmlDeviceGetCurrPcieLinkWidth(h)),
                    "perf_state": _safe(lambda: N.nvmlDeviceGetPerformanceState(h)),
                    "reasons_hex": hex(bits),
                }
                for label, bit in reasons:
                    row[label] = int(bool(bits & bit))
                w.writerow(row)
                fh.flush()
                os.fsync(fh.fileno())
            except Exception as e:
                # The card going away lands here. Record it, loudly, then stop.
                stamp = dt.datetime.now().isoformat(timespec="seconds")
                fh.write(f"# GPU_QUERY_FAILED,{stamp},{type(e).__name__},{str(e).replace(chr(10), ' ')}\n")
                fh.flush()
                os.fsync(fh.fileno())
                print(f"\n*** GPU QUERY FAILED at {stamp}: {type(e).__name__}: {e}", flush=True)
                print("*** card is gone -- last good sample is the row above the marker", flush=True)
                return 2

            time.sleep(args.interval)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nstopped", flush=True)
