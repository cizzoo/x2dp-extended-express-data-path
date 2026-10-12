#!/usr/bin/env python3
"""Run an X2DP evaluation suite.

A suite (eval/suites/*.json) is a list of runs. Each run puts the card in one
mode, optionally sweeps the batch size, and for every program: starts its
loader, measures the configured metrics for `time` seconds each, and stops it.
Repeated `repetitions` times; results go to <out>/results.csv (mean and std)
and <out>/all_results.csv (one row per repetition).

Usage: sudo eval/run.py eval/suites/apps.json --ifname <if> --ioctl <path>
"""

import argparse
import csv
import json
import os
import re
import shlex
import statistics
import subprocess as sp
import sys
from time import sleep

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# onic-driver `ioctl` utility commands
IOCTL_MODE = {"baseline": ["-c", "0"], "x2dp": ["-c", "1"]}
IOCTL_BATCH_SIZE = ["-c", "9", "-w"]
IOCTL_RX_PACKETS = ["-c", "3", "-w"]  # prints the packets received in -w seconds

METRICS = ("throughput", "cpu", "ipc", "stalls", "l1-misses")

# Checked before the suite starts: a mismatch is reported, not fatal.
CHECKS = [
    ("bpf_stats disabled", "sysctl -n kernel.bpf_stats_enabled", r"^0$"),
]


def sh(cmd, **kw):
    return sp.run(cmd, capture_output=True, text=True, check=True, **kw)


def log(out, msg):
    print(msg)
    with open(os.path.join(out, "log.txt"), "a") as f:
        f.write(msg + "\n")


def set_mode(ioctl, mode, batch_size):
    sh([ioctl, *IOCTL_MODE[mode]])
    if mode == "x2dp":
        sh([ioctl, *IOCTL_BATCH_SIZE, str(batch_size)])


def prog_id(name):
    out = sh(["bpftool", "prog", "show", "name", name]).stdout
    m = re.search(r"^(\d+):\s*xdp", out, re.M)
    if not m:
        raise RuntimeError(f"XDP program {name} is not loaded")
    return m.group(1)


def perf_stat(perf, name, events, time):
    """Count `events` on the BPF program only (perf stat -b)."""
    r = sh([perf, "stat", "-b", prog_id(name), "-e", ",".join(events),
            "--timeout", str(time * 1000)])
    return r.stderr


def perf_per_run(perf, name, event, time):
    out = perf_stat(perf, name, [event], time)
    count = re.search(rf"([\d,]+)\s+{re.escape(event)}", out)
    runs = re.search(r"run:\s*(\d+)", out)
    if not count or not runs:
        raise RuntimeError(f"cannot parse perf output:\n{out}")
    return int(count.group(1).replace(",", "")) / int(runs.group(1))


def measure(metric, args, cfg, name):
    time = cfg["time"]
    if metric == "throughput":
        return int(sh([args.ioctl, *IOCTL_RX_PACKETS, str(time)]).stdout) / time
    if metric == "cpu":
        import psutil
        return psutil.cpu_percent(interval=1, percpu=True)[cfg["cpu"]]
    if metric == "ipc":
        out = perf_stat(args.perf, name, ["cycles", "instructions"], time)
        m = re.search(r"([\d.]+)\s+insn per cycle", out)
        if not m:
            raise RuntimeError(f"cannot parse perf output:\n{out}")
        return float(m.group(1))
    if metric == "stalls":
        return perf_per_run(args.perf, name, "cycle_activity.stalls_total", time)
    if metric == "l1-misses":
        return perf_per_run(args.perf, name, "L1-dcache-load-misses", time)
    raise ValueError(metric)


def run_prog(prog, args, cfg, metrics, out):
    if isinstance(prog, str):
        prog = {"path": prog}
    path = os.path.join(REPO, prog["path"])
    name = os.path.basename(path)
    extra = prog.get("args", "").replace("@", REPO)
    samples = {m: [] for m in metrics}

    for rep in range(cfg["repetitions"]):
        # Loaders resolve their data files relative to their own directory.
        loader = sp.Popen([path, args.ifname, *shlex.split(extra)],
                          cwd=os.path.dirname(path), stdout=sp.PIPE,
                          stderr=sp.STDOUT, text=True)
        sleep(1)
        if loader.poll() is not None:
            raise RuntimeError(f"{name} exited:\n{loader.communicate()[0]}")
        try:
            row = []
            for m in metrics:
                v = measure(m, args, cfg, name)
                samples[m].append(v)
                row.append(v)
                log(out, f"  {name} rep {rep + 1} {m}: {v}")
        finally:
            loader.terminate()
            loader.wait()
        yield "rep", [name, rep + 1, *row]

    row = [name]
    for m in metrics:
        row.append(statistics.mean(samples[m]))
        row.append(statistics.pstdev(samples[m]))
    yield "mean", row


def main():
    p = argparse.ArgumentParser(description=(__doc__ or "").strip().splitlines()[0])
    p.add_argument("suite", help="suite JSON file")
    p.add_argument("--ifname", required=True, help="onic interface")
    p.add_argument("--ioctl", default=os.environ.get("ONIC_IOCTL", "ioctl"),
                   help="onic-driver ioctl utility (default: $ONIC_IOCTL)")
    p.add_argument("--perf", default=os.environ.get("PERF", "perf"),
                   help="perf binary with BPF support (default: $PERF)")
    p.add_argument("--out", help="output directory "
                   "(default: eval/results/<suite name>)")
    args = p.parse_args()

    if os.geteuid() != 0:
        sys.exit("run as root")

    with open(args.suite) as f:
        suite = json.load(f)
    suite_name = os.path.splitext(os.path.basename(args.suite))[0]
    out = args.out or os.path.join(REPO, "eval", "results", suite_name)
    os.makedirs(out, exist_ok=True)
    open(os.path.join(out, "log.txt"), "w").close()

    for check, cmd, expected in CHECKS:
        got = sh(shlex.split(cmd)).stdout.strip()
        if not re.search(expected, got):
            log(out, f"WARNING: {check}: got '{got}'")

    defaults = {k: v for k, v in suite.items() if k != "runs"}
    metrics_all = []
    for run in suite["runs"]:
        for m in run.get("metrics", defaults.get("metrics", ["throughput"])):
            if m not in METRICS:
                sys.exit(f"unknown metric {m} (known: {', '.join(METRICS)})")
            if m not in metrics_all:
                metrics_all.append(m)

    head = ["mode", "batch_size", "program"]
    with open(os.path.join(out, "results.csv"), "w", newline="") as f:
        csv.writer(f).writerow(
            head + [c for m in metrics_all for c in (m, f"{m}_std")])
    with open(os.path.join(out, "all_results.csv"), "w", newline="") as f:
        csv.writer(f).writerow(head + ["repetition"] + metrics_all)

    for run in suite["runs"]:
        cfg = {**defaults, **run}
        metrics = cfg.get("metrics", ["throughput"])
        mode = cfg["mode"]
        sizes = cfg.get("batch-sizes", [16]) if mode == "x2dp" else [1]
        for n in sizes:
            set_mode(args.ioctl, mode, n)
            log(out, f"mode {mode}, batch size {n}")
            for prog in cfg["progs"]:
                for kind, row in run_prog(prog, args, cfg, metrics, out):
                    # pad missing metrics so the columns stay aligned
                    if kind == "rep":
                        vals = dict(zip(metrics, row[2:]))
                        row = row[:2] + [vals.get(m, "") for m in metrics_all]
                        fname = "all_results.csv"
                    else:
                        vals = {m: row[1 + 2 * i: 3 + 2 * i]
                                for i, m in enumerate(metrics)}
                        row = row[:1] + [x for m in metrics_all
                                         for x in vals.get(m, ["", ""])]
                        fname = "results.csv"
                    with open(os.path.join(out, fname), "a", newline="") as f:
                        csv.writer(f).writerow([mode, n] + row)

    # leave the card in baseline mode
    set_mode(args.ioctl, "baseline", 1)


if __name__ == "__main__":
    main()
