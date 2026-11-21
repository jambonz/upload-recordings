#!/usr/bin/env python3
"""Turns the raw benchmark results (one JSON object per run) into the
Markdown tables used in BENCHMARKS.md.

    python3 report.py [results-dir]

Every cell is "median (min-max)" over the repeated runs of that configuration.
"""
import json
import os
import statistics
import sys
from collections import defaultdict

d = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "raw")


def load(name):
    path = os.path.join(d, name + ".jsonl")
    if not os.path.exists(path):
        return []
    return [json.loads(line) for line in open(path) if line.strip()]


def spread(values, fmt="%.0f"):
    values = list(values)
    if not values:
        return "-"
    med = statistics.median(values)
    if min(values) == max(values):
        return fmt % med
    return (fmt + " (" + fmt + "-" + fmt + ")") % (med, min(values), max(values))


def table(header, rows):
    print("| " + " | ".join(header) + " |")
    print("|" + "|".join("---" for _ in header) + "|")
    for row in rows:
        print("| " + " | ".join(str(c) for c in row) + " |")
    print()


def load_table(runs, key_fields):
    groups = defaultdict(list)
    for r in runs:
        groups[tuple(key_fields(r))].append(r)
    rows = []
    for key in sorted(groups, key=lambda k: [x if isinstance(x, (int, float)) else str(x) for x in k]):
        g = groups[key]
        audio_secs = [r["load"]["bytes_sent"] / (r["load"]["rate"] * 4) for r in g]
        rows.append(list(key) + [
            len(g),
            spread((r["server"]["cpu_secs"] for r in g), "%.1f"),
            spread((r["server"]["cpu_secs"] / a * 1000 for r, a in zip(g, audio_secs)), "%.2f"),
            spread(r["server"]["peak_cpu_pct"] for r in g),
            spread(r["server"]["median_rss_mb"] for r in g),
            spread(r["server"]["peak_rss_mb"] for r in g),
            spread(r["load"]["latency_ms"]["P50"] for r in g),
            spread(r["load"]["latency_ms"]["P99"] for r in g),
            spread(r["load"]["latency_ms"]["Max"] for r in g),
            "%d / %d / %d" % (sum(r["load"]["objects_missing"] for r in g), sum(r["load"]["objects_short"] for r in g),
                              sum(r["load"]["connect_errors"] + r["load"]["send_errors"] for r in g)),
            spread((r["load"]["audio_bytes_lost"] / 1e6 for r in g), "%.1f"),
            spread(r["load"]["max_late_ms"] for r in g),
            spread(r["server"]["busiest_thread_share_pct"] for r in g),
        ])
    return rows


COLS = ["runs", "CPU s", "CPU ms per audio s", "peak CPU %", "RSS median MB", "RSS peak MB",
        "latency p50 ms", "p99 ms", "max ms", "missing / short / errors", "audio lost MB",
        "sender lag max ms", "busiest thread % of CPU"]

for suite, title in (("main", "Main: 4 cores, 8 kHz stereo, 60 s calls"),
                     ("rate16k", "16 kHz stereo, 500 sessions, 4 cores, 60 s calls")):
    runs = load(suite)
    if runs:
        print("### " + title + "\n")
        table(["format", "sessions", "impl"] + COLS,
              load_table(runs, lambda r: (r["format"], r["load"]["sessions"], r["impl"])))

runs = load("scaling")
if runs:
    print("### Scaling: 1000 sessions, 30 s calls, 1/2/4/8 cores\n")
    table(["format", "cores", "impl"] + COLS, load_table(runs, lambda r: (r["format"], r["cores"], r["impl"])))

runs = load("blast")
if runs:
    print("### Ingest ceiling: 8 connections sending as fast as the server reads, 1 s\n")
    groups = defaultdict(list)
    for r in runs:
        groups[(r["cores"], r["impl"])].append(r)
    rows = []
    for (cores, impl), g in sorted(groups.items()):
        wall = [r["load"]["send_secs"] for r in g]
        rows.append([cores, impl, len(g),
                     spread((r["load"]["bytes_sent"] / 1e6 / w for r, w in zip(g, wall))),
                     spread(r["load"]["ingest_mb_per_sec"] for r in g),
                     spread((r["load"]["audio_bytes_lost"] / max(1, r["load"]["bytes_sent"]) * 100 for r in g), "%.1f"),
                     spread((r["load"]["ingest_mb_per_sec"] * 1e6 / 32000 for r in g)),
                     spread(r["server"]["peak_cpu_pct"] for r in g),
                     spread(r["server"]["peak_rss_mb"] for r in g),
                     spread(r["server"]["busiest_thread_share_pct"] for r in g)])
    table(["cores", "impl", "runs", "accepted MB/s", "stored MB/s", "audio lost %",
           "stored rate as 8 kHz calls", "peak CPU %", "RSS peak MB", "busiest thread % of CPU"], rows)

for suite, title, a_name in (("slow", "Slow storage for one tenant (uploads take 20 s)", "A (slow bucket, 24 x 10 s)"),
                             ("stalled", "Stalled storage for one tenant (uploads time out)", "A (stalled bucket, 24 x 10 s)")):
    runs = load(suite)
    if not runs:
        continue
    print("### " + title + "\n")
    rows = []
    for r in runs:
        for t, name in (("tenantA", a_name), ("tenantB", "B (healthy bucket, 50 x 150 s)")):
            l = r[t]
            rows.append([r["impl"], r["rep"], name, l["objects_found"], l["objects_missing"], l["objects_short"],
                         "%.1f of %.1f" % (l["audio_bytes_lost"] / 1e6, l["bytes_sent"] / 1e6),
                         "%.1f" % (l["latency_ms"]["P50"] / 1000), "%.1f" % (l["latency_ms"]["Max"] / 1000),
                         "%.0f" % r["server"]["peak_rss_mb"], r["drop_log_lines"]])
    table(["impl", "run", "tenant", "stored", "missing", "short", "audio lost MB", "latency p50 s", "max s",
           "server RSS peak MB", "'dropping' log lines"], rows)

runs = load("failing")
if runs:
    print("### Storage answering 503\n")
    rows = []
    for r in runs:
        f, h = r["failing"], r["healthy_after"]
        rows.append([r["impl"], "%d of %d" % (f["objects_missing"], f["sessions"]), r["upload_error_lines"],
                     r["spool_files_left"], "%d of %d" % (h["objects_found"], h["sessions"]),
                     "%.0f" % r["server"]["peak_rss_mb"], "%.1f" % r["server"]["cpu_secs"]])
    table(["impl", "recordings lost", "upload errors logged", "spool files left", "healthy tenant stored afterwards",
           "RSS peak MB", "CPU s"], rows)

runs = load("coldstart")
if runs:
    print("### Cold start\n")
    groups = defaultdict(list)
    for r in runs:
        groups[r["impl"]].append(r["ms"])
    table(["impl", "runs", "ms to accepting connections"],
          [[impl, len(v), spread(v) + "; all: " + ", ".join(str(x) for x in v)] for impl, v in sorted(groups.items())])
