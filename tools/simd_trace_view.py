
import json, sys
from pathlib import Path
import matplotlib.pyplot as plt

def load_events(path):
    events = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip(): continue
            events.append(json.loads(line))
    return events

def main():
    if len(sys.argv) < 3:
        print("Usage: python simd_trace_view.py trace.jsonl output.png")
        sys.exit(1)
    events = load_events(sys.argv[1])
    if not events:
        print("No events found.")
        sys.exit(0)

    # Normalize times
    t0 = min(e["t_ns"] for e in events)
    for e in events:
        e["t_ms"] = (e["t_ns"] - t0) / 1e6

    # Split by action
    actions = ["select", "switch", "calibrate", "call"]
    ys = {a:i for i,a in enumerate(actions)}
    xs = [e["t_ms"] for e in events]
    ys_plot = [ys.get(e["action"], len(actions)) for e in events]

    plt.figure(figsize=(10,4))
    plt.scatter(xs, ys_plot, s=8)
    plt.yticks(list(ys.values()), list(ys.keys()))
    plt.xlabel("time (ms)")
    plt.title("SIMD Dispatch Trace")
    plt.tight_layout()
    plt.savefig(sys.argv[2], dpi=150)

if __name__ == "__main__":
    main()
