"""Cheap observability: one JSON log line per event (ECS awslogs -> CloudWatch Logs Insights) + in-process counters
exposed at /metrics in Prometheus text format. No collector, no extra service, no per-metric AWS charges.
ponytail: counters are per-process and reset on restart; add OpenTelemetry/Grafana Cloud when you need cross-task history."""
import json
import threading
import time
from collections import Counter

_c, _lock = Counter(), threading.Lock()


def inc(name, n=1, **labels):
    with _lock:
        _c[(name, tuple(sorted(labels.items())))] += n


def log(event, **fields):
    print(json.dumps({"ts": round(time.time(), 3), "event": event, **fields}, default=str), flush=True)


def _line(name, labels, value):
    if not labels:
        return f"{name} {value}\n"
    inner = ",".join(k + '="' + str(v) + '"' for k, v in labels)
    return f"{name}{{{inner}}} {value}\n"


def render():
    with _lock:
        items = sorted(_c.items())
    return "".join(_line(n, labels, v) for (n, labels), v in items)
