"""Read the audit log for /guard report. Read-only; the log holds masked values only."""
import json
import os
from collections import Counter, deque
from typing import List, Optional


class AuditSummary:
    def __init__(self):
        self.entries = 0
        self.bad_lines = 0
        self.by_rule: Counter = Counter()
        self.by_action: Counter = Counter()
        self.size_skips = 0
        self.last: List[dict] = []


def summarize(path: str, last: int = 5, max_bytes: Optional[int] = None) -> Optional[AuditSummary]:
    """Counts by rule and action over the whole log, plus the last `last` entries.
    Returns None if the log does not exist. Never raises on malformed lines.
    With max_bytes, only the final max_bytes of a larger log are read (counts then cover that tail)."""
    if not os.path.exists(path):
        return None
    s = AuditSummary()
    tail: deque = deque(maxlen=last)
    with open(path, "rb") as fh:
        if max_bytes is not None and os.path.getsize(path) > max_bytes:
            fh.seek(-max_bytes, os.SEEK_END)
            fh.readline()                       # drop the partial first line
        for raw in fh:
            try:
                e = json.loads(raw)
                if not isinstance(e, dict):
                    raise ValueError
            except ValueError:
                s.bad_lines += 1
                continue
            s.entries += 1
            s.by_action[str(e.get("action", "?"))] += 1
            counts = e.get("rule_counts")
            if not isinstance(counts, dict):    # entries written before v0.2 list every finding
                counts = Counter(str(f.get("rule", "?")) for f in e.get("findings", []) if isinstance(f, dict))
            for rule, n in counts.items():
                if isinstance(n, int):
                    s.by_rule[str(rule)] += n
            if any(str(x).startswith("size:") for x in e.get("errors", [])):
                s.size_skips += 1
            tail.append(e)
    s.last = list(tail)
    return s
