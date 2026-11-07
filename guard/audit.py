"""Append-only JSONL audit log. Stores masked previews only, never raw values."""
import hashlib
import json
import os
import time
from typing import Optional

from .engine import Decision


MAX_FINDINGS = 50          # findings listed per entry; findings_total always has the full count
MAX_LINE_BYTES = 65536     # hard cap on one JSONL line
_MAX_FIELD = 300           # per-string cap used when an entry is still over MAX_LINE_BYTES
_MAX_ERRORS = 10


def _clip(v: str, n: int) -> str:
    return v if len(v) <= n else v[:n - 1] + "…"


def _rule_counts(findings) -> dict:
    out = {}
    for f in findings:
        out[f.rule] = out.get(f.rule, 0) + 1
    return out


def _encode(entry: dict) -> str:
    return json.dumps(entry)


def _fit(entry: dict) -> str:
    """Serialize entry within MAX_LINE_BYTES: clip strings first, then drop listed findings."""
    line = _encode(entry)
    if len(line.encode()) <= MAX_LINE_BYTES:
        return line
    entry["truncated"] = True
    entry["findings"] = [{k: _clip(v, _MAX_FIELD) if isinstance(v, str) else v for k, v in f.items()}
                         for f in entry["findings"]]
    entry["errors"] = [_clip(e, _MAX_FIELD) for e in entry["errors"]]
    entry["tool"] = _clip(entry["tool"], _MAX_FIELD)
    line = _encode(entry)
    while len(line.encode()) > MAX_LINE_BYTES and entry["findings"]:
        entry["findings"] = entry["findings"][:len(entry["findings"]) // 2]
        line = _encode(entry)
    return line


def record(decision: Decision, path: str, direction: str = "", tool: str = "",
           source_text: Optional[str] = None) -> bool:
    """Write one audit line. Returns False (never raises) if logging fails.

    At most MAX_FINDINGS findings are listed (findings_total has the real count) and the
    line never exceeds MAX_LINE_BYTES; "truncated": true marks an entry that was shortened."""
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        fs = decision.findings
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "direction": direction,
            "tool": tool or "",
            "action": decision.action,
            "findings_total": len(fs),
            "rule_counts": _rule_counts(fs),
            "findings": [{"rule": f.rule, "severity": f.severity, "masked": f.masked,
                          "reason": f.reason} for f in fs[:MAX_FINDINGS]],
            "errors": list(decision.errors[:_MAX_ERRORS]),
        }
        if len(fs) > MAX_FINDINGS or len(decision.errors) > _MAX_ERRORS:
            entry["truncated"] = True
        if source_text is not None:
            entry["input_sha256_12"] = hashlib.sha256(
                source_text.encode("utf-8", "surrogatepass")).hexdigest()[:12]
        line = _fit(entry)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        return True
    except (OSError, ValueError, TypeError):
        return False
