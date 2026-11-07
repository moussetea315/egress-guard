from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Finding:
    """One thing a detector noticed. Never stores the raw secret."""
    rule: str                 # e.g. "secret.aws_access_key", "smallcell.count"
    reason: str               # human-readable explanation
    start: int                # offset in the inspected text
    end: int
    masked: str               # safe preview, never the full value
    severity: str = "medium"  # low | medium | high
    replacement: Optional[str] = None   # what redaction would substitute
    meta: dict = field(default_factory=dict)


def mask(value: str, keep: int = 4) -> str:
    """Show only the first few characters of a sensitive value."""
    value = value.strip()
    if len(value) <= keep * 2:
        return "*" * len(value)
    return value[:keep] + "…" + "*" * 4
