"""Run detectors, apply policy, return a decision."""
import re
from dataclasses import dataclass, field
from typing import List

from .findings import Finding
from .policy import Policy
from .microdata import find_microdata
from .network import find_network_egress
from .secrets import find_secrets
from .smallcell import find_small_cells, find_tables

ACTION_ORDER = ("allow", "warn", "redact", "approve", "block")


@dataclass
class Decision:
    action: str = "allow"                   # allow | warn | redact | approve | block
    findings: List[Finding] = field(default_factory=list)
    redacted_text: str = ""                 # input with flagged spans replaced
    errors: List[str] = field(default_factory=list)
    skipped: str = ""                       # why the input was not scanned (e.g. over max_scan_bytes)

    @property
    def summary(self) -> str:
        if not self.findings:
            return "No issues found."
        by_rule = {}
        for f in self.findings:
            by_rule[f.rule] = by_rule.get(f.rule, 0) + 1
        parts = ", ".join(f"{n}× {r}" for r, n in sorted(by_rule.items()))
        return f"{self.action.upper()}: {parts}"

    def explain(self) -> str:
        """Plain-language reasons, safe to show to the user or the model."""
        return "\n".join(f"- [{f.severity}] {f.reason} (found: {f.masked})" for f in self.findings)


def apply_redactions(text: str, findings: List[Finding]) -> str:
    out, last = [], 0
    for f in sorted(findings, key=lambda f: f.start):
        if f.replacement is None or f.start < last:
            continue
        out.append(text[last:f.start])
        out.append(f.replacement)
        last = f.end
    out.append(text[last:])
    return "".join(out)


def _utf8_len_over(text: str, limit: int) -> int:
    """Return the UTF-8 size of text if it exceeds limit, else 0. Cheap for short text."""
    if len(text) > limit:                    # every char is >= 1 byte
        return len(text.encode("utf-8", "surrogatepass"))
    if len(text) * 4 <= limit:               # every char is <= 4 bytes
        return 0
    n = len(text.encode("utf-8", "surrogatepass"))
    return n if n > limit else 0


def inspect_text(text: str, policy: Policy, scope: str = None, command: bool = False) -> Decision:
    """Inspect one piece of text. Never raises: detector errors follow policy.fail_mode.

    scope: 'args' | 'result' | 'reply' restricts to rule groups enabled for that scope
    (None = every enabled group). command=True also runs the shell-egress check.
    """
    decision = Decision(redacted_text=text)
    if not isinstance(text, str) or not text:
        return decision

    # Size cap: Hermes drops a pre_tool_call callback that runs over 30 s, and regex/table
    # parsing time grows with input size. Oversize text is not parsed; fail_mode decides.
    size = _utf8_len_over(text, getattr(policy, "max_scan_bytes", 1048576))
    if size:
        decision.skipped = (f"input is {size} bytes, over max_scan_bytes "
                            f"({policy.max_scan_bytes}); not scanned")
        decision.errors.append(f"size: {decision.skipped}")
        decision.action = "block" if policy.fail_mode == "closed" else "allow"
        return decision

    allow = [re.compile(p) for p in policy.allowlist]
    raw: List[Finding] = []
    rules = policy.rules

    try:
        if policy.applies("secrets", scope):
            raw += find_secrets(text, rules["secrets"].get("entropy_threshold", 3.5))
    except Exception as e:                     # noqa: BLE001 - guard must not crash the agent
        decision.errors.append(f"secrets: {type(e).__name__}: {e}")
    tables = None                              # parsed once, shared by smallcell and microdata
    try:
        sc = rules.get("smallcell", {})
        if policy.applies("smallcell", scope):
            tables = find_tables(text)
            raw += find_small_cells(text, sc.get("threshold", 5), sc.get("min_value", 1),
                                    sc.get("complementary", True), tables=tables,
                                    method=sc.get("method", "suppress"))
    except Exception as e:                     # noqa: BLE001
        decision.errors.append(f"smallcell: {type(e).__name__}: {e}")

    try:
        if policy.applies("microdata", scope):
            raw += find_microdata(text, rules["microdata"].get("max_rows", 20), tables=tables)
    except Exception as e:                     # noqa: BLE001
        decision.errors.append(f"microdata: {type(e).__name__}: {e}")

    try:
        if command and policy.applies("network", scope):
            raw += find_network_egress(text, rules["network"].get("allowed_hosts", []),
                                       rules["network"].get("match", "uploads"))
    except Exception as e:                     # noqa: BLE001
        decision.errors.append(f"network: {type(e).__name__}: {e}")

    findings = [f for f in raw if not any(rx.search(text[f.start:f.end]) for rx in allow)]
    decision.findings = findings

    action = "allow"
    for f in findings:
        mode = policy.mode_for(f.rule)
        action = max(action, "warn" if mode == "warn" else mode, key=ACTION_ORDER.index) \
            if mode != "off" else action
    if decision.errors and policy.fail_mode == "closed":
        action = max(action, "block", key=ACTION_ORDER.index)
    decision.action = action

    # Only substitute for rules whose mode actually asks for it (redact or stricter).
    to_redact = [f for f in findings
                 if policy.mode_for(f.rule) in ("redact", "approve", "block")]
    decision.redacted_text = apply_redactions(text, to_redact)
    return decision
