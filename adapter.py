"""Hermes hook adapter: thin glue between Hermes hook contracts and the guard engine.

Contracts (Hermes v0.22.2, verified against the installed source):
  pre_tool_call(tool_name, args, **kw)  -> None | {"action": "block"|"approve"|"modify", ...}
  transform_tool_result(tool_name, args, result, **kw) -> None | str
  transform_llm_output(response_text, **kw)            -> None | str
Hermes fails pre_tool_call CLOSED if a callback raises, so every function here
catches its own errors and applies policy.fail_mode instead. Exception text
reaches the model, so no message here ever contains a raw flagged value.
"""
import json
import re
from typing import Any, Callable, Optional

from .guard import audit
from .guard.engine import ACTION_ORDER, apply_redactions, inspect_text
from .guard.report import summarize
from .guard.secrets import find_secrets

PREVIEW_MAX = 120

CODES = {"secret": "EG-SECRET-001", "smallcell": "EG-CELL-001", "microdata": "EG-MICRO-001",
         "network": "EG-NET-001"}


def _code(rule: str) -> str:
    return CODES.get(rule.split(".")[0], "EG-GENERIC")


def _codes(decisions) -> str:
    seen = []
    for d in decisions:
        if d.skipped and d.action == "block" and "EG-SIZE-001" not in seen:
            seen.append("EG-SIZE-001")
        for f in d.findings:
            c = _code(f.rule)
            if c not in seen:
                seen.append(c)
    return ", ".join(seen)


def _reasons(decisions, limit: int = 3) -> str:
    out = []
    for d in decisions:
        if d.skipped and d.action == "block":
            r = "Input too large to scan (over max_scan_bytes) and policy is fail-closed."
            if r not in out:
                out.append(r)
        for f in d.findings:
            if f.reason not in out:
                out.append(f.reason)
    return " ".join(out[:limit])


def _top(decisions) -> str:
    top = "allow"
    for d in decisions:
        top = max(top, d.action, key=ACTION_ORDER.index)
    return top


def command_preview(text: str, decision=None, limit: int = PREVIEW_MAX) -> str:
    """One-line, masked, truncated preview of a shell command for approval/block messages.

    Secrets are always masked here, whatever the secrets rule's mode (even warn/off), and
    any other redaction the decision made (e.g. small cells) is applied too. A command that
    was too large to scan is never previewed, since its content was not checked."""
    if decision is not None and decision.skipped:
        return "(not shown: command is over max_scan_bytes)"
    spans = find_secrets(text)
    if decision is not None:
        spans += [f for f in decision.findings if f.replacement]
    masked = re.sub(r"\s+", " ", apply_redactions(text, spans)).strip()
    return masked if len(masked) <= limit else masked[:limit - 1].rstrip() + "…"


def _log(policy, decision, scope: str, tool: str, text: str) -> None:
    if policy.audit_enabled and (decision.findings or decision.errors):
        audit.record(decision, policy.audit_path, direction=scope, tool=tool, source_text=text)


def _map_strings(obj: Any, fn: Callable[[str, bool], str], key: str = "") -> Any:
    """Rebuild obj with fn applied to every string leaf. fn(text, is_command_key)."""
    if isinstance(obj, str):
        return fn(obj, key == "command")
    if isinstance(obj, dict):
        return {k: _map_strings(v, fn, str(k)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_map_strings(v, fn, key) for v in obj]
    return obj


# ---------------------------------------------------------------- pre_tool_call
def pre_tool_call(policy, tool_name: str = "", args: Any = None, **_kw) -> Optional[dict]:
    try:
        if not isinstance(args, dict):
            return None
        decisions = []
        commands = []                       # (text, decision) for each 'command' argument

        def visit(text: str, is_cmd: bool) -> str:
            d = inspect_text(text, policy, scope="args", command=is_cmd)
            if is_cmd:
                commands.append((text, d))
            if d.findings or d.errors:
                decisions.append(d)
                _log(policy, d, "args", tool_name, text)
            return d.redacted_text

        new_args = _map_strings(args, visit)
        action = _top(decisions)
        if action in ("allow", "warn"):
            return None
        msg = f"[egress-guard] {action.upper()}: {_reasons(decisions) or 'policy check failed.'} ({_codes(decisions) or 'EG-ERROR'})"
        if commands and action in ("approve", "block"):
            # One line: Hermes's approval box wraps the text but draws a raw "\n" through its border.
            msg += " Command: " + command_preview(*commands[0])
        if action == "block":
            return {"action": "block", "message": msg}
        if action == "approve":
            first = next((f.rule for d in decisions for f in d.findings), "policy")
            return {"action": "approve", "message": msg, "rule_key": f"egress-guard:{first}"}
        changed = {k: v for k, v in new_args.items() if v != args.get(k)}   # redact
        return {"action": "modify", "args": changed} if changed else None
    except Exception:                                        # noqa: BLE001
        if getattr(policy, "fail_mode", "open") == "closed":
            return {"action": "block",
                    "message": "[egress-guard] BLOCKED: internal check failed and policy is fail-closed. (EG-ERROR)"}
        return None


# ---------------------------------------------------------- transform_tool_result
def transform_tool_result(policy, tool_name: str = "", args: Any = None, result: Any = None,
                          **_kw) -> Optional[str]:
    try:
        if not isinstance(result, str) or not result:
            return None
        decisions = []

        def visit(text: str, _is_cmd: bool) -> str:
            d = inspect_text(text, policy, scope="result")
            if d.findings or d.errors:
                decisions.append(d)
                _log(policy, d, "result", tool_name, text)
            return d.redacted_text

        try:
            parsed = json.loads(result)
        except ValueError:
            parsed = None
        if isinstance(parsed, (dict, list)):
            new = _map_strings(parsed, visit)
            out = json.dumps(new, ensure_ascii=False)
        else:
            out = visit(result, False)
        action = _top(decisions)
        if action == "block":
            return json.dumps({"error": f"[egress-guard] Result withheld by policy. ({_codes(decisions)})"})
        if action in ("redact", "approve") and out != result:
            return out
        return None
    except Exception:                                        # noqa: BLE001
        if getattr(policy, "fail_mode", "open") == "closed":
            return json.dumps({"error": "[egress-guard] Result withheld: internal check failed. (EG-ERROR)"})
        return None


# ----------------------------------------------------------- transform_llm_output
def transform_llm_output(policy, response_text: Any = None, **_kw) -> Optional[str]:
    try:
        if not isinstance(response_text, str) or not response_text:
            return None
        d = inspect_text(response_text, policy, scope="reply")
        if d.findings or d.errors:
            _log(policy, d, "reply", "", response_text)
        if d.action == "block":
            return f"[egress-guard] Reply withheld by policy. ({_codes([d])})"
        if d.action in ("redact", "approve") and d.redacted_text != response_text:
            rounded = sum(1 for f in d.findings if f.rule == "smallcell.rounded")
            n = sum(1 for f in d.findings if f.replacement) - rounded
            notes = []
            if n:
                notes.append(f"{n} value(s) withheld by policy")
            if rounded:
                notes.append("counts randomly rounded to base 5 by policy")
            return d.redacted_text + f"\n\n[egress-guard] {'; '.join(notes)} ({_codes([d])})."
        return None
    except Exception:                                        # noqa: BLE001
        if getattr(policy, "fail_mode", "open") == "closed":
            return "[egress-guard] Reply withheld: internal check failed. (EG-ERROR)"
        return None


# ------------------------------------------------------------------ /guard command
GUARD_HELP = ("Usage: /guard status | /guard report | /guard check <text>\n"
              "  status        active policy and preset\n"
              "  report        finding counts by rule and the last 5 audit entries (masked)\n"
              "  check <text>  dry run of every enabled rule on <text>; writes no audit entry")
REPORT_MAX_BYTES = 16 * 1024 * 1024          # read at most the last 16 MB of the audit log


def _status(policy, policy_path: str) -> str:
    src = policy_path or "none found (built-in defaults)"
    lines = [f"egress-guard policy: {src}",
             f"  preset: {policy.preset or 'none'}   fail_mode: {policy.fail_mode}   "
             f"max_scan_bytes: {policy.max_scan_bytes}",
             f"  audit: {'on' if policy.audit_enabled else 'off'} -> {policy.audit_path}",
             f"  allowlist: {len(policy.allowlist)} pattern(s)"]
    for group in ("secrets", "smallcell", "microdata", "network"):
        r = policy.rules.get(group, {})
        extra = ""
        if group == "smallcell":
            extra = (f"  method: round (base 5)" if r.get("method") == "round" else
                     f"  threshold: {r.get('threshold')}  min_value: {r.get('min_value')}  "
                     f"complementary: {r.get('complementary')}")
        elif group == "microdata":
            extra = f"  max_rows: {r.get('max_rows')}"
        elif group == "network":
            extra = f"  match: {r.get('match')}  allowed_hosts: {', '.join(map(str, r.get('allowed_hosts', [])))}"
        lines.append(f"  {group}: {r.get('mode', 'off')}  scopes: {', '.join(r.get('scopes', []))}{extra}")
    return "\n".join(lines)


def _report(policy) -> str:
    s = summarize(policy.audit_path, last=5, max_bytes=REPORT_MAX_BYTES)
    if s is None:
        return f"egress-guard: no audit log yet at {policy.audit_path}" + \
            ("" if policy.audit_enabled else " (audit is off)")
    lines = [f"egress-guard audit: {policy.audit_path}",
             f"  {s.entries} entries" + (f", {s.bad_lines} unreadable line(s)" if s.bad_lines else "") +
             (f", {s.size_skips} over max_scan_bytes" if s.size_skips else "")]
    if s.by_action:
        lines.append("  actions: " + ", ".join(f"{a} {n}" for a, n in s.by_action.most_common()))
    lines.append("  findings by rule:" if s.by_rule else "  findings by rule: none")
    for rule, n in sorted(s.by_rule.items(), key=lambda kv: (-kv[1], kv[0])):
        lines.append(f"    {n:6d}  {rule}")
    if s.last:
        lines.append(f"  last {len(s.last)} entries:")
    for e in reversed(s.last):
        fs = [f for f in e.get("findings", []) if isinstance(f, dict)]
        shown = ", ".join(f"{f.get('rule')}={f.get('masked')}" for f in fs[:3])
        more = e.get("findings_total", len(fs)) - min(3, len(fs))
        what = shown + (f" (+{more} more)" if more > 0 else "") or "; ".join(map(str, e.get("errors", [])))[:120]
        tool = f" {e.get('tool')}" if e.get("tool") else ""
        lines.append(f"    {str(e.get('ts', '?'))[:19]}  {e.get('direction', '?')}{tool} -> "
                     f"{e.get('action', '?')}: {what}")
    return "\n".join(lines)


def _check(policy, text: str) -> str:
    if not text.strip():
        return "Usage: /guard check <text>"
    lines = ["egress-guard dry run (no audit entry written):"]
    seen = set()
    for scope, as_cmd in (("args", True), ("result", False), ("reply", False)):
        d = inspect_text(text, policy, scope=scope, command=as_cmd)
        label = {"args": "as a tool argument / shell command", "result": "as a tool result",
                 "reply": "as a model reply"}[scope]
        if d.skipped:
            lines.append(f"  {label}: not scanned ({d.skipped}); fail_mode {policy.fail_mode} -> {d.action}")
            continue
        rules = sorted({f.rule for f in d.findings})
        lines.append(f"  {label}: {d.action.upper()}" + (f"  [{', '.join(rules)}]" if rules else ""))
        for f in d.findings:
            key = (f.rule, f.start, f.end)
            if key not in seen:
                seen.add(key)
                lines.append(f"    - {f.reason} (found: {f.masked})")
        if d.errors:
            lines.append("    errors: " + "; ".join(d.errors)[:200])
    d = inspect_text(text, policy, scope=None, command=True)
    if not d.skipped:
        lines.append("  masked preview: " + command_preview(text, d, limit=300))
    return "\n".join(lines)


def guard_command(policy, policy_path: str = "", raw_args: Any = "") -> str:
    """/guard handler. Read-only: never writes the audit log or changes the policy."""
    try:
        raw = raw_args if isinstance(raw_args, str) else ""
        sub, _, rest = raw.strip().partition(" ")
        sub = sub.lower()
        if sub in ("", "status"):
            return _status(policy, policy_path)
        if sub == "report":
            return _report(policy)
        if sub == "check":
            return _check(policy, rest)
        return GUARD_HELP
    except Exception as e:                                   # noqa: BLE001
        return f"egress-guard: /guard failed ({type(e).__name__}). {GUARD_HELP}"
