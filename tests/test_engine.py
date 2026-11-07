import os

from guard.audit import record
from guard.engine import inspect_text
from guard.policy import PolicyError, policy_from_dict
import pytest

from fakes import AWS_KEY, FAKE_ENV, GITHUB_TOKEN

DEMO = os.path.join(os.path.dirname(__file__), "..", "demo_data")


def read(name):
    if name == "fake_env.txt":       # generated at runtime, never stored on disk
        return FAKE_ENV
    return open(os.path.join(DEMO, name)).read()


def test_default_policy_redacts_secrets_and_small_cells():
    p = policy_from_dict({})
    d = inspect_text(read("fake_env.txt"), p)
    assert d.action == "redact"
    assert AWS_KEY not in d.redacted_text
    assert GITHUB_TOKEN[:10] not in d.redacted_text
    d2 = inspect_text(read("crosstab_region_outcome.md"), p)
    assert d2.action == "redact" and "[suppressed]" in d2.redacted_text


def test_strictest_mode_wins():
    p = policy_from_dict({"rules": {"secrets": {"mode": "block"}, "smallcell": {"mode": "warn"}}})
    text = read("fake_env.txt") + "\n" + read("crosstab_region_outcome.md")
    assert inspect_text(text, p).action == "block"


def test_warn_does_not_modify_text():
    p = policy_from_dict({"rules": {"secrets": {"mode": "warn"}}})
    t = read("fake_env.txt")
    d = inspect_text(t, p)
    assert d.action == "warn" and d.redacted_text == t


def test_off_means_off():
    p = policy_from_dict({"rules": {"secrets": {"mode": "off"}, "smallcell": {"mode": "off"}}})
    assert inspect_text(read("fake_env.txt"), p).action == "allow"


def test_allowlist_suppresses_finding():
    p = policy_from_dict({"allowlist": ["^" + AWS_KEY[:14]], "rules": {"secrets": {"mode": "block"}}})
    d = inspect_text("AWS_ACCESS_KEY_ID=" + AWS_KEY, p)
    assert not [f for f in d.findings if f.rule == "secret.aws_access_key"]


def test_clean_text_passes():
    assert inspect_text("Here is the summary: all good.", policy_from_dict({})).action == "allow"


def test_non_string_and_empty_inputs_are_safe():
    p = policy_from_dict({})
    assert inspect_text("", p).action == "allow"
    assert inspect_text(None, p).action == "allow"


def test_fail_closed_blocks_when_detector_errors(monkeypatch):
    import guard.engine as eng
    monkeypatch.setattr(eng, "find_secrets", lambda *a, **k: 1 / 0)
    open_p = policy_from_dict({"fail_mode": "open"})
    closed_p = policy_from_dict({"fail_mode": "closed"})
    assert eng.inspect_text("anything", open_p).action == "allow"
    assert eng.inspect_text("anything", closed_p).action == "block"


def test_invalid_policy_rejected():
    with pytest.raises(PolicyError):
        policy_from_dict({"rules": {"secrets": {"mode": "yolo"}}})
    with pytest.raises(PolicyError):
        policy_from_dict({"rules": {"smallcell": {"threshold": 1}}})


def test_audit_log_has_no_raw_secrets(tmp_path):
    p = policy_from_dict({})
    t = read("fake_env.txt")
    d = inspect_text(t, p)
    log = tmp_path / "audit.jsonl"
    assert record(d, str(log), direction="tool_result", tool="terminal", source_text=t)
    body = log.read_text()
    assert AWS_KEY not in body and GITHUB_TOKEN not in body
    assert "secret.aws_access_key" in body


def test_audit_failure_never_raises():
    d = inspect_text("x", policy_from_dict({}))
    assert record(d, "/proc/nonexistent/dir/audit.jsonl") is False
