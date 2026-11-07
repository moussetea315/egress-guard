"""max_scan_bytes: oversize strings are not parsed; fail_mode decides (item 2)."""
import json
import time

import pytest

from fakes import AWS_KEY
from guard.engine import inspect_text
from guard.policy import PolicyError, policy_from_dict

MB = 1024 * 1024


def pol(fail_mode="open", audit=None, **extra):
    a = {"enabled": bool(audit), "path": str(audit or "unused")}
    return policy_from_dict({"fail_mode": fail_mode, "audit": a, **extra})


def big_text(n_bytes, secret=True):
    line = "export AWS_ACCESS_KEY_ID=" + AWS_KEY + "\n" if secret else "x = 1\n"
    return (line * (n_bytes // len(line) + 1))[:n_bytes]


def test_default_and_validation():
    assert policy_from_dict({}).max_scan_bytes == MB
    assert policy_from_dict({"max_scan_bytes": 2048}).max_scan_bytes == 2048
    for bad in (0, -1, "1MB", 1.5, True):
        with pytest.raises(PolicyError):
            policy_from_dict({"max_scan_bytes": bad})


def test_just_under_cap_is_scanned_just_over_is_not():
    p = pol(max_scan_bytes=4096)
    under = inspect_text(big_text(4096), p, scope="args")
    assert under.findings and not under.skipped
    over = inspect_text(big_text(4097), p, scope="args")
    assert not over.findings and over.skipped and over.action == "allow"


def test_cap_counts_utf8_bytes_not_characters():
    p = pol(fail_mode="closed", max_scan_bytes=1000)
    text = "€" * 400                         # 400 chars, 1200 bytes
    assert inspect_text(text, p).action == "block"
    assert inspect_text("€" * 333, p).action == "allow"   # 999 bytes, scanned


def test_10mb_open_passes_through_fast_with_audit_entry(adapter, tmp_path):
    log = tmp_path / "audit.jsonl"
    p = pol(audit=log)
    text = big_text(10 * MB)
    t0 = time.perf_counter()
    r = adapter.pre_tool_call(p, tool_name="terminal", args={"command": text})
    dt = time.perf_counter() - t0
    assert r is None                          # fail open: passes through unmodified
    assert dt < 0.5, f"took {dt:.3f}s"
    entries = [json.loads(x) for x in log.read_text().splitlines()]
    assert len(entries) == 1 and entries[0]["action"] == "allow"
    assert "max_scan_bytes" in entries[0]["errors"][0]
    assert AWS_KEY not in log.read_text()


def test_10mb_closed_blocks_fast_message_is_safe(adapter):
    text = big_text(10 * MB)
    t0 = time.perf_counter()
    r = adapter.pre_tool_call(pol("closed"), tool_name="terminal", args={"command": text})
    dt = time.perf_counter() - t0
    assert r["action"] == "block" and "EG-SIZE-001" in r["message"]
    assert AWS_KEY not in r["message"] and len(r["message"]) < 300
    assert dt < 0.5, f"took {dt:.3f}s"


def test_10mb_tool_result_and_reply(adapter):
    content = big_text(10 * MB)
    payload = json.dumps({"content": content, "truncated": False})
    t0 = time.perf_counter()
    assert adapter.transform_tool_result(pol(), tool_name="read_file", result=payload) is None
    withheld = adapter.transform_tool_result(pol("closed"), tool_name="read_file", result=payload)
    assert "EG-SIZE-001" in withheld and AWS_KEY not in withheld
    assert adapter.transform_llm_output(pol(), response_text=content) is None
    assert "EG-SIZE-001" in adapter.transform_llm_output(pol("closed"), response_text=content)
    assert time.perf_counter() - t0 < 1.0


def test_small_strings_beside_an_oversize_one_are_still_scanned(adapter):
    p = pol(max_scan_bytes=1000)
    r = adapter.pre_tool_call(p, tool_name="x", args={"blob": "a" * 5000, "note": "key " + AWS_KEY})
    assert r["action"] == "modify" and AWS_KEY not in r["args"]["note"] and "blob" not in r["args"]
