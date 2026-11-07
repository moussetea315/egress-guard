"""Audit entry limits (decision 1): first 50 findings + total count, each line <= 64 KB."""
import json

from fakes import AWS_KEY
from guard import audit
from guard.engine import Decision, inspect_text
from guard.findings import Finding
from guard.policy import policy_from_dict


def read(path):
    lines = path.read_text().splitlines()
    return [json.loads(x) for x in lines], [len(x.encode()) + 1 for x in lines]


def test_small_entry_unchanged_shape(tmp_path):
    p = policy_from_dict({"audit": {"enabled": False}})
    d = inspect_text("key " + AWS_KEY, p)
    log = tmp_path / "a.jsonl"
    assert audit.record(d, str(log), direction="args", tool="terminal", source_text="key " + AWS_KEY)
    (e,), _ = read(log)
    assert e["findings_total"] == 1 and len(e["findings"]) == 1 and "truncated" not in e
    assert AWS_KEY not in log.read_text()


def test_many_findings_listed_up_to_50_with_total(tmp_path):
    p = policy_from_dict({"audit": {"enabled": False}})
    text = "".join(f"export AWS_ACCESS_KEY_ID={AWS_KEY}\n" for _ in range(500))
    d = inspect_text(text, p)
    assert len(d.findings) == 500
    log = tmp_path / "a.jsonl"
    audit.record(d, str(log), source_text=text)
    (e,), (size,) = read(log)
    assert e["findings_total"] == 500 and len(e["findings"]) == 50 and e["truncated"] is True
    assert size <= audit.MAX_LINE_BYTES and AWS_KEY not in log.read_text()


def test_worst_case_csv_line_is_capped(tmp_path):
    """Tier 1 worst case was a 1 MB CSV (~393k small cells) -> one 55 MB line. 256 KB keeps the test fast."""
    p = policy_from_dict({"audit": {"enabled": False}})
    text = "a,1,2,3\n" * 32768
    d = inspect_text(text, p, scope="args")
    log = tmp_path / "a.jsonl"
    audit.record(d, str(log), source_text=text)
    (e,), (size,) = read(log)
    assert e["findings_total"] == len(d.findings) > 90000
    assert len(e["findings"]) == 50 and size <= audit.MAX_LINE_BYTES


def test_huge_fields_are_clipped_to_fit(tmp_path):
    big = "h" * 200_000
    fs = [Finding(rule="network.upload", reason="r" * 5000, start=0, end=1, masked=big) for _ in range(50)]
    d = Decision(action="approve", findings=fs, errors=["e" * 100_000] * 30)
    log = tmp_path / "a.jsonl"
    assert audit.record(d, str(log), tool="t" * 100_000)
    (e,), (size,) = read(log)
    assert size <= audit.MAX_LINE_BYTES and e["truncated"] is True
    assert e["findings_total"] == 50 and len(e["errors"]) == 10
    assert all(len(f["masked"]) <= 300 for f in e["findings"])


def test_adapter_end_to_end_capped(adapter, tmp_path):
    log = tmp_path / "audit.jsonl"
    p = policy_from_dict({"audit": {"path": str(log)}})
    text = "".join(f"export AWS_ACCESS_KEY_ID={AWS_KEY}\n" for _ in range(2000))
    adapter.transform_tool_result(p, tool_name="read_file", result=text)
    (e,), (size,) = read(log)
    assert e["findings_total"] == 2000 and len(e["findings"]) == 50 and size <= audit.MAX_LINE_BYTES


def test_rule_counts_cover_all_findings_even_when_list_is_capped(tmp_path):
    p = policy_from_dict({"audit": {"enabled": False}})
    text = "".join(f"export AWS_ACCESS_KEY_ID={AWS_KEY}\n" for _ in range(120)) + "| A | 2 |\n|---|---|\n| B | 50 |\n"
    d = inspect_text(text, p, scope="args")
    log = tmp_path / "a.jsonl"
    audit.record(d, str(log))
    (e,), _ = read(log)
    assert e["rule_counts"]["secret.aws_access_key"] == 120 and sum(e["rule_counts"].values()) == e["findings_total"]
