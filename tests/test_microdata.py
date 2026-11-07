"""Microdata egress detector (item 9)."""
import json
import os

import pytest

from guard.engine import inspect_text
from guard.microdata import find_microdata, is_id_column
from guard.policy import PolicyError, policy_from_dict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VISITS = open(os.path.join(ROOT, "demo_data", "synthetic_visits.csv")).read()
CROSSTAB = open(os.path.join(ROOT, "demo_data", "crosstab_region_outcome.md")).read()


def test_synthetic_visits_flagged_crosstab_not():
    fs = find_microdata(VISITS)
    assert len(fs) == 1 and fs[0].rule == "microdata.table"
    assert fs[0].meta == {"rows": 800, "id_column": "record_id"}
    assert "SYN-" not in fs[0].masked and "SYN-" not in fs[0].reason       # no record values leak
    assert find_microdata(CROSSTAB) == []


def test_row_threshold_is_more_than_n():
    head, *rows = VISITS.splitlines()
    assert find_microdata("\n".join([head] + rows[:20])) == []
    assert len(find_microdata("\n".join([head] + rows[:21]))) == 1
    assert find_microdata("\n".join([head] + rows[:21]), max_rows=50) == []


@pytest.mark.parametrize("h,ok", [
    ("id", True), ("ID", True), ("record_id", True), ("Record ID", True), ("uuid", True), ("case", True),
    ("person", True), ("patient_id", True), ("PatientId", True), ("person_uuid", True), ('"case"', True),
    ("Case type", False), ("idea", False), ("valid", False), ("region", False), ("Persons", False),
    ("provider", False), ("guide", False)])
def test_id_column_names(h, ok):
    assert is_id_column(h) is ok


def test_markdown_microdata_and_read_file_gutter():
    rows = "".join(f"| P{i:03d} | {20 + i % 50} | {'F' if i % 2 else 'M'} |\n" for i in range(25))
    md = "| person_id | age | sex |\n|---|---|---|\n" + rows
    assert len(find_microdata(md)) == 1
    gutter = "".join(f"{n}|{l}\n" for n, l in enumerate(md.splitlines(), 1))
    assert len(find_microdata(gutter)) == 1


def test_long_aggregate_without_id_not_flagged():
    agg = "region,age_band,n\n" + "".join(f"R{i},{b},{50 + i}\n" for i in range(30) for b in ("0-17", "18+"))
    assert find_microdata(agg) == []


def test_default_policy_warns_in_args_and_reply_only():
    p = policy_from_dict({"audit": {"enabled": False}})
    assert p.rules["microdata"] == {"mode": "warn", "max_rows": 20, "scopes": ["args", "reply"]}
    d = inspect_text(VISITS, p, scope="reply")
    assert d.action == "warn" and d.redacted_text == VISITS                 # warn changes nothing
    assert not any(f.rule.startswith("microdata") for f in inspect_text(VISITS, p, scope="result").findings)
    with pytest.raises(PolicyError):
        policy_from_dict({"rules": {"microdata": {"max_rows": 0}}})


def test_warn_is_audit_only_and_redact_withholds(adapter, tmp_path):
    log = tmp_path / "a.jsonl"
    p = policy_from_dict({"audit": {"path": str(log)}})
    assert adapter.transform_llm_output(p, response_text=VISITS) is None    # warn: reply untouched
    e = json.loads(log.read_text().splitlines()[0])
    assert e["action"] == "warn" and e["rule_counts"] == {"microdata.table": 1}
    assert "SYN-0001" not in log.read_text()
    p2 = policy_from_dict({"audit": {"enabled": False}, "rules": {"microdata": {"mode": "redact"}}})
    out = adapter.transform_llm_output(p2, response_text="Here:\n" + VISITS)
    assert out.startswith("Here:\n[microdata table withheld: 800 rows]") and "SYN-0001" not in out
    assert "EG-MICRO-001" in out


def test_upload_args_with_microdata_table(adapter):
    p = policy_from_dict({"audit": {"enabled": False}, "rules": {"microdata": {"mode": "block"}}})
    r = adapter.pre_tool_call(p, tool_name="write_file", args={"path": "out.csv", "content": VISITS})
    assert r["action"] == "block" and "EG-MICRO-001" in r["message"] and "SYN-" not in r["message"]
