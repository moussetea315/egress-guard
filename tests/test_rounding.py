"""smallcell.method: round (item 10): unbiased random rounding to base 5, deterministic per table."""
import os

import pytest

from guard.engine import apply_redactions, inspect_text
from guard.policy import PolicyError, policy_from_dict
from guard.smallcell import _rounded, _table_seed, find_small_cells, find_tables

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CROSSTAB = open(os.path.join(ROOT, "demo_data", "crosstab_region_outcome.md")).read()


def rounded(text):
    return apply_redactions(text, find_small_cells(text, method="round"))


def grid(text):
    return [[c.strip() for c in l.strip().strip("|").split("|")] for l in text.strip().splitlines()[2:]]


def test_every_count_is_a_multiple_of_5_and_labels_untouched():
    out = grid(rounded(CROSSTAB))
    raw = grid(CROSSTAB)
    for r_out, r_raw in zip(out, raw):
        assert r_out[0] == r_raw[0]                                    # region label kept
        for v_out, v_raw in zip(r_out[1:], r_raw[1:]):
            v, w = int(v_out), int(v_raw)
            assert v % 5 == 0 and abs(v - w) < 5                       # base 5, nearest multiple
            assert v == w if w % 5 == 0 else v in (w - w % 5, w - w % 5 + 5)


def test_deterministic_for_the_same_table_wherever_it_appears():
    once = rounded(CROSSTAB)
    assert all(rounded(CROSSTAB) == once for _ in range(5))
    spaced = CROSSTAB.replace("| ", "|  ")                             # different whitespace
    assert grid(rounded(spaced)) == grid(once)
    gutter = "".join(f"{i}|{l}\n" for i, l in enumerate(CROSSTAB.splitlines(), 1))   # read_file view
    assert grid("\n".join(l.split("|", 1)[1] for l in rounded(gutter).splitlines())) == grid(once)
    embedded = "Here is the table:\n\n" + CROSSTAB + "\nThanks."
    assert grid(rounded(embedded).split("\n\n", 1)[1].split("\nThanks")[0]) == grid(once)


def test_different_tables_get_independent_draws():
    a, b = find_tables(CROSSTAB)[0], find_tables(CROSSTAB.replace("Island", "Islands"))[0]
    assert _table_seed(a) != _table_seed(b)


def test_totals_are_rounded_independently_not_summed():
    t = find_tables(CROSSTAB)[0]
    seed = _table_seed(t)
    out = grid(rounded(CROSSTAB))
    ti = len(out) - 1                                                  # the Total row
    true_totals = [606, 150, 44, 800]
    # each published total is its own draw from the TRUE total, not the sum of rounded cells
    assert [int(x) for x in out[ti][1:5]] == [_rounded(v, seed, ti, ci) for ci, v in enumerate(true_totals, 1)]
    row_totals = [int(r[4]) for r in out[:-1]]
    assert row_totals == [_rounded(int(r[4]), seed, ri, 4) for ri, r in enumerate(grid(CROSSTAB)[:-1])]
    # and on this table the two differ for at least one line (so the test is meaningful)
    sums = [sum(int(r[ci]) for r in out[:-1]) for ci in range(1, 5)] + [sum(int(x) for x in r[1:4]) for r in out[:-1]]
    pub = [int(x) for x in out[ti][1:5]] + row_totals
    assert sums != pub


def test_rounding_is_unbiased_over_many_tables():
    # Each value v in 1..4 should round up with probability v/5; check the mean over 4000 seeds.
    for v in (1, 2, 3, 4):
        ups = sum(_rounded(v, f"seed-{i}".encode(), 0, 1) == 5 for i in range(4000))
        assert abs(ups / 4000 - v / 5) < 0.03, (v, ups)
    assert all(_rounded(v, b"s", 0, 1) == v for v in (0, 5, 10, 800))


def test_formatting_quotes_and_thousands_kept():
    md = "| site | visits | total |\n|---|---|---|\n| A | 1,232 | 1,301 |\n| B | 3 | 1,304 |\n| C | 12 | 2,601 |\n"
    seed = _table_seed(find_tables(md)[0])
    exp = [_rounded(x, seed, ri, 1) for ri, x in enumerate((1232, 3, 12))]
    rows = grid(rounded(md))
    assert [r[1] for r in rows] == [f"{exp[0]:,}", str(exp[1]), str(exp[2])]
    assert all("," in r[2] for r in rows)                              # totals keep their separators
    csv = 'site,visits,total\nA,"1232",1301\nB,3,1304\nC,"12",2601\n'
    seed = _table_seed(find_tables(csv)[0])
    exp = [_rounded(x, seed, ri, 1) for ri, x in enumerate((1232, 3, 12))]
    rows = rounded(csv).strip().splitlines()[1:]
    assert [r.split(",")[1] for r in rows] == [f'"{exp[0]}"', str(exp[1]), f'"{exp[2]}"']


def test_percentages_hidden_in_round_mode():
    t = ("| Region | n | % |\n|---|---|---|\n| A | 7 | 7.0% |\n| B | 43 | 43.0% |\n| C | 50 | 50.0% |\n")
    out = rounded(t)
    assert "7.0%" not in out and "43.0%" not in out and out.count("[suppressed]") == 3


def test_policy_and_hooks(adapter, tmp_path):
    with pytest.raises(PolicyError):
        policy_from_dict({"rules": {"smallcell": {"method": "random"}}})
    assert policy_from_dict({}).rules["smallcell"]["method"] == "suppress"          # default unchanged
    p = policy_from_dict({"audit": {"path": str(tmp_path / "a.jsonl")},
                          "rules": {"smallcell": {"method": "round"}}})
    out = adapter.transform_llm_output(p, response_text=CROSSTAB)
    assert "counts randomly rounded to base 5 by policy (EG-CELL-001)" in out and "withheld" not in out
    assert "| Peace Valley | 7 |" not in out and "[suppressed]" not in out
    assert "method: round (base 5)" in adapter.guard_command(p, "", "status")
    log = (tmp_path / "a.jsonl").read_text()
    assert '"masked": "[rounded]"' in log and "| 7 |" not in log
    d = inspect_text(CROSSTAB, p, scope="result")
    assert d.action == "allow"                                                  # result scope off by default
