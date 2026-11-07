from guard.smallcell import find_small_cells

TABLE = """| Region | Yes | No | Total |
|---|---|---|---|
| A | 120 | 80 | 200 |
| B | 3 | 47 | 50 |
| C | 60 | 40 | 100 |
| Total | 183 | 167 | 350 |
"""


def test_flags_small_cell_and_not_large_ones():
    f = [x for x in find_small_cells(TABLE) if x.rule == "smallcell.count"]
    assert len(f) == 1
    assert TABLE[f[0].start:f[0].end] == "3"
    assert "3" not in f[0].masked          # exact value not echoed back


def test_complementary_suppression_added_when_total_reveals_it():
    f = find_small_cells(TABLE)
    comp = [x for x in f if x.rule == "smallcell.complementary"]
    assert comp, "single hidden cell + visible totals should trigger a second suppression"


def test_threshold_and_zero_handling():
    t = "| G | n |\n|---|---|\n| a | 4 |\n| b | 0 |\n| c | 9 |\n"
    assert len(find_small_cells(t, threshold=5)) == 1       # zero ignored by default
    assert len(find_small_cells(t, threshold=5, min_value=0)) == 2
    assert len(find_small_cells(t, threshold=10)) == 2


def test_skips_year_id_age_and_percent_columns():
    t = "| Year | Age | Pct | n |\n|---|---|---|---|\n| 2021 | 3 | 2 | 50 |\n| 2022 | 4 | 1 | 60 |\n"
    assert find_small_cells(t) == []


def test_csv_block():
    csv_text = "region,count\nA,2\nB,40\nC,55\n"
    f = find_small_cells(csv_text)
    assert len(f) == 1 and csv_text[f[0].start:f[0].end] == "2"


def test_prose_and_messy_input_do_not_crash_or_flag():
    assert find_small_cells("I saw 3 birds, 2 cats, and 1 dog today.") == []
    assert find_small_cells("| broken | table\n|--|\n| 1 |") is not None
    assert find_small_cells("") == []


# ---- iterative complementary suppression -------------------------------------------
import os
from fractions import Fraction

from guard.smallcell import TOTAL_LABEL, _parse_int, find_tables

DEMO = os.path.join(os.path.dirname(__file__), "..", "demo_data")


def _grid(text):
    """Return (header, rows) of the first table as plain strings."""
    t = find_tables(text)[0]
    return [c.text for c in t.header], [[c.text for c in r] for r in t.rows]


def _apply(text, findings):
    out, last = [], 0
    for f in sorted(findings, key=lambda f: f.start):
        out.append(text[last:f.start]); out.append("[suppressed]"); last = f.end
    return "".join(out) + text[last:]


def _recoverable(text):
    """Hidden cells uniquely determined by the visible row/column totals (exact rank test).

    Ignores non-negativity, so it checks for exact recovery by linear algebra, not interval bounds.
    """
    header, rows = _grid(text)
    tcol = next(i for i, h in enumerate(header) if TOTAL_LABEL.match(h))
    trow = next(i for i, r in enumerate(rows) if TOTAL_LABEL.match(r[0]))
    vcols = [c for c in range(1, len(header)) if c != tcol]
    body = [r for r in range(len(rows)) if r != trow]
    hidden = [(r, c) for r in range(len(rows)) for c in range(1, len(header))
              if rows[r][c] == "[suppressed]"]
    idx = {h: i for i, h in enumerate(hidden)}
    eqs = []
    lines = [([(r, c) for c in vcols], (r, tcol)) for r in body + [trow]]
    lines += [([(r, c) for r in body], (trow, c)) for c in vcols + [tcol]]
    for members, total in lines:
        if total in idx:
            members = members + [total]       # total hidden too: sum(members) - total = 0
        vec = [Fraction(0)] * len(hidden)
        for m in members:
            if m in idx:
                vec[idx[m]] += -1 if m == total else 1
        if any(vec):
            eqs.append(vec)
    # Row-reduce, then a cell is recoverable iff its unit vector lies in the row space.
    m, rank, piv = [r[:] for r in eqs], 0, []
    for col in range(len(hidden)):
        p = next((i for i in range(rank, len(m)) if m[i][col] != 0), None)
        if p is None:
            continue
        m[rank], m[p] = m[p], m[rank]
        m[rank] = [x / m[rank][col] for x in m[rank]]
        for i in range(len(m)):
            if i != rank and m[i][col] != 0:
                m[i] = [a - m[i][col] * b for a, b in zip(m[i], m[rank])]
        piv.append(col); rank += 1
    out = []
    for r_i in range(rank):
        nz = [j for j, x in enumerate(m[r_i]) if x != 0]
        if len(nz) == 1:
            out.append(hidden[nz[0]])
    return out


def _single_hidden_lines(text):
    header, rows = _grid(text)
    tcol = next(i for i, h in enumerate(header) if TOTAL_LABEL.match(h))
    trow = next(i for i, r in enumerate(rows) if TOTAL_LABEL.match(r[0]))
    vcols = [c for c in range(1, len(header)) if c != tcol]
    body = [r for r in range(len(rows)) if r != trow]
    bad = []
    lines = [([(r, c) for c in vcols], (r, tcol)) for r in body + [trow]]
    lines += [([(r, c) for r in body], (trow, c)) for c in vcols + [tcol]]
    for members, (tr, tc) in lines:
        if rows[tr][tc] != "[suppressed]" and \
                sum(rows[r][c] == "[suppressed]" for r, c in members) == 1:
            bad.append(members)
    return bad


def test_demo_crosstab_hidden_cells_not_recoverable():
    text = open(os.path.join(DEMO, "crosstab_region_outcome.md")).read()
    out = _apply(text, find_small_cells(text))
    header, rows = _grid(out)
    peace = next(r for r in rows if r[0] == "Peace Valley")
    interior = next(r for r in rows if r[0] == "Interior")
    # 3 is the small cell; the old single pass hid 7 and 9 but left them recoverable.
    assert peace[header.index("Referred")] == "[suppressed]"
    assert peace[header.index("Recovered")] == "[suppressed]"
    assert interior[header.index("Referred")] == "[suppressed]"
    assert _single_hidden_lines(out) == []
    assert _recoverable(out) == []
    # Totals stay visible: the guard hides cells, not margins, when it can.
    assert peace[header.index("Total")] == "10"


def test_old_single_pass_pattern_would_have_been_recoverable():
    """Sanity check of the checker itself: hiding only 3, 7 and 9 is recoverable."""
    text = open(os.path.join(DEMO, "crosstab_region_outcome.md")).read()
    header, rows = _grid(text)
    out = text.replace("| Peace Valley | 7 | 0 | 3 |", "| Peace Valley | [suppressed] | 0 | [suppressed] |") \
              .replace("| Interior | 105 | 29 | 9 |", "| Interior | 105 | 29 | [suppressed] |")
    rec = _recoverable(out)
    assert len(rec) == 3     # all three cells come back by subtraction


SPARSE = """| Group | A | B | C | D | Total |
|---|---|---|---|---|---|
| g1 | 2 | 40 | 31 | 18 | 91 |
| g2 | 25 | 1 | 33 | 4 | 63 |
| g3 | 30 | 28 | 3 | 22 | 83 |
| g4 | 17 | 12 | 26 | 2 | 57 |
| Total | 74 | 81 | 93 | 46 | 294 |
"""


def test_iteration_converges_on_many_small_cells():
    f = find_small_cells(SPARSE)
    out = _apply(SPARSE, f)
    assert _single_hidden_lines(out) == []
    assert _recoverable(out) == []


def test_terminates_when_only_option_is_hiding_the_total():
    # Only one value column: the row total equals the hidden cell, so the total must go.
    t = "| Site | Count | Total |\n|---|---|---|\n| a | 3 | 3 |\n| b | 40 | 40 |\n| Total | 43 | 43 |\n"
    f = find_small_cells(t)
    out = _apply(t, f)
    assert "| a | [suppressed] | [suppressed] |" in out
    assert _single_hidden_lines(out) == []


def test_existing_suppression_markers_count_as_hidden():
    t = ("| R | X | Y | Total |\n|---|---|---|---|\n| a | s | 3 | 20 |\n| b | 30 | 40 | 70 |\n"
         "| Total | 47 | 43 | 90 |\n")
    f = find_small_cells(t)
    out = _apply(t, f)
    # Row a already has 2 hidden (s, 3): no extra cell needed there, but columns need fixing.
    assert _single_hidden_lines(out.replace("| a | s |", "| a | [suppressed] |")) == []


def test_complementary_off_hides_only_small_cells():
    f = find_small_cells(SPARSE, complementary=False)
    assert {x.rule for x in f} == {"smallcell.count"}


# ---- line-number gutters (read_file / cat -n) ---------------------------------------
import json


def _hermes_read_file(text, start=1):
    """Exactly Hermes v0.22.2 FileOperations._add_line_numbers (no clamp)."""
    text = text.removesuffix("\n")
    return "\n".join(f"{i}|{ln}" for i, ln in enumerate(text.split("\n"), start=start))


def _cat_n(text, start=1):
    return "".join(f"{i:6d}\t{ln}" for i, ln in enumerate(text.splitlines(keepends=True), start=start))


def _redacted(text):
    return _apply(text, find_small_cells(text))


def test_read_file_gutter_markdown_redacts_same_cells():
    text = open(os.path.join(DEMO, "crosstab_region_outcome.md")).read()
    plain = _redacted(text)
    gut = _hermes_read_file(text)
    out = _redacted(gut)
    assert out == _hermes_read_file(plain)          # same cells, gutters untouched
    assert "7|| Peace Valley | [suppressed] | 0 | [suppressed] | 10 |" in out


def test_real_read_file_json_payload_through_adapter(adapter):
    """The literal payload shape Hermes passed to transform_tool_result in Step 2 C."""
    from guard.policy import policy_from_dict
    text = open(os.path.join(DEMO, "crosstab_region_outcome.md")).read()
    payload = json.dumps({"content": _hermes_read_file(text), "total_lines": 8, "file_size": 284,
                          "truncated": False, "is_binary": False, "is_image": False,
                          "not_found": False})
    p = policy_from_dict({"audit": {"enabled": False},
                          "rules": {"smallcell": {"scopes": ["args", "result", "reply"]}}})
    out = adapter.transform_tool_result(p, tool_name="read_file", args={}, result=payload)
    content = json.loads(out)["content"]
    assert "7|| Peace Valley | [suppressed] | 0 | [suppressed] | 10 |" in content
    assert content.startswith("1|| Region |")


def test_read_file_gutter_with_offset_and_csv():
    csv_text = "region,count\nA,2\nB,40\nC,55\n"
    gut = _hermes_read_file(csv_text, start=120)
    f = find_small_cells(gut)
    assert len(f) == 1 and gut[f[0].start:f[0].end] == "2"
    assert _redacted(gut).splitlines()[1] == "121|A,[suppressed]"


def test_fuzzy_match_and_cat_n_gutters():
    text = open(os.path.join(DEMO, "crosstab_region_outcome.md")).read()
    plain = _redacted(text)
    fm = "\n".join(f"{i:4d}| {ln}" for i, ln in enumerate(text.splitlines(), start=1))
    assert _redacted(fm) == "\n".join(f"{i:4d}| {ln}" for i, ln in enumerate(plain.splitlines(), start=1))
    assert _redacted(_cat_n(text)) == _cat_n(plain)


def test_numeric_first_column_tsv_is_not_treated_as_gutter():
    # Not consecutive -> not a gutter; the id column must stay intact.
    tsv = "id\tsite\tcount\n101\tA\t3\n205\tB\t40\n307\tC\t50\n"
    f = find_small_cells(tsv)
    assert len(f) == 1 and tsv[f[0].start:f[0].end] == "3"
    # Consecutive numbers but a header without one -> also not a gutter.
    tsv2 = "id\tcount\n1\t3\n2\t40\n3\t50\n"
    f2 = find_small_cells(tsv2)
    assert len(f2) == 1 and tsv2[f2[0].start:f2[0].end] == "3"


def test_partial_gutter_is_ignored():
    mixed = "1|| G | n |\n| --- | --- |\n3|| a | 2 |\n"
    assert find_small_cells(mixed) is not None       # no crash, no offset drift


# ---- percentage companion suppression (item 8)
# demo_data/crosstab_region_outcome.md extended with a paired "Referred %" column (Referred / row
# Total) and an unpaired "% of all" column (row Total / 800).
CROSSTAB_PCT = """| Region | Recovered | Follow-up | Referred | Total | Referred % | % of all |
|---|---|---|---|---|---|---|
| North Coast | 20 | 8 | 0 | 28 | 0.0% | 3.5% |
| Interior | 105 | 29 | 9 | 143 | 6.3% | 17.9% |
| Fraser Valley | 320 | 72 | 22 | 414 | 5.3% | 51.8% |
| Island | 154 | 41 | 10 | 205 | 4.9% | 25.6% |
| Peace Valley | 7 | 0 | 3 | 10 | 30.0% | 1.3% |
| Total | 606 | 150 | 44 | 800 | 5.5% | 100.0% |
"""


def _pct_view(text, **kw):
    from guard.engine import apply_redactions
    fs = find_small_cells(text, **kw)
    out = apply_redactions(text, fs)
    return {r[0]: r for r in (l.strip("|").split("|") for l in out.splitlines()[2:])}, fs


def test_percentages_follow_suppressed_counts():
    rows, fs = _pct_view(CROSSTAB_PCT)
    cell = lambda region, i: rows[" " + region + " "][i].strip()
    # counts as before: 3 primary + 20, 29, 7, 8, 9 complementary
    assert sum(f.rule == "smallcell.percentage" for f in fs) == 5
    # paired "Referred %": hidden exactly where Referred is hidden (Interior 9, Peace Valley 3)
    assert cell("Interior", 5) == "[suppressed]" and cell("Peace Valley", 5) == "[suppressed]"
    assert cell("North Coast", 5) == "0.0%" and cell("Island", 5) == "4.9%" and cell("Total", 5) == "5.5%"
    # unpaired "% of all": hidden in every row with any hidden count
    assert [cell(r, 6) for r in ("North Coast", "Interior", "Peace Valley")] == ["[suppressed]"] * 3
    assert cell("Fraser Valley", 6) == "51.8%" and cell("Total", 6) == "100.0%"
    # 30.0% of Peace Valley's visible total 10 would give back the hidden 3
    assert "30.0%" not in "|".join(rows[" Peace Valley "])


def test_percentage_rule_with_rate_and_share_headers_and_csv():
    csv = "Clinic,Visits,Visit rate,Share\nA,3,0.6,1.2%\nB,250,50.0,98.8%\nC,200,40.0,0.0%\n"
    fs = find_small_cells(csv, complementary=False)
    hit = {(f.rule, csv[f.start:f.end]) for f in fs}
    assert hit == {("smallcell.count", "3"), ("smallcell.percentage", "0.6"), ("smallcell.percentage", "1.2%")}


def test_percentage_paired_by_name_only_hides_its_own_column():
    t = ("| Group | Men | Men % | Women | Women % |\n|---|---|---|---|---|\n"
         "| A | 2 | 10% | 40 | 90% |\n| B | 60 | 50% | 60 | 50% |\n| C | 70 | 50% | 70 | 50% |\n")
    rows, fs = _pct_view(t, complementary=False)
    a = [c.strip() for c in rows[" A "]]
    assert a == ["A", "[suppressed]", "[suppressed]", "40", "90%"]


def test_percentage_not_double_flagged_when_already_hidden_or_empty():
    t = ("| Region | n | % |\n|---|---|---|\n| A | 2 | [suppressed] |\n| B | 60 |  |\n"
         "| C | 70 | 54% |\n")
    fs = find_small_cells(t, complementary=False)
    assert [f.rule for f in fs] == ["smallcell.count"]


def test_input_marker_count_with_visible_percentage_is_hidden():
    t = "| Region | n | % |\n|---|---|---|\n| A | x | 2% |\n| B | 60 | 46% |\n| C | 70 | 52% |\n"
    fs = find_small_cells(t)
    assert [(f.rule, t[f.start:f.end]) for f in fs] == [("smallcell.percentage", "2%")]


def test_percentage_rule_through_read_file_gutter():
    gut = "".join(f"{i}|{l}\n" for i, l in enumerate(CROSSTAB_PCT.splitlines(), 1))
    assert sum(f.rule == "smallcell.percentage" for f in find_small_cells(gut)) == 5
