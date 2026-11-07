"""Small-cell detection in tables embedded in text (markdown tables and CSV/TSV blocks).

Heuristic, rule-based, and deliberately conservative about what counts as a
"count" column. This flags risk under a configurable policy threshold; it
does not certify that a table is safe to release.

When a count is suppressed, percentage/rate/share cells in the same row are suppressed
too, since a count can be recovered from its percentage when the total is known.

method="round" replaces suppression with unbiased random rounding to base 5 (see
_rounding_findings): deterministic per table, totals rounded independently.
"""
import hashlib
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

from .findings import Finding

COUNT_HINTS = re.compile(
    r"(?i)\b(count|counts|n|num|number|freq|frequency|total|persons?|people|patients?|"
    r"respondents?|cases?|visits?|population|pop|enrol(?:l)?ed|students?|households?|"
    r"admissions?|events?|deaths?|births?)\b")
SKIP_HINTS = re.compile(
    r"(?i)\b(year|yr|id|identifier|age|zip|postal|code|phone|rank|index|row|date|month|day|"
    r"pct|percent|percentage|rate|mean|median|avg|average|sd|std|p-?value|score)\b|[#%]")
PCT_HINTS = re.compile(r"(?i)%|\b(pct|percent|percentage|rate|rates|share)\b")
TOTAL_LABEL = re.compile(r"(?i)^\s*(total|all|overall|grand total|sum)\b")
SUPPRESSION_MARKERS = {"", "s", "x", "*", "..", "-", "n/a", "na", "[suppressed]", "suppressed"}
_INT = re.compile(r"^\d{1,3}(?:,\d{3})+$|^\d+$")
_MD_SEP = re.compile(r"^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$")


@dataclass
class Cell:
    text: str
    start: int
    end: int


@dataclass
class Table:
    header: List[Cell]
    rows: List[List[Cell]]
    kind: str  # "markdown" | "csv"


def _split_cells(line: str, base: int, delim: str) -> List[Cell]:
    """Split a line into trimmed cells with absolute offsets."""
    cells, pos = [], 0
    parts = line.rstrip("\r\n").split(delim)
    for part in parts:
        raw_start = base + pos
        lead = len(part) - len(part.lstrip())
        stripped = part.strip()
        cells.append(Cell(stripped, raw_start + lead, raw_start + lead + len(stripped)))
        pos += len(part) + len(delim)
    return cells


def _md_cells(line: str, base: int) -> List[Cell]:
    cells = _split_cells(line, base, "|")
    body = line.strip()
    if body.startswith("|") and cells:
        cells = cells[1:]
    if body.endswith("|") and cells:
        cells = cells[:-1]
    return cells


# Line-number gutters added by file viewers: Hermes read_file "12|", Hermes fuzzy-match
# "  12| ", and `cat -n` "    12\t". Only the gutter is removed; the line's own text
# (including a markdown table's leading "|") is kept.
_GUTTER = re.compile(r"^ *(\d+)(?:\| ?|\t)")


def _gutter_widths(lines: List[str]) -> Optional[List[int]]:
    """Gutter length per line if EVERY non-blank line has one and the numbers run
    consecutively (n, n+1, ...); otherwise None. The consecutive-number check keeps
    a TSV or CSV whose first column happens to be numeric from being mangled."""
    widths, expect, seen = [], None, 0
    for ln in lines:
        if not ln.strip():
            widths.append(0)
            continue
        m = _GUTTER.match(ln)
        if not m:
            return None
        n = int(m.group(1))
        if expect is not None and n != expect:
            return None
        expect, seen = n + 1, seen + 1
        widths.append(m.end())
    return widths if seen >= 2 else None


def _lines_with_offsets(text: str) -> List[Tuple[str, int]]:
    """(line, absolute offset of the line's first character), with any line-number
    gutter stripped. Offsets point past the gutter, so cell spans map back exactly
    onto the original text and redaction edits the right characters."""
    raw, off = [], 0
    for ln in text.splitlines(keepends=True):
        raw.append((ln, off))
        off += len(ln)
    widths = _gutter_widths([ln for ln, _ in raw])
    if widths is None:
        return raw
    return [(ln[w:], o + w) for (ln, o), w in zip(raw, widths)]


def find_tables(text: str) -> List[Table]:
    lines = _lines_with_offsets(text)
    tables: List[Table] = []
    i, n = 0, len(lines)
    while i < n:
        ln, off = lines[i]
        # markdown table: a header line with pipes followed by a separator row
        if "|" in ln and i + 1 < n and _MD_SEP.match(lines[i + 1][0].rstrip("\r\n")) and "-" in lines[i + 1][0]:
            header = _md_cells(ln, off)
            j, rows = i + 2, []
            while j < n and "|" in lines[j][0] and lines[j][0].strip():
                rows.append(_md_cells(lines[j][0], lines[j][1]))
                j += 1
            if header and rows:
                tables.append(Table(header, rows, "markdown"))
            i = j
            continue
        # delimited block: >=3 consecutive lines with the same number of delimiters
        for delim in (",", "\t", ";"):
            c = ln.count(delim)
            if c >= 1 and ln.strip():
                j = i
                while j < n and lines[j][0].strip() and lines[j][0].count(delim) == c:
                    j += 1
                if j - i >= 3:
                    block = lines[i:j]
                    header = _split_cells(block[0][0], block[0][1], delim)
                    rows = [_split_cells(b[0], b[1], delim) for b in block[1:]]
                    tables.append(Table(header, rows, "csv"))
                    i = j - 1
                    break
        i += 1
    return tables


def _parse_int(s: str) -> Optional[int]:
    s = s.strip().strip('"').strip("'")
    return int(s.replace(",", "")) if _INT.match(s) else None


def _is_total_col(header: str) -> bool:
    return bool(TOTAL_LABEL.match(header))


def _count_columns(table: Table) -> List[int]:
    cols = []
    width = len(table.header)
    for ci in range(width):
        h = table.header[ci].text.strip('"')
        body = [r[ci].text.strip('"') for r in table.rows if ci < len(r)]
        numeric = [b for b in body if _parse_int(b) is not None]
        non_numeric = [b for b in body if _parse_int(b) is None and b.lower() not in SUPPRESSION_MARKERS]
        if not numeric or non_numeric:
            continue
        if SKIP_HINTS.search(h):
            continue
        if COUNT_HINTS.search(h) or (ci > 0 and len(numeric) >= 2):
            cols.append(ci)
    return cols


def _pct_columns(table: Table, count_cols: List[int]) -> List[Tuple[int, Optional[int]]]:
    """(percentage column, the count column it is named after or None) for each column whose
    header looks like a percentage, rate or share ('%', pct, percent, rate, share)."""
    out = []
    for ci, h in enumerate(table.header):
        if ci in count_cols or ci == 0 or not PCT_HINTS.search(h.text):
            continue
        name = h.text.strip('"').lower()
        paired = [cc for cc in count_cols if table.header[cc].text.strip('"').strip()
                  and re.search(r"(?<![\w-])" + re.escape(table.header[cc].text.strip('"').strip().lower())
                                + r"(?![\w-])", name)]
        out.append((ci, max(paired, key=lambda cc: len(table.header[cc].text)) if paired else None))
    return out


ROUND_BASE = 5
METHODS = ("suppress", "round")


def _table_seed(t: Table) -> bytes:
    """Hash of the table's cell values only (not whitespace, gutters or offsets), so the same
    table always rounds the same way wherever and however often it appears."""
    h = hashlib.sha256(b"egress-guard/round/v1")
    for row in [t.header] + t.rows:
        h.update(b"\x1e" + "\x1f".join(c.text for c in row).encode("utf-8", "surrogatepass"))
    return h.digest()


def _rounded(v: int, seed: bytes, ri: int, ci: int, base: int = ROUND_BASE) -> int:
    """Unbiased random rounding: up with probability (v mod base)/base, else down."""
    rem = v % base
    if rem == 0:
        return v
    d = hashlib.sha256(seed + f"{ri},{ci}".encode()).digest()
    u = int.from_bytes(d[:8], "big") / 2 ** 64                 # uniform in [0, 1)
    return v - rem + (base if u < rem / base else 0)


def _format_like(original: str, v: int) -> str:
    q = original[0] if original[:1] in ('"', "'") else ""
    body = original.strip("\"'")
    s = f"{v:,}" if "," in body else str(v)
    return f"{q}{s}{q}"


def _rounding_findings(t: Table, cols: List[int]) -> List[Finding]:
    seed = _table_seed(t)
    out: List[Finding] = []
    for ri, row in enumerate(t.rows):
        for ci in cols:                                       # totals included, each drawn on its own
            if ci >= len(row):
                continue
            c = row[ci]
            v = _parse_int(c.text)
            if v is None:
                continue
            r = _rounded(v, seed, ri, ci)
            if r != v:
                out.append(Finding(
                    rule="smallcell.rounded",
                    reason=f"Counts in this table are randomly rounded to base {ROUND_BASE} by policy.",
                    start=c.start, end=c.end, masked="[rounded]", severity="low",
                    replacement=_format_like(c.text, r), meta={"row": ri, "col": ci}))
    # Percentages come from the unrounded counts and would give them back: hide them all.
    for pc, _paired in _pct_columns(t, cols):
        for ri, row in enumerate(t.rows):
            if pc < len(row) and row[pc].text.strip('"').lower() not in SUPPRESSION_MARKERS:
                c = row[pc]
                out.append(Finding(
                    rule="smallcell.percentage",
                    reason=(f"Value in column '{t.header[pc].text}' is computed from unrounded counts; "
                            f"suppressing it in rounding mode."),
                    start=c.start, end=c.end, masked="[hidden]", severity="medium",
                    replacement="[suppressed]", meta={"row": ri, "col": pc}))
    return out


def find_small_cells(text: str, threshold: int = 5, min_value: int = 1,
                     complementary: bool = True, tables: Optional[List[Table]] = None,
                     method: str = "suppress") -> List[Finding]:
    """Flag counts with min_value <= v < threshold, plus complementary suppression hints.
    method="round": round every count to base 5 instead (threshold/min_value/complementary unused).
    tables: find_tables(text), if the caller already parsed it."""
    findings: List[Finding] = []
    for t in (find_tables(text) if tables is None else tables):
        cols = _count_columns(t)
        if not cols:
            continue
        if method == "round":
            findings += _rounding_findings(t, cols)
            continue
        total_cols = [c for c in cols if _is_total_col(t.header[c].text)]
        value_cols = [c for c in cols if c not in total_cols]
        flagged = set()  # (row_idx, col_idx)

        for ri, row in enumerate(t.rows):
            for ci in cols:
                if ci >= len(row):
                    continue
                v = _parse_int(row[ci].text)
                if v is not None and min_value <= v < threshold:
                    flagged.add((ri, ci))
                    c = row[ci]
                    findings.append(Finding(
                        rule="smallcell.count",
                        reason=(f"Count of {v} in column '{t.header[ci].text}' is below the "
                                f"minimum cell size of {threshold}."),
                        start=c.start, end=c.end, masked=f"<{threshold}", severity="high",
                        replacement="[suppressed]",
                        meta={"value_bucket": f"<{threshold}", "row": ri, "col": ci}))

        hidden = set(flagged)
        if complementary:
            for ri, ci, where in _complementary_cells(t, cols, total_cols, flagged):
                hidden.add((ri, ci))
                c = t.rows[ri][ci]
                findings.append(Finding(
                    rule="smallcell.complementary",
                    reason=(f"Hidden small cell in {where} could be recovered from the total; "
                            f"also suppressing another cell."),
                    start=c.start, end=c.end, masked="[hidden]", severity="medium",
                    replacement="[suppressed]", meta={"row": ri, "col": ci}))
        hidden |= {(ri, ci) for ri, r in enumerate(t.rows) for ci in cols
                   if ci < len(r) and r[ci].text.strip('"').lower() in SUPPRESSION_MARKERS - {""}}

        # A count can be recovered from its percentage when the total is known, so hide the
        # row's percentage/rate cells too: the one named after a hidden count column, or, for a
        # column not named after any count column, any hidden count in the row.
        for pc, paired in _pct_columns(t, cols):
            for ri, row in enumerate(t.rows):
                if pc >= len(row):
                    continue
                c = row[pc]
                if c.text.strip('"').lower() in SUPPRESSION_MARKERS:
                    continue                                       # empty or already hidden
                hit = (ri, paired) in hidden if paired is not None else any((ri, cc) in hidden for cc in cols)
                if hit:
                    findings.append(Finding(
                        rule="smallcell.percentage",
                        reason=(f"Value in column '{t.header[pc].text}' could reveal a suppressed count "
                                f"in the same row; suppressing it too."),
                        start=c.start, end=c.end, masked="[hidden]", severity="medium",
                        replacement="[suppressed]", meta={"row": ri, "col": pc}))
    return sorted(findings, key=lambda f: f.start)


def _complementary_cells(t: Table, cols: List[int], total_cols: List[int],
                         flagged: set) -> List[Tuple[int, int, str]]:
    """Iterative complementary suppression (a heuristic, not a disclosure guarantee).

    A "line" is a non-total row (its cells sum to the row total), the Total row
    (its cells sum to the grand total), or a column (its non-total cells sum to the
    Total row's cell). Rule, applied until nothing changes: if a line's total is
    visible and exactly one of its cells is hidden, that cell can be recovered by
    subtraction, so hide one more cell in the line: the smallest positive visible
    value, else any visible value, else the line's total itself.

    Terminates: each pass either changes nothing (stop) or hides at least one
    previously visible cell, and there are finitely many cells. A hard cap of
    (cells + 1) passes is enforced as a backstop.

    Known limits: it only removes the "one hidden cell per line" attack. It does
    not solve the full linear system, so combinations of lines can still pin
    down a hidden cell in unusual layouts, and it does not compute tight
    feasibility intervals (e.g. a hidden pair summing to 4 bounds each cell to
    0..4). Cells already showing a suppression marker in the input count as hidden.
    """
    total_rows = [ri for ri, r in enumerate(t.rows) if r and TOTAL_LABEL.match(r[0].text)]
    value_cols = [c for c in cols if c not in total_cols]
    tcol = total_cols[0] if total_cols else None
    trow = total_rows[0] if total_rows else None
    body_rows = [ri for ri in range(len(t.rows)) if ri not in total_rows]

    def cell(ri, ci):
        r = t.rows[ri]
        return r[ci] if ci < len(r) else None

    def value(ri, ci):
        c = cell(ri, ci)
        return _parse_int(c.text) if c is not None else None

    def is_marker(ri, ci):
        c = cell(ri, ci)
        return c is not None and c.text.strip('"').lower() in SUPPRESSION_MARKERS

    hidden = set(flagged)
    hidden |= {(ri, ci) for ri in range(len(t.rows)) for ci in cols if is_marker(ri, ci)}

    lines = []  # (members, total_cell, description)
    if tcol is not None:
        for ri in body_rows:
            lines.append(([(ri, ci) for ci in value_cols], (ri, tcol), f"row {ri + 1}"))
        if trow is not None:
            lines.append(([(trow, ci) for ci in value_cols], (trow, tcol), "the Total row"))
    if trow is not None:
        for ci in value_cols + ([tcol] if tcol is not None else []):
            lines.append(([(ri, ci) for ri in body_rows], (trow, ci),
                          f"column '{t.header[ci].text}'"))

    def visible_value(rc):
        return rc not in hidden and value(*rc) is not None

    added: List[Tuple[int, int, str]] = []
    cap = len(t.rows) * max(len(t.header), 1) + 1
    for _ in range(cap):
        changed = False
        for members, total, where in lines:
            if not visible_value(total):
                continue
            members = [m for m in members if cell(*m) is not None]
            if sum(1 for m in members if m in hidden) != 1:
                continue
            others = [m for m in members if visible_value(m)]
            positive = [m for m in others if value(*m) > 0]
            pool = positive or others
            pick = min(pool, key=lambda m: (value(*m), m)) if pool else total
            hidden.add(pick)
            added.append((pick[0], pick[1], where))
            changed = True
        if not changed:
            break
    else:  # pragma: no cover - backstop, should be unreachable
        raise RuntimeError("complementary suppression did not converge")
    return added
