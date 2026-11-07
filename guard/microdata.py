"""Microdata detection: record-level tables (one row per person/case) leaving the agent.

A table (markdown or delimited, same parser as the small-cell rule) is flagged when it has an
ID-like column and more than max_rows data rows. Heuristic: an aggregate table with an ID-like
column name, or microdata without one, is misjudged. It flags; it does not certify.
"""
import re
from typing import List, Optional

from .findings import Finding
from .smallcell import Table, find_tables

ID_NAMES = {"id", "record_id", "uuid", "case", "person"}
_SEP = re.compile(r"[^a-z0-9]+")


def is_id_column(header: str) -> bool:
    """'record_id', 'Record ID', 'patient_id', 'PersonUUID'? -> normalized and matched."""
    h = header.strip().strip('"').strip("'")
    h = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", h)            # PatientId -> Patient_Id
    norm = _SEP.sub("_", h.lower()).strip("_")
    return norm in ID_NAMES or norm.endswith(("_id", "_uuid"))


def find_microdata(text: str, max_rows: int = 20, tables: Optional[List[Table]] = None) -> List[Finding]:
    findings: List[Finding] = []
    for t in (find_tables(text) if tables is None else tables):
        if len(t.rows) <= max_rows:
            continue
        ids = [c.text for c in t.header if is_id_column(c.text)]
        if not ids:
            continue
        start = t.header[0].start if t.header else 0
        last = t.rows[-1]
        end = last[-1].end if last else start
        findings.append(Finding(
            rule="microdata.table",
            reason=(f"Record-level table: {len(t.rows)} rows with ID-like column "
                    f"'{ids[0]}' (more than {max_rows} rows)."),
            start=start, end=end, masked=f"{len(t.rows)} rows, id column '{ids[0][:40]}'",
            severity="medium", replacement=f"[microdata table withheld: {len(t.rows)} rows]",
            meta={"rows": len(t.rows), "id_column": ids[0]}))
    return findings
