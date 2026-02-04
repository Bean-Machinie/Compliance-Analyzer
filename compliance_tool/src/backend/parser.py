import re
from typing import Iterable, List, Optional

from docx import Document

from src.backend.models import Requirement, TestCase


REQ_PREFIXES_SYSTEM = ("BNC", "DLS", "NSE")
REQ_PREFIXES_STAKEHOLDER = ("BNCS", "DLSS", "NSES")

ID_PATTERN = re.compile(
    r"[#\[\(]?\s*(?P<id>(?:BNC|DLS|NSE|BNCS|DLSS|NSES)\d+)\s*[\]\)]?"
)
TS_PATTERN = re.compile(r"^\d+(?:\.\d+)*$")


def _extract_ids(text: str) -> List[str]:
    return [m.group("id") for m in ID_PATTERN.finditer(text or "")]


def _normalize_header(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (text or "").lower())


def _find_header_indices(header_row: List[str]) -> Optional[tuple]:
    normalized = [_normalize_header(c) for c in header_row]
    ts_idx = None
    ref_idx = None
    for i, cell in enumerate(normalized):
        if cell == "ts":
            ts_idx = i
        if cell in ("ref", "reference"):
            ref_idx = i
    if ts_idx is None or ref_idx is None:
        return None
    return ts_idx, ref_idx


def _is_acceptance_heading(text: str) -> bool:
    normalized = " ".join(text.strip().lower().split())
    return normalized in ("accept criteria", "acceptance criteria")


def parse_requirements(doc_path: str) -> List[Requirement]:
    doc = Document(doc_path)
    requirements: List[Requirement] = []
    seen = set()
    current_stakeholder: Optional[str] = None
    in_acceptance = False

    for para in doc.paragraphs:
        text = (para.text or "").strip()
        if not text:
            continue

        ids = _extract_ids(text)
        stakeholder_ids = [i for i in ids if i.startswith(REQ_PREFIXES_STAKEHOLDER)]
        if stakeholder_ids:
            current_stakeholder = stakeholder_ids[-1]

        if _is_acceptance_heading(text):
            in_acceptance = True
            continue

        if in_acceptance and para.style is not None:
            style_name = (para.style.name or "").lower()
            if style_name.startswith("heading") and not _is_acceptance_heading(text):
                in_acceptance = False

        if not in_acceptance:
            continue

        system_ids = [i for i in ids if i.startswith(REQ_PREFIXES_SYSTEM)]
        for req_id in system_ids:
            key = (req_id, current_stakeholder, doc_path)
            if key in seen:
                continue
            seen.add(key)
            requirements.append(
                Requirement(req_id=req_id, stakeholder_id=current_stakeholder, source_doc=doc_path)
            )

    return requirements


def parse_test_procedures(doc_path: str) -> List[TestCase]:
    doc = Document(doc_path)
    test_cases: List[TestCase] = []

    for table in doc.tables:
        header_idx = None
        header_cols = None
        for i, row in enumerate(table.rows):
            row_text = [c.text.strip() for c in row.cells]
            header_cols = _find_header_indices(row_text)
            if header_cols is not None:
                header_idx = i
                break

        if header_idx is None or header_cols is None:
            continue

        ts_col, ref_col = header_cols
        for row in table.rows[header_idx + 1 :]:
            cells = [c.text.strip() for c in row.cells]
            if len(cells) < max(ts_col, ref_col) + 1:
                continue

            ts_val = cells[ts_col]
            ref_val = cells[ref_col]

            if not ts_val or not ref_val:
                continue

            if not TS_PATTERN.match(ts_val):
                continue

            ids = _extract_ids(ref_val)
            if not ids:
                continue
            for ref_id in ids:
                test_cases.append(TestCase(ts_id=ts_val, ref_id=ref_id, source_doc=doc_path))

    return test_cases
