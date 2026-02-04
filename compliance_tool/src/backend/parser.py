import re
from typing import Iterable, List, Optional, Set

from docx import Document

from src.backend.models import Requirement, TestCase


REQ_PREFIXES_SYSTEM = ("BNC", "DLS", "NSE")
REQ_PREFIXES_STAKEHOLDER = ("BNCS", "DLSS", "NSES")
ALL_PREFIXES = REQ_PREFIXES_SYSTEM + REQ_PREFIXES_STAKEHOLDER

ID_PATTERN = re.compile(r"(?:#|\[)?(?P<id>(?:BNC|DLS|NSE|BNCS|DLSS|NSES)\d+)(?:\])?")


def _extract_ids(text: str) -> List[str]:
    return [m.group("id") for m in ID_PATTERN.finditer(text or "")]


def _iter_doc_text(doc: Document) -> Iterable[str]:
    for p in doc.paragraphs:
        if p.text:
            yield p.text
    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                if cell.text:
                    yield cell.text


def parse_requirements(doc_path: str, include_stakeholder: bool = False) -> List[Requirement]:
    doc = Document(doc_path)
    req_ids: Set[str] = set()
    for text in _iter_doc_text(doc):
        for req_id in _extract_ids(text):
            if include_stakeholder:
                req_ids.add(req_id)
            else:
                if req_id.startswith(REQ_PREFIXES_SYSTEM):
                    req_ids.add(req_id)
    return [Requirement(req_id=r, source_doc=doc_path) for r in sorted(req_ids)]


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
            if ts_col >= len(cells) or ref_col >= len(cells):
                continue
            ts_val = cells[ts_col]
            ref_val = cells[ref_col]
            if not ts_val or not ref_val:
                continue
            ids = _extract_ids(ref_val)
            if not ids:
                continue
            ref_id = ids[0]
            test_cases.append(TestCase(ts_id=ts_val, ref_id=ref_id, source_doc=doc_path))

    return test_cases
