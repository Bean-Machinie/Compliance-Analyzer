from dataclasses import dataclass, field
from typing import List, Optional


@dataclass(frozen=True)
class Requirement:
    req_id: str
    stakeholder_id: Optional[str]
    source_doc: str


@dataclass(frozen=True)
class TestCase:
    ts_id: str
    ref_id: str
    source_doc: str
    test_case_id: Optional[str] = None
    test_case_title: Optional[str] = None


@dataclass(frozen=True)
class AnalysisResult:
    req_id: str
    stakeholder_id: Optional[str]
    source_doc: str
    covered: bool
    test_steps: List[str] = field(default_factory=list)
    test_cases: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class OrphanReference:
    ts_id: str
    ref_id: str
    source_doc: str
