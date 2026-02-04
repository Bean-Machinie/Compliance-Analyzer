from dataclasses import dataclass, field
from typing import List


@dataclass(frozen=True)
class Requirement:
    req_id: str
    source_doc: str


@dataclass(frozen=True)
class TestCase:
    ts_id: str
    ref_id: str
    source_doc: str


@dataclass
class AnalysisResult:
    req_id: str
    covered: bool
    test_steps: List[str] = field(default_factory=list)
