from typing import Dict, Iterable, List

from src.backend.models import AnalysisResult, Requirement, TestCase


def analyze(requirements: Iterable[Requirement], test_cases: Iterable[TestCase]) -> List[AnalysisResult]:
    coverage: Dict[str, List[str]] = {}
    for tc in test_cases:
        coverage.setdefault(tc.ref_id, []).append(tc.ts_id)

    results: List[AnalysisResult] = []
    for req in requirements:
        test_steps = sorted(set(coverage.get(req.req_id, [])))
        results.append(
            AnalysisResult(
                req_id=req.req_id,
                covered=bool(test_steps),
                test_steps=test_steps,
            )
        )
    return results
