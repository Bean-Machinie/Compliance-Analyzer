from typing import Dict, Iterable, List, Tuple

from src.backend.models import AnalysisResult, OrphanReference, Requirement, TestCase


def analyze(
    requirements: Iterable[Requirement],
    test_cases: Iterable[TestCase],
) -> Tuple[List[AnalysisResult], List[OrphanReference], Dict[str, float]]:
    req_list = list(requirements)
    tc_list = list(test_cases)
    req_ids = {r.req_id for r in req_list}

    coverage: Dict[str, List[str]] = {}
    for tc in tc_list:
        coverage.setdefault(tc.ref_id, []).append(tc.ts_id)

    results: List[AnalysisResult] = []
    for req in req_list:
        test_steps = sorted(set(coverage.get(req.req_id, [])))
        results.append(
            AnalysisResult(
                req_id=req.req_id,
                stakeholder_id=req.stakeholder_id,
                source_doc=req.source_doc,
                covered=bool(test_steps),
                test_steps=test_steps,
            )
        )

    orphans = [
        OrphanReference(ts_id=tc.ts_id, ref_id=tc.ref_id, source_doc=tc.source_doc)
        for tc in tc_list
        if tc.ref_id not in req_ids
    ]

    total = len(req_list)
    covered = sum(1 for r in results if r.covered)
    uncovered = total - covered
    coverage_pct = (covered / total * 100.0) if total else 0.0

    summary = {
        "total_requirements": total,
        "covered_requirements": covered,
        "uncovered_requirements": uncovered,
        "coverage_percent": round(coverage_pct, 2),
    }

    return results, orphans, summary
