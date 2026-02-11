from typing import Dict, Iterable, List, Optional, Set, Tuple

from src.backend.models import AnalysisResult, OrphanReference, Requirement, TestCase

STAKEHOLDER_PREFIXES = ("BNCS", "DLSS", "NSES")


def analyze(
    requirements: Iterable[Requirement],
    test_cases: Iterable[TestCase],
    excluded_req_ids: Optional[Set[str]] = None,
) -> Tuple[List[AnalysisResult], List[OrphanReference], Dict[str, float]]:
    req_list = list(requirements)
    tc_list = list(test_cases)
    req_ids = {r.req_id for r in req_list}
    excluded = set(excluded_req_ids or set())
    req_ids_for_orphans = req_ids | excluded

    coverage: Dict[str, List[str]] = {}
    case_coverage: Dict[str, List[str]] = {}
    for tc in tc_list:
        if tc.ts_id:
            coverage.setdefault(tc.ref_id, []).append(tc.ts_id)
        if tc.test_case_id:
            label = f"Test Case {tc.test_case_id}"
            if tc.test_case_title:
                label = f"{label}: {tc.test_case_title}"
            case_coverage.setdefault(tc.ref_id, []).append(label)

    results: List[AnalysisResult] = []
    for req in req_list:
        test_steps = sorted(set(coverage.get(req.req_id, [])))
        test_cases = sorted(set(case_coverage.get(req.req_id, [])))
        results.append(
            AnalysisResult(
                req_id=req.req_id,
                stakeholder_id=req.stakeholder_id,
                source_doc=req.source_doc,
                covered=bool(test_steps or test_cases),
                test_steps=test_steps,
                test_cases=test_cases,
            )
        )

    orphans = [
        OrphanReference(ts_id=tc.ts_id, ref_id=tc.ref_id, source_doc=tc.source_doc)
        for tc in tc_list
        if tc.ref_id not in req_ids_for_orphans
        and not tc.ref_id.startswith(STAKEHOLDER_PREFIXES)
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
