from dataclasses import dataclass
from typing import Dict, List, Tuple

from src.backend.models import AnalysisResult, Requirement, TestCase
from src.ui.visualization.visual_model import SankeyLink, SankeyNode


def test_case_id(ts_id: str) -> str:
    return ts_id.split(".")[0] if ts_id else ts_id


def _coverage_for(req_id: str, results_map: Dict[str, AnalysisResult]) -> bool:
    res = results_map.get(req_id)
    return res.covered if res else False


def _filter_requirements(
    requirements: List[Requirement],
    results_map: Dict[str, AnalysisResult],
    stakeholder: str,
    prefix: str,
    coverage: str,
    selected_reqs: List[str],
) -> List[Requirement]:
    filtered = []
    for req in requirements:
        if stakeholder and stakeholder != "All" and req.stakeholder_id != stakeholder:
            continue
        if prefix and prefix != "All" and not req.req_id.startswith(prefix):
            continue
        if coverage and coverage != "All":
            is_covered = _coverage_for(req.req_id, results_map)
            if coverage == "Covered" and not is_covered:
                continue
            if coverage == "Uncovered" and is_covered:
                continue
        if selected_reqs and req.req_id not in selected_reqs:
            continue
        filtered.append(req)
    return filtered


def build_view1_data(
    requirements: List[Requirement],
    test_cases: List[TestCase],
    results: List[AnalysisResult],
    stakeholder: str,
    prefix: str,
    coverage: str,
    selected_reqs: List[str],
) -> Tuple[List[SankeyNode], List[SankeyLink]]:
    results_map = {r.req_id: r for r in results}
    filtered_reqs = _filter_requirements(requirements, results_map, stakeholder, prefix, coverage, selected_reqs)
    filtered_req_ids = {r.req_id for r in filtered_reqs}

    nodes: Dict[str, SankeyNode] = {}
    links: Dict[Tuple[str, str], SankeyLink] = {}

    def add_node(node_id: str, label: str, node_type: str, metadata: dict) -> None:
        if node_id not in nodes:
            nodes[node_id] = SankeyNode(node_id=node_id, label=label, node_type=node_type, metadata=metadata)

    def add_link(source: str, target: str, color: str) -> None:
        key = (source, target)
        if key not in links:
            links[key] = SankeyLink(source=source, target=target, value=1, color=color)
        else:
            links[key].value += 1

    for req in filtered_reqs:
        req_node = f"system:{req.req_id}"
        add_node(req_node, req.req_id, "system", {
            "stakeholder": req.stakeholder_id,
            "source": req.source_doc,
            "covered": _coverage_for(req.req_id, results_map),
        })

    for tc in test_cases:
        if tc.ref_id not in filtered_req_ids:
            continue
        req_node = f"system:{tc.ref_id}"
        tc_id = test_case_id(tc.ts_id)
        tc_node = f"testcase:{tc_id}"
        add_node(tc_node, tc_id, "testcase", {"source": tc.source_doc})
        color = "covered" if _coverage_for(tc.ref_id, results_map) else "uncovered"
        add_link(req_node, tc_node, color)

    return list(nodes.values()), list(links.values())


def build_view2_data(
    requirements: List[Requirement],
    test_cases: List[TestCase],
    results: List[AnalysisResult],
    selected_test_case: str,
    stakeholder: str,
    prefix: str,
    coverage: str,
    selected_reqs: List[str],
) -> Tuple[List[SankeyNode], List[SankeyLink]]:
    if not selected_test_case:
        return [], []

    results_map = {r.req_id: r for r in results}
    req_map = {r.req_id: r for r in requirements}
    filtered_reqs = _filter_requirements(requirements, results_map, stakeholder, prefix, coverage, selected_reqs)
    filtered_req_ids = {r.req_id for r in filtered_reqs}

    nodes: Dict[str, SankeyNode] = {}
    links: Dict[Tuple[str, str], SankeyLink] = {}

    def add_node(node_id: str, label: str, node_type: str, metadata: dict) -> None:
        if node_id not in nodes:
            nodes[node_id] = SankeyNode(node_id=node_id, label=label, node_type=node_type, metadata=metadata)

    def add_link(source: str, target: str, color: str) -> None:
        key = (source, target)
        if key not in links:
            links[key] = SankeyLink(source=source, target=target, value=1, color=color)
        else:
            links[key].value += 1

    for tc in test_cases:
        if test_case_id(tc.ts_id) != selected_test_case:
            continue
        if tc.ref_id not in filtered_req_ids:
            continue
        req = req_map.get(tc.ref_id)
        if not req:
            continue
        req_node = f"system:{req.req_id}"
        step_node = f"teststep:{tc.ts_id}"
        add_node(req_node, req.req_id, "system", {
            "stakeholder": req.stakeholder_id,
            "source": req.source_doc,
            "covered": _coverage_for(req.req_id, results_map),
        })
        add_node(step_node, tc.ts_id, "teststep", {
            "source": tc.source_doc,
            "requirements": req.req_id,
        })
        color = "covered" if _coverage_for(req.req_id, results_map) else "uncovered"
        add_link(req_node, step_node, color)

    return list(nodes.values()), list(links.values())
